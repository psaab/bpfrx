//! End-to-end tests for the WG engine.
//!
//! These tests build two engines (one initiator, one responder),
//! drive a Noise IK handshake between them, install the resulting
//! transport sessions, then verify encap/decap roundtrip and the
//! AllowedIPs / replay / VLAN / DSCP / MSS properties.

use super::allowed_ips::AllowedIps;
use super::dscp::tos_from_dscp;
use super::engine::{DecapError, EncapError, WgEngine, WgEngineConfig, WgPeerConfig};
use super::framing::{encode_data_header, parse_data_header};
use super::mss::wg_tcp_mss;
use super::outer::{outer_l2_len, write_outer_eth, write_outer_ipv4_udp};
use super::scratch::WgWorkerScratch;
use super::session::WgSession;
use snow::Builder;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

/// Generate a fresh X25519 keypair using snow's resolver. Slow
/// path — fine for tests.
fn keypair() -> ([u8; 32], [u8; 32]) {
    let kp = Builder::new(super::WG_NOISE_PATTERN.parse().unwrap())
        .generate_keypair()
        .unwrap();
    let mut priv_k = [0u8; 32];
    let mut pub_k = [0u8; 32];
    priv_k.copy_from_slice(&kp.private);
    pub_k.copy_from_slice(&kp.public);
    (priv_k, pub_k)
}

/// Set up two engines and drive the IK handshake between them.
/// Returns `(initiator_engine, responder_engine, init_pub, resp_pub)`.
///
/// The handshake is driven entirely on the slow path of both
/// sides — exactly the pattern a real worker would use to install
/// sessions for the hot path.
fn established_pair(
    init_allowed_for_resp: Vec<ipnet::IpNet>,
    resp_allowed_for_init: Vec<ipnet::IpNet>,
) -> (WgEngine, WgEngine, [u8; 32], [u8; 32]) {
    let (init_priv, init_pub) = keypair();
    let (resp_priv, resp_pub) = keypair();

    let init_engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv,
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: resp_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: init_allowed_for_resp,
        }],
    });
    let resp_engine = WgEngine::new(WgEngineConfig {
        local_private_key: resp_priv,
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: init_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: resp_allowed_for_init,
        }],
    });

    // Drive the IK handshake. Two messages: init→resp, then
    // resp→init. No further pumping needed; snow has no hidden
    // queues to drain.
    let mut init_hs = init_engine.build_initiator_handshake(&resp_pub).unwrap();
    let mut resp_hs = resp_engine.build_responder_handshake().unwrap();
    let mut buf = [0u8; 1024];

    // Initiation.
    let n1 = init_hs.write_message(&[], &mut buf).unwrap();
    let mut sink = [0u8; 1024];
    resp_hs.read_message(&buf[..n1], &mut sink).unwrap();

    // Response.
    let n2 = resp_hs.write_message(&[], &mut buf).unwrap();
    init_hs.read_message(&buf[..n2], &mut sink).unwrap();

    let init_xport = init_hs.into_stateless_transport_mode().unwrap();
    let resp_xport = resp_hs.into_stateless_transport_mode().unwrap();

    // Choose receiver indices. In real WG they're chosen at
    // handshake-message build time. For the engine tests we pick
    // them deterministically here and tell each side what the peer
    // chose.
    let init_local_index = 0xaaaa_0001;
    let resp_local_index = 0xbbbb_0001;
    // Initiator session is created with Initiator-role (confirmed at
    // install per WG spec — the initiator is the side that sends
    // first). Responder session is created with Responder-role to be
    // faithful to the wire contract; we then pre-confirm it so existing
    // round-trip tests that encap from the responder side continue
    // to function. The key-confirmation invariant itself is exercised
    // by `responder_session_blocks_encap_until_initiator_data_authenticated`
    // and `established_pair_responder_confirmation_flips_via_decap_path`
    // — see Copilot inline finding on the prior round of this PR.
    let init_session = Arc::new(WgSession::new_with_role(
        init_xport,
        init_local_index,
        resp_local_index,
        resp_pub,
        super::session::SessionRole::Initiator,
    ));
    let resp_session = Arc::new(WgSession::new_with_role(
        resp_xport,
        resp_local_index,
        init_local_index,
        init_pub,
        super::session::SessionRole::Responder,
    ));
    // Pre-confirm the responder so callers that don't want to drive
    // the gate (the bulk of the tests in this file) can encap from
    // either side immediately. The gate tests do NOT call this
    // helper and manage confirmation explicitly.
    resp_session.mark_confirmed();
    init_engine
        .install_session(&resp_pub, init_session)
        .unwrap();
    resp_engine
        .install_session(&init_pub, resp_session)
        .unwrap();

    (init_engine, resp_engine, init_pub, resp_pub)
}

/// Build a minimal IPv4 packet with the given src/dst and a 20-byte
/// payload. Returns the IP-header-onward bytes (no L2).
fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let mut p = vec![0u8; 40];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&40u16.to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p
}

#[test]
fn handshake_completes_and_roundtrip_encap_decap() {
    let resp_allowed = vec!["10.0.0.0/24".parse().unwrap()];
    let init_allowed = vec!["10.0.1.0/24".parse().unwrap()];
    let (init_engine, resp_engine, init_pub, resp_pub) =
        established_pair(init_allowed, resp_allowed);

    let inner = ipv4_packet(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 1, 5));
    let mut wire = [0u8; 2048];
    let enc = init_engine.try_encap(&resp_pub, &inner, &mut wire).unwrap();

    // Wire image: header (16) + padded_plaintext (16-byte multiple
    // >= inner.len()) + tag (16). WG spec §5.4.6 mandates the
    // plaintext be zero-padded to a 16-byte multiple before AEAD.
    let padded = (inner.len() + 15) & !15;
    assert_eq!(enc.len, 16 + padded + 16);
    assert!(padded >= inner.len());
    assert_eq!(padded % 16, 0);

    let mut plain = [0u8; 2048];
    let dec = resp_engine.try_decap(&wire[..enc.len], &mut plain).unwrap();
    assert_eq!(dec.peer_pubkey, init_pub);
    // `dec.len` is the un-padded inner-IP packet length read from
    // the IPv4 `total_length` field. It must equal the original
    // sent inner packet length, not the padded plaintext length.
    assert_eq!(dec.len, inner.len());
    assert_eq!(&plain[..dec.len], &inner[..]);
}

#[test]
fn decap_rejects_inner_src_outside_allowed_ips() {
    // The responder's peer (the initiator) is allowed 10.0.0.0/24.
    // The initiator sends a packet with src 10.0.99.99 — must be
    // dropped by the AllowedIPs gate, NOT silently accepted.
    let (init_engine, resp_engine, _init_pub, resp_pub) = established_pair(
        vec!["10.0.1.0/24".parse().unwrap()],
        vec!["10.0.0.0/24".parse().unwrap()],
    );
    let inner = ipv4_packet(Ipv4Addr::new(10, 0, 99, 99), Ipv4Addr::new(10, 0, 1, 5));
    let mut wire = [0u8; 2048];
    let enc = init_engine.try_encap(&resp_pub, &inner, &mut wire).unwrap();
    let mut plain = [0u8; 2048];
    let err = resp_engine
        .try_decap(&wire[..enc.len], &mut plain)
        .unwrap_err();
    assert_eq!(err, DecapError::AllowedIpsViolation);
}

#[test]
fn replay_window_rejects_duplicate_ciphertext() {
    let (init_engine, resp_engine, _init_pub, resp_pub) = established_pair(
        vec!["10.0.1.0/24".parse().unwrap()],
        vec!["10.0.0.0/24".parse().unwrap()],
    );
    let inner = ipv4_packet(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 1, 5));
    let mut wire = [0u8; 2048];
    let enc = init_engine.try_encap(&resp_pub, &inner, &mut wire).unwrap();
    let mut plain = [0u8; 2048];
    assert!(resp_engine.try_decap(&wire[..enc.len], &mut plain).is_ok());
    let err = resp_engine
        .try_decap(&wire[..enc.len], &mut plain)
        .unwrap_err();
    assert_eq!(err, DecapError::ReplayDuplicate);
}

#[test]
fn encap_unknown_peer_returns_error_not_random_session() {
    // The cryptokey-routing safety property — if the caller asks
    // us to encrypt to a peer we don't have, we must error, NOT
    // fall back to some other peer.
    let (init_engine, _resp_engine, _init_pub, _resp_pub) = established_pair(
        vec!["10.0.1.0/24".parse().unwrap()],
        vec!["10.0.0.0/24".parse().unwrap()],
    );
    let bogus = [0xcd; 32];
    let inner = ipv4_packet(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 1, 5));
    let mut wire = [0u8; 2048];
    let err = init_engine
        .try_encap(&bogus, &inner, &mut wire)
        .unwrap_err();
    assert_eq!(err, EncapError::UnknownPeer);
}

#[test]
fn cryptokey_routing_overlapping_allowed_ips() {
    let (init_priv, init_pub) = keypair();
    let (peer_a_priv, peer_a_pub) = keypair();
    let (peer_b_priv, peer_b_pub) = keypair();

    let init_engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv,
        listen_port: 51820,
        peers: vec![
            WgPeerConfig {
                pubkey: peer_a_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            },
            WgPeerConfig {
                pubkey: peer_b_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            },
        ],
    });
    // Stand up real engines for both peers.
    let resp_a = WgEngine::new(WgEngineConfig {
        local_private_key: peer_a_priv,
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: init_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
        }],
    });
    let resp_b = WgEngine::new(WgEngineConfig {
        local_private_key: peer_b_priv,
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: init_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
        }],
    });

    // Drive IK init↔A.
    let mut init_hs = init_engine.build_initiator_handshake(&peer_a_pub).unwrap();
    let mut resp_hs = resp_a.build_responder_handshake().unwrap();
    let mut buf = [0u8; 1024];
    let mut sink = [0u8; 1024];
    let n1 = init_hs.write_message(&[], &mut buf).unwrap();
    resp_hs.read_message(&buf[..n1], &mut sink).unwrap();
    let n2 = resp_hs.write_message(&[], &mut buf).unwrap();
    init_hs.read_message(&buf[..n2], &mut sink).unwrap();

    let init_xport = init_hs.into_stateless_transport_mode().unwrap();
    let resp_xport = resp_hs.into_stateless_transport_mode().unwrap();
    let init_idx = 0x1111_2222;
    let resp_idx = 0x3333_4444;
    init_engine
        .install_session(
            &peer_a_pub,
            Arc::new(WgSession::new(init_xport, init_idx, resp_idx, peer_a_pub)),
        )
        .unwrap();
    resp_a
        .install_session(
            &init_pub,
            Arc::new(WgSession::new(resp_xport, resp_idx, init_idx, init_pub)),
        )
        .unwrap();

    // Drive IK init↔B.
    let mut init_hs = init_engine.build_initiator_handshake(&peer_b_pub).unwrap();
    let mut resp_hs = resp_b.build_responder_handshake().unwrap();
    let n1 = init_hs.write_message(&[], &mut buf).unwrap();
    resp_hs.read_message(&buf[..n1], &mut sink).unwrap();
    let n2 = resp_hs.write_message(&[], &mut buf).unwrap();
    init_hs.read_message(&buf[..n2], &mut sink).unwrap();
    let init_xport = init_hs.into_stateless_transport_mode().unwrap();
    let resp_xport = resp_hs.into_stateless_transport_mode().unwrap();
    let init_idx = 0x5555_6666;
    let resp_idx = 0x7777_8888;
    init_engine
        .install_session(
            &peer_b_pub,
            Arc::new(WgSession::new(init_xport, init_idx, resp_idx, peer_b_pub)),
        )
        .unwrap();
    resp_b
        .install_session(
            &init_pub,
            Arc::new(WgSession::new(resp_xport, resp_idx, init_idx, init_pub)),
        )
        .unwrap();

    let inner = ipv4_packet(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 9));
    let mut wire = [0u8; 2048];

    // Asking for A must use A's session, not silently route to B.
    let enc = init_engine
        .try_encap(&peer_a_pub, &inner, &mut wire)
        .unwrap();
    let mut plain = [0u8; 2048];
    let dec = resp_a.try_decap(&wire[..enc.len], &mut plain).unwrap();
    assert_eq!(dec.peer_pubkey, init_pub);
    let err = resp_b.try_decap(&wire[..enc.len], &mut plain).unwrap_err();
    assert_eq!(err, DecapError::UnknownSession);

    // Asking for B still works and decrypts only at B.
    let enc = init_engine
        .try_encap(&peer_b_pub, &inner, &mut wire)
        .unwrap();
    let dec = resp_b.try_decap(&wire[..enc.len], &mut plain).unwrap();
    assert_eq!(dec.peer_pubkey, init_pub);
}

#[test]
fn framing_layout_matches_spec() {
    // Belt-and-braces check that what try_encap emits has the
    // expected on-wire shape: type=4 in byte 0, receiver_index
    // little-endian in bytes 4..8, counter little-endian in 8..16.
    let (init_engine, _resp_engine, _init_pub, resp_pub) = established_pair(
        vec!["10.0.1.0/24".parse().unwrap()],
        vec!["10.0.0.0/24".parse().unwrap()],
    );
    let inner = ipv4_packet(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 1, 5));
    let mut wire = [0u8; 2048];
    let enc = init_engine.try_encap(&resp_pub, &inner, &mut wire).unwrap();
    let parsed = parse_data_header(&wire[..enc.len]).unwrap();
    assert_eq!(parsed.receiver_index, enc.receiver_index);
    assert_eq!(parsed.counter, enc.counter);
    assert_eq!(wire[0], 4);
}

#[test]
fn outer_l2_with_vlan_when_set() {
    // VLAN-safe encap: when tx_vlan_id != 0, the outer L2 carries
    // an 802.1Q tag. This was the #1492 VLAN-unsafe miss.
    let mut buf = [0u8; 64];
    let n_no_vlan = write_outer_eth(&mut buf, [0; 6], [0; 6], 0, 0x0800).unwrap();
    assert_eq!(n_no_vlan, 14);
    let n_vlan = write_outer_eth(&mut buf, [0; 6], [0; 6], 100, 0x0800).unwrap();
    assert_eq!(n_vlan, 18);
    assert_eq!(&buf[12..14], &[0x81, 0x00]);
    assert_eq!(outer_l2_len(0), 14);
    assert_eq!(outer_l2_len(100), 18);
}

#[test]
fn outer_ipv4_tos_propagates_dscp() {
    // EF (DSCP 46) must show up in the outer TOS byte as 0xb8.
    // ECN bits remain cleared.
    let mut buf = [0u8; 64];
    let tos = tos_from_dscp(46);
    assert_eq!(tos, 0xb8);
    let _ = write_outer_ipv4_udp(
        &mut buf,
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        51820,
        51820,
        tos,
        64,
        100,
    )
    .unwrap();
    assert_eq!(buf[1], 0xb8);
    assert_eq!(buf[1] & 0x03, 0); // ECN cleared
}

#[test]
fn mss_clamp_matches_byte_breakdown() {
    // Sanity: 1500-byte outer MTU, v4-in-v4, MSS = 1385. The 1385
    // (vs the pre-padding-fix 1400) leaves room for the worst-case
    // 15 bytes of WG §5.4.6 padding the encap side may add. See
    // mss.rs for the byte-by-byte derivation. Repeated here in the
    // integration tests because review-time errors on MSS math
    // ship and silently fragment.
    assert_eq!(wg_tcp_mss(libc::AF_INET, libc::AF_INET, 1500), 1385);
}

#[test]
fn worker_scratch_no_realloc_under_repeated_encap() {
    let (init_engine, _resp_engine, _init_pub, resp_pub) = established_pair(
        vec!["10.0.1.0/24".parse().unwrap()],
        vec!["10.0.0.0/24".parse().unwrap()],
    );
    let inner = ipv4_packet(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 1, 5));
    let scratch = WgWorkerScratch::new(2048);
    let initial_ptr = scratch.encap_out.borrow().as_ptr();
    for _ in 0..256 {
        let mut buf = scratch.encap_out.borrow_mut();
        let _ = init_engine.try_encap(&resp_pub, &inner, &mut buf).unwrap();
    }
    // No reallocation across 256 encaps. If a future change adds
    // a per-packet `vec![]` on the scratch buffer, this test will
    // catch it.
    //
    // TODO(#1499 r4 / hot-path-discipline): this test only proves
    // the scratch `Vec` doesn't grow. It does NOT prove that
    // `try_encap` itself avoids internal allocation (e.g. an
    // accidental `Vec::with_capacity` inside snow or the engine).
    // The proper instrumentation is `assert_no_alloc` or a custom
    // `GlobalAlloc` that panics on alloc during the hot section.
    // Adding it now would change crate-level test infra; deferred
    // to a follow-up PR that introduces the harness once the
    // integration PR has the full hot path under test.
    assert_eq!(scratch.encap_out.borrow().as_ptr(), initial_ptr);
}

#[test]
fn transport_plaintext_is_padded_to_16_byte_multiple() {
    // WG spec §5.4.6 — every plaintext input to the data-AEAD must
    // be zero-padded to a multiple of 16 before encryption. Test
    // several inner-packet lengths to cover both the "exact
    // multiple" and "needs padding" arms.
    let (init_engine, resp_engine, _init_pub, resp_pub) = established_pair(
        vec!["10.0.1.0/24".parse().unwrap()],
        vec!["10.0.0.0/24".parse().unwrap()],
    );
    for inner_len in [20usize, 32, 33, 47, 48, 49, 1500] {
        let mut inner = vec![0u8; inner_len];
        inner[0] = 0x45; // IPv4
        inner[2..4].copy_from_slice(&(inner_len as u16).to_be_bytes());
        inner[9] = 17; // UDP
        inner[12..16].copy_from_slice(&[10, 0, 0, 5]);
        inner[16..20].copy_from_slice(&[10, 0, 1, 5]);
        let mut wire = [0u8; 4096];
        let enc = init_engine
            .try_encap(&resp_pub, &inner, &mut wire)
            .unwrap_or_else(|e| panic!("inner_len={inner_len}: {e:?}"));
        let expected_padded = (inner_len + 15) & !15;
        let ciphertext_len = enc.len - 16 /* hdr */ - 16 /* tag */;
        assert_eq!(
            ciphertext_len, expected_padded,
            "padding mismatch at inner_len={inner_len}: got {ciphertext_len}, want {expected_padded}",
        );
        // Roundtrip: decap returns the un-padded inner-IP length.
        // The first `inner_len` bytes of `plain` must equal the
        // original inner packet; `dec.len` must equal `inner_len`,
        // NOT `expected_padded`.
        let mut plain = [0u8; 4096];
        let dec = resp_engine.try_decap(&wire[..enc.len], &mut plain).unwrap();
        assert_eq!(&plain[..inner_len], &inner[..]);
        assert_eq!(
            dec.len, inner_len,
            "DecapOutcome.len must be the inner-IP packet length, not the padded plaintext length",
        );
    }
}

#[test]
fn decap_rejects_counter_at_reject_after_messages() {
    // WG spec §6.5 — receiver MUST refuse data messages whose
    // counter is at or above REJECT_AFTER_MESSAGES, without
    // attempting AEAD. Symmetric to the encap-side guard.
    use super::framing::encode_data_header;
    use super::session::REJECT_AFTER_MESSAGES;
    let (_init_engine, resp_engine, _init_pub, _resp_pub) = established_pair(
        vec!["10.0.1.0/24".parse().unwrap()],
        vec!["10.0.0.0/24".parse().unwrap()],
    );
    // Hand-craft a record with a counter at the spec limit. We
    // don't need real ciphertext — the counter check fires before
    // the demux lookup or AEAD attempt.
    let mut wire = [0u8; 64];
    encode_data_header(&mut wire, /*receiver_idx*/ 0xdead_beef, REJECT_AFTER_MESSAGES).unwrap();
    let mut plain = [0u8; 128];
    let err = resp_engine.try_decap(&wire[..32], &mut plain).unwrap_err();
    assert_eq!(err, DecapError::CounterRejectAfterMessages);
}

/// Cross-peer overlapping AllowedIPs MUST honor WG §5.4.6 global
/// LPM cryptokey routing. If peer A owns `10.0.0.0/8` and peer B
/// owns `10.1.1.0/24`, a packet authenticated by A with inner src
/// `10.1.1.5` must be rejected — the global LPM resolves that
/// address to B, not A. An earlier r4 revision used a per-peer
/// "any prefix covers" check that wrongly accepted A's spoofed
/// source; this regression test fails under that semantic.
#[test]
fn decap_lpm_rejects_spoofed_source_inside_more_specific_peer_prefix() {
    let (init_priv, init_pub) = keypair();
    let (peer_a_priv, peer_a_pub) = keypair();
    let (peer_b_priv, peer_b_pub) = keypair();

    // Initiator engine owns AllowedIPs for both peers: A=/8 (less
    // specific) and B=/24 (more specific, inside A's prefix).
    let init_engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv,
        listen_port: 51820,
        peers: vec![
            WgPeerConfig {
                pubkey: peer_a_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec!["10.0.0.0/8".parse().unwrap()],
            },
            WgPeerConfig {
                pubkey: peer_b_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec!["10.1.1.0/24".parse().unwrap()],
            },
        ],
    });
    // Responder engines mirror that view from each peer's side.
    let resp_a = WgEngine::new(WgEngineConfig {
        local_private_key: peer_a_priv,
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: init_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec!["10.0.0.0/8".parse().unwrap()],
        }],
    });
    let _resp_b = WgEngine::new(WgEngineConfig {
        local_private_key: peer_b_priv,
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: init_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec!["10.1.1.0/24".parse().unwrap()],
        }],
    });

    // We want to demonstrate: a packet that AUTHENTICATES under
    // peer A's session (because A's session was used to encrypt)
    // but whose inner src lies inside peer B's /24 must be
    // rejected by the DECAP-side AllowedIPs gate. Drive the
    // handshake init↔A, install sessions, and have A encrypt a
    // packet with src `10.1.1.5`. The init engine must then
    // verify on receive that the inner src doesn't belong to A.
    let mut init_hs = init_engine.build_initiator_handshake(&peer_a_pub).unwrap();
    let mut resp_hs = resp_a.build_responder_handshake().unwrap();
    let mut buf = [0u8; 1024];
    let mut sink = [0u8; 1024];
    let n1 = init_hs.write_message(&[], &mut buf).unwrap();
    resp_hs.read_message(&buf[..n1], &mut sink).unwrap();
    let n2 = resp_hs.write_message(&[], &mut buf).unwrap();
    init_hs.read_message(&buf[..n2], &mut sink).unwrap();
    let init_xport = init_hs.into_stateless_transport_mode().unwrap();
    let resp_xport = resp_hs.into_stateless_transport_mode().unwrap();
    let init_idx = 0x1111_aaaa;
    let resp_idx = 0x2222_aaaa;
    init_engine
        .install_session(
            &peer_a_pub,
            Arc::new(WgSession::new(init_xport, init_idx, resp_idx, peer_a_pub)),
        )
        .unwrap();
    resp_a
        .install_session(
            &init_pub,
            Arc::new(WgSession::new(resp_xport, resp_idx, init_idx, init_pub)),
        )
        .unwrap();

    // A sends a packet with src 10.1.1.5 (inside B's /24, NOT
    // authoritative for A under global LPM) to init_engine.
    let inner = ipv4_packet(Ipv4Addr::new(10, 1, 1, 5), Ipv4Addr::new(10, 0, 0, 9));
    let mut wire = [0u8; 2048];
    let enc = resp_a.try_encap(&init_pub, &inner, &mut wire).unwrap();
    let mut plain = [0u8; 2048];
    let err = init_engine
        .try_decap(&wire[..enc.len], &mut plain)
        .unwrap_err();
    assert_eq!(
        err,
        DecapError::AllowedIpsViolation,
        "global LPM resolves 10.1.1.5 to peer B; A's /8 must NOT authorize that source"
    );
}

/// On every post-AEAD error arm, `out[..n]` must be wiped before
/// returning so the contract "on Err the caller MUST NOT inspect
/// `out`" is structurally enforced. Earlier r4 revisions covered
/// only 3 of 5 error arms; Codex r4 finding 3 / Gemini r4 finding F.
#[test]
fn decap_zeros_plaintext_on_allowed_ips_violation() {
    // Set the AllowedIPs trie so the responder's view of the
    // initiator covers `10.0.0.0/24` only. The initiator then
    // sends with inner src `10.0.99.99` — authenticates, fails
    // AllowedIPs gate, must return AllowedIpsViolation AND wipe.
    let (init_engine, resp_engine, _init_pub, resp_pub) = established_pair(
        vec!["10.0.1.0/24".parse().unwrap()],
        vec!["10.0.0.0/24".parse().unwrap()],
    );
    let inner = ipv4_packet(Ipv4Addr::new(10, 0, 99, 99), Ipv4Addr::new(10, 0, 1, 5));
    let mut wire = [0u8; 2048];
    let enc = init_engine.try_encap(&resp_pub, &inner, &mut wire).unwrap();
    let mut plain = [0u8; 2048];
    // Pre-fill `plain` with a recognizable pattern; the wipe must
    // overwrite any decrypted bytes back to zero by the time we
    // observe `plain` after the error return.
    plain.fill(0xa5);
    let err = resp_engine
        .try_decap(&wire[..enc.len], &mut plain)
        .unwrap_err();
    assert_eq!(err, DecapError::AllowedIpsViolation);
    // The plaintext-bearing region — the first `padded_inner_len`
    // bytes that snow decrypted into `out` — must be all zeros.
    // Bytes past that region were never touched by the engine and
    // still hold the 0xa5 pre-fill. snow writes
    // `(inner.len() + 15) & !15` bytes (the padded plaintext).
    let padded_inner_len = (inner.len() + 15) & !15;
    assert!(
        plain[..padded_inner_len].iter().all(|&b| b == 0),
        "AllowedIpsViolation must zero out[..n] ({} bytes); first {} bytes are {:?}",
        padded_inner_len,
        padded_inner_len,
        &plain[..padded_inner_len],
    );
}

#[test]
fn decap_zeros_plaintext_on_malformed_inner() {
    // Force a `MalformedInner` arm: encap a payload whose first
    // byte has IP version != 4/6 so `inner_src_ip` returns None.
    // The packet authenticates (it's just bytes to the AEAD) but
    // the post-decrypt parse fails, and the engine must wipe.
    let (init_engine, resp_engine, _init_pub, resp_pub) = established_pair(
        vec!["10.0.1.0/24".parse().unwrap()],
        vec!["10.0.0.0/24".parse().unwrap()],
    );
    // 32-byte payload, first nibble = 0 (no valid IP version).
    let mut inner = vec![0u8; 32];
    inner[0] = 0x05;
    let mut wire = [0u8; 2048];
    let enc = init_engine.try_encap(&resp_pub, &inner, &mut wire).unwrap();
    let mut plain = [0u8; 2048];
    plain.fill(0xa5);
    let err = resp_engine
        .try_decap(&wire[..enc.len], &mut plain)
        .unwrap_err();
    assert_eq!(err, DecapError::MalformedInner);
    let padded_inner_len = (inner.len() + 15) & !15;
    assert!(
        plain[..padded_inner_len].iter().all(|&b| b == 0),
        "MalformedInner must zero out[..n] ({} bytes); first {} bytes are {:?}",
        padded_inner_len,
        padded_inner_len,
        &plain[..padded_inner_len],
    );
}

/// r5 regression: the encap path stages plaintext through a
/// stack `MaybeUninit<[u8; PADDED_PLAINTEXT_MAX]>` and writes it
/// via raw pointer (not via a `&mut [u8; N]` reference) to keep
/// the un-padded bytes truly uninitialized without crossing the
/// reference-validity invariant. This test bombards the path with
/// a range of inner-IP sizes (covering 0-byte padding, full-15-byte
/// padding, and the PADDED_PLAINTEXT_MAX upper bound) and verifies
/// every roundtrip succeeds with the correct un-padded length —
/// any UB in the raw-pointer write or any miscounted padding
/// boundary would either corrupt the AEAD (decap returns
/// CryptoFailed) or produce a wrong `dec.len`.
#[test]
fn encap_decap_varied_inner_sizes_roundtrip() {
    let (init_engine, resp_engine, init_pub, resp_pub) = established_pair(
        vec!["10.0.1.0/24".parse().unwrap()],
        vec!["10.0.0.0/24".parse().unwrap()],
    );
    // Sizes chosen to span:
    //   - 20: minimum IPv4 header, padding = 12
    //   - 32: padding boundary, padding = 0
    //   - 33: padding = 15 (worst case)
    //   - 1280, 1500: typical MTU sizes
    //   - 4080: the PADDED_PLAINTEXT_MAX inner-payload cap (padded
    //     to 4080 + 0 = 4080, exercises the upper boundary of the
    //     raw-pointer write region)
    for size in [20usize, 32, 33, 64, 100, 256, 1280, 1500, 4080] {
        let mut inner = vec![0u8; size];
        // IPv4 header: version 4, IHL 5, total_length = size.
        inner[0] = 0x45;
        let len_be = (size as u16).to_be_bytes();
        inner[2] = len_be[0];
        inner[3] = len_be[1];
        // src 10.0.0.5 → must match the responder's allowed_ips for the initiator.
        inner[12..16].copy_from_slice(&[10, 0, 0, 5]);
        // dst 10.0.1.5
        inner[16..20].copy_from_slice(&[10, 0, 1, 5]);
        // Fill the rest with a non-zero marker so any uninitialized-
        // memory leak would visibly perturb the decapped output.
        for (i, b) in inner.iter_mut().enumerate().skip(20) {
            *b = ((i * 31) & 0xff) as u8;
        }

        // Pre-fill the output buffer with a non-zero marker — if the
        // raw-pointer write accidentally left a "hole" in the padded
        // plaintext, the AEAD would authenticate the marker bytes
        // and decap would either fail or return mismatched plaintext.
        let mut wire = [0xa5u8; 6000];
        let enc = init_engine
            .try_encap(&resp_pub, &inner, &mut wire)
            .unwrap_or_else(|e| panic!("encap failed at size={}: {:?}", size, e));
        let padded = (size + 15) & !15;
        assert_eq!(enc.len, 16 + padded + 16, "wire len off at size={}", size);

        let mut plain = [0u8; 6000];
        let dec = resp_engine
            .try_decap(&wire[..enc.len], &mut plain)
            .unwrap_or_else(|e| panic!("decap failed at size={}: {:?}", size, e));
        assert_eq!(dec.peer_pubkey, init_pub, "wrong peer at size={}", size);
        assert_eq!(dec.len, size, "wrong un-padded len at size={}", size);
        assert_eq!(
            &plain[..dec.len],
            &inner[..],
            "plaintext mismatch at size={}",
            size
        );
        // Bytes beyond the un-padded inner-IP length up to the
        // padded length must be zero — WG §5.4.6. The decap already
        // verifies this; we assert it explicitly here to anchor the
        // padding contract under the raw-pointer write path.
        for j in dec.len..padded {
            assert_eq!(
                plain[j], 0,
                "padding byte at plain[{}] should be 0, was 0x{:02x} (size={})",
                j, plain[j], size
            );
        }
    }
}

/// r5 regression: encap with an inner_ip whose padded length lands
/// exactly at PADDED_PLAINTEXT_MAX = 4096 must succeed; one byte
/// over must fail with `BufferTooSmall`. The boundary fixes the
/// raw-pointer write to the exact `[0..padded_len)` range — an
/// off-by-one would either write past the staging buffer (UB) or
/// fail to write enough padding bytes (mismatched AEAD tag).
#[test]
fn encap_padded_plaintext_max_boundary() {
    let (init_engine, resp_engine, init_pub, resp_pub) = established_pair(
        vec!["10.0.1.0/24".parse().unwrap()],
        vec!["10.0.0.0/24".parse().unwrap()],
    );

    let make = |size: usize| -> Vec<u8> {
        let mut inner = vec![0u8; size];
        inner[0] = 0x45;
        let len_be = (size as u16).to_be_bytes();
        inner[2] = len_be[0];
        inner[3] = len_be[1];
        inner[12..16].copy_from_slice(&[10, 0, 0, 5]);
        inner[16..20].copy_from_slice(&[10, 0, 1, 5]);
        for (i, b) in inner.iter_mut().enumerate().skip(20) {
            *b = ((i * 17) & 0xff) as u8;
        }
        inner
    };

    // 4096 → padded to 4096 = PADDED_PLAINTEXT_MAX → fits at the
    // exact boundary. The raw-pointer write fills bytes
    // `[0..4096)` of the staging store, which is the maximum
    // legal range.
    let inner = make(4096);
    let mut wire = [0u8; 8000];
    let enc = init_engine
        .try_encap(&resp_pub, &inner, &mut wire)
        .expect("4096 must encap (at PADDED_PLAINTEXT_MAX boundary)");
    assert_eq!(enc.len, 16 + 4096 + 16);
    let mut plain = [0u8; 8000];
    let dec = resp_engine.try_decap(&wire[..enc.len], &mut plain).unwrap();
    assert_eq!(dec.len, 4096);
    assert_eq!(dec.peer_pubkey, init_pub);

    // 4097 → padded to 4112 > PADDED_PLAINTEXT_MAX; the engine
    // refuses with BufferTooSmall, preventing any write past the
    // staging buffer.
    let inner = make(4097);
    let mut wire = [0u8; 8000];
    let err = init_engine.try_encap(&resp_pub, &inner, &mut wire).unwrap_err();
    assert_eq!(err, EncapError::BufferTooSmall);
}

/// r-final-fix regression for Codex final pre-merge finding 1:
/// `build_initiator_handshake` and `build_responder_handshake` MUST
/// call `.prologue(WG_PROTOCOL_ID_BYTES)` so the initial Noise hash
/// matches kernel WireGuard and wireguard-go. We can't reach inside
/// snow's `HandshakeState` to read the hash directly, but we CAN
/// prove the prologue is actually consumed by showing that two
/// engines that disagree on the prologue fail to authenticate each
/// other while two engines that agree complete the handshake.
///
/// The control engine in this test bypasses `WgEngine::build_*` and
/// constructs the `Builder` directly with an empty prologue. If our
/// production builders silently dropped the prologue, the control
/// peer would still authenticate them; with the prologue actually
/// mixed into the hash, the control peer's `read_message` rejects
/// the production initiator with a snow error.
#[test]
fn handshake_prologue_is_required_for_authentication() {
    use super::{WG_NOISE_PATTERN, WG_PROTOCOL_ID_BYTES, WG_ZERO_PSK};
    use snow::Builder;

    let (init_priv, init_pub) = keypair();
    let (resp_priv, resp_pub) = keypair();

    // Production initiator: prologue set via our `build_initiator_handshake`.
    let init_engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv,
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: resp_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
        }],
    });
    let mut init_hs = init_engine.build_initiator_handshake(&resp_pub).unwrap();

    // Bad responder: prologue OMITTED. If our engine doesn't actually
    // mix the prologue into the hash, this responder would still
    // authenticate the init message; with the prologue properly
    // mixed in, snow rejects.
    let mut bad_resp_hs = Builder::new(WG_NOISE_PATTERN.parse().unwrap())
        .local_private_key(&resp_priv)
        .unwrap()
        .psk(2, &WG_ZERO_PSK)
        .unwrap()
        .build_responder()
        .unwrap();

    let mut buf = [0u8; 1024];
    let mut sink = [0u8; 1024];
    let n1 = init_hs.write_message(&[], &mut buf).unwrap();
    let res = bad_resp_hs.read_message(&buf[..n1], &mut sink);
    assert!(
        res.is_err(),
        "responder without prologue must reject an initiator that mixed the WG prologue \
         (otherwise the prologue is silently dropped and the engine is not WireGuard-compat)"
    );

    // Sanity: a responder built via `build_responder_handshake`
    // (which sets the prologue) does authenticate the same init
    // message. This shows the rejection above is the prologue
    // difference, not some unrelated handshake mismatch.
    let good_resp_engine = WgEngine::new(WgEngineConfig {
        local_private_key: resp_priv,
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: init_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
        }],
    });
    let mut init_hs2 = init_engine.build_initiator_handshake(&resp_pub).unwrap();
    let mut good_resp_hs = good_resp_engine.build_responder_handshake().unwrap();
    let n1 = init_hs2.write_message(&[], &mut buf).unwrap();
    good_resp_hs
        .read_message(&buf[..n1], &mut sink)
        .expect("matched-prologue responder must authenticate the initiator");

    // Verify the prologue bytes are exactly the WireGuard protocol
    // identifier — 34 bytes, no trailing NUL. The kernel WG source
    // (`drivers/net/wireguard/noise.c`) uses the same byte string.
    assert_eq!(WG_PROTOCOL_ID_BYTES.len(), 34);
    assert_eq!(WG_PROTOCOL_ID_BYTES, b"WireGuard v1 zx2c4 Jason@zx2c4.com");
}

/// r-final-fix regression for Codex final pre-merge finding 2:
/// responder key-confirmation. A responder-role session MUST NOT be
/// usable for `try_encap` until it has authenticated at least one
/// inbound transport packet (the initiator's first data record).
/// Initiator-role sessions are confirmed at install. After the
/// responder authenticates the initiator's first packet, the
/// responder's session flips to confirmed and egress is allowed.
#[test]
fn responder_session_blocks_encap_until_initiator_data_authenticated() {
    use super::session::SessionRole;

    let (init_priv, init_pub) = keypair();
    let (resp_priv, resp_pub) = keypair();

    let init_engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv,
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: resp_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
        }],
    });
    let resp_engine = WgEngine::new(WgEngineConfig {
        local_private_key: resp_priv,
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: init_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
        }],
    });

    // Drive the IK handshake.
    let mut init_hs = init_engine.build_initiator_handshake(&resp_pub).unwrap();
    let mut resp_hs = resp_engine.build_responder_handshake().unwrap();
    let mut buf = [0u8; 1024];
    let mut sink = [0u8; 1024];
    let n1 = init_hs.write_message(&[], &mut buf).unwrap();
    resp_hs.read_message(&buf[..n1], &mut sink).unwrap();
    let n2 = resp_hs.write_message(&[], &mut buf).unwrap();
    init_hs.read_message(&buf[..n2], &mut sink).unwrap();

    let init_xport = init_hs.into_stateless_transport_mode().unwrap();
    let resp_xport = resp_hs.into_stateless_transport_mode().unwrap();
    let init_local = 0xc0de_0001;
    let resp_local = 0xc0de_0002;

    // Install the initiator session as Initiator-role → confirmed.
    init_engine
        .install_session(
            &resp_pub,
            Arc::new(WgSession::new_with_role(
                init_xport,
                init_local,
                resp_local,
                resp_pub,
                SessionRole::Initiator,
            )),
        )
        .unwrap();
    // Install the responder session as Responder-role → unconfirmed.
    let resp_session = Arc::new(WgSession::new_with_role(
        resp_xport,
        resp_local,
        init_local,
        init_pub,
        SessionRole::Responder,
    ));
    assert!(
        !resp_session.is_confirmed(),
        "responder session must start unconfirmed"
    );
    resp_engine
        .install_session(&init_pub, resp_session.clone())
        .unwrap();

    // The responder MUST refuse to encap before the initiator's
    // first data record arrives — this is the WG anti-reflection
    // invariant. The caller sees `NoSession` and falls through to
    // its slow path.
    let inner = ipv4_packet(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 9));
    let mut wire_pre = [0u8; 2048];
    let err = resp_engine
        .try_encap(&init_pub, &inner, &mut wire_pre)
        .unwrap_err();
    assert_eq!(
        err,
        EncapError::NoSession,
        "responder MUST NOT encap before authenticating initiator's first data record"
    );

    // Initiator sends the first transport packet. Responder
    // authenticates it — that flips `confirmed = true`.
    let mut wire_first = [0u8; 2048];
    let enc = init_engine
        .try_encap(&resp_pub, &inner, &mut wire_first)
        .unwrap();
    let mut plain = [0u8; 2048];
    let dec = resp_engine
        .try_decap(&wire_first[..enc.len], &mut plain)
        .unwrap();
    assert_eq!(dec.peer_pubkey, init_pub);
    assert!(
        resp_session.is_confirmed(),
        "successful AEAD authentication of inbound data must flip the responder \
         session's confirmation flag (WG key-confirmation invariant)"
    );

    // Responder can now encap to the initiator.
    let inner_reply = ipv4_packet(Ipv4Addr::new(10, 0, 0, 9), Ipv4Addr::new(10, 0, 0, 5));
    let mut wire_post = [0u8; 2048];
    let enc_post = resp_engine
        .try_encap(&init_pub, &inner_reply, &mut wire_post)
        .expect("responder must be able to encap after confirmation flips");
    assert!(enc_post.len > 0);
}

/// r-final-fix regression for Codex final pre-merge finding 3:
/// `reconcile_peers` must update mutable per-peer config fields
/// (endpoint, persistent_keepalive) in place on an existing peer
/// Arc rather than silently keeping stale values. Pre-fix: the Peer
/// struct held immutable `endpoint` / `persistent_keepalive`, so a
/// config commit that changed those values for an existing pubkey
/// was lost.
#[test]
fn reconcile_peers_updates_endpoint_and_keepalive_for_existing_peer() {
    use std::net::SocketAddr;
    let (init_priv, _init_pub) = keypair();
    let (_peer_priv, peer_pub) = keypair();
    let engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv,
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: peer_pub,
            endpoint: Some(SocketAddr::from(([192, 0, 2, 1], 51820))),
            persistent_keepalive: 25,
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
        }],
    });

    // Sanity: initial fields applied.
    {
        let table = engine.table_for_test();
        let idx = *table.peer_index_by_pubkey.get(&peer_pub).unwrap();
        let peer = table.peers[idx as usize].clone();
        assert_eq!(peer.endpoint(), Some(SocketAddr::from(([192, 0, 2, 1], 51820))));
        assert_eq!(peer.persistent_keepalive(), 25);
    }

    // Commit a new config that changes the endpoint AND keepalive
    // for the SAME pubkey. The engine reuses the existing peer Arc
    // (same pubkey) but must apply the field updates in place.
    engine.reconcile_peers(&[WgPeerConfig {
        pubkey: peer_pub,
        endpoint: Some(SocketAddr::from(([198, 51, 100, 7], 51900))),
        persistent_keepalive: 60,
        allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
    }]);

    let table = engine.table_for_test();
    let idx = *table.peer_index_by_pubkey.get(&peer_pub).unwrap();
    let peer = table.peers[idx as usize].clone();
    assert_eq!(
        peer.endpoint(),
        Some(SocketAddr::from(([198, 51, 100, 7], 51900))),
        "reconcile must apply endpoint update to the reused peer Arc"
    );
    assert_eq!(
        peer.persistent_keepalive(),
        60,
        "reconcile must apply persistent_keepalive update to the reused peer Arc"
    );

    // Clearing the endpoint (responder-only) must also propagate.
    engine.reconcile_peers(&[WgPeerConfig {
        pubkey: peer_pub,
        endpoint: None,
        persistent_keepalive: 0,
        allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
    }]);
    let table = engine.table_for_test();
    let idx = *table.peer_index_by_pubkey.get(&peer_pub).unwrap();
    let peer = table.peers[idx as usize].clone();
    assert_eq!(peer.endpoint(), None);
    assert_eq!(peer.persistent_keepalive(), 0);
}

/// r-final-fix regression for Copilot inline finding on
/// `inner_ip_len_after_decap`: an IPv4 inner packet with a bogus
/// IHL (< 5) or a `total_length` shorter than the header length
/// MUST be rejected as `MalformedInner`. Pre-fix the engine
/// returned `Some(claimed)` for any `total_length <= pkt.len()`,
/// so a downstream parser could see `DecapOutcome.len < 20` and
/// mis-parse the bytes as a real IPv4 header.
#[test]
fn decap_rejects_inner_ipv4_with_invalid_ihl_or_total_length() {
    let (init_engine, resp_engine, _init_pub, resp_pub) = established_pair(
        vec!["10.0.1.0/24".parse().unwrap()],
        vec!["10.0.0.0/24".parse().unwrap()],
    );

    // Case 1: IHL = 4 (impossible — < 5 means no room for the fixed
    // header). The first byte's low nibble holds IHL. version=4,
    // IHL=4 → byte 0 = 0x44.
    {
        let mut inner = vec![0u8; 32];
        inner[0] = 0x44; // version=4, IHL=4 (invalid)
        inner[2..4].copy_from_slice(&32u16.to_be_bytes());
        // Need a valid src for AllowedIPs gate to PASS so the
        // failure attributes to inner_ip_len_after_decap, not the
        // AllowedIPs gate. inner_src_ip reads bytes 12..16
        // unconditionally.
        inner[12..16].copy_from_slice(&[10, 0, 0, 5]);
        inner[16..20].copy_from_slice(&[10, 0, 1, 5]);
        let mut wire = [0u8; 2048];
        let enc = init_engine.try_encap(&resp_pub, &inner, &mut wire).unwrap();
        let mut plain = [0u8; 2048];
        let err = resp_engine
            .try_decap(&wire[..enc.len], &mut plain)
            .unwrap_err();
        assert_eq!(
            err,
            DecapError::MalformedInner,
            "IHL < 5 must be rejected as MalformedInner"
        );
    }

    // Case 2: IHL = 5, total_length = 10 (claims fewer bytes than
    // the fixed header). Must reject.
    {
        let mut inner = vec![0u8; 32];
        inner[0] = 0x45; // version=4, IHL=5
        inner[2..4].copy_from_slice(&10u16.to_be_bytes());
        inner[12..16].copy_from_slice(&[10, 0, 0, 5]);
        inner[16..20].copy_from_slice(&[10, 0, 1, 5]);
        let mut wire = [0u8; 2048];
        let enc = init_engine.try_encap(&resp_pub, &inner, &mut wire).unwrap();
        let mut plain = [0u8; 2048];
        let err = resp_engine
            .try_decap(&wire[..enc.len], &mut plain)
            .unwrap_err();
        assert_eq!(
            err,
            DecapError::MalformedInner,
            "total_length < ihl*4 must be rejected as MalformedInner"
        );
    }
}

/// r-final-fix regression for Copilot inline finding on
/// `TunnelEndpointSnapshot::wg_local_privkey_hex`: the private key
/// field MUST NOT be serialized into the on-disk state file, and a
/// `Debug` impl MUST redact it so accidental log calls cannot leak
/// key material.
#[test]
fn tunnel_endpoint_snapshot_private_key_is_skipped_and_redacted() {
    use crate::protocol::TunnelEndpointSnapshot;

    let snap = TunnelEndpointSnapshot {
        wg_local_privkey_hex: "deadbeef".repeat(8), // 64 hex chars = "private key"
        wg_peer_pubkey_hex: "abc123".to_string(),
        wg_listen_port: 51820,
        ..Default::default()
    };

    // Serialization must NOT include the private key — this is the
    // surface that ends up in the state file on disk.
    let json = serde_json::to_string(&snap).expect("snapshot must serialize");
    assert!(
        !json.contains(&snap.wg_local_privkey_hex),
        "wg_local_privkey_hex must NOT appear in serialized output (state file would leak); \
         got: {json}"
    );

    // Debug must redact — accidental {:?} log lines can't leak.
    let debug_str = format!("{snap:?}");
    assert!(
        !debug_str.contains(&snap.wg_local_privkey_hex),
        "Debug for TunnelEndpointSnapshot must NOT include the raw private key bytes; \
         got: {debug_str}"
    );
    assert!(
        debug_str.contains("<redacted>"),
        "Debug for TunnelEndpointSnapshot must show <redacted> placeholder; got: {debug_str}"
    );

    // Empty-key case: must show <unset> placeholder.
    let empty = TunnelEndpointSnapshot::default();
    let debug_str = format!("{empty:?}");
    assert!(
        debug_str.contains("<unset>"),
        "empty privkey must Debug as <unset>; got: {debug_str}"
    );

    // Deserialization still accepts the field — the control plane
    // delivers the key on the control socket.
    let wire = serde_json::json!({
        "wg_local_privkey_hex": "0123456789abcdef".repeat(4),
        "wg_listen_port": 51820,
    });
    let snap: TunnelEndpointSnapshot = serde_json::from_value(wire).unwrap();
    assert_eq!(snap.wg_local_privkey_hex.len(), 64);
    assert_eq!(snap.wg_listen_port, 51820);
}

#[test]
fn allowed_ips_unit_check() {
    // Direct AllowedIps test — extra coverage on top of the
    // module's own unit tests, exercising the same API the engine
    // uses on the decap path.
    let mut t = AllowedIps::new();
    t.insert("10.0.0.0/24".parse().unwrap(), 0);
    t.insert("10.0.0.128/25".parse().unwrap(), 1);
    assert_eq!(t.lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))), Some(0));
    assert_eq!(t.lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 200))), Some(1));
}

/// Regression test for the truncated-record remote DoS that Codex
/// caught on the r-final-2 review (all 9 prior review rounds missed
/// it). A hostile peer that observes a valid `receiver_index` for a
/// live session can send 16..31-byte UDP datagrams; `parse_data_header`
/// accepts any record ≥ 16 bytes, leaving a sub-Poly1305-tag
/// ciphertext that snow 0.10's ChaCha-Poly1305 decrypt cannot handle
/// safely (the internal `ciphertext.len() - TAGLEN` either underflows
/// to a debug-assert or wraps to a huge usize that panics on the
/// subsequent slice op). The fix: reject sub-tag records with
/// `DecapError::ShortRecord` before invoking snow.
///
/// This test installs a live session, then walks `ciphertext.len()`
/// across {0, 1, 8, 14, 15} and asserts the engine returns the new
/// error variant rather than panicking. The assertion is on the
/// returned error — if the bug regressed, the test would panic
/// instead of failing with a wrong-error.
#[test]
fn try_decap_rejects_sub_poly1305_tag_records_without_panicking() {
    use super::framing::encode_data_header;

    let (init_engine, resp_engine, _init_pub, resp_pub) = established_pair(
        vec!["10.0.1.0/24".parse().unwrap()],
        vec!["10.0.0.0/24".parse().unwrap()],
    );

    // Encrypt one real packet through the engine to learn what
    // `receiver_index` the responder demuxes on. We extract that
    // index from the encrypted record so the hostile-attacker probe
    // uses a live session's index.
    let inner = ipv4_packet(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 1, 5));
    let mut wire = [0u8; 2048];
    let enc = init_engine
        .try_encap(&resp_pub, &inner, &mut wire)
        .expect("baseline encap should succeed");
    let receiver_index = enc.receiver_index;

    // Walk ciphertext lengths from 0 through 15 (i.e. record lengths
    // 16..31). Every one of these must return ShortRecord, NOT panic.
    for ct_len in [0usize, 1, 8, 14, 15] {
        let mut probe = vec![0u8; super::WG_DATA_HEADER_LEN + ct_len];
        encode_data_header(&mut probe, receiver_index, 0xdead_beef).unwrap();
        // The header counter we used (0xdeadbeef) is well below
        // REJECT_AFTER_MESSAGES — so the rejection MUST come from the
        // short-record guard, not from the counter-ceiling guard or
        // from a panic inside snow.
        let mut plain = [0u8; 2048];
        let err = resp_engine.try_decap(&probe, &mut plain).unwrap_err();
        assert_eq!(
            err,
            DecapError::ShortRecord,
            "record with ciphertext.len()={ct_len} must reject as ShortRecord; \
             got {err:?}. If this test panics instead of asserting, the \
             truncated-record DoS has regressed and snow is being handed \
             a sub-tag ciphertext."
        );
    }

    // Boundary case: ciphertext.len() == POLY1305_TAG_LEN (16) is no
    // longer ShortRecord — it's an empty-payload record. Snow will
    // reject it for failing the AEAD tag (we haven't crafted a real
    // tag), which surfaces as CryptoFailed. Important contract: the
    // short-record guard's cutoff is `< POLY1305_TAG_LEN`, not `<=`.
    let mut sixteen_byte_ct = vec![0u8; super::WG_DATA_HEADER_LEN + super::POLY1305_TAG_LEN];
    encode_data_header(&mut sixteen_byte_ct, receiver_index, 0xdead_beef).unwrap();
    let mut plain = [0u8; 2048];
    let err = resp_engine.try_decap(&sixteen_byte_ct, &mut plain).unwrap_err();
    assert_ne!(
        err,
        DecapError::ShortRecord,
        "a ciphertext.len() == POLY1305_TAG_LEN record is NOT short — must \
         reach snow and reject as CryptoFailed (or similar) instead"
    );
}

/// Builds an `established_pair` where the responder session starts
/// unconfirmed (responder-role) and is confirmed by the engine's
/// own `try_decap` rather than by a manual `mark_confirmed` test
/// helper. This is what a real responder integration path will do
/// — the first authenticated inbound data record flips the gate.
///
/// Addresses the Copilot inline finding on `established_pair`: the
/// bulk of the file's round-trip tests use the helper which
/// pre-confirms the responder, so the key-confirmation gate is not
/// exercised by them. This test exercises it end-to-end without
/// touching `mark_confirmed`.
#[test]
fn established_pair_responder_confirmation_flips_via_decap_path() {
    use super::session::SessionRole;

    let (init_priv, init_pub) = keypair();
    let (resp_priv, resp_pub) = keypair();

    let init_engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv,
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: resp_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
        }],
    });
    let resp_engine = WgEngine::new(WgEngineConfig {
        local_private_key: resp_priv,
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: init_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
        }],
    });

    let mut init_hs = init_engine.build_initiator_handshake(&resp_pub).unwrap();
    let mut resp_hs = resp_engine.build_responder_handshake().unwrap();
    let mut buf = [0u8; 1024];
    let mut sink = [0u8; 1024];
    let n1 = init_hs.write_message(&[], &mut buf).unwrap();
    resp_hs.read_message(&buf[..n1], &mut sink).unwrap();
    let n2 = resp_hs.write_message(&[], &mut buf).unwrap();
    init_hs.read_message(&buf[..n2], &mut sink).unwrap();

    let init_xport = init_hs.into_stateless_transport_mode().unwrap();
    let resp_xport = resp_hs.into_stateless_transport_mode().unwrap();
    let init_local = 0xc0de_4001;
    let resp_local = 0xc0de_4002;

    init_engine
        .install_session(
            &resp_pub,
            Arc::new(WgSession::new_with_role(
                init_xport,
                init_local,
                resp_local,
                resp_pub,
                SessionRole::Initiator,
            )),
        )
        .unwrap();
    let resp_session = Arc::new(WgSession::new_with_role(
        resp_xport,
        resp_local,
        init_local,
        init_pub,
        SessionRole::Responder,
    ));
    resp_engine
        .install_session(&init_pub, resp_session.clone())
        .unwrap();
    assert!(!resp_session.is_confirmed());

    // Initiator sends; engine `try_decap` MUST flip confirmation.
    let inner = ipv4_packet(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 9));
    let mut wire = [0u8; 2048];
    let enc = init_engine.try_encap(&resp_pub, &inner, &mut wire).unwrap();
    let mut plain = [0u8; 2048];
    resp_engine.try_decap(&wire[..enc.len], &mut plain).unwrap();
    assert!(
        resp_session.is_confirmed(),
        "successful AEAD via try_decap must flip confirmation without any test-only mark_confirmed call"
    );

    // Responder can now encap; the gate is open.
    let reply = ipv4_packet(Ipv4Addr::new(10, 0, 0, 9), Ipv4Addr::new(10, 0, 0, 5));
    let mut wire2 = [0u8; 2048];
    resp_engine
        .try_encap(&init_pub, &reply, &mut wire2)
        .expect("post-confirmation encap must succeed");
}
