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
    let init_session = Arc::new(WgSession::new(
        init_xport,
        init_local_index,
        resp_local_index,
        resp_pub,
    ));
    let resp_session = Arc::new(WgSession::new(
        resp_xport,
        resp_local_index,
        init_local_index,
        init_pub,
    ));
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
