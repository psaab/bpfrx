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
    // Decrypted plaintext is the padded form. The first `inner.len()`
    // bytes must equal the original inner packet; trailing bytes are
    // zero padding.
    assert_eq!(&plain[..inner.len()], &inner[..]);
    assert!(plain[inner.len()..dec.len].iter().all(|&b| b == 0));
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
    // Sanity: 1500-byte outer MTU, v4-in-v4, MSS = 1400. See
    // mss.rs for the byte-by-byte derivation. Repeated here in
    // the integration tests because review-time errors on MSS
    // math are the kind of bug that ships and silently fragments.
    assert_eq!(wg_tcp_mss(libc::AF_INET, libc::AF_INET, 1500), 1400);
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
        // Roundtrip: decap and verify the original prefix survives.
        let mut plain = [0u8; 4096];
        let dec = resp_engine.try_decap(&wire[..enc.len], &mut plain).unwrap();
        assert_eq!(&plain[..inner_len], &inner[..]);
        assert_eq!(dec.len, expected_padded);
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
