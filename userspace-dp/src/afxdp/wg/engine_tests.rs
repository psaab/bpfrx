// Internal unit tests for the WireGuard engine.
//
// Relocated verbatim from engine.rs (#2158 file-split, #1046 pattern):
// loaded via `#[cfg(test)] #[path = "engine_tests.rs"] mod
// engine_internal_tests;` so `#[path]` keeps this a child of
// `wg::engine` and `use super::*;` reaches the prod-file private
// items unchanged. Pure code-motion: bodies are byte-identical to the
// former inline module modulo a uniform 4-space dedent.

use super::*;
use std::str::FromStr;
use std::sync::atomic::Ordering;

fn keypair() -> ([u8; 32], [u8; 32]) {
    let kp = Builder::new(WG_NOISE_PATTERN.parse().unwrap())
        .generate_keypair()
        .unwrap();
    let mut priv_k = [0u8; 32];
    let mut pub_k = [0u8; 32];
    priv_k.copy_from_slice(&kp.private);
    pub_k.copy_from_slice(&kp.public);
    (priv_k, pub_k)
}

#[test]
fn inner_src_ip_v4() {
    let mut pkt = [0u8; 40];
    pkt[0] = 0x45;
    pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
    assert_eq!(
        inner_src_ip(&pkt),
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
    );
}

#[test]
fn inner_src_ip_v6() {
    let mut pkt = [0u8; 40];
    pkt[0] = 0x60;
    pkt[8] = 0xfe;
    pkt[9] = 0x80;
    let got = inner_src_ip(&pkt).unwrap();
    match got {
        IpAddr::V6(v6) => assert_eq!(v6.segments()[0], 0xfe80),
        _ => panic!("expected v6"),
    }
}

#[test]
fn inner_src_ip_rejects_short() {
    assert!(inner_src_ip(&[0x45u8; 10]).is_none());
    assert!(inner_src_ip(&[0x60u8; 20]).is_none());
    assert!(inner_src_ip(&[]).is_none());
}

#[test]
fn inner_src_ip_rejects_unknown_version() {
    assert!(inner_src_ip(&[0x05u8; 40]).is_none()); // bogus version 0
}

/// Drive a real IK handshake between two engines and return the
/// initiator-side transport session. Helper used by the
/// install_session unit tests below — going through snow is
/// cheaper than a separate mock and keeps the test honest.
fn make_session_for(
    engine: &WgEngine,
    peer_pub: [u8; 32],
    peer_engine: &WgEngine,
    local_index: u32,
    peer_index: u32,
) -> Arc<WgSession> {
    let mut init_hs = engine.build_initiator_handshake(&peer_pub).unwrap();
    let mut resp_hs = peer_engine.build_responder_handshake().unwrap();
    let mut buf = [0u8; 1024];
    let mut sink = [0u8; 1024];
    let n1 = init_hs.write_message(&[], &mut buf).unwrap();
    resp_hs.read_message(&buf[..n1], &mut sink).unwrap();
    let n2 = resp_hs.write_message(&[], &mut buf).unwrap();
    init_hs.read_message(&buf[..n2], &mut sink).unwrap();
    let xport = init_hs.into_stateless_transport_mode().unwrap();
    Arc::new(WgSession::new(xport, local_index, peer_index, peer_pub))
}

/// Same-peer same-local-index collision must be refused. Letting
/// it through would move the existing current session into
/// `previous`, but rewrite its demux entry to point at the new
/// session — in-flight ciphertexts addressed to the previous
/// session (which legitimately still decode against its key
/// during the rotation grace window) would demux to the new
/// session, fail AEAD, and drop silently. Codex r4 finding 1 /
/// Gemini r4 finding B. r3's test (now removed) blessed this
/// wrong behavior.
#[test]
fn install_session_same_peer_same_local_index_is_collision() {
    let (init_priv, _init_pub) = keypair();
    let (peer_priv, peer_pub) = keypair();
    let engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: peer_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let peer_engine = WgEngine::new(WgEngineConfig {
        local_private_key: peer_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: [0u8; 32],
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let s1 = make_session_for(&engine, peer_pub, &peer_engine, 0xaaaa_0001, 2);
    let s1_ptr = Arc::as_ptr(&s1);
    engine.install_session(&peer_pub, s1).unwrap();
    // Re-handshake with the SAME local_index for the SAME peer
    // must be rejected with LocalIndexCollision.
    let s2 = make_session_for(&engine, peer_pub, &peer_engine, 0xaaaa_0001, 3);
    let err = engine.install_session(&peer_pub, s2).unwrap_err();
    assert_eq!(err, InstallSessionError::LocalIndexCollision);
    // The original session must still be the demux target.
    let by_index = engine.sessions_by_local_index.read().unwrap();
    assert_eq!(
        Arc::as_ptr(by_index.get(&0xaaaa_0001).unwrap()),
        s1_ptr,
        "collision must NOT overwrite the existing same-peer session"
    );
}

/// Successful same-peer rekey on a FRESH `local_index` must:
///   (a) succeed,
///   (b) leave the new session as the demux target for the new
///       index,
///   (c) leave the old session still demuxable on its old index
///       (it has rotated to `previous` and continues to receive
///       in-flight ciphertexts until the next rotation).
#[test]
fn install_session_fresh_index_rekey_preserves_previous_demux() {
    let (init_priv, _init_pub) = keypair();
    let (peer_priv, peer_pub) = keypair();
    let engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: peer_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let peer_engine = WgEngine::new(WgEngineConfig {
        local_private_key: peer_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: [0u8; 32],
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let s1 = make_session_for(&engine, peer_pub, &peer_engine, 0xaaaa_0001, 2);
    let s1_ptr = Arc::as_ptr(&s1);
    engine.install_session(&peer_pub, s1).unwrap();
    let s2 = make_session_for(&engine, peer_pub, &peer_engine, 0xaaaa_0002, 3);
    let s2_ptr = Arc::as_ptr(&s2);
    engine.install_session(&peer_pub, s2).unwrap();
    let by_index = engine.sessions_by_local_index.read().unwrap();
    // New session is demuxable on the new index.
    assert_eq!(Arc::as_ptr(by_index.get(&0xaaaa_0002).unwrap()), s2_ptr);
    // Old session is still demuxable on the old index (rotated
    // to `previous`, not dropped yet).
    assert_eq!(Arc::as_ptr(by_index.get(&0xaaaa_0001).unwrap()), s1_ptr);
}

/// A second rekey (s3 on a third fresh index) drops s1 out of
/// (current, previous). The engine must then remove s1's demux
/// entry so its index can be reused for future handshakes.
#[test]
fn install_session_second_rekey_evicts_dropped_session() {
    let (init_priv, _init_pub) = keypair();
    let (peer_priv, peer_pub) = keypair();
    let engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: peer_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let peer_engine = WgEngine::new(WgEngineConfig {
        local_private_key: peer_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: [0u8; 32],
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let s1 = make_session_for(&engine, peer_pub, &peer_engine, 0xaaaa_0001, 2);
    engine.install_session(&peer_pub, s1).unwrap();
    let s2 = make_session_for(&engine, peer_pub, &peer_engine, 0xaaaa_0002, 3);
    engine.install_session(&peer_pub, s2).unwrap();
    let s3 = make_session_for(&engine, peer_pub, &peer_engine, 0xaaaa_0003, 4);
    engine.install_session(&peer_pub, s3).unwrap();
    let by_index = engine.sessions_by_local_index.read().unwrap();
    assert!(
        by_index.get(&0xaaaa_0001).is_none(),
        "s1 must be evicted from demux after second rotation drops it"
    );
    assert!(by_index.get(&0xaaaa_0002).is_some());
    assert!(by_index.get(&0xaaaa_0003).is_some());
}

/// Collision detection: installing two distinct sessions with the
/// same `local_index` for DIFFERENT peers (or stale handshake
/// race) must return LocalIndexCollision rather than silently
/// overwriting the existing entry.
#[test]
fn install_session_rejects_local_index_collision_across_peers() {
    let (init_priv, _init_pub) = keypair();
    let (peer_a_priv, peer_a_pub) = keypair();
    let (peer_b_priv, peer_b_pub) = keypair();
    let engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![
            WgPeerConfig {
                pubkey: peer_a_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
                preshared_key: [0u8; 32].into(),
            },
            WgPeerConfig {
                pubkey: peer_b_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
                preshared_key: [0u8; 32].into(),
            },
        ],
    });
    let peer_a_engine = WgEngine::new(WgEngineConfig {
        local_private_key: peer_a_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: [0u8; 32],
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let peer_b_engine = WgEngine::new(WgEngineConfig {
        local_private_key: peer_b_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: [0u8; 32],
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let sa = make_session_for(&engine, peer_a_pub, &peer_a_engine, 0x1234_5678, 2);
    let sa_ptr = Arc::as_ptr(&sa);
    engine.install_session(&peer_a_pub, sa).unwrap();
    let sb = make_session_for(&engine, peer_b_pub, &peer_b_engine, 0x1234_5678, 3);
    let err = engine.install_session(&peer_b_pub, sb).unwrap_err();
    assert_eq!(err, InstallSessionError::LocalIndexCollision);
    // Peer A's session must still be the one in the demux map.
    let by_index = engine.sessions_by_local_index.read().unwrap();
    assert_eq!(
        Arc::as_ptr(by_index.get(&0x1234_5678).unwrap()),
        sa_ptr,
        "collision must NOT overwrite the existing session"
    );
}

#[test]
fn encap_rejects_after_message_limit() {
    let (init_priv, _init_pub) = keypair();
    let (peer_priv, peer_pub) = keypair();
    let engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: peer_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let resp = WgEngine::new(WgEngineConfig {
        local_private_key: peer_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: [0u8; 32],
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let mut init_hs = engine.build_initiator_handshake(&peer_pub).unwrap();
    let mut resp_hs = resp.build_responder_handshake().unwrap();
    let mut buf = [0u8; 1024];
    let mut sink = [0u8; 1024];
    let n1 = init_hs.write_message(&[], &mut buf).unwrap();
    resp_hs.read_message(&buf[..n1], &mut sink).unwrap();
    let n2 = resp_hs.write_message(&[], &mut buf).unwrap();
    init_hs.read_message(&buf[..n2], &mut sink).unwrap();
    let session = Arc::new(WgSession::new(
        init_hs.into_stateless_transport_mode().unwrap(),
        1,
        2,
        peer_pub,
    ));
    session.tx_counter.store(
        super::super::session::REJECT_AFTER_MESSAGES,
        Ordering::Relaxed,
    );
    engine.install_session(&peer_pub, session).unwrap();
    let inner = [
        0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
    ];
    let mut out = [0u8; 128];
    let err = engine.try_encap(&peer_pub, &inner, &mut out).unwrap_err();
    assert_eq!(err, EncapError::RekeyRequired);
}

/// r5 regression: when `reconcile_peers` drops a peer whose
/// pubkey is absent in the new config, the peer's
/// `(current, previous)` session entries MUST be drained from
/// `sessions_by_local_index`. Codex r5 finding: without the
/// drain, every config refresh that removes a peer leaks that
/// peer's session Arcs in the demux map forever (until engine
/// drop). The Arcs also keep `WgSession` (transport key
/// material) alive past peer removal, which violates the
/// expectation that removing a peer immediately revokes its
/// session material from the live state.
#[test]
fn reconcile_peers_drains_dropped_peer_sessions_from_demux() {
    let (init_priv, _init_pub) = keypair();
    let (peer_priv, peer_pub) = keypair();
    let engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: peer_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let peer_engine = WgEngine::new(WgEngineConfig {
        local_private_key: peer_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: [0u8; 32],
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    // Install two sessions on the peer (current + previous).
    let s1 = make_session_for(&engine, peer_pub, &peer_engine, 0xaaaa_0001, 2);
    engine.install_session(&peer_pub, s1).unwrap();
    let s2 = make_session_for(&engine, peer_pub, &peer_engine, 0xaaaa_0002, 3);
    engine.install_session(&peer_pub, s2).unwrap();
    // Both indices must be in the demux pre-reconcile.
    {
        let by_index = engine.sessions_by_local_index.read().unwrap();
        assert!(by_index.contains_key(&0xaaaa_0001));
        assert!(by_index.contains_key(&0xaaaa_0002));
    }
    // Reconcile with the peer removed.
    engine.reconcile_peers(&[]);
    // Both demux entries must now be gone — the leak is fixed.
    let by_index = engine.sessions_by_local_index.read().unwrap();
    assert!(
        !by_index.contains_key(&0xaaaa_0001),
        "dropped peer's `previous` session must be drained from demux"
    );
    assert!(
        !by_index.contains_key(&0xaaaa_0002),
        "dropped peer's `current` session must be drained from demux"
    );
    assert!(
        by_index.is_empty(),
        "no stray demux entries should remain after peer removal"
    );
}

/// r5 regression: peer removal must NOT touch unrelated peers'
/// sessions. A reconcile that drops peer A while keeping peer B
/// must drain A's demux entries and leave B's intact.
#[test]
fn reconcile_peers_leaves_kept_peer_sessions_intact() {
    let (init_priv, _init_pub) = keypair();
    let (peer_a_priv, peer_a_pub) = keypair();
    let (peer_b_priv, peer_b_pub) = keypair();
    let engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![
            WgPeerConfig {
                pubkey: peer_a_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
                preshared_key: [0u8; 32].into(),
            },
            WgPeerConfig {
                pubkey: peer_b_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec![ipnet::IpNet::from_str("10.0.1.0/24").unwrap()],
                preshared_key: [0u8; 32].into(),
            },
        ],
    });
    let peer_a_engine = WgEngine::new(WgEngineConfig {
        local_private_key: peer_a_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: [0u8; 32],
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let peer_b_engine = WgEngine::new(WgEngineConfig {
        local_private_key: peer_b_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: [0u8; 32],
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.1.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let s_a = make_session_for(&engine, peer_a_pub, &peer_a_engine, 0xaaaa_0001, 2);
    engine.install_session(&peer_a_pub, s_a).unwrap();
    let s_b = make_session_for(&engine, peer_b_pub, &peer_b_engine, 0xbbbb_0001, 4);
    engine.install_session(&peer_b_pub, s_b).unwrap();
    // Reconcile dropping only peer A.
    engine.reconcile_peers(&[WgPeerConfig {
        pubkey: peer_b_pub,
        endpoint: None,
        persistent_keepalive: 0,
        allowed_ips: vec![ipnet::IpNet::from_str("10.0.1.0/24").unwrap()],
        preshared_key: [0u8; 32].into(),
    }]);
    let by_index = engine.sessions_by_local_index.read().unwrap();
    assert!(
        !by_index.contains_key(&0xaaaa_0001),
        "peer A's session must be drained"
    );
    assert!(
        by_index.contains_key(&0xbbbb_0001),
        "peer B's session must remain — unrelated peer reconcile must not touch it"
    );
}

/// r5 regression: hot-path readers must observe a torn-free
/// snapshot across `reconcile_peers`. A concurrent
/// reconcile/hot-read interleaving where the reader sees
/// `peer_index_by_pubkey` from the new snapshot but `peers`
/// from the old (or vice versa) would route to the wrong peer.
/// We hammer reconcile in one thread and assert internal
/// consistency from another.
///
/// Invariant verified: every snapshot returned by `load_table()`
/// is internally consistent — for every (pubkey, idx) entry in
/// `peer_index_by_pubkey`, `peers[idx].pubkey == pubkey`. The
/// invariant would fail under torn snapshots if reconcile
/// published the index map and peer vec via separate stores.
#[test]
fn reconcile_peers_snapshot_is_atomic_under_concurrent_load() {
    use std::sync::atomic::{AtomicBool, Ordering as AOrd};
    use std::thread;
    let (init_priv, _init_pub) = keypair();
    let (peer_a_priv, peer_a_pub) = keypair();
    let (peer_b_priv, peer_b_pub) = keypair();
    let (_peer_c_priv, peer_c_pub) = keypair();
    let _ = (peer_a_priv, peer_b_priv);
    let engine = Arc::new(WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: peer_a_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    }));
    let stop = Arc::new(AtomicBool::new(false));
    let config_alt = vec![
        WgPeerConfig {
            pubkey: peer_b_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.1.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        },
        WgPeerConfig {
            pubkey: peer_c_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.2.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        },
    ];
    let config_orig = vec![WgPeerConfig {
        pubkey: peer_a_pub,
        endpoint: None,
        persistent_keepalive: 0,
        allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
        preshared_key: [0u8; 32].into(),
    }];
    let writer = {
        let engine = engine.clone();
        let stop = stop.clone();
        thread::spawn(move || {
            for i in 0..2000 {
                if i % 2 == 0 {
                    engine.reconcile_peers(&config_alt);
                } else {
                    engine.reconcile_peers(&config_orig);
                }
            }
            stop.store(true, AOrd::Relaxed);
        })
    };
    let reader = {
        let engine = engine.clone();
        let stop = stop.clone();
        thread::spawn(move || {
            let mut observed = 0u64;
            // #3457: take at least one snapshot BEFORE consulting `stop`
            // (do-while). Under heavy CPU oversubscription the writer can
            // finish all 2000 reconciles and store `stop=true` before this
            // thread is first scheduled; a leading `while !stop` would then
            // observe zero snapshots and fail the `n >= 1` sanity check —
            // a scheduler artifact, not an atomicity violation. The
            // torn-snapshot invariant below still runs on every real
            // snapshot, so the safety check is unchanged; only the
            // reader-starvation flake is removed.
            loop {
                let snapshot = engine.load_table();
                // The invariant: every (pubkey, idx) pair in
                // the index map must map to a peer in `peers`
                // whose pubkey matches. A torn snapshot would
                // pair an old-config pubkey with a new-config
                // peer slot (or vice versa) — different pubkey.
                for (pubkey, idx) in snapshot.peer_index_by_pubkey.iter() {
                    let peer = snapshot
                        .peers
                        .get(*idx as usize)
                        .expect("idx must be in bounds within a snapshot");
                    assert_eq!(
                        &peer.peer.pubkey, pubkey,
                        "torn snapshot: index map and peer vec disagree"
                    );
                }
                observed += 1;
                if stop.load(AOrd::Relaxed) {
                    break;
                }
            }
            observed
        })
    };
    writer.join().unwrap();
    let n = reader.join().unwrap();
    // Sanity: the reader must have done at least one full pass. The
    // do-while above guarantees this deterministically (#3457).
    assert!(n >= 1, "reader thread observed no snapshots");
}

/// r6 regression: `install_session` and `reconcile_peers` must
/// serialize so a removed peer cannot orphan a freshly-installed
/// demux entry.
///
/// Race (pre-fix):
///   1. install_session(P) loads `peer` via `peer_arc(P)` from
///      `PeerTable_v1` and drops the snapshot reference.
///   2. reconcile_peers(&[]) publishes `PeerTable_v2` without P.
///      Its drain loop reads `peer.current.read()` and
///      `peer.previous.read()` — both `None` because step (1)
///      hasn't called `rotate_session` yet.
///   3. install_session continues against the orphan Arc<Peer>,
///      inserts the demux entry, and calls rotate_session. The
///      demux entry now references a peer pubkey absent from
///      every future `peer_index_by_pubkey`, so subsequent
///      reconciles cannot drain it.
///
/// Fix: `install_session` takes `reconcile_lock` for the entire
/// critical region. The lookup-then-mutate sequence is then
/// serialized against any concurrent `reconcile_peers`, and if
/// the peer is removed before the install acquires the lock, the
/// `peer_arc(pubkey)` lookup returns None and the install fails
/// with `UnknownPeer` — no demux mutation occurs.
///
/// Invariant verified across the race: every entry in
/// `sessions_by_local_index` has its `session.peer_pubkey`
/// present in the currently published `peer_index_by_pubkey`.
/// Under the pre-fix code path, this invariant would fail
/// whenever the orphan interleaving fires.
#[test]
fn install_session_serializes_with_reconcile_removal() {
    use std::sync::atomic::{AtomicBool, Ordering as AOrd};
    use std::thread;
    let (init_priv, _init_pub) = keypair();
    let (peer_priv, peer_pub) = keypair();
    let engine = Arc::new(WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: peer_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    }));
    let peer_engine = WgEngine::new(WgEngineConfig {
        local_private_key: peer_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: [0u8; 32],
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let cfg_with_peer = vec![WgPeerConfig {
        pubkey: peer_pub,
        endpoint: None,
        persistent_keepalive: 0,
        allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
        preshared_key: [0u8; 32].into(),
    }];
    // Pre-build a batch of sessions off the hot path. Each one
    // gets a fresh local_index so installs never collide on the
    // demux map for the wrong reason.
    let iterations = 400u32;
    let mut sessions: Vec<Arc<WgSession>> = Vec::with_capacity(iterations as usize);
    for i in 0..iterations {
        sessions.push(make_session_for(
            &engine,
            peer_pub,
            &peer_engine,
            0xcafe_0000 + i,
            100 + i,
        ));
    }
    let stop = Arc::new(AtomicBool::new(false));
    // Thread A: install_session in a tight loop, alternating
    // with reconciles that re-add the peer so installs can
    // succeed sometimes.
    let installer = {
        let engine = engine.clone();
        thread::spawn(move || {
            let mut ok = 0u32;
            let mut unknown = 0u32;
            let mut collision = 0u32;
            for s in sessions {
                match engine.install_session(&peer_pub, s) {
                    Ok(()) => ok += 1,
                    Err(InstallSessionError::UnknownPeer) => unknown += 1,
                    Err(InstallSessionError::LocalIndexCollision) => collision += 1,
                }
                thread::yield_now();
            }
            (ok, unknown, collision)
        })
    };
    // Thread B: alternate removing and re-adding the peer.
    let reconciler = {
        let engine = engine.clone();
        let stop = stop.clone();
        let cfg = cfg_with_peer.clone();
        thread::spawn(move || {
            let mut iters = 0u32;
            while !stop.load(AOrd::Relaxed) {
                engine.reconcile_peers(&[]);
                engine.reconcile_peers(&cfg);
                iters += 1;
                thread::yield_now();
            }
            iters
        })
    };
    let (ok, unknown, collision) = installer.join().unwrap();
    stop.store(true, AOrd::Relaxed);
    let reconcile_iters = reconciler.join().unwrap();
    // We made progress on both sides — otherwise the test is
    // not actually exercising the race window.
    assert!(
        ok + unknown + collision == iterations,
        "every install attempt accounted for"
    );
    assert!(
        reconcile_iters >= 1,
        "reconcile loop must have completed at least one full add/remove cycle"
    );
    // r7 Codex hostile finding: a tautological pass shape exists
    // if the reconciler always wins the lock — every install
    // returns UnknownPeer, demux stays empty, and the post-loop
    // invariants are trivially satisfied even with the lock
    // removed. Require at least one Ok install so the lock-
    // protected path (peer_arc-then-rotate_session under the
    // same guard) is actually exercised. With 400 iterations and
    // reconcile alternating add/remove on a separate thread, the
    // installer typically lands 50-300 Ok results in practice;
    // requiring just `ok > 0` is conservative against schedule
    // skew while keeping the gate non-vacuous.
    assert!(
        ok > 0,
        "race regression must exercise at least one successful install \
         (ok={ok}, unknown={unknown}, collision={collision}); without an \
         Ok the lock-protected demux insert path is not on the test \
         trajectory and the gate is tautological"
    );
    // Post-condition invariant: every entry in
    // `sessions_by_local_index` must reference a peer pubkey
    // that is present in the currently published table. An
    // orphan demux entry (the race the fix closes) would have a
    // `session.peer_pubkey` that is not in the index map of any
    // future snapshot — and we can detect it by re-reconciling
    // the peer back in and checking the index map directly.
    engine.reconcile_peers(&cfg_with_peer);
    let table = engine.load_table();
    let by_index = engine.sessions_by_local_index.read().unwrap();
    for (local_index, session) in by_index.iter() {
        assert!(
            table.peer_index_by_pubkey.contains_key(&session.peer_pubkey),
            "demux entry {local_index:#x} references unknown peer pubkey \
             — orphan from install/reconcile race"
        );
    }
    // Now flip the peer out one more time. Reconcile's drain
    // path must remove every session belonging to that peer; any
    // surviving entry would prove the orphan slipped through.
    engine.reconcile_peers(&[]);
    let by_index = engine.sessions_by_local_index.read().unwrap();
    assert!(
        by_index.is_empty(),
        "after removing the only peer, no demux entries should remain; \
         found {} — install/reconcile race left orphans",
        by_index.len()
    );
}

/// r6 regression for the MINOR Codex finding: `try_encap` must
/// not consume a tx counter (or write the WG header) when it
/// returns `BufferTooSmall` because the inner IP would overflow
/// the PADDED_PLAINTEXT_MAX staging buffer.
///
/// Pre-fix sequence at engine.rs:
///   1. `out.len() < required` check (fires for small `out`).
///   2. `next_tx_counter()` — counter advances.
///   3. `encode_data_header(out, ...)` — 16 bytes written.
///   4. `padded_len > PADDED_PLAINTEXT_MAX` check — fires here.
/// Result on the failure path: counter consumed, header dirty,
/// and the caller sees BufferTooSmall but cannot rely on
/// "Err leaves state untouched".
///
/// Post-fix: the PADDED_PLAINTEXT_MAX guard is hoisted above
/// `next_tx_counter()` (and above the header write), so the
/// failure path leaves both the counter and `out` untouched.
#[test]
fn encap_padded_plaintext_overflow_leaves_counter_and_buffer_untouched() {
    let (init_priv, _init_pub) = keypair();
    let (peer_priv, peer_pub) = keypair();
    let engine = WgEngine::new(WgEngineConfig {
        local_private_key: init_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: peer_pub,
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let peer_engine = WgEngine::new(WgEngineConfig {
        local_private_key: peer_priv.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: [0u8; 32],
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let session = make_session_for(&engine, peer_pub, &peer_engine, 0xdead_0001, 2);
    engine.install_session(&peer_pub, session).unwrap();
    // inner_ip = 4097 bytes → pad_to_16(4097) = 4112 >
    // PADDED_PLAINTEXT_MAX (4096). `out` is sized large enough to
    // hold header + 4112 + 16 so it cleanly passes the
    // `out.len() < required` guard and only the staging guard
    // can fire.
    let inner = vec![0x45u8; 4097];
    let mut out = vec![0xa5u8; WG_DATA_HEADER_LEN + 4112 + POLY1305_TAG_LEN];
    // Snapshot the per-session counter pre-encap.
    let counter_before = session_tx_counter(&engine, &peer_pub);
    let err = engine.try_encap(&peer_pub, &inner, &mut out).unwrap_err();
    assert_eq!(err, EncapError::BufferTooSmall);
    let counter_after = session_tx_counter(&engine, &peer_pub);
    assert_eq!(
        counter_before, counter_after,
        "BufferTooSmall on PADDED_PLAINTEXT_MAX overflow must NOT advance tx counter"
    );
    // First 16 bytes of `out` must remain the 0xa5 sentinel — no
    // partial header write on the failure path.
    assert!(
        out[..WG_DATA_HEADER_LEN].iter().all(|&b| b == 0xa5),
        "BufferTooSmall must NOT write the WG header into `out`"
    );
}

/// Helper for the BufferTooSmall counter-leak test: read the
/// `current` session's tx_counter for `pubkey`.
fn session_tx_counter(engine: &WgEngine, pubkey: &[u8; 32]) -> u64 {
    let table = engine.load_table();
    let idx = *table.peer_index_by_pubkey.get(pubkey).unwrap();
    let peer = table.peers[idx as usize].peer.clone();
    let cur = peer.current.read().unwrap().clone().unwrap();
    cur.tx_counter.load(Ordering::Relaxed)
}

// === #1434 multi-peer tests ===

/// #1434 B1b: the encap-side cryptokey-routing lookup must select the
/// peer whose AllowedIPs cover the inner DESTINATION (longest-prefix
/// match), returning that peer's pubkey + endpoint. A dst no peer claims
/// returns None (the frame is dropped — nowhere to send it).
#[test]
fn peer_for_dest_lpm_selects_owning_peer() {
    let (local_priv, _local_pub) = keypair();
    let (_a_priv, a_pub) = keypair();
    let (_b_priv, b_pub) = keypair();
    let a_ep: std::net::SocketAddr = "203.0.113.1:51820".parse().unwrap();
    let b_ep: std::net::SocketAddr = "198.51.100.7:51820".parse().unwrap();
    let engine = WgEngine::new(WgEngineConfig {
        local_private_key: local_priv.into(),
        listen_port: 51820,
        peers: vec![
            WgPeerConfig {
                pubkey: a_pub,
                endpoint: Some(a_ep),
                persistent_keepalive: 0,
                allowed_ips: vec![ipnet::IpNet::from_str("10.1.0.0/16").unwrap()],
                preshared_key: [0u8; 32].into(),
            },
            WgPeerConfig {
                pubkey: b_pub,
                endpoint: Some(b_ep),
                persistent_keepalive: 0,
                // A more-specific /24 inside A would still resolve to B for
                // that /24 (global LPM), proving longest-prefix wins.
                allowed_ips: vec![
                    ipnet::IpNet::from_str("10.2.0.0/16").unwrap(),
                    ipnet::IpNet::from_str("10.1.5.0/24").unwrap(),
                ],
                preshared_key: [0u8; 32].into(),
            },
        ],
    });
    // 10.1.9.9 → A's /16.
    let (pk, ep) = engine
        .peer_for_dest("10.1.9.9".parse().unwrap())
        .expect("A covers 10.1.9.9");
    assert_eq!(pk, a_pub, "10.1.9.9 routes to peer A");
    assert_eq!(ep, Some(a_ep));
    // 10.2.3.4 → B's /16.
    let (pk, ep) = engine
        .peer_for_dest("10.2.3.4".parse().unwrap())
        .expect("B covers 10.2.3.4");
    assert_eq!(pk, b_pub, "10.2.3.4 routes to peer B");
    assert_eq!(ep, Some(b_ep));
    // 10.1.5.7 → B's MORE-SPECIFIC /24 even though A's /16 also covers it.
    let (pk, _ep) = engine
        .peer_for_dest("10.1.5.7".parse().unwrap())
        .expect("B's /24 covers 10.1.5.7");
    assert_eq!(pk, b_pub, "longest-prefix /24 wins over the covering /16");
    // 192.0.2.1 → no peer.
    assert!(
        engine.peer_for_dest("192.0.2.1".parse().unwrap()).is_none(),
        "an unclaimed dst selects no peer"
    );
}

/// #1434 B2: a per-peer preshared key must round-trip through a real
/// handshake — matching PSKs complete, a mismatched PSK fails the AEAD
/// in msg2. Exercises the initiator (build-time PSK) and responder
/// (set_psk-after-msg1) paths together.
#[test]
fn per_peer_psk_handshake_roundtrip() {
    let (init_priv, init_pub) = keypair();
    let (resp_priv, resp_pub) = keypair();
    let psk = [0x5au8; 32];

    let make = |local_priv: [u8; 32], peer_pub, peer_psk: [u8; 32]| {
        WgEngine::new(WgEngineConfig {
            local_private_key: local_priv.into(),
            listen_port: 51820,
            peers: vec![WgPeerConfig {
                pubkey: peer_pub,
                endpoint: None,
                persistent_keepalive: 0,
                allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
                preshared_key: peer_psk.into(),
            }],
        })
    };

    // Matching PSK on both sides → full handshake completes.
    {
        let init = make(init_priv, resp_pub, psk);
        let resp = make(resp_priv, init_pub, psk);
        let mut init_hs = init.build_initiator_handshake(&resp_pub).unwrap();
        let mut msg1 = [0u8; 1024];
        let mut sink = [0u8; 1024];
        let n1 = init_hs.write_message(&[], &mut msg1).unwrap();
        // Responder side: build, read msg1, set the peer's PSK, write msg2.
        let mut resp_hs = resp.build_responder_handshake().unwrap();
        resp_hs.read_message(&msg1[..n1], &mut sink).unwrap();
        let rs = resp_hs.get_remote_static().unwrap();
        assert_eq!(rs, init_pub, "responder recovers the initiator pubkey");
        resp_hs.set_psk(2, &psk).unwrap();
        let mut msg2 = [0u8; 1024];
        let n2 = resp_hs.write_message(&[], &mut msg2).unwrap();
        // Initiator reads msg2 (PSK was set at build via build_initiator).
        init_hs
            .read_message(&msg2[..n2], &mut sink)
            .expect("matching PSK must complete the handshake");
        assert!(init_hs.is_handshake_finished());
    }

    // Mismatched PSK (initiator zero, responder real) → msg2 AEAD fails.
    {
        let init = make(init_priv, resp_pub, [0u8; 32]); // no PSK
        let resp = make(resp_priv, init_pub, psk); // real PSK
        let mut init_hs = init.build_initiator_handshake(&resp_pub).unwrap();
        let mut msg1 = [0u8; 1024];
        let mut sink = [0u8; 1024];
        let n1 = init_hs.write_message(&[], &mut msg1).unwrap();
        let mut resp_hs = resp.build_responder_handshake().unwrap();
        resp_hs.read_message(&msg1[..n1], &mut sink).unwrap();
        resp_hs.set_psk(2, &psk).unwrap();
        let mut msg2 = [0u8; 1024];
        let n2 = resp_hs.write_message(&[], &mut msg2).unwrap();
        assert!(
            init_hs.read_message(&msg2[..n2], &mut sink).is_err(),
            "a PSK mismatch must fail the msg2 AEAD"
        );
    }
}

#[test]
fn wg_config_secret_carriers_are_zeroizing() {
    // #4103 F12: the config carriers for the X25519 private key and the
    // per-peer PSK must be `Zeroizing<[u8; 32]>` (matching the runtime
    // copies — the engine's `local_private_key` and `PeerConfig`'s PSK) so
    // a cloned/dropped WG config does not leave plaintext key material in
    // freed heap/stack. Reverting either field back to a plain `[u8; 32]`
    // makes these type-annotated bindings fail to compile (RED).
    let cfg = WgEngineConfig {
        local_private_key: [1u8; 32].into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: [2u8; 32],
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![],
            preshared_key: [3u8; 32].into(),
        }],
    };
    let priv_ref: &zeroize::Zeroizing<[u8; 32]> = &cfg.local_private_key;
    let psk_ref: &zeroize::Zeroizing<[u8; 32]> = &cfg.peers[0].preshared_key;
    assert_eq!(**priv_ref, [1u8; 32]);
    assert_eq!(**psk_ref, [3u8; 32]);
    // Clone preserves the Zeroizing wrapper (no plaintext copy escapes).
    let cloned: zeroize::Zeroizing<[u8; 32]> = cfg.local_private_key.clone();
    assert_eq!(*cloned, [1u8; 32]);
}

// ===================================================================
// #4094 PR-A: responder under-load cookie / MAC2 anti-flood gate.
// classify_initiation is the DoS-mitigation seam that decides whether
// an inbound type-1 initiation reaches the expensive Noise handshake.
// ===================================================================

/// Build an engine whose responder static pubkey is known to the test,
/// plus a synthetic VALID-MAC1 initiation toward it (MAC2 = zeros, as a
/// not-yet-challenged initiator sends). The Noise body is a fixed pattern
/// — classify_initiation never runs snow, it only inspects MAC1/MAC2, so a
/// real snow body is unnecessary here (the handshake path itself is
/// covered by the interop tests).
fn under_load_fixture() -> (WgEngine, [u8; 32], [u8; super::super::WG_MSG_INIT_LEN]) {
    let (priv_k, _pub_k) = keypair();
    let engine = WgEngine::new(WgEngineConfig {
        local_private_key: priv_k.into(),
        listen_port: 51820,
        peers: vec![WgPeerConfig {
            pubkey: [0x99u8; 32],
            endpoint: None,
            persistent_keepalive: 0,
            allowed_ips: vec![ipnet::IpNet::from_str("10.0.0.0/24").unwrap()],
            preshared_key: [0u8; 32].into(),
        }],
    });
    let our_pub = engine.local_public_key();
    let noise = [0x3Cu8; crate::afxdp::wg::handshake::MSG_INIT_NOISE_LEN];
    let mut init = [0u8; super::super::WG_MSG_INIT_LEN];
    crate::afxdp::wg::handshake::build_initiation(&mut init, 0xCAFE_1234, &noise, &our_pub)
        .unwrap();
    (engine, our_pub, init)
}

/// RED-on-revert: under a simulated initiation flood the responder MUST
/// answer a spoofed/unprimed initiation (valid MAC1, no valid MAC2) with a
/// cookie challenge and NOT run the Noise handshake. On revert (no cookie
/// gate) classify_initiation would return `Process` for every initiation —
/// the CPU-exhaustion DoS. An initiation that echoes a valid MAC2 (derived
/// from the cookie the responder issued to its real source) IS processed,
/// and a peer that never crossed the load threshold is processed with no
/// challenge (no regression on the normal path).
#[test]
fn classify_initiation_under_load_requires_mac2() {
    use crate::afxdp::wg::cookie::{
        CookieChecker, INITIATIONS_UNDER_LOAD_THRESHOLD, stamp_initiation_mac2,
    };
    use std::net::SocketAddr;

    let (engine, our_pub, init) = under_load_fixture();
    let now = 10_000_000_000u64; // 10 s (nonzero: engages the mock clock)
    engine.set_mock_now_ns(now);
    let from: SocketAddr = "203.0.113.9:51820".parse().unwrap();
    let mut out = [0u8; 256];

    // Normal load: a valid initiation is processed WITHOUT a challenge —
    // the not-under-load path is byte-identical to today (skip-verify).
    assert_eq!(
        engine.classify_initiation(&init, from, &mut out, now),
        InitiationAction::Process,
        "under threshold, a normal initiation must proceed with no cookie"
    );

    // Drive the arrival rate past the threshold within the same 1 s window.
    for _ in 0..(INITIATIONS_UNDER_LOAD_THRESHOLD + 4) {
        engine.classify_initiation(&init, from, &mut out, now);
    }

    // Under load, an initiation with NO valid MAC2 is cookie-challenged and
    // DROPPED — the Noise handshake is never spent. This is the RED-on-
    // revert assertion (reverting the gate makes this `Process`).
    let action = engine.classify_initiation(&init, from, &mut out, now);
    let cookie_len = match action {
        InitiationAction::SendCookie(len) => len,
        other => panic!("under-load init without MAC2 must be cookie-challenged, got {other:?}"),
    };
    assert_eq!(cookie_len, crate::afxdp::wg::cookie::WG_MSG_COOKIE_LEN);
    assert_eq!(out[0], crate::afxdp::wg::WG_TYPE_COOKIE);

    // A real initiator decrypts the cookie (PR-B mirror) using our pubkey +
    // the initiation's MAC1 as AAD, then stamps a valid MAC2 over the same
    // source. That initiation IS processed under load.
    let aad_mac1 = &init[116..132];
    let cookie = CookieChecker::decrypt_cookie_reply(&out[..cookie_len], &our_pub, aad_mac1)
        .expect("cookie reply must decrypt");
    let mut primed = init;
    stamp_initiation_mac2(&mut primed, &cookie);
    assert_eq!(
        engine.classify_initiation(&primed, from, &mut out, now),
        InitiationAction::Process,
        "under load, an initiation with a VALID MAC2 must reach the handshake"
    );

    // The SAME MAC2 replayed from a DIFFERENT source is still challenged:
    // the cookie binds to the source that received the reply, so a spoofed
    // source cannot borrow another endpoint's MAC2.
    let spoof: SocketAddr = "198.51.100.7:51820".parse().unwrap();
    assert!(
        matches!(
            engine.classify_initiation(&primed, spoof, &mut out, now),
            InitiationAction::SendCookie(_)
        ),
        "a stolen MAC2 must not authorize a handshake from a different source"
    );

    // The DoS-mitigation counters moved.
    let c = engine.counters();
    assert!(
        c.hs_cookie_replies_sent.load(Ordering::Relaxed) >= 2,
        "cookie replies issued for the unprimed + spoofed initiations"
    );
    assert!(
        c.hs_rx_under_load_mac2_ok.load(Ordering::Relaxed) >= 1,
        "the primed initiation counted as an under-load MAC2 pass"
    );
    assert!(c.hs_rx_under_load_no_mac2.load(Ordering::Relaxed) >= 2);
}

/// A bad-MAC1 initiation under load is NOT reflected: it returns `Process`
/// so the consume path drops it cheaply (before any crypto) with the
/// mac1_mismatch counter, and NO cookie reply is emitted — a random /
/// bad-MAC1 flood cannot turn the responder into a reflector.
#[test]
fn classify_initiation_bad_mac1_under_load_no_reflection() {
    use crate::afxdp::wg::cookie::INITIATIONS_UNDER_LOAD_THRESHOLD;
    use std::net::SocketAddr;

    let (engine, _our_pub, good) = under_load_fixture();
    let now = 20_000_000_000u64;
    engine.set_mock_now_ns(now);
    let from: SocketAddr = "203.0.113.9:51820".parse().unwrap();
    let mut out = [0u8; 256];

    // Corrupt the MAC1 field (msg[116..132]) so parse_initiation rejects it.
    let mut bad = good;
    bad[116] ^= 0xFF;

    for _ in 0..(INITIATIONS_UNDER_LOAD_THRESHOLD + 4) {
        engine.classify_initiation(&good, from, &mut out, now);
    }
    let before = engine
        .counters()
        .hs_cookie_replies_sent
        .load(Ordering::Relaxed);
    // Under load, a bad-MAC1 init falls through to the cheap consume drop.
    assert_eq!(
        engine.classify_initiation(&bad, from, &mut out, now),
        InitiationAction::Process,
        "bad-MAC1 under load must not be challenged (no reflection)"
    );
    assert_eq!(
        engine
            .counters()
            .hs_cookie_replies_sent
            .load(Ordering::Relaxed),
        before,
        "no cookie reply is emitted for a bad-MAC1 initiation"
    );
}
