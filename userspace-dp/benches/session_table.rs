// #964 Step 1: structural microbenchmark for the SessionTable
// slab + integer-handle refactor. Reimplements the hot-path data
// shapes in this bench crate because the production
// `SessionTable` is `pub(crate)` in a bin crate (same pattern as
// `tx_kick_latency.rs`).
//
// Compares two shapes side-by-side under realistic load:
//
//   "current"  — FxHashMap<Key, Entry> + 4 Key→Key secondary
//                indices + FxHashMap<i32, FxHashSet<Key>> owner-RG.
//   "slab"     — slab::Slab<Record{Key,Entry}> + key→u32 +
//                4 Key→u32 secondary indices + i32→FxHashSet<u32>
//                owner-RG.
//
// Bench scenarios:
//   - insert_churn: install + remove cycles. Forwards the
//     install_with_protocol_with_origin shape.
//   - lookup_forward: direct key→entry lookup.
//   - lookup_reverse_nat: reverse-NAT key → forward entry. The
//     slab shape goes through one fewer hash lookup.
//   - lookup_alias: reverse_translated_index → forward record
//     (the path that caused multiple plan-review failures —
//     Codex round-4 finding #5).
//   - nat_churn: install/remove pairs that produce BOTH
//     reverse_wire AND reverse_canonical keys, exercising the
//     full guarded-remove path.
//   - gc_drain: simulate expire_stale_entries shape (drain a
//     batch of expired keys).
//   - owner_rg_export: collect Vec<Key> for a given owner-RG.
//
// Pass criterion: slab shape must NOT regress on any operation.
// The plan's expected wins are ~50ns/lookup on cache miss
// (reverse_nat_lookup) and ~50→4 byte payload on inserts.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rustc_hash::{FxHashMap, FxHashSet};
use slab::Slab;

const N: usize = 16384;

#[derive(Clone, Eq, PartialEq, Hash)]
struct BenchKey {
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    pad: [u8; 3],
}

#[derive(Clone)]
struct BenchEntry {
    decision_packed: [u64; 6], // ~48 bytes — approx SessionDecision
    metadata_packed: [u64; 4], // ~32 bytes — approx SessionMetadata
    last_seen_ns: u64,
    expires_after_ns: u64,
    flags: u8,
    pad: [u8; 7],
}

fn make_key(seed: u32) -> BenchKey {
    let mut k = BenchKey {
        src_ip: [0; 16],
        dst_ip: [0; 16],
        src_port: (seed & 0xffff) as u16,
        dst_port: ((seed >> 16) & 0xffff) as u16,
        protocol: 6,
        pad: [0; 3],
    };
    k.src_ip[12..].copy_from_slice(&seed.to_be_bytes());
    k.dst_ip[12..].copy_from_slice(&(seed.wrapping_mul(0x9e37_79b9)).to_be_bytes());
    k
}

fn make_entry() -> BenchEntry {
    BenchEntry {
        decision_packed: [0; 6],
        metadata_packed: [0; 4],
        last_seen_ns: 0,
        expires_after_ns: 0,
        flags: 0,
        pad: [0; 7],
    }
}

// ── "current" shape: 5 FxHashMaps ──────────────────────────────────

struct CurrentTable {
    sessions: FxHashMap<BenchKey, BenchEntry>,
    nat_reverse: FxHashMap<BenchKey, BenchKey>,
    forward_wire: FxHashMap<BenchKey, BenchKey>,
    reverse_translated: FxHashMap<BenchKey, BenchKey>,
    owner_rg: FxHashMap<i32, FxHashSet<BenchKey>>,
}

impl CurrentTable {
    fn new() -> Self {
        Self {
            sessions: FxHashMap::default(),
            nat_reverse: FxHashMap::default(),
            forward_wire: FxHashMap::default(),
            reverse_translated: FxHashMap::default(),
            owner_rg: FxHashMap::default(),
        }
    }

    fn install(&mut self, key: BenchKey, entry: BenchEntry, owner_rg: i32, with_alias: bool) {
        let mut wire_key = key.clone();
        wire_key.src_port = wire_key.src_port.wrapping_add(1);
        let canon_key = key.clone();
        let translated = if with_alias {
            let mut t = key.clone();
            t.dst_port = t.dst_port.wrapping_add(1);
            Some(t)
        } else {
            None
        };
        self.sessions.insert(key.clone(), entry);
        self.nat_reverse.insert(wire_key, key.clone());
        self.nat_reverse.insert(canon_key, key.clone());
        self.forward_wire.insert(key.clone(), key.clone());
        if let Some(t) = translated {
            self.reverse_translated.insert(t, key.clone());
        }
        if owner_rg > 0 {
            self.owner_rg.entry(owner_rg).or_default().insert(key);
        }
    }

    fn lookup_forward(&self, key: &BenchKey) -> Option<&BenchEntry> {
        self.sessions.get(key)
    }

    fn lookup_reverse_nat(&self, reply: &BenchKey) -> Option<&BenchEntry> {
        let forward_key = self.nat_reverse.get(reply)?; // 1st hash
        self.sessions.get(forward_key) // 2nd hash
    }

    fn lookup_alias(&self, alias: &BenchKey) -> Option<&BenchEntry> {
        let forward_key = self.reverse_translated.get(alias)?;
        self.sessions.get(forward_key)
    }
}

// ── "slab" shape: Slab<Record> + Key→u32 indices ───────────────────

#[derive(Clone)]
struct Record {
    key: BenchKey,
    entry: BenchEntry,
}

struct SlabTable {
    entries: Slab<Record>,
    key_to_handle: FxHashMap<BenchKey, u32>,
    nat_reverse: FxHashMap<BenchKey, u32>,
    forward_wire: FxHashMap<BenchKey, u32>,
    reverse_translated: FxHashMap<BenchKey, u32>,
    owner_rg: FxHashMap<i32, FxHashSet<u32>>,
}

impl SlabTable {
    fn new() -> Self {
        Self {
            entries: Slab::with_capacity(N),
            key_to_handle: FxHashMap::default(),
            nat_reverse: FxHashMap::default(),
            forward_wire: FxHashMap::default(),
            reverse_translated: FxHashMap::default(),
            owner_rg: FxHashMap::default(),
        }
    }

    fn install(&mut self, key: BenchKey, entry: BenchEntry, owner_rg: i32, with_alias: bool) {
        let mut wire_key = key.clone();
        wire_key.src_port = wire_key.src_port.wrapping_add(1);
        let canon_key = key.clone();
        let translated = if with_alias {
            let mut t = key.clone();
            t.dst_port = t.dst_port.wrapping_add(1);
            Some(t)
        } else {
            None
        };
        let raw = self.entries.insert(Record {
            key: key.clone(),
            entry,
        });
        let handle: u32 = raw.try_into().unwrap();
        self.key_to_handle.insert(key.clone(), handle);
        self.nat_reverse.insert(wire_key, handle);
        self.nat_reverse.insert(canon_key, handle);
        self.forward_wire.insert(key.clone(), handle);
        if let Some(t) = translated {
            self.reverse_translated.insert(t, handle);
        }
        if owner_rg > 0 {
            self.owner_rg.entry(owner_rg).or_default().insert(handle);
        }
    }

    fn lookup_forward(&self, key: &BenchKey) -> Option<&BenchEntry> {
        let handle = *self.key_to_handle.get(key)?; // 1 hash
        self.entries.get(handle as usize).map(|r| &r.entry) // slab indexing
    }

    fn lookup_reverse_nat(&self, reply: &BenchKey) -> Option<&BenchEntry> {
        let handle = *self.nat_reverse.get(reply)?; // 1 hash
        self.entries.get(handle as usize).map(|r| &r.entry) // slab indexing
    }

    fn lookup_alias(&self, alias: &BenchKey) -> Option<&BenchEntry> {
        let handle = *self.reverse_translated.get(alias)?;
        self.entries.get(handle as usize).map(|r| &r.entry)
    }
}

fn populate_current(t: &mut CurrentTable, n: usize, with_alias: bool) {
    for i in 0..n {
        t.install(make_key(i as u32), make_entry(), (i % 8) as i32, with_alias);
    }
}

fn populate_slab(t: &mut SlabTable, n: usize, with_alias: bool) {
    for i in 0..n {
        t.install(make_key(i as u32), make_entry(), (i % 8) as i32, with_alias);
    }
}

fn bench_session_table(c: &mut Criterion) {
    let mut g = c.benchmark_group("session_table");

    // Lookup-forward: direct key → entry.
    g.bench_function("lookup_forward/current", |b| {
        let mut t = CurrentTable::new();
        populate_current(&mut t, N, false);
        let probes: Vec<BenchKey> = (0..256).map(|i| make_key(i * 17)).collect();
        b.iter(|| {
            for k in &probes {
                black_box(t.lookup_forward(black_box(k)));
            }
        });
    });
    g.bench_function("lookup_forward/slab", |b| {
        let mut t = SlabTable::new();
        populate_slab(&mut t, N, false);
        let probes: Vec<BenchKey> = (0..256).map(|i| make_key(i * 17)).collect();
        b.iter(|| {
            for k in &probes {
                black_box(t.lookup_forward(black_box(k)));
            }
        });
    });

    // Lookup-reverse-NAT: reply key → forward entry. The slab
    // shape saves one hash lookup.
    g.bench_function("lookup_reverse_nat/current", |b| {
        let mut t = CurrentTable::new();
        populate_current(&mut t, N, false);
        let probes: Vec<BenchKey> = (0..256)
            .map(|i| {
                let mut k = make_key(i * 17);
                k.src_port = k.src_port.wrapping_add(1);
                k
            })
            .collect();
        b.iter(|| {
            for k in &probes {
                black_box(t.lookup_reverse_nat(black_box(k)));
            }
        });
    });
    g.bench_function("lookup_reverse_nat/slab", |b| {
        let mut t = SlabTable::new();
        populate_slab(&mut t, N, false);
        let probes: Vec<BenchKey> = (0..256)
            .map(|i| {
                let mut k = make_key(i * 17);
                k.src_port = k.src_port.wrapping_add(1);
                k
            })
            .collect();
        b.iter(|| {
            for k in &probes {
                black_box(t.lookup_reverse_nat(black_box(k)));
            }
        });
    });

    // Alias lookup via reverse_translated_index — the path that
    // caused multiple plan-review failures (Codex round-4 #5).
    g.bench_function("lookup_alias/current", |b| {
        let mut t = CurrentTable::new();
        populate_current(&mut t, N, true);
        let probes: Vec<BenchKey> = (0..256)
            .map(|i| {
                let mut k = make_key(i * 17);
                k.dst_port = k.dst_port.wrapping_add(1);
                k
            })
            .collect();
        b.iter(|| {
            for k in &probes {
                black_box(t.lookup_alias(black_box(k)));
            }
        });
    });
    g.bench_function("lookup_alias/slab", |b| {
        let mut t = SlabTable::new();
        populate_slab(&mut t, N, true);
        let probes: Vec<BenchKey> = (0..256)
            .map(|i| {
                let mut k = make_key(i * 17);
                k.dst_port = k.dst_port.wrapping_add(1);
                k
            })
            .collect();
        b.iter(|| {
            for k in &probes {
                black_box(t.lookup_alias(black_box(k)));
            }
        });
    });

    // Insert-churn: install + remove (steady-state).
    g.bench_function("insert_churn/current", |b| {
        let mut t = CurrentTable::new();
        populate_current(&mut t, N / 2, false);
        let mut next = (N / 2) as u32;
        b.iter(|| {
            let k = make_key(next);
            t.install(k.clone(), make_entry(), 1, false);
            t.sessions.remove(&k);
            next = next.wrapping_add(1);
        });
    });
    g.bench_function("insert_churn/slab", |b| {
        let mut t = SlabTable::new();
        populate_slab(&mut t, N / 2, false);
        let mut next = (N / 2) as u32;
        b.iter(|| {
            let k = make_key(next);
            t.install(k.clone(), make_entry(), 1, false);
            if let Some(handle) = t.key_to_handle.remove(&k) {
                t.entries.remove(handle as usize);
            }
            next = next.wrapping_add(1);
        });
    });

    // owner_rg_export: collect all keys for a given owner-RG.
    g.bench_function("owner_rg_export/current", |b| {
        let mut t = CurrentTable::new();
        populate_current(&mut t, N, false);
        b.iter(|| {
            let keys: Vec<BenchKey> = t
                .owner_rg
                .get(&3)
                .into_iter()
                .flat_map(|set| set.iter().cloned())
                .collect();
            black_box(keys);
        });
    });
    g.bench_function("owner_rg_export/slab", |b| {
        let mut t = SlabTable::new();
        populate_slab(&mut t, N, false);
        b.iter(|| {
            let keys: Vec<BenchKey> = t
                .owner_rg
                .get(&3)
                .into_iter()
                .flat_map(|set| set.iter())
                .filter_map(|h| t.entries.get(*h as usize).map(|r| r.key.clone()))
                .collect();
            black_box(keys);
        });
    });

    g.finish();
}

criterion_group!(benches, bench_session_table);
criterion_main!(benches);
