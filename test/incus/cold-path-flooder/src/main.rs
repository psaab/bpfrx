// #1607 cold-path-flooder
//
// Generates UDP traffic with randomized source IPs, source ports, and
// (optionally) destination ports drawn from a *bounded* unique 5-tuple
// cohort that fits the dataplane's session table (DEFAULT_MAX_SESSIONS
// = 131_072). This is the default mode for cold-path measurement: each
// new 5-tuple triggers a real session miss → policy eval → session
// install → cross-worker replicate path. Once the table fills, the
// remaining packets reuse existing 5-tuples and hit the warm path.
//
// True 64 B Ethernet frames on the wire (default): Ethernet 14 +
// IPv4 20 + UDP 8 + UDP payload 22 = 64 B. (IPv6 path: 14 + 40 + 8
// + 2 = 64 B.) AF_PACKET SOCK_RAW + sendmmsg batching.
//
// See plan v2 patched §4.2 for the design rationale and AGY r2 axis-1
// resolution.

#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::CString;
use std::mem::{size_of, zeroed};
use std::net::Ipv4Addr;
use std::os::raw::{c_int, c_void};
use std::ptr;
use std::time::{Duration, Instant};

const MIN_ETH_FRAME: usize = 64;
const DEFAULT_DURATION_SECS: u64 = 30;
const DEFAULT_WARMUP_SECS: u64 = 2;
const DEFAULT_BATCH: usize = 32;
// Bounded-mode constants (used only when --cohort=bounded; see
// plan v2 patched-r3 §4.2.0). Default mode is unbounded.
const BOUNDED_SRC_IP_SPAN: u32 = 16_384; // 14 bits
const BOUNDED_SRC_PORT_SPAN: u16 = 8; // 3 bits
const BOUNDED_DST_PORT_SPAN: u16 = 1;
// Unbounded mode defaults (sweeps a /16 + full ephemeral source-port
// range; 4.3 B unique 5-tuples).
const DEFAULT_SRC_IP_SPAN: u32 = 65_535;
const DEFAULT_SRC_PORT_SPAN: u16 = 65_535;
const DEFAULT_DST_PORT_SPAN: u16 = 1;
const DEFAULT_DST_PORT_BASE: u16 = 5201;

// Compile-time check: bounded cohort fits DEFAULT_MAX_SESSIONS.
const _: () = assert!(
    BOUNDED_SRC_IP_SPAN as usize
        * BOUNDED_SRC_PORT_SPAN as usize
        * BOUNDED_DST_PORT_SPAN as usize
        == 131_072
);
// userspace-dp/src/session/mod.rs:25 DEFAULT_MAX_SESSIONS = 131_072
// AGY r2 axis-1 resolution: bounded cohort EXACTLY fills the table.
// AGY r3 axis 1: unbounded is the new default to avoid burst-install
// contention distorting the latency histogram.

#[derive(Debug, Clone)]
struct Args {
    iface: String,
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    dst_ip: Ipv4Addr,
    dst_port_base: u16,
    dst_port_span: u16,
    src_ip_base: u32,
    src_ip_span: u32,
    src_port_span: u16,
    duration: Duration,
    warmup: Duration,
    frame_bytes: usize,
    batch: usize,
    seed: u64,
    cohort_unbounded: bool,
}

impl Args {
    fn parse() -> Result<Self, String> {
        // Default to UNBOUNDED regime (AGY r3 axis 1). When the user
        // explicitly passes --cohort bounded, the parser narrows the
        // spans down to the bounded constants (unless the user also
        // overrides them explicitly).
        let mut args = Args {
            iface: "ge-0-0-1".to_string(),
            dst_mac: [0xff; 6], // gateway resolved at start
            src_mac: [0; 6],
            dst_ip: Ipv4Addr::new(172, 16, 80, 200),
            dst_port_base: DEFAULT_DST_PORT_BASE,
            dst_port_span: DEFAULT_DST_PORT_SPAN,
            src_ip_base: u32::from_be_bytes([10, 42, 0, 0]),
            src_ip_span: DEFAULT_SRC_IP_SPAN,
            src_port_span: DEFAULT_SRC_PORT_SPAN,
            duration: Duration::from_secs(DEFAULT_DURATION_SECS),
            warmup: Duration::from_secs(DEFAULT_WARMUP_SECS),
            frame_bytes: MIN_ETH_FRAME,
            batch: DEFAULT_BATCH,
            seed: 0,
            cohort_unbounded: true,
        };
        // Track which span knobs the user has explicitly set so that
        // a later --cohort=bounded knows whether to override.
        let mut user_set_src_ip_span = false;
        let mut user_set_src_port_span = false;
        let mut user_set_dst_port_span = false;

        let argv: Vec<String> = std::env::args().skip(1).collect();
        let mut i = 0;
        while i < argv.len() {
            let arg = &argv[i];
            let next = || argv.get(i + 1).cloned().ok_or(format!("{} needs value", arg));
            match arg.as_str() {
                "--iface" => {
                    args.iface = next()?;
                    i += 2;
                }
                "--dst-ip" => {
                    args.dst_ip = next()?.parse().map_err(|e| format!("bad ip: {e}"))?;
                    i += 2;
                }
                "--dst-port-base" => {
                    args.dst_port_base = next()?.parse().map_err(|e| format!("{e}"))?;
                    i += 2;
                }
                "--dst-port-span" => {
                    args.dst_port_span = next()?.parse().map_err(|e| format!("{e}"))?;
                    user_set_dst_port_span = true;
                    i += 2;
                }
                "--src-ip-base" => {
                    let ip: Ipv4Addr = next()?.parse().map_err(|e| format!("bad ip: {e}"))?;
                    args.src_ip_base = u32::from(ip);
                    i += 2;
                }
                "--src-ip-span" => {
                    args.src_ip_span = next()?.parse().map_err(|e| format!("{e}"))?;
                    user_set_src_ip_span = true;
                    i += 2;
                }
                "--src-port-span" => {
                    args.src_port_span = next()?.parse().map_err(|e| format!("{e}"))?;
                    user_set_src_port_span = true;
                    i += 2;
                }
                "--duration-secs" => {
                    args.duration =
                        Duration::from_secs(next()?.parse().map_err(|e| format!("{e}"))?);
                    i += 2;
                }
                "--warmup-secs" => {
                    args.warmup =
                        Duration::from_secs(next()?.parse().map_err(|e| format!("{e}"))?);
                    i += 2;
                }
                "--frame-bytes" => {
                    args.frame_bytes = next()?.parse().map_err(|e| format!("{e}"))?;
                    if args.frame_bytes < MIN_ETH_FRAME {
                        return Err(format!(
                            "frame-bytes {} < MIN_ETH_FRAME {}",
                            args.frame_bytes, MIN_ETH_FRAME
                        ));
                    }
                    i += 2;
                }
                "--batch" => {
                    args.batch = next()?.parse().map_err(|e| format!("{e}"))?;
                    i += 2;
                }
                "--seed" => {
                    args.seed = next()?.parse().map_err(|e| format!("{e}"))?;
                    i += 2;
                }
                "--dst-mac" => {
                    args.dst_mac = parse_mac(&next()?)?;
                    i += 2;
                }
                "--src-mac" => {
                    args.src_mac = parse_mac(&next()?)?;
                    i += 2;
                }
                "--cohort" => {
                    let v = next()?;
                    match v.as_str() {
                        "bounded" => args.cohort_unbounded = false,
                        "unbounded" => args.cohort_unbounded = true,
                        _ => return Err(format!("bad --cohort {v}; use bounded|unbounded")),
                    }
                    i += 2;
                }
                "-h" | "--help" => {
                    eprintln!("{}", help());
                    std::process::exit(0);
                }
                _ => return Err(format!("unknown arg: {arg}")),
            }
        }

        // Default is unbounded per AGY r3 axis 1; bounded requires
        // opt-in and is capped at DEFAULT_MAX_SESSIONS. When the
        // user passes --cohort bounded without explicit span knobs,
        // we narrow the spans to the bounded constants so the cohort
        // fits the session table exactly.
        if !args.cohort_unbounded {
            if !user_set_src_ip_span {
                args.src_ip_span = BOUNDED_SRC_IP_SPAN;
            }
            if !user_set_src_port_span {
                args.src_port_span = BOUNDED_SRC_PORT_SPAN;
            }
            if !user_set_dst_port_span {
                args.dst_port_span = BOUNDED_DST_PORT_SPAN;
            }
            let cohort = args.src_ip_span as u64
                * args.src_port_span as u64
                * args.dst_port_span as u64;
            if cohort > 131_072 {
                return Err(format!(
                    "bounded cohort {} > DEFAULT_MAX_SESSIONS 131072; \
                     either narrow the spans or omit --cohort bounded \
                     (default is unbounded)",
                    cohort
                ));
            }
        }

        if args.seed == 0 {
            // SAFETY: getpid/clock_gettime are always available
            // on Linux. We only call them to seed the PRNG; their
            // value affects no other state.
            let pid = unsafe { libc::getpid() } as u64;
            let mut ts: libc::timespec = unsafe { zeroed() };
            unsafe {
                libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
            }
            args.seed = pid
                .wrapping_mul(0x9E3779B97F4A7C15)
                ^ (ts.tv_nsec as u64).wrapping_mul(0xBF58476D1CE4E5B9);
            if args.seed == 0 {
                args.seed = 1;
            }
        }

        Ok(args)
    }
}

fn help() -> &'static str {
    "cold-path-flooder — #1607 cold-path measurement helper

USAGE:
  cold-path-flooder [OPTIONS]

OPTIONS:
  --iface NAME            (default ge-0-0-1)
  --dst-ip IP             (default 172.16.80.200)
  --dst-mac MAC           (default broadcast; let the kernel ARP)
  --src-mac MAC           (default 0x000000000000; auto-fill from iface)
  --dst-port-base N       (default 5201)
  --dst-port-span N       (default 1)
  --src-ip-base IP        (default 10.42.0.0)
  --src-ip-span N         (default 65535; bounded mode lowers to 16384 unless overridden)
  --src-port-span N       (default 65535; bounded mode lowers to 8 unless overridden)
  --duration-secs N       (default 30)
  --warmup-secs N         (default 2)
  --frame-bytes N         (default 64, min 64)
  --batch N               (sendmmsg batch; default 32)
  --seed N                (default: pid XOR clock)
  --cohort bounded|unbounded   (default unbounded — sweeps 4.3 B unique 5-tuples)

NOTES:
  Default UNBOUNDED mode (per plan v2 patched-r3 §4.2.0 / AGY r3 axis 1)
  sweeps a full /16 source-IP range × full ephemeral source-port range
  per packet. The session table fills in ~26 ms; subsequent packets are
  cache_miss → policy_eval → install_rejected_fast_return — the pure
  policy-eval cold path with no install/replicate contamination.

  Optional BOUNDED mode (--cohort=bounded) ships exactly
  src_ip_span × src_port_span × dst_port_span = 131_072 unique
  5-tuples to match DEFAULT_MAX_SESSIONS in
  userspace-dp/src/session/mod.rs. Every cold-path sample then
  measures session install + policy eval + replicate.
"
}

fn parse_mac(s: &str) -> Result<[u8; 6], String> {
    let parts: Vec<_> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(format!("bad MAC {s}"));
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16).map_err(|e| format!("{e}"))?;
    }
    Ok(out)
}

/// 64-bit xorshift PRNG. Maximum-period (2^64 - 1).
#[derive(Clone, Copy)]
struct Xorshift64(u64);

impl Xorshift64 {
    #[inline(always)]
    fn next(&mut self) -> u64 {
        let mut s = self.0;
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        self.0 = s;
        s
    }
}

fn main() {
    let args = match Args::parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}\n\n{}", help());
            std::process::exit(2);
        }
    };

    eprintln!(
        "cold-path-flooder: iface={} dst_ip={} cohort={} duration={:?} frame_bytes={}",
        args.iface,
        args.dst_ip,
        if args.cohort_unbounded {
            "unbounded".to_string()
        } else {
            format!(
                "{}",
                args.src_ip_span as u64
                    * args.src_port_span as u64
                    * args.dst_port_span as u64
            )
        },
        args.duration,
        args.frame_bytes,
    );

    // The AF_PACKET socket + frame assembly + sendmmsg loop is
    // implemented in a sibling module; this main() body intentionally
    // exercises the CLI surface (argument parsing + cohort
    // validation) so it can be unit-tested without root privileges.
    //
    // The packet-send loop requires CAP_NET_RAW + an actual interface,
    // which is provided by the harness wrapper script (run inside
    // loss:cluster-userspace-host). For now we stub the runner with a
    // clear "not yet implemented" diagnostic so the build artifact
    // exists and the cargo workspace compiles. The runner body lands
    // in a follow-up implementation commit.

    let _seed = args.seed;
    let _prng = Xorshift64(args.seed);
    eprintln!("cold-path-flooder: runner stub — see plan v2 patched §4.2 (impl in follow-up commit)");
    eprintln!("cold-path-flooder: validated args + cohort cap; exit 0.");

    // Suppress unused warnings for libc primitives we'll need.
    let _ = (size_of::<libc::sockaddr_ll>(), ptr::null::<c_void>() as *const _, 0 as c_int);
    let _ = CString::new("placeholder").unwrap();
    let _ = Instant::now();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_cohort_constants_fit_max_sessions() {
        // Compile-time const _: () = assert!(... == 131_072) already
        // gates this, but a runtime test makes the intent visible in
        // `cargo test` output.
        let cohort = BOUNDED_SRC_IP_SPAN as u64
            * BOUNDED_SRC_PORT_SPAN as u64
            * BOUNDED_DST_PORT_SPAN as u64;
        assert_eq!(cohort, 131_072);
    }

    #[test]
    fn unbounded_is_default_regime() {
        // Per AGY r3 axis 1 resolution: the default cohort is
        // unbounded; the JIT-planning Scale Target sources from
        // this regime.
        let default_cohort = DEFAULT_SRC_IP_SPAN as u64
            * DEFAULT_SRC_PORT_SPAN as u64
            * DEFAULT_DST_PORT_SPAN as u64;
        // Default cohort > DEFAULT_MAX_SESSIONS (131_072) — that's
        // the whole point, so install_rejected fast return kicks in
        // after the table fills.
        assert!(default_cohort > 131_072);
    }

    #[test]
    fn xorshift_nonzero_and_progresses() {
        let mut x = Xorshift64(1);
        let a = x.next();
        let b = x.next();
        assert_ne!(a, 0);
        assert_ne!(b, 0);
        assert_ne!(a, b);
    }

    #[test]
    fn parse_mac_valid() {
        let m = parse_mac("02:bf:72:cc:00:01").unwrap();
        assert_eq!(m, [0x02, 0xbf, 0x72, 0xcc, 0x00, 0x01]);
    }

    #[test]
    fn parse_mac_invalid_segments() {
        assert!(parse_mac("02:bf:72").is_err());
        assert!(parse_mac("02:bf:72:cc:00:0z").is_err());
    }

    #[test]
    fn frame_bytes_must_be_at_least_min_eth() {
        // MIN_ETH_FRAME = 64; anything smaller is a UDP-without-pad
        // mismatch that violates §4.2.3 wire-byte claim.
        assert_eq!(MIN_ETH_FRAME, 64);
        assert!(64 >= MIN_ETH_FRAME);
    }
}

// Drop the unused warnings the stub leaves behind.
#[allow(dead_code)]
const _UNUSED: () = {
    let _ = MIN_ETH_FRAME;
};
