use std::path::PathBuf;

pub(crate) struct Args {
    pub(crate) iperf_json: PathBuf,
    pub(crate) binding_flows: PathBuf,
    pub(crate) cos_flows: Option<PathBuf>,
    pub(crate) cos_ifindex: Option<i32>,
    pub(crate) cos_queue_id: Option<u32>,
    /// Filter binding-flows rows to this interface name. Empty string =
    /// no filter (sum across all interfaces — only correct if your
    /// topology has just one). Defaults blank; harness script sets it.
    pub(crate) iface: String,
    pub(crate) warmup_secs: u64,
    pub(crate) final_burst_secs: u64,
    pub(crate) n_workers: u32,
    pub(crate) shaper_rate_bps: u64,
    pub(crate) rss_expectation: String,
    /// Operator declaration that the offered load is expected to
    /// saturate the Nₐ/Nᵥ-scaled structural cap. When set, Gate 3
    /// (aggregate throughput) is enforced: the observed aggregate must
    /// reach >=95% of the scaled cap, else the run FAILs. Without it the
    /// aggregate leg stays diagnostic-only (the doc's non-saturated
    /// exemption).
    pub(crate) expect_saturation: bool,
}

const USAGE: &str = "Usage: fairness-eval --iperf-json PATH --binding-flows PATH \\\n  [--cos-flows PATH --cos-ifindex N --cos-queue-id N] \\\n  [--iface NAME] [--warmup-secs N] [--final-burst-secs N] \\\n  [--n-workers N] [--shaper-rate-bps N] [--rss-expectation EXPR] \\\n  [--expect-saturation]\n\n--iface NAME: filter binding-flows rows to this interface (recommended for legacy per-binding mode).\n--cos-flows: class-specific CoS active-flow TSV; when present, Cstruct uses the selected CoS queue.\n--rss-expectation: any, balanced, at-least-active-workers:N, max-worker-flow-share:X, or cstruct-max:X.\n--expect-saturation: declare the offered load >= structural cap; enforces Gate 3 (aggregate >= 95% of the Na/Nv-scaled cap).";

/// Outcome of a failed `parse_args_from` — distinguishes a usage/validation
/// error (exit 2) from an explicit `--help` request (exit 0).
#[derive(Debug)]
pub(crate) enum ParseError {
    /// Bad or missing argument. Carries the operator-facing message.
    Usage(String),
    /// `-h`/`--help` was passed; the caller prints usage and exits 0.
    HelpRequested,
}

pub(crate) fn parse_args() -> Args {
    match parse_args_from(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(ParseError::HelpRequested) => {
            eprintln!("{USAGE}");
            std::process::exit(0);
        }
        Err(ParseError::Usage(msg)) => {
            eprintln!("fairness-eval: {msg}");
            std::process::exit(2);
        }
    }
}

/// Parse an argument iterator into `Args`, returning a structured error
/// instead of calling `std::process::exit`. This is the testable core of
/// `parse_args`.
///
/// A mistyped or out-of-range numeric value for `--warmup-secs`,
/// `--final-burst-secs`, `--n-workers`, or `--shaper-rate-bps` now returns
/// `ParseError::Usage` rather than silently falling back to the default
/// (ps-038-A1 F1). A silent fallback here could seed a false PASS/FAIL from
/// this fairness merge gate (#1630/#1614), so the harness fails fast on an
/// operator CLI mistake.
pub(crate) fn parse_args_from<I>(raw_args: I) -> Result<Args, ParseError>
where
    I: IntoIterator<Item = String>,
{
    let mut iperf_json: Option<PathBuf> = None;
    let mut binding_flows: Option<PathBuf> = None;
    let mut cos_flows: Option<PathBuf> = None;
    let mut cos_ifindex: Option<i32> = None;
    let mut cos_queue_id: Option<u32> = None;
    let mut iface: String = String::new();
    let mut warmup_secs: u64 = 5;
    let mut final_burst_secs: u64 = 1;
    let mut n_workers: u32 = 6;
    let mut shaper_rate_bps: u64 = 0;
    let mut rss_expectation: String = "any".to_string();
    let mut expect_saturation: bool = false;
    let mut args = raw_args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--iperf-json" => {
                iperf_json = Some(PathBuf::from(numeric_or_string(
                    parse_required_string_value("--iperf-json", args.next()),
                )?));
            }
            "--binding-flows" => {
                binding_flows = Some(PathBuf::from(numeric_or_string(
                    parse_required_string_value("--binding-flows", args.next()),
                )?));
            }
            "--cos-flows" => {
                cos_flows = Some(PathBuf::from(numeric_or_string(
                    parse_required_string_value("--cos-flows", args.next()),
                )?));
            }
            "--cos-ifindex" => {
                cos_ifindex = Some(numeric_or_string(parse_required_numeric_value(
                    "--cos-ifindex",
                    args.next(),
                ))?);
            }
            "--cos-queue-id" => {
                cos_queue_id = Some(numeric_or_string(parse_required_numeric_value(
                    "--cos-queue-id",
                    args.next(),
                ))?);
            }
            "--iface" => {
                // #6898 A1-b6-F3: use the SAME helper the other string-valued
                // flags use. This arm was the lone exception in the match —
                // `--iperf-json`, `--binding-flows` and `--cos-flows` all go
                // through `parse_required_string_value`, and every numeric flag
                // through `parse_required_numeric_value`. The inconsistency is
                // the argument: there is no reading under which `--iface`
                // should be the one flag that accepts a missing value.
                //
                // `unwrap_or_default()` failed silently in TWO ways, and the
                // second is worse than the empty string the audit named:
                // `--iface` as the final token left the interface `""`, and
                // `--iface --warmup-secs 5` set the interface to the STRING
                // "--warmup-secs" and then dropped the 5. The helper rejects
                // both — it refuses a missing value and refuses a value that
                // starts with `--`.
                iface = numeric_or_string(parse_required_string_value("--iface", args.next()))?;
            }
            "--warmup-secs" => {
                warmup_secs =
                    numeric_or_string(parse_required_numeric_value("--warmup-secs", args.next()))?;
            }
            "--final-burst-secs" => {
                final_burst_secs = numeric_or_string(parse_required_numeric_value(
                    "--final-burst-secs",
                    args.next(),
                ))?;
            }
            "--n-workers" => {
                n_workers =
                    numeric_or_string(parse_required_numeric_value("--n-workers", args.next()))?;
            }
            "--shaper-rate-bps" => {
                shaper_rate_bps = numeric_or_string(parse_required_numeric_value(
                    "--shaper-rate-bps",
                    args.next(),
                ))?;
            }
            "--rss-expectation" => {
                rss_expectation = numeric_or_string(parse_required_string_value(
                    "--rss-expectation",
                    args.next(),
                ))?;
            }
            "--expect-saturation" => {
                expect_saturation = true;
            }
            "-h" | "--help" => {
                return Err(ParseError::HelpRequested);
            }
            _ => {
                return Err(ParseError::Usage(format!("unknown arg {arg}; try --help")));
            }
        }
    }
    let iperf_json =
        iperf_json.ok_or_else(|| ParseError::Usage("--iperf-json is required".to_string()))?;
    let binding_flows = binding_flows
        .ok_or_else(|| ParseError::Usage("--binding-flows is required".to_string()))?;
    // A zero worker count is always an operator mistake: the per-worker
    // aggregation runs over `0..n_workers`, so n_workers==0 yields an empty
    // distribution and the verdict passes on no data. Reject it
    // unconditionally, not only under --expect-saturation (ps-038-A1 F1).
    if n_workers == 0 {
        return Err(ParseError::Usage("--n-workers must be > 0".to_string()));
    }
    // --expect-saturation requires the Nₐ/Nᵥ-scaled cap inputs. A missing
    // --shaper-rate-bps is an operator CLI mistake, not a fairness
    // regression, so fail fast with an arg-validation error (exit 2) instead
    // of letting it surface as a Gate-3 FAIL (exit 1) — otherwise automation
    // would misclassify a config error as a fairness failure (Copilot #2).
    if expect_saturation && shaper_rate_bps == 0 {
        return Err(ParseError::Usage(
            "--expect-saturation requires --shaper-rate-bps > 0 to compute the Na/Nv-scaled structural cap".to_string(),
        ));
    }
    Ok(Args {
        iperf_json,
        binding_flows,
        cos_flows,
        cos_ifindex,
        cos_queue_id,
        iface,
        warmup_secs,
        final_burst_secs,
        n_workers,
        shaper_rate_bps,
        rss_expectation,
        expect_saturation,
    })
}

/// Map a `Result<T, String>` from the low-level parse helpers into the
/// structured `ParseError::Usage` used by `parse_args_from`.
fn numeric_or_string<T>(res: Result<T, String>) -> Result<T, ParseError> {
    res.map_err(ParseError::Usage)
}

fn parse_required_string_value(flag: &str, raw: Option<String>) -> Result<String, String> {
    let value = raw.ok_or_else(|| format!("{flag} requires a value"))?;
    if value.starts_with("--") {
        return Err(format!("{flag} requires a value, got {value:?}"));
    }
    Ok(value)
}

fn parse_required_numeric_value<T>(flag: &str, raw: Option<String>) -> Result<T, String>
where
    T: std::str::FromStr,
{
    let value = raw.ok_or_else(|| format!("{flag} requires a value"))?;
    value
        .parse::<T>()
        .map_err(|_| format!("{flag} must be numeric, got {value:?}"))
}

fn parse_number_or_percent(raw: &str) -> Result<f64, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("missing value".to_string());
    }
    let value = if let Some(percent) = raw.strip_suffix('%') {
        percent
            .parse::<f64>()
            .map_err(|_| format!("{raw} is not a number"))?
            / 100.0
    } else {
        raw.parse::<f64>()
            .map_err(|_| format!("{raw} is not a number"))?
    };
    if !value.is_finite() {
        return Err(format!("{raw} is not a finite number"));
    }
    Ok(value)
}

pub(crate) fn parse_fraction_or_percent(raw: &str) -> Result<f64, String> {
    let value = parse_number_or_percent(raw)?;
    if !(0.0..=1.0).contains(&value) {
        return Err(format!("{raw} must be between 0 and 1 or 0% and 100%"));
    }
    Ok(value)
}

pub(crate) fn parse_nonnegative_number_or_percent(raw: &str) -> Result<f64, String> {
    let value = parse_number_or_percent(raw)?;
    if value < 0.0 {
        return Err(format!("{raw} must be non-negative"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cos_numeric_flags_reports_bad_values() {
        let parsed: i32 = parse_required_numeric_value("--cos-ifindex", Some("12".to_string()))
            .expect("valid ifindex");
        assert_eq!(parsed, 12);

        let err = parse_required_numeric_value::<u32>("--cos-queue-id", Some("bad".to_string()))
            .unwrap_err();
        assert!(
            err.contains("--cos-queue-id") && err.contains("bad"),
            "err: {err}"
        );

        let err = parse_required_numeric_value::<i32>("--cos-ifindex", None).unwrap_err();
        assert!(err.contains("requires a value"), "err: {err}");
    }

    #[test]
    fn parse_required_string_flags_report_missing_values() {
        let err = parse_required_string_value("--rss-expectation", None).unwrap_err();
        assert!(err.contains("requires a value"), "err: {err}");

        let err = parse_required_string_value("--cos-flows", Some("--cos-ifindex".to_string()))
            .unwrap_err();
        assert!(err.contains("--cos-flows"), "err: {err}");
    }

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn usage_msg(res: Result<Args, ParseError>) -> String {
        match res {
            Err(ParseError::Usage(msg)) => msg,
            Err(ParseError::HelpRequested) => panic!("expected Usage error, got HelpRequested"),
            Ok(_) => panic!("expected Usage error, got Ok"),
        }
    }

    /// #6898 A1-b6-F3: `--iface` must fail fast like every other valued flag.
    ///
    /// Driven through `parse_args_from`, NOT through
    /// `parse_required_string_value`. The helper was never broken — three other
    /// string flags already used it correctly. The defect was that this arm did
    /// not CALL it, so a test of the helper would have passed against the
    /// unfixed code and bound nothing.
    ///
    /// The module's own contract is the argument: "A silent fallback here could
    /// seed a false PASS/FAIL from this fairness merge gate (#1630/#1614), so
    /// the harness fails fast on an operator CLI mistake." `--iface` was the
    /// one arm violating it.
    #[test]
    fn iface_flag_requires_a_value_6898() {
        // 1. Missing value — `--iface` as the final token. Pre-fix this left
        //    the interface as "" and parsed successfully, so the harness ran
        //    against no interface and reported a verdict anyway.
        // Every case carries the two REQUIRED flags (`--iperf-json`,
        // `--binding-flows`) so the only thing under test is the `--iface`
        // handling. Without them a reverted build still errors — with
        // "--iperf-json is required" — and the cell would red for a reason
        // that has nothing to do with this fix.
        const REQ: [&str; 4] = [
            "--iperf-json",
            "/tmp/iperf.json",
            "--binding-flows",
            "/tmp/bind.tsv",
        ];
        let with_req = |extra: &[&str]| -> Vec<String> {
            REQ.iter().chain(extra.iter()).map(|s| s.to_string()).collect()
        };

        let Err(ParseError::Usage(msg)) = parse_args_from(with_req(&["--iface"])) else {
            panic!(
                "#6898: `--iface` with no value must be a usage error, not an empty interface"
            );
        };
        assert!(
            msg.contains("--iface") && msg.contains("requires a value"),
            "the error must name the flag and the reason; got {msg:?}"
        );

        // 2. THE WORSE CASE, which the audit item did not name: the next FLAG
        //    swallowed as the value. Pre-fix this set the interface to the
        //    literal string "--warmup-secs" and silently dropped the 5, so the
        //    run used a default warmup AND a nonsense interface — two wrong
        //    values from one typo, with no diagnostic.
        let Err(ParseError::Usage(msg)) = parse_args_from(with_req(&["--iface", "--warmup-secs", "5"]))
        else {
            panic!("#6898: a following flag must not be consumed as the interface name");
        };
        assert!(msg.contains("--iface"), "the error must name --iface; got {msg:?}");

        // 3. CONTROL — the happy path still works. Without this, "reject
        //    everything" satisfies both assertions above.
        let Ok(args) = parse_args_from(with_req(&["--iface", "ge-0-0-2"])) else {
            panic!("control: a valid --iface must still parse");
        };
        assert_eq!(args.iface, "ge-0-0-2");
    }

    #[test]
    fn parse_args_from_accepts_valid_numeric_flags() {
        let args = parse_args_from(argv(&[
            "--iperf-json",
            "/tmp/iperf.json",
            "--binding-flows",
            "/tmp/bind.tsv",
            "--warmup-secs",
            "7",
            "--final-burst-secs",
            "3",
            "--n-workers",
            "12",
            "--shaper-rate-bps",
            "25000000000",
        ]))
        .expect("valid args parse");
        assert_eq!(args.warmup_secs, 7);
        assert_eq!(args.final_burst_secs, 3);
        assert_eq!(args.n_workers, 12);
        assert_eq!(args.shaper_rate_bps, 25_000_000_000);
    }

    #[test]
    fn parse_args_from_rejects_bad_numeric_value_no_silent_fallback() {
        // ps-038-A1 F1: a mistyped / overflowing numeric value must error,
        // NOT silently fall back to the default.
        for flag in [
            "--warmup-secs",
            "--final-burst-secs",
            "--n-workers",
            "--shaper-rate-bps",
        ] {
            let msg = usage_msg(parse_args_from(argv(&[
                "--iperf-json",
                "/tmp/iperf.json",
                "--binding-flows",
                "/tmp/bind.tsv",
                flag,
                "not-a-number",
            ])));
            assert!(
                msg.contains(flag) && msg.contains("numeric"),
                "flag {flag}: msg {msg}"
            );
        }

        // u32 overflow on --n-workers is also a parse error, not a default.
        let msg = usage_msg(parse_args_from(argv(&[
            "--iperf-json",
            "/tmp/iperf.json",
            "--binding-flows",
            "/tmp/bind.tsv",
            "--n-workers",
            "99999999999",
        ])));
        assert!(msg.contains("--n-workers"), "msg {msg}");
    }

    #[test]
    fn parse_args_from_rejects_zero_workers_unconditionally() {
        // ps-038-A1 F1: n_workers==0 yields an empty per-worker distribution
        // and a verdict on no data — reject even without --expect-saturation.
        let msg = usage_msg(parse_args_from(argv(&[
            "--iperf-json",
            "/tmp/iperf.json",
            "--binding-flows",
            "/tmp/bind.tsv",
            "--n-workers",
            "0",
        ])));
        assert!(
            msg.contains("--n-workers") && msg.contains("> 0"),
            "msg {msg}"
        );
    }

    #[test]
    fn parse_args_from_requires_inputs_and_reports_help() {
        assert!(
            usage_msg(parse_args_from(argv(&["--binding-flows", "/tmp/b.tsv"])))
                .contains("--iperf-json")
        );
        assert!(
            usage_msg(parse_args_from(argv(&["--iperf-json", "/tmp/i.json"])))
                .contains("--binding-flows")
        );
        assert!(matches!(
            parse_args_from(argv(&["--help"])),
            Err(ParseError::HelpRequested)
        ));
        assert!(usage_msg(parse_args_from(argv(&["--bogus"]))).contains("unknown arg"));
    }
}
