# Codex r1 — #1752 plan @ 75a21e4e5 — PLAN-NEEDS-MAJOR

Blocking (all folded into v3):
1. Path B safety unacceptable as written — strongSwan-stop/xfrm-flush on fw0 is
   not safe even "RG-0-primary-only, briefly"; XFRM is not RG-scoped. → v3: no
   HA-node config A/B at all; non-invasive trace only; standalone-VM exception.
2. mlx5 DEK hypothesis too confidently tied to strongSwan/xfrm — DEK pool is
   generic mlx5 crypto machinery used by kTLS AND IPsec offload; "unexpected"
   right, "probably strongSwan" not proven; stack + event-rate first. → v3
   Finding 3 reworded; table evidence softened.
3. CoS CPU attribution fair; 7.4 Gb/s value claim overstated (gross sender thpt,
   loss/backpressure differs; crypto present != constant across packet rates). →
   v3: "~19% CPU; up to +7.4 Gb/s gross, goodput TBD."
4. Driver RX dismissed too fast ("No (inherent)") — busy-poll, NAPI budget,
   IRQ/worker isolation, queue count, XDP prog cost, XDP_PASS check all matter. →
   v3: "Partly"; separate driver physics from xpf/XDP work.
5. Path A keep only as gated research: sub-profile + concrete sub-cost +
   no-code-kill exit. → v3 Path A gated.
