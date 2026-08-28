# docs: name the "instrument answers nothing when it means I cannot see" class

- **Timestamp**: 2026-08-27
  - **Action**: recorded as a class in `docs/testing.md`, beside the concrete
    AF_XDP instance, after it bit five separate investigations. The shared
    shape: an instrument that cannot observe something reports a well-formed,
    plausible negative with no error and no unavailable marker, and it is most
    dangerous on investigations where a negative is the expected finding,
    because there it reads as confirmation. Table of all five, then the four
    mitigations in order of strength — a positive control from OUTSIDE the
    instrument, a marker check that GATES rather than annotates, making
    "could not see" a distinct outcome from "saw nothing", and reporting
    "not measured" rather than "no evidence found". Carries a hook line
    leaving the `engineering-style.md` question to the repository owner,
    since that file is an agent-behaviour contract rather than an operations
    guide.
  - **File(s)**: docs/testing.md
