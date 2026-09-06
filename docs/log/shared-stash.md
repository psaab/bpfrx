# `git stash` is a shared stack, and it has already cost work twice

- **Timestamp**: 2026-09-05
  - **Action**: documented the shared-stash protocol in
    `docs/engineering-style.md`, beside the diffstat rule it sits next to in
    practice — a stale base is what usually prompts a stash, and merging master
    is the better answer.

    Raised by lane-8526, who needed a stash to take a clean
    `git merge origin/master`, handled it correctly (push, pop immediately,
    verify the restored files were theirs), and flagged the hazard rather than
    moving on.

    Inspecting the stack made it worse than reported. **32 entries, oldest
    2026-05-28**, and two of them are recoveries from this exact accident:

    ```
    RESCUE-2026-08-21-foreign-stash-accidentally-popped-into-wt-close-cohorts
                                        (icmp_embed/nat64/wg WIP, NOT mine)
    RESCUE-2026-06-17-displaced-1635wip-from-errant-pop
    ```

    The hazard is recurrent, and the evidence for it was inside the thing being
    warned about. The rescues are themselves on the shared stack, where the next
    bare `pop` can displace them again.

    **Nothing was popped, dropped or cleared.** Several entries look like real
    stranded work (`1635-wip`, an `snmp-trap-batch` pair, a
    `2419-spelling-differential-gate` WIP). Tidying the stack is precisely the
    destructive move it documents, and entries that look like debris from
    outside are how stranded work looks from outside.

    Also recorded in the same section: `git diff --stat` alone UNDERSTATES a
    change, because an un-added new file is invisible to it. lane-8526 landed
    #8993 with two new files a diffstat did not mention.
  - **File(s)**: docs/engineering-style.md, docs/log/shared-stash.md
