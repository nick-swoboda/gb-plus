# Gate 1 walking-skeleton fixture

This fixture starts incomplete. Its locked acceptance command is:

```sh
cargo test --offline --locked
```

The deterministic fake provider must inspect `AGENTS.md` and `src/lib.rs`,
search for `TODO`, execute at least one sandboxed command, change `status()` to
`"ready"`, and create `docs/report.txt`. The production snapshot, verification,
application, persistence, restart, and rollback paths—not test doubles—must
carry those changes.

The final live tree must pass the command. Rollback must restore the original
`src/lib.rs` and remove `docs/report.txt`, after which the command is expected
to fail again because the requested change is absent.
