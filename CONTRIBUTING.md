# Contributing to GB Plus

Bug reports, focused fixes and documentation improvements are welcome. For a
larger change, open an issue first to agree on scope. Include the operating
system, app version and reproduction steps in bug reports. Report security
issues through the process in [SECURITY.md](SECURITY.md).

## Development

Use the exact Rust version in `rust-toolchain.toml`. macOS builds also require
Apple's command-line developer tools; packaging requires the reviewed Linux
helper and corresponding license inputs. The scripts report missing inputs
instead of installing software automatically.

Keep changes focused. Preserve existing project data, the app's visual design,
permission boundaries and the guarantee that interrupted work never reruns
automatically. Tests must exercise the behavior being changed.

Before committing, run these checks in order:

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features --locked
./scripts/linux-verify.sh
cargo build -p grok-build-runner --bin grok-build-runner --all-features --locked
cargo test -p grok-build-runner --lib --all-features --locked source_policy_permits_only_the_closed_target_gated_unsafe_modules -- --test-threads=1
cargo test -p grok-build-runner --lib --all-features --locked -- --test-threads=1
```

On Linux, use `./scripts/linux-verify.sh --native` after fetching the locked
dependencies. The container route requires an existing reviewed image and
volumes and at least 4 GiB of guest memory; it does not create them. Native Linux
permits no failing tests. The container's named environment exceptions are
confined to that environment.

Run relevant package and integration tests, plus the complete workspace suite
when a change affects shared contracts:

```sh
cargo test --workspace --all-targets --all-features --locked -- --test-threads=1
```

Run the binding suite alone, with no other tests using the host. Rebuild the
runner before tests that launch it. Check free disk space before parallel
builds and remove temporary worktrees when their changes are merged.

Do not remove assertions, relax security expectations or add ignored tests to
make a check pass. Source and artifact limits are enforced by
`scripts/verify-code-quality-budget.sh`.

## Dependencies and build inputs

Review new dependencies before installing or executing them. Record their
purpose, exact version, source and checksum, licenses, advisories, transitive
and native dependencies, build scripts, required environment/network access,
and rollback plan in the pull request. Keep exact pins and `Cargo.lock` current.
Do not install packages or package managers on a contributor's machine
automatically. CI uses the verified package identities in
`scripts/ci/ubuntu-native.json` on disposable Ubuntu runners.

Keep credentials, conversation data, personal project files and generated logs
out of commits. The checked-in SQLite schema and example projects under
`fixtures/` and `tests/` are synthetic test inputs.

Keep working notes, plans and validation logs in the ignored `.cache/` directory.
Public documentation belongs in the root guides; source exports reject the
retired internal documentation paths.

## Pull requests and licensing

Describe the change, how it was tested, and any compatibility or security impact.
Link related issues and update user-facing documentation when behavior changes.

Original GB Plus components use MIT. The adapted Grok Build prompt and workflow
interpreter use Apache-2.0; third-party components keep their own licenses.
Apply the license of the component being changed, retain copyright and NOTICE
material, and record copied upstream code in [ATTRIBUTION.md](ATTRIBUTION.md).

All contributions require [Developer Certificate of Origin 1.1](DCO) sign-off:

```sh
git commit --signoff
```

Use a name and email address you are authorized to use. Preserve all applicable
sign-offs when rebasing or squashing contributions.
