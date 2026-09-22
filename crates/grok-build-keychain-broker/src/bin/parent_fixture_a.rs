//! First changed-parent fixture for the stable-helper control.

#[cfg(target_os = "macos")]
const VARIANT_IDENTITY: &str = "parent-fixture-a";

#[cfg(target_os = "macos")]
fn main() {
    std::hint::black_box(VARIANT_IDENTITY);
    if let Err(error) = grok_build_keychain_broker::run_fixture_parent(
        grok_build_keychain_broker::FixtureParentVariant::A,
        std::env::args_os().skip(1),
    ) {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("Keychain fixtures are available only on macOS.");
    std::process::exit(2);
}
