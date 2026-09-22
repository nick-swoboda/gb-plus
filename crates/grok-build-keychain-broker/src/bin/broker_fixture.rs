//! Test-only stable helper used by the cross-build Keychain control.

#[cfg(target_os = "macos")]
fn main() {
    if let Err(error) = grok_build_keychain_broker::run_fixture_broker(std::env::args_os().skip(1))
    {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("Keychain fixtures are available only on macOS.");
    std::process::exit(2);
}
