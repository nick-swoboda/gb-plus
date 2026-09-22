//! Generates the Tauri build context from the pinned application config.

#[cfg(target_os = "macos")]
fn main() {
    // Build dependencies use the host platform; a macOS host may still build
    // the explicit unsupported-platform entry point for a Linux target.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    println!("cargo:rerun-if-env-changed=RUSTC");
    println!("cargo:rerun-if-env-changed=GROK_BUILD_REVISION");
    println!("cargo:rerun-if-env-changed=GROK_BUILD_DIRTY");
    println!("cargo:rerun-if-env-changed=GROK_BUILD_SIGNING_IDENTITY");
    println!("cargo:rerun-if-env-changed=GROK_BUILD_KEYCHAIN_BROKER_SHA256");
    println!("cargo:rerun-if-env-changed=GROK_BUILD_KEYCHAIN_BROKER_CDHASH");
    println!("cargo:rerun-if-env-changed=GROK_BUILD_MCP_BROKER_SHA256");
    println!("cargo:rerun-if-env-changed=GROK_BUILD_MCP_BROKER_CDHASH");
    for name in [
        "GROK_BUILD_LINUX_PAYLOAD_SHA256",
        "GROK_BUILD_LINUX_PAYLOAD_BYTES",
        "GROK_BUILD_LINUX_HELPER_SHA256",
        "GROK_BUILD_LINUX_HELPER_BYTES",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    let rustc_version = std::env::var_os("RUSTC")
        .and_then(|rustc| {
            std::process::Command::new(rustc)
                .arg("--version")
                .env_clear()
                .output()
                .ok()
        })
        .filter(|output| output.status.success() && output.stdout.len() <= 256)
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|output| {
            let line = output.lines().next()?.trim();
            (!line.is_empty() && !line.chars().any(char::is_control)).then(|| line.to_owned())
        })
        .unwrap_or_else(|| "Unknown (rustc version query failed)".to_owned());
    println!("cargo:rustc-env=GROK_BUILD_RUSTC_VERSION={rustc_version}");
    let signing_identity = match std::env::var("GROK_BUILD_SIGNING_IDENTITY") {
        Err(std::env::VarError::NotPresent) => "adhoc".to_owned(),
        Ok(identity)
            if identity == "adhoc"
                || (identity.len() == 40
                    && identity.bytes().all(|byte| byte.is_ascii_hexdigit())) =>
        {
            identity
        }
        Ok(_) | Err(std::env::VarError::NotUnicode(_)) => {
            panic!(
                "GROK_BUILD_SIGNING_IDENTITY must be 'adhoc' or an exact 40-character public certificate fingerprint"
            );
        }
    };
    println!("cargo:rustc-env=GROK_BUILD_SIGNING_IDENTITY={signing_identity}");
    let broker_sha256 = hex_environment("GROK_BUILD_KEYCHAIN_BROKER_SHA256", 64);
    println!("cargo:rustc-env=GROK_BUILD_KEYCHAIN_BROKER_SHA256={broker_sha256}");
    let broker_cdhash = hex_environment("GROK_BUILD_KEYCHAIN_BROKER_CDHASH", 40);
    println!("cargo:rustc-env=GROK_BUILD_KEYCHAIN_BROKER_CDHASH={broker_cdhash}");
    for (name, length) in [
        ("GROK_BUILD_MCP_BROKER_SHA256", 64),
        ("GROK_BUILD_MCP_BROKER_CDHASH", 40),
        ("GROK_BUILD_LINUX_PAYLOAD_SHA256", 64),
        ("GROK_BUILD_LINUX_HELPER_SHA256", 64),
    ] {
        println!("cargo:rustc-env={name}={}", hex_environment(name, length));
    }
    for name in [
        "GROK_BUILD_LINUX_PAYLOAD_BYTES",
        "GROK_BUILD_LINUX_HELPER_BYTES",
    ] {
        println!(
            "cargo:rustc-env={name}={}",
            positive_integer_environment(name)
        );
    }
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        // Keep the exact locked Cargo build and the manual `.app` assembler on
        // the same supported-platform floor; an Info.plist claim alone is not
        // sufficient because the Mach-O load command is authoritative.
        println!("cargo:rustc-link-arg=-mmacosx-version-min=15.0");
    }
    tauri_build::build();
}

#[cfg(not(target_os = "macos"))]
fn main() {
    assert_ne!(
        std::env::var("CARGO_CFG_TARGET_OS").as_deref(),
        Ok("macos"),
        "The macOS app must be built on its supported macOS host."
    );
}

#[cfg(target_os = "macos")]
fn hex_environment(name: &str, length: usize) -> String {
    match std::env::var(name) {
        Err(std::env::VarError::NotPresent) => "unavailable".into(),
        Ok(value)
            if value == "unavailable"
                || (value.len() == length
                    && value.bytes().all(|byte| byte.is_ascii_hexdigit())) =>
        {
            value.to_ascii_lowercase()
        }
        _ => panic!("{name} must be 'unavailable' or exactly {length} hexadecimal characters"),
    }
}

#[cfg(target_os = "macos")]
fn positive_integer_environment(name: &str) -> String {
    match std::env::var(name) {
        Err(std::env::VarError::NotPresent) => "unavailable".into(),
        Ok(value) if value.parse::<u64>().is_ok_and(|number| number > 0) => value,
        _ => panic!("{name} must be 'unavailable' or a positive integer"),
    }
}
