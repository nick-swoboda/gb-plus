//! Build-time validation for the public local signing identity.

fn main() {
    println!("cargo:rerun-if-env-changed=GROK_BUILD_SIGNING_IDENTITY");
    let identity = match std::env::var("GROK_BUILD_SIGNING_IDENTITY") {
        Err(std::env::VarError::NotPresent) => "adhoc".to_owned(),
        Ok(identity)
            if identity == "adhoc"
                || (identity.len() == 40
                    && identity.bytes().all(|byte| byte.is_ascii_hexdigit())) =>
        {
            identity.to_ascii_uppercase()
        }
        Ok(_) | Err(std::env::VarError::NotUnicode(_)) => {
            panic!(
                "GROK_BUILD_SIGNING_IDENTITY must be 'adhoc' or an exact 40-character public certificate fingerprint"
            );
        }
    };
    println!("cargo:rustc-env=GROK_BUILD_SIGNING_IDENTITY={identity}");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-arg=-mmacosx-version-min=15.0");
    }
}
