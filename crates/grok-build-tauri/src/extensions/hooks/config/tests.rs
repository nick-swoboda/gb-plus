use super::*;
use crate::extensions::content::Blob;
use std::collections::BTreeMap;

fn bundle() -> Bundle {
    let mut image = vec![0; 64];
    image[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    image[16] = 3;
    image[18] = 183;
    Bundle {
        files: BTreeMap::from([(
            "bin/guard".into(),
            Blob {
                bytes: image,
                executable: true,
            },
        )]),
    }
}

fn hooks() -> Value {
    json!({"PreToolUse":[{"matcher":"propose_write|propose_replace",
        "hooks":[{"type":"command","command":"bin/guard","args":["--hook"],"timeout":10}]}]})
}

#[test]
fn native_hook_admission_binds_content_argv_matcher_and_timeout_without_running_code() {
    let bundle = bundle();
    let original = parse(&hooks(), &"a".repeat(64), "component", &bundle).unwrap();
    assert!(original[0].matches("propose_write"));
    assert!(!original[0].matches("read_file"));
    for (pointer, value) in [
        ("/PreToolUse/0/matcher", json!("*")),
        ("/PreToolUse/0/hooks/0/args", json!(["--different"])),
        ("/PreToolUse/0/hooks/0/timeout", json!(11)),
    ] {
        let mut changed = hooks();
        *changed.pointer_mut(pointer).unwrap() = value;
        let candidate = parse(&changed, &"a".repeat(64), "component", &bundle).unwrap();
        assert_ne!(candidate[0].identity, original[0].identity);
    }
    assert_ne!(
        original[0].identity,
        parse(&hooks(), &"b".repeat(64), "component", &bundle).unwrap()[0].identity
    );
}

#[test]
fn hook_configuration_refuses_ambient_commands_regex_async_and_unknown_boundaries() {
    let bundle = bundle();
    for (pointer, value) in [
        ("/PreToolUse/0/matcher", json!("(.*)+")),
        ("/PreToolUse/0/hooks/0/type", json!("prompt")),
        ("/PreToolUse/0/hooks/0/command", json!("/bin/sh")),
        ("/PreToolUse/0/hooks/0/command", json!("bin/guard --hook")),
        ("/PreToolUse/0/hooks/0/timeout", json!(31)),
        ("/PreToolUse/0/hooks/0/timeout", json!(0)),
    ] {
        let mut candidate = hooks();
        *candidate.pointer_mut(pointer).unwrap() = value;
        assert!(parse(&candidate, "content", "component", &bundle).is_err());
    }
    let mut candidate = hooks();
    candidate["PreToolUse"][0]["hooks"][0]["async"] = json!(true);
    assert!(parse(&candidate, "content", "component", &bundle).is_err());
    assert!(parse(&json!({"Stop":[]}), "content", "component", &bundle).is_err());
    assert!(
        parse(
            &json!({"PreToolUse":vec![hooks()["PreToolUse"][0].clone();9]}),
            "content",
            "component",
            &bundle
        )
        .is_err()
    );
}

#[test]
fn hook_output_cannot_grant_authority_and_malformed_or_failed_output_refuses() {
    assert_eq!(decision(b"", Some(0)).unwrap(), Decision::Continue);
    for (text, expected) in [
        ("allow", Decision::Continue),
        ("deny", Decision::Deny),
        ("ask", Decision::Ask),
    ] {
        let value =
            json!({"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":text}});
        assert_eq!(
            decision(value.to_string().as_bytes(), Some(0)).unwrap(),
            expected
        );
    }
    for (output, exit) in [
        (b"".as_slice(), None), (b"", Some(2)), (b"{}", Some(0)),
        (b"{\"hookSpecificOutput\":{\"hookEventName\":\"Stop\",\"permissionDecision\":\"allow\"}}", Some(0)),
        (b"{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"allow\"},\"updatedInput\":{}}", Some(0)),
        (b"{}\n{}", Some(0)),
    ] {
        assert!(decision(output, exit).is_err());
    }
    assert!(decision(&vec![b' '; 16385], Some(0)).is_err());
}
