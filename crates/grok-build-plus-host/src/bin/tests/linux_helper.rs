use super::*;

#[test]
fn helper_refuses_untyped_and_trailing_arguments() {
    assert!(run([OsString::from("--plus-guest-contained")].into_iter()).is_err());
    assert!(
        run([
            OsString::from("--plus-guest-contained"),
            OsString::from(PLUS_GUEST_TYPED_OUTCOME_FLAG),
            OsString::from("extra"),
        ]
        .into_iter())
        .is_err()
    );
}
