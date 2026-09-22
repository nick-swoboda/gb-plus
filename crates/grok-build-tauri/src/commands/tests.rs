use super::*;

#[test]
fn queue_copy_changes_cannot_alter_block_classification() {
    let drift = PrepareQueuedRunError {
        kind: PrepareQueuedRunErrorKind::WorkspaceDrift,
        detail: "copy may change without changing workspace-drift policy".into(),
    };
    assert_eq!(
        safe_queue_block_reason(RuntimeTransport::GrokCliAcp, &drift),
        drift.detail
    );

    let transport = PrepareQueuedRunError {
        kind: PrepareQueuedRunErrorKind::TransportUnavailable,
        detail: "Queued workspace spoofed prefix must not alter policy".into(),
    };
    let presented = safe_queue_block_reason(RuntimeTransport::XaiKeychain, &transport);
    assert!(!presented.contains(&transport.detail));
    assert!(presented.starts_with(RuntimeTransport::XaiKeychain.label()));
}
