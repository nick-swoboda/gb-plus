use std::collections::BTreeMap;

use grok_build_core::CONTRACT_VERSION;

use super::*;
use crate::macos_helper_protocol::{
    MACOS_HELPER_PROTOCOL_VERSION, MacosChildDescriptorBinding, MacosChildDescriptorPurpose,
    MacosExecutableIdentity, MacosHelperNetwork, decode_canonical_launch_request,
    descriptor_bindings_digest,
};

fn digest(byte: u8) -> Digest {
    Digest::sha256(&[byte])
}

/// The install audit these fixtures pin against.
const fn install_audit() -> MacosHelperInstallAudit {
    MacosHelperInstallAudit {
        auditing_uid: 501,
        binary_owner_uid: 0,
        binary_mode: 0o755,
        directory_owner_uid: 0,
        directory_mode: 0o755,
    }
}

/// A structurally valid production-shaped session.
///
/// The transport never mints one of these; it is the shape the installed helper
/// is contracted to publish, and the request-path tests need a session that
/// already passes `MacosHelperSession::validate`.
fn session() -> MacosHelperSession {
    MacosHelperSession {
        protocol_version: MACOS_HELPER_PROTOCOL_VERSION,
        policy_version: 7,
        session_nonce: digest(1),
        helper_binary_digest: digest(2),
        helper_requirement_digest: digest(3),
        client_binary_digest: digest(4),
        client_requirement_digest: digest(5),
        pool_record_digest: digest(6),
        workspace_grant_hash: digest(7),
        execution_policy_hash: digest(8),
        command_network: MacosHelperNetwork::Denied,
        authenticated_at_unix_ms: 10,
        peer_requirement_matched: true,
        attestation: MacosHelperAttestation::LocalCodeIdentity {
            install_audit: install_audit(),
        },
    }
}

fn preparation() -> MacosHelperPreparationBinding {
    MacosHelperPreparationBinding {
        contract_version: CONTRACT_VERSION,
        attempt_id: "attempt-1".into(),
        sprint_id: "sprint-1".into(),
        launch_id: "launch-1".into(),
        runner_session_id: "runner-1".into(),
        cleanup_effect_id: "cleanup-effect-1".into(),
        input_snapshot: digest(19),
        native_journal_id: "native-journal-1".into(),
        expected_platform_binding_digest: digest(21),
        claimed_at_unix_ms: 11,
    }
}

fn descriptors() -> Vec<MacosChildDescriptorBinding> {
    [
        (0, MacosChildDescriptorPurpose::StandardInput, true),
        (1, MacosChildDescriptorPurpose::StandardOutput, true),
        (2, MacosChildDescriptorPurpose::StandardError, true),
        (3, MacosChildDescriptorPurpose::HoldControl, false),
        (4, MacosChildDescriptorPurpose::SetupReport, false),
    ]
    .into_iter()
    .map(
        |(target_fd, purpose, inherited_through_exec)| MacosChildDescriptorBinding {
            target_fd,
            purpose,
            object_digest: digest(30 + u8::try_from(target_fd).expect("descriptor fits a byte")),
            inherited_through_exec,
        },
    )
    .collect()
}

fn request() -> MacosHelperLaunchRequest {
    let session = session();
    let mut request = MacosHelperLaunchRequest {
        protocol_version: MACOS_HELPER_PROTOCOL_VERSION,
        policy_version: session.policy_version,
        session_nonce: session.session_nonce,
        request_id: "request-1".into(),
        preparation: preparation(),
        runner_session_id: "runner-1".into(),
        effect_id: "effect-1".into(),
        workspace_grant_hash: session.workspace_grant_hash,
        execution_policy_hash: session.execution_policy_hash,
        staged_workspace_id: "shadow_1".into(),
        executable_identity: MacosExecutableIdentity::SystemToolchain {
            policy_entry_id: "cargo-1.97.0".into(),
            binary_digest: digest(9),
        },
        descriptor_bindings: descriptors(),
        argv: vec!["cargo".into(), "test".into(), "--offline".into()],
        relative_working_directory: "project".into(),
        environment: BTreeMap::from([("PATH".into(), "/usr/bin".into())]),
        deadline_unix_ms: 1_000,
        max_output_bytes: 1_024,
        max_processes: 32,
        max_memory_bytes: None,
        command_network: MacosHelperNetwork::Denied,
        seatbelt_profile_digest: digest(10),
        request_digest: digest(0),
    };
    request.request_digest = request.computed_digest().expect("request digest");
    request
}

fn assigned_identity() -> MacosAssignedIdentity {
    MacosAssignedIdentity {
        account_name: "_grokbuild601".into(),
        uid: 601,
        gid: 601,
        account_record_digest: digest(11),
    }
}

fn held_evidence(
    session: &MacosHelperSession,
    request: &MacosHelperLaunchRequest,
    assigned: &MacosAssignedIdentity,
) -> MacosHeldPreparationEvidence {
    let mut evidence = MacosHeldPreparationEvidence {
        authenticated_session: session.clone(),
        request_digest: request.request_digest.clone(),
        preparation: request.preparation.clone(),
        assigned_identity: assigned.clone(),
        descriptor_bindings_digest: descriptor_bindings_digest(&request.descriptor_bindings)
            .expect("descriptor bindings digest"),
        setup_readback_digest: digest(40),
        held_at_unix_ms: 20,
        evidence_digest: digest(0),
    };
    evidence.evidence_digest = evidence.computed_digest().expect("evidence digest");
    evidence
}

/// Pins the requirement to this very test binary's code-directory hash.
///
/// A `cargo test` executable on Apple silicon carries the linker's automatic
/// ad-hoc signature, so it has a real code-directory hash and no certificate
/// chain. That is exactly the development-helper shape.
fn self_pinned_requirement(stream: &UnixStream) -> MacosPeerCodeRequirement {
    let observed = observe_peer(stream.as_fd()).expect("observe socket peer");
    MacosPeerCodeRequirement::pinned_to_code_directory_hash(observed.code_directory_hash())
        .expect("pin observed code-directory hash")
}

fn self_pinned_client(stream: UnixStream) -> MacosHelperTransportClient {
    let requirement = self_pinned_requirement(&stream);
    MacosHelperTransportClient::authenticated(stream, requirement)
        .expect("authenticate this process as its own socket peer")
}

/// A session whose helper identity fields match what the client authenticated.
fn peer_bound_session(
    client: &MacosHelperTransportClient,
    attestation: MacosHelperAttestation,
) -> MacosHelperSession {
    let mut session = session();
    session.attestation = attestation;
    session.helper_requirement_digest = client.requirement().digest();
    session.helper_binary_digest = client.peer().code_identity_digest();
    session
}

/// The attestation an ad-hoc, locally installed helper honestly publishes.
const fn local_attestation() -> MacosHelperAttestation {
    MacosHelperAttestation::LocalCodeIdentity {
        install_audit: install_audit(),
    }
}

fn write_session_frame(stream: &mut UnixStream, session: &MacosHelperSession) {
    let payload =
        encode_canonical_payload(MacosHelperFrameKind::Session, session).expect("encode session");
    write_frame(stream, MacosHelperFrameKind::Session, &payload).expect("write session frame");
}

fn header(kind: u8, length: u32) -> Vec<u8> {
    let mut bytes = Vec::from(MACOS_HELPER_FRAME_MAGIC);
    bytes.push(kind);
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes
}

#[test]
fn frame_ceiling_equals_the_protocol_request_ceiling() {
    assert_eq!(
        MAX_MACOS_HELPER_FRAME_PAYLOAD_BYTES,
        MAX_MACOS_HELPER_REQUEST_BYTES
    );
    assert_eq!(MAX_MACOS_HELPER_FRAME_PAYLOAD_BYTES, 64 * 1_024);
    assert_eq!(MACOS_HELPER_FRAME_HEADER_BYTES, 9);
    for kind in [
        MacosHelperFrameKind::Session,
        MacosHelperFrameKind::LaunchRequest,
        MacosHelperFrameKind::HeldPreparationEvidence,
        MacosHelperFrameKind::CleanupEvidence,
    ] {
        assert_eq!(MacosHelperFrameKind::from_code(kind.code()), Some(kind));
    }
}

#[test]
fn frame_round_trip_preserves_kind_and_payload() {
    let mut wire = Vec::new();
    let payload = vec![7_u8; 4_096];
    write_frame(&mut wire, MacosHelperFrameKind::CleanupEvidence, &payload)
        .expect("write cleanup frame");
    assert_eq!(wire.len(), MACOS_HELPER_FRAME_HEADER_BYTES + payload.len());
    let (kind, decoded) = read_frame(&mut wire.as_slice()).expect("read cleanup frame");
    assert_eq!(kind, MacosHelperFrameKind::CleanupEvidence);
    assert_eq!(decoded, payload);
}

#[test]
fn frame_writer_refuses_an_oversize_or_empty_payload_before_writing() {
    let mut wire = Vec::new();
    let oversize = vec![0_u8; MAX_MACOS_HELPER_FRAME_PAYLOAD_BYTES + 1];
    assert_eq!(
        write_frame(&mut wire, MacosHelperFrameKind::LaunchRequest, &oversize),
        Err(MacosHelperTransportError::FrameTooLarge {
            bytes: oversize.len()
        })
    );
    assert_eq!(
        write_frame(&mut wire, MacosHelperFrameKind::LaunchRequest, &[]),
        Err(MacosHelperTransportError::EmptyFrame {
            kind: MacosHelperFrameKind::LaunchRequest
        })
    );
    assert!(wire.is_empty(), "no partial frame may reach the stream");

    let exact = vec![0_u8; MAX_MACOS_HELPER_FRAME_PAYLOAD_BYTES];
    write_frame(&mut wire, MacosHelperFrameKind::LaunchRequest, &exact)
        .expect("the ceiling itself is admitted");
}

#[test]
fn frame_reader_refuses_an_oversize_declaration_without_allocating_it() {
    let declared = u32::try_from(MAX_MACOS_HELPER_FRAME_PAYLOAD_BYTES + 1).expect("fits a u32");
    let bytes = header(MacosHelperFrameKind::LaunchRequest.code(), declared);
    assert_eq!(
        read_frame(&mut bytes.as_slice()),
        Err(MacosHelperTransportError::FrameTooLarge {
            bytes: MAX_MACOS_HELPER_FRAME_PAYLOAD_BYTES + 1
        })
    );

    let empty = header(MacosHelperFrameKind::Session.code(), 0);
    assert_eq!(
        read_frame(&mut empty.as_slice()),
        Err(MacosHelperTransportError::EmptyFrame {
            kind: MacosHelperFrameKind::Session
        })
    );
}

#[test]
fn frame_reader_refuses_foreign_magic_and_unassigned_kinds() {
    let mut foreign = header(MacosHelperFrameKind::Session.code(), 1);
    foreign[..4].copy_from_slice(b"XPC1");
    foreign.push(0);
    assert_eq!(
        read_frame(&mut foreign.as_slice()),
        Err(MacosHelperTransportError::FrameMagic {
            observed: *b"XPC1"
        })
    );

    let mut unassigned = header(9, 1);
    unassigned.push(0);
    assert_eq!(
        read_frame(&mut unassigned.as_slice()),
        Err(MacosHelperTransportError::FrameKind { code: 9 })
    );
}

#[test]
fn frame_reader_refuses_a_truncated_header_and_a_truncated_payload() {
    let short_header = header(MacosHelperFrameKind::Session.code(), 4);
    assert_eq!(
        read_frame(&mut &short_header[..MACOS_HELPER_FRAME_HEADER_BYTES - 1]),
        Err(MacosHelperTransportError::TruncatedFrame {
            stage: "frame header",
            expected: MACOS_HELPER_FRAME_HEADER_BYTES
        })
    );

    let mut short_payload = header(MacosHelperFrameKind::Session.code(), 4);
    short_payload.extend_from_slice(&[1, 2, 3]);
    assert_eq!(
        read_frame(&mut short_payload.as_slice()),
        Err(MacosHelperTransportError::TruncatedFrame {
            stage: "frame payload",
            expected: 4
        })
    );
}

#[test]
fn canonical_payload_decoding_refuses_an_alternate_encoding() {
    let request = request();
    let canonical =
        encode_canonical_payload(MacosHelperFrameKind::LaunchRequest, &request).expect("encode");
    let decoded: MacosHelperLaunchRequest =
        decode_canonical_payload(MacosHelperFrameKind::LaunchRequest, &canonical).expect("decode");
    assert_eq!(decoded, request);

    let pretty = serde_json::to_vec_pretty(&request).expect("pretty encode");
    assert_eq!(
        decode_canonical_payload::<MacosHelperLaunchRequest>(
            MacosHelperFrameKind::LaunchRequest,
            &pretty
        ),
        Err(MacosHelperTransportError::NonCanonicalPayload {
            kind: MacosHelperFrameKind::LaunchRequest
        })
    );
}

#[test]
fn launch_request_round_trips_canonically_over_a_unix_socket_pair() {
    let (client_end, mut helper_end) = UnixStream::pair().expect("unix socket pair");
    let mut client = self_pinned_client(client_end);
    let session = session();
    let request = request();
    let preparation = request.preparation.clone();
    let profile_digest = request.seatbelt_profile_digest.clone();

    client
        .send_launch_request(&request, &session, &preparation, &profile_digest, 20)
        .expect("send launch request");

    let (kind, payload) = read_frame(&mut helper_end).expect("read launch frame");
    assert_eq!(kind, MacosHelperFrameKind::LaunchRequest);
    assert!(payload.len() <= MAX_MACOS_HELPER_REQUEST_BYTES);
    let received = decode_canonical_launch_request(&payload, &session, &preparation, 20)
        .expect("helper-side canonical decode");
    assert_eq!(received, request);
}

#[test]
fn send_launch_request_refuses_a_seatbelt_profile_mismatch_without_writing() {
    let (client_end, mut helper_end) = UnixStream::pair().expect("unix socket pair");
    let mut client = self_pinned_client(client_end);
    let session = session();
    let request = request();
    let preparation = request.preparation.clone();

    assert_eq!(
        client.send_launch_request(&request, &session, &preparation, &digest(99), 20),
        Err(MacosHelperTransportError::SeatbeltProfileDigestMismatch)
    );

    helper_end
        .set_nonblocking(true)
        .expect("probe the helper end without blocking");
    let mut probe = [0_u8; 1];
    assert_eq!(
        helper_end
            .read(&mut probe)
            .expect_err("a refused request must write nothing")
            .kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn send_launch_request_refuses_a_request_that_fails_protocol_validation() {
    let (client_end, _helper_end) = UnixStream::pair().expect("unix socket pair");
    let mut client = self_pinned_client(client_end);
    let session = session();
    let mut request = request();
    request.max_memory_bytes = Some(1_024);
    request.request_digest = request.computed_digest().expect("request digest");
    let preparation = request.preparation.clone();
    let profile_digest = request.seatbelt_profile_digest.clone();

    let failure = client
        .send_launch_request(&request, &session, &preparation, &profile_digest, 20)
        .expect_err("a finite memory ceiling must fail before transport");
    assert!(matches!(
        failure,
        MacosHelperTransportError::Protocol(MacosHelperProtocolError::Invalid { .. })
    ));
}

#[test]
fn peer_audit_token_identifies_this_process_across_a_unix_socket_pair() {
    let (client_end, _helper_end) = UnixStream::pair().expect("unix socket pair");
    let token = peer_audit_token(client_end.as_fd()).expect("read peer audit token");

    assert_eq!(token.words().len(), 8);
    assert_eq!(token.process_id(), std::process::id());
    assert_eq!(token.real_uid(), rustix::process::getuid().as_raw());
    assert_eq!(token.effective_uid(), rustix::process::geteuid().as_raw());
    assert_eq!(token.real_gid(), rustix::process::getgid().as_raw());
    assert_eq!(token.effective_gid(), rustix::process::getegid().as_raw());
    assert_ne!(token.process_id_version(), 0);
    assert_eq!(
        peer_process_id(client_end.as_fd()).expect("read peer pid"),
        std::process::id()
    );
}

#[test]
fn peer_authentication_accepts_this_binary_pinned_by_its_code_directory_hash() {
    let (client_end, _helper_end) = UnixStream::pair().expect("unix socket pair");
    let observed = observe_peer(client_end.as_fd()).expect("observe socket peer");
    assert!(
        !observed.code_directory_hash().is_empty(),
        "a loaded macOS image always carries a code-directory hash"
    );
    let requirement =
        MacosPeerCodeRequirement::pinned_to_code_directory_hash(observed.code_directory_hash())
            .expect("pin observed code-directory hash");
    assert!(requirement.text().starts_with("cdhash H\""));

    let peer = authenticate_peer(client_end.as_fd(), &requirement).expect("authenticate peer");
    assert_eq!(peer.code_directory_hash(), observed.code_directory_hash());
    assert_eq!(peer.requirement_digest(), &requirement.digest());
    assert_eq!(peer.audit_token().process_id(), std::process::id());
    assert_eq!(
        peer.code_identity_digest(),
        code_identity_digest(observed.code_directory_hash())
    );
}

#[test]
fn peer_authentication_refuses_a_requirement_the_peer_does_not_satisfy() {
    let (client_end, _helper_end) = UnixStream::pair().expect("unix socket pair");
    let wrong = MacosPeerCodeRequirement::pinned_to_code_directory_hash(&[0_u8; 20])
        .expect("pin an unrelated hash");
    let failure = authenticate_peer(client_end.as_fd(), &wrong)
        .expect_err("a foreign code-directory pin must be refused");
    assert!(
        matches!(
            failure,
            MacosPeerAuthenticationError::RequirementRejected { .. }
        ),
        "unexpected refusal: {failure}"
    );

    let malformed = MacosPeerCodeRequirement::new("this is not a requirement expression")
        .expect("syntactically admitted text");
    let failure = authenticate_peer(client_end.as_fd(), &malformed)
        .expect_err("unparsable requirement text must be refused");
    assert!(
        matches!(
            failure,
            MacosPeerAuthenticationError::RequirementSyntax { .. }
        ),
        "unexpected refusal: {failure}"
    );
}

#[test]
fn an_ad_hoc_signed_peer_is_authenticated_but_never_publisher_attested() {
    let (client_end, _helper_end) = UnixStream::pair().expect("unix socket pair");
    let requirement = self_pinned_requirement(&client_end);
    let peer = authenticate_peer(client_end.as_fd(), &requirement).expect("authenticate peer");

    assert!(
        !peer.apple_anchored(),
        "an ad-hoc signature carries no Apple certificate chain"
    );
    assert!(
        !peer.publisher_attested(),
        "a code-directory pin proves bytes, never a publisher"
    );
    assert_eq!(
        peer.attestation_for(install_audit()),
        local_attestation(),
        "the honest attestation for an ad-hoc peer is the local kind, not nothing"
    );
}

#[test]
fn a_session_claiming_publisher_attestation_is_refused_against_an_ad_hoc_peer() {
    let (client_end, mut helper_end) = UnixStream::pair().expect("unix socket pair");
    let mut client = self_pinned_client(client_end);
    let claimed = peer_bound_session(
        &client,
        MacosHelperAttestation::PublisherCodeIdentity {
            install_audit: install_audit(),
        },
    );
    write_session_frame(&mut helper_end, &claimed);

    assert_eq!(
        client.receive_session(&install_audit()),
        Err(MacosHelperTransportError::UnprovenPublisherClaim {
            peer_apple_anchored: false
        })
    );
}

/// ADR-0012's behavioral inversion, pinned.
///
/// This test previously asserted the opposite: that an ad-hoc helper can never
/// open a production session, which made Phase 2 unreachable on every
/// build-from-source host. Local code identity is now the runtime predicate, so
/// the same session is admitted — and the guard against an *unattested* helper
/// is asserted in the same place so the change cannot be read as a removal.
#[test]
fn a_locally_attested_helper_opens_a_production_session_and_an_unattested_one_does_not() {
    let (client_end, mut helper_end) = UnixStream::pair().expect("unix socket pair");
    let mut client = self_pinned_client(client_end);

    let honest = peer_bound_session(&client, local_attestation());
    write_session_frame(&mut helper_end, &honest);
    let admitted = client
        .receive_session(&install_audit())
        .expect("an ad-hoc, cdhash-pinned, correctly installed helper is a production peer");
    assert_eq!(admitted, honest);
    assert!(!admitted.attestation.claims_publisher());

    let unattested = peer_bound_session(&client, MacosHelperAttestation::Unattested);
    write_session_frame(&mut helper_end, &unattested);
    assert_eq!(
        client.receive_session(&install_audit()),
        Err(MacosHelperTransportError::InstallAuditMismatch {
            observed: install_audit(),
            claimed: None,
        }),
        "an unattested session carries no audit at all and is refused before validation"
    );
}

/// The client's own filesystem reading is the authority, not the message.
#[test]
fn a_session_install_audit_that_differs_from_the_clients_own_reading_is_refused() {
    let (client_end, mut helper_end) = UnixStream::pair().expect("unix socket pair");
    let mut client = self_pinned_client(client_end);

    let flattering = peer_bound_session(&client, local_attestation());
    write_session_frame(&mut helper_end, &flattering);
    // The client really observed a group-writable helper binary. The helper
    // published the clean audit. The client's own reading wins.
    let observed = MacosHelperInstallAudit {
        binary_mode: 0o775,
        ..install_audit()
    };
    assert_eq!(
        client.receive_session(&observed),
        Err(MacosHelperTransportError::InstallAuditMismatch {
            observed,
            claimed: Some(install_audit()),
        })
    );

    // And an honestly reported bad install is refused by the predicate itself.
    let honest_but_bad = peer_bound_session(
        &client,
        MacosHelperAttestation::LocalCodeIdentity {
            install_audit: observed,
        },
    );
    write_session_frame(&mut helper_end, &honest_but_bad);
    assert_eq!(
        client.receive_session(&observed),
        Err(MacosHelperTransportError::Protocol(
            MacosHelperProtocolError::Invalid {
                field: "session.attestation.binary_mode",
                reason: "the installed helper binary is writable by group or other",
            }
        ))
    );
}

/// The install audit this process reads for its own executable.
///
/// A live probe rather than a fixture: it proves the audit function reaches the
/// filesystem and returns this machine's real ownership and mode, and that the
/// predicate's verdict follows from those observed values rather than from a
/// compiled-in assumption about how a checkout is laid out.
#[test]
fn the_install_audit_reads_this_hosts_real_ownership_and_mode() {
    let program = std::env::current_exe().expect("resolve the running executable");
    let audit = audit_installed_binary(&program).expect("audit the running executable");

    assert_eq!(audit.auditing_uid, rustix::process::getuid().as_raw());
    let metadata = std::fs::symlink_metadata(&program).expect("stat the running executable");
    assert_eq!(audit.binary_owner_uid, metadata.uid());
    assert_eq!(audit.binary_mode, metadata.permissions().mode() & 0o7777);

    let trusted_owner =
        audit.binary_owner_uid == 0 || audit.binary_owner_uid == audit.auditing_uid;
    let trusted_directory =
        audit.directory_owner_uid == 0 || audit.directory_owner_uid == audit.auditing_uid;
    let no_foreign_write = audit.binary_mode & 0o022 == 0 && audit.directory_mode & 0o022 == 0;
    assert_eq!(
        audit.validate().is_ok(),
        trusted_owner && trusted_directory && no_foreign_write,
        "the verdict must follow from the observed values: {audit:?}"
    );
}

#[test]
fn session_helper_requirement_and_binary_substitution_are_refused() {
    let (client_end, mut helper_end) = UnixStream::pair().expect("unix socket pair");
    let mut client = self_pinned_client(client_end);

    let mut swapped_requirement = peer_bound_session(&client, local_attestation());
    swapped_requirement.helper_requirement_digest = digest(200);
    write_session_frame(&mut helper_end, &swapped_requirement);
    assert_eq!(
        client.receive_session(&install_audit()),
        Err(MacosHelperTransportError::HelperRequirementDigestMismatch)
    );

    let mut swapped_binary = peer_bound_session(&client, local_attestation());
    swapped_binary.helper_binary_digest = digest(201);
    write_session_frame(&mut helper_end, &swapped_binary);
    assert_eq!(
        client.receive_session(&install_audit()),
        Err(MacosHelperTransportError::HelperBinaryDigestMismatch)
    );
}

#[test]
fn receive_session_refuses_a_frame_of_another_payload_class() {
    let (client_end, mut helper_end) = UnixStream::pair().expect("unix socket pair");
    let mut client = self_pinned_client(client_end);
    let payload = encode_canonical_payload(MacosHelperFrameKind::LaunchRequest, &request())
        .expect("encode request");
    write_frame(
        &mut helper_end,
        MacosHelperFrameKind::LaunchRequest,
        &payload,
    )
    .expect("write a launch-request frame where a session belongs");

    assert_eq!(
        client.receive_session(&install_audit()),
        Err(MacosHelperTransportError::UnexpectedFrameKind {
            expected: MacosHelperFrameKind::Session,
            observed: MacosHelperFrameKind::LaunchRequest,
        })
    );
}

#[test]
fn held_preparation_evidence_round_trips_and_refuses_a_substituted_identity() {
    let (client_end, mut helper_end) = UnixStream::pair().expect("unix socket pair");
    let mut client = self_pinned_client(client_end);
    let session = session();
    let request = request();
    let assigned = assigned_identity();
    let evidence = held_evidence(&session, &request, &assigned);

    let payload =
        encode_canonical_payload(MacosHelperFrameKind::HeldPreparationEvidence, &evidence)
            .expect("encode held evidence");
    write_frame(
        &mut helper_end,
        MacosHelperFrameKind::HeldPreparationEvidence,
        &payload,
    )
    .expect("write held evidence frame");
    assert_eq!(
        client
            .receive_held_preparation_evidence(&session, &request, &assigned)
            .expect("accept bound held evidence"),
        evidence
    );

    write_frame(
        &mut helper_end,
        MacosHelperFrameKind::HeldPreparationEvidence,
        &payload,
    )
    .expect("write held evidence frame again");
    let mut substituted = assigned;
    substituted.uid = 602;
    let failure = client
        .receive_held_preparation_evidence(&session, &request, &substituted)
        .expect_err("evidence must bind to the assigned identity");
    assert!(matches!(
        failure,
        MacosHelperTransportError::Protocol(MacosHelperProtocolError::Invalid { .. })
    ));
}

#[test]
fn requirement_text_is_validated_and_its_digest_is_domain_separated() {
    let anchored = MacosPeerCodeRequirement::new("anchor apple generic").expect("admit anchor");
    let identified = MacosPeerCodeRequirement::new("anchor apple generic and identifier \"helper\"")
        .expect("admit identifier");
    assert_ne!(anchored.digest(), identified.digest());
    assert_ne!(anchored.digest(), Digest::sha256(anchored.text().as_bytes()));
    assert_eq!(
        anchored.digest(),
        MacosPeerCodeRequirement::new(anchored.text())
            .expect("readmit anchor")
            .digest()
    );

    assert_eq!(
        MacosPeerCodeRequirement::new(""),
        Err(MacosPeerAuthenticationError::EmptyRequirement)
    );
    assert_eq!(
        MacosPeerCodeRequirement::new("cdhash\nH\"00\""),
        Err(MacosPeerAuthenticationError::RequirementByte { byte: b'\n' })
    );
    let oversize = "a".repeat(MAX_MACOS_PEER_REQUIREMENT_BYTES + 1);
    assert_eq!(
        MacosPeerCodeRequirement::new(&oversize),
        Err(MacosPeerAuthenticationError::RequirementTooLarge {
            bytes: oversize.len()
        })
    );
    assert_eq!(
        MacosPeerCodeRequirement::pinned_to_code_directory_hash(&[0_u8; 19]),
        Err(MacosPeerAuthenticationError::CodeDirectoryHashLength { bytes: 19 })
    );
    assert_eq!(
        MacosPeerCodeRequirement::pinned_to_code_directory_hash(&[0xab_u8; 20])
            .expect("pin twenty bytes")
            .text(),
        "cdhash H\"abababababababababababababababababababab\""
    );
    assert_eq!(
        MacosPeerCodeRequirement::pinned_to_code_directory_hash(&[0x0f_u8; 32])
            .expect("pin thirty-two bytes")
            .text()
            .len(),
        "cdhash H\"\"".len() + 64
    );
}
