//! Host-owned snapshot binding and transfer, before protocol readiness starts.

use super::{
    ContainedServiceProfile, ContainedServiceRequest, Duration, Instant, Path, Phase,
    PlusContainedService, ServiceObservation, ServiceOperation, ServiceSnapshot,
};
use grok_build_runner::{ServiceSnapshotOperation, ServiceView};

pub(super) fn admission_lock(
    cancelled: &dyn Fn() -> bool,
) -> Result<std::sync::MutexGuard<'static, ()>, String> {
    static ADMISSION: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let deadline = Instant::now() + Duration::from_mins(2);
    loop {
        if cancelled() || Instant::now() >= deadline {
            return Err("Service admission was cancelled or exceeded its queue deadline.".into());
        }
        match ADMISSION.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err("Service admission needs recovery after an interrupted owner.".into());
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

pub(super) fn bind(
    request: &mut ContainedServiceRequest,
    profile: &ContainedServiceProfile,
    (workspace, extension): (&ServiceSnapshot, &ServiceSnapshot),
) -> Result<(), String> {
    workspace.revalidate()?;
    extension.revalidate()?;
    if workspace.digest() != &request.scope.workspace_digest
        || extension.digest() != &request.scope.extension_digest
    {
        return Err("Service admission belongs to different captured views.".into());
    }
    let executable = Path::new(&request.executable)
        .strip_prefix(&request.content_root)
        .map_err(|e| e.to_string())?
        .to_owned();
    extension.verify_image(
        &executable,
        request.executable_bytes,
        &request.executable_digest,
        request.architecture,
    )?;
    let (workspace, content) = profile.snapshot_paths(request)?;
    request.executable = Path::new(&content)
        .join(executable)
        .to_str()
        .ok_or("Staged service executable path is not UTF-8.")?
        .into();
    request.workspace = workspace;
    request.content_root = content;
    request.validate_shape()
}

pub(super) fn transfer(
    service: &mut PlusContainedService,
    (workspace, extension): (&ServiceSnapshot, &ServiceSnapshot),
    cancelled: &dyn Fn() -> bool,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_mins(2);
    let stopped = || cancelled() || Instant::now() >= deadline;
    for (view, snapshot) in [
        (ServiceView::Workspace, workspace),
        (ServiceView::Extension, extension),
    ] {
        snapshot.transfer(
            &mut |frame| {
                if view == ServiceView::Extension
                    && matches!(frame.operation, ServiceSnapshotOperation::Finish { .. })
                {
                    service.phase = Phase::AwaitingViews;
                }
                service.control(ServiceOperation::Snapshot {
                    view,
                    frame: frame.clone(),
                })
            },
            &stopped,
        )?;
    }
    loop {
        if stopped() {
            return Err("Service staging was cancelled or exceeded its deadline.".into());
        }
        match service.poll()? {
            Some(ServiceObservation::ViewsReady { commitment }) => {
                if stopped() || service.phase != Phase::AwaitingLaunch {
                    return Err(
                        "Service startup was cancelled before its positive confirmation.".into(),
                    );
                }
                service.control(ServiceOperation::Launch { commitment })?;
                service.phase = Phase::Starting;
                return Ok(());
            }
            Some(_) => {
                return Err("Service did not acknowledge both verified private views.".into());
            }
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    }
}
