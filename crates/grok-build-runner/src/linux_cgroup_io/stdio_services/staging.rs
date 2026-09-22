//! Transfer both captured views before the first service process can be created.

use super::{
    ContainedServiceRequest, Duration, Instant, ServiceControl, ServiceFrameReader,
    ServiceTermination, domain,
};
use crate::contained_service::{ServiceStagingError, ServiceStagingReceiver};
use crate::service_snapshot::MAX_SERVICE_VIEW_FRAME_BYTES;

pub(super) fn confirm_launch(
    domain: &domain::Domain,
    request: &ContainedServiceRequest,
    input: &mut std::io::Stdin,
    frames: &mut ServiceFrameReader,
    next: u64,
) -> Result<u64, ServiceTermination> {
    let mut gate = crate::contained_service::launch::ServiceLaunchGate::new(request, next)
        .map_err(|_| ServiceTermination::Failed)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    domain
        .installation
        .revalidate()
        .map_err(|_| ServiceTermination::ContainmentChanged)?;
    let mut checked = Instant::now();
    loop {
        if Instant::now() >= deadline {
            return Err(ServiceTermination::StagingTimeout);
        }
        if checked.elapsed() >= Duration::from_secs(1) {
            domain
                .installation
                .revalidate()
                .map_err(|_| ServiceTermination::ContainmentChanged)?;
            checked = Instant::now();
        }
        if let Some(bytes) = frames
            .next(input)
            .map_err(|_| ServiceTermination::OwnerLost)?
        {
            if bytes.len() > 4096 {
                return Err(ServiceTermination::LimitExceeded);
            }
            let control: ServiceControl =
                serde_json::from_slice(&bytes).map_err(|_| ServiceTermination::OwnerLost)?;
            return gate.accept(&control);
        }
        if frames.ended() {
            return Err(ServiceTermination::OwnerLost);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

pub(super) fn receive(
    domain: &mut domain::Domain,
    request: &ContainedServiceRequest,
    input: &mut std::io::Stdin,
    frames: &mut ServiceFrameReader,
) -> Result<u64, ServiceTermination> {
    let root = domain.view_path().map_err(|_| ServiceTermination::Failed)?;
    let mut receiver =
        ServiceStagingReceiver::new(&root, request).map_err(|_| ServiceTermination::Failed)?;
    let deadline = Instant::now() + Duration::from_mins(2);
    let mut checked = Instant::now();
    loop {
        if Instant::now() >= deadline {
            return Err(ServiceTermination::StagingTimeout);
        }
        if checked.elapsed() >= Duration::from_secs(1) {
            domain
                .installation
                .revalidate()
                .map_err(|_| ServiceTermination::ContainmentChanged)?;
            domain
                .view_path()
                .map_err(|_| ServiceTermination::ContainmentChanged)?;
            checked = Instant::now();
        }
        if let Some(bytes) = frames
            .next(input)
            .map_err(|_| ServiceTermination::OwnerLost)?
        {
            if bytes.len() > MAX_SERVICE_VIEW_FRAME_BYTES + 1024 {
                return Err(ServiceTermination::LimitExceeded);
            }
            let control: ServiceControl =
                serde_json::from_slice(&bytes).map_err(|_| ServiceTermination::OwnerLost)?;
            match receiver.accept(&control) {
                Ok(true) => break,
                Ok(false) => {}
                Err(ServiceStagingError::Cancelled) => return Err(ServiceTermination::Cancelled),
                Err(ServiceStagingError::Refused(_)) => return Err(ServiceTermination::OwnerLost),
            }
        } else if frames.ended() {
            return Err(ServiceTermination::OwnerLost);
        } else {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    let (snapshots, next) = receiver.finish().map_err(|_| ServiceTermination::Failed)?;
    domain.retain_views(snapshots);
    Ok(next)
}
