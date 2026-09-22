//! The same pre-launch ownership/order state machine on host tests and the guest.

use std::path::Path;

use super::{ServiceControl, ServiceOperation};
use crate::service_contract::{ContainedServiceRequest, ServiceView};
use crate::service_snapshot::{ServiceSnapshot, ServiceSnapshotReceiver};

/// A stop request is distinguished from invalid or failed transfer data.
#[derive(Debug, Eq, PartialEq)]
pub enum ServiceStagingError {
    /// The owning app explicitly cancelled this exact lease.
    Cancelled,
    /// Protocol or filesystem validation refused the transfer.
    Refused(String),
}

/// Receives two views in a fixed order under one app-issued lease. Successful
/// transfer provides captured data only; the guest separately authorizes startup.
pub struct ServiceStagingReceiver {
    lease: String,
    next: u64,
    current: Option<ServiceSnapshotReceiver>,
    snapshots: Vec<ServiceSnapshot>,
    root: std::path::PathBuf,
    extension_digest: grok_build_core::Digest,
    poisoned: bool,
}

impl ServiceStagingReceiver {
    /// Bind transfer to the independently resolved private root and exact request.
    ///
    /// # Errors
    /// Refuses unowned paths, an invalid request, or a reused/non-private destination.
    pub fn new(root: &Path, request: &ContainedServiceRequest) -> Result<Self, String> {
        request.validate_shape()?;
        if Path::new(&request.workspace) != root.join("workspace")
            || Path::new(&request.content_root) != root.join("extension")
        {
            return Err("Service transfer belongs to a different private view root.".into());
        }
        let current = ServiceSnapshotReceiver::new(
            root,
            "workspace",
            request.scope.workspace_digest.clone(),
        )?;
        Ok(Self {
            lease: request.lease_id.clone(),
            next: 1,
            current: Some(current),
            snapshots: Vec::new(),
            root: root.to_owned(),
            extension_digest: request.scope.extension_digest.clone(),
            poisoned: false,
        })
    }

    /// Accept one identified control. Returns true only when both views completed.
    ///
    /// # Errors
    /// Refuses cross-lease controls, duplicate IDs, premature execution/input,
    /// swapped views and any invalid snapshot. Every refusal is permanent.
    pub fn accept(&mut self, control: &ServiceControl) -> Result<bool, ServiceStagingError> {
        if self.poisoned || self.snapshots.len() == 2 {
            self.poisoned = true;
            return Err(ServiceStagingError::Refused(
                "Service staging already ended.".into(),
            ));
        }
        let result = self.accept_inner(control);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn accept_inner(&mut self, control: &ServiceControl) -> Result<bool, ServiceStagingError> {
        let refused = ServiceStagingError::Refused;
        if control.version != 1 || control.lease_id != self.lease || control.sequence != self.next {
            return Err(refused(
                "Service staging identity or sequence changed.".into(),
            ));
        }
        self.next = self
            .next
            .checked_add(1)
            .ok_or_else(|| refused("Service control sequence overflow.".into()))?;
        let expected_view = if self.snapshots.is_empty() {
            ServiceView::Workspace
        } else {
            ServiceView::Extension
        };
        match &control.operation {
            ServiceOperation::Cancel => return Err(ServiceStagingError::Cancelled),
            ServiceOperation::Snapshot { view, frame } if *view == expected_view => {
                if self.current.is_none() {
                    self.current = Some(
                        ServiceSnapshotReceiver::new(
                            &self.root,
                            "extension",
                            self.extension_digest.clone(),
                        )
                        .map_err(refused)?,
                    );
                }
                if let Some(snapshot) = self
                    .current
                    .as_mut()
                    .ok_or_else(|| refused("Missing view receiver.".into()))?
                    .accept(frame)
                    .map_err(refused)?
                {
                    self.snapshots.push(snapshot);
                    self.current.take();
                }
            }
            _ => {
                return Err(refused(
                    "Only the expected snapshot can precede service startup.".into(),
                ));
            }
        }
        Ok(self.snapshots.len() == 2)
    }

    /// Consume a completed transfer and return its views and next control identity.
    ///
    /// # Errors
    /// Refuses interrupted, invalid and incomplete transfers; partial views drop.
    pub fn finish(self) -> Result<(Vec<ServiceSnapshot>, u64), String> {
        if self.poisoned || self.snapshots.len() != 2 || self.current.is_some() {
            return Err("Both private service views must complete before startup.".into());
        }
        Ok((self.snapshots, self.next))
    }
}
