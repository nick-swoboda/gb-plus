//! One-use positive startup confirmation after private view transfer.

use grok_build_core::Digest;

use super::{ServiceControl, ServiceOperation, ServiceTermination};
#[cfg(target_os = "linux")]
use crate::service_contract::ContainedServiceRequest;

pub(crate) struct ServiceLaunchGate {
    lease: String,
    commitment: Digest,
    next: u64,
    ended: bool,
}

impl ServiceLaunchGate {
    #[cfg(target_os = "linux")]
    pub(crate) fn new(request: &ContainedServiceRequest, next: u64) -> Result<Self, String> {
        if next == 0 || next == u64::MAX {
            return Err("Service startup control sequence is invalid.".into());
        }
        Ok(Self {
            lease: request.lease_id.clone(),
            commitment: request.commitment()?,
            next,
            ended: false,
        })
    }

    pub(crate) fn accept(&mut self, control: &ServiceControl) -> Result<u64, ServiceTermination> {
        if std::mem::replace(&mut self.ended, true)
            || control.version != 1
            || control.lease_id != self.lease
            || control.sequence != self.next
        {
            return Err(ServiceTermination::OwnerLost);
        }
        match &control.operation {
            ServiceOperation::Cancel => Err(ServiceTermination::Cancelled),
            ServiceOperation::Launch { commitment } if commitment == &self.commitment => {
                Ok(self.next + 1)
            }
            _ => Err(ServiceTermination::OwnerLost),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> ServiceLaunchGate {
        ServiceLaunchGate {
            lease: "one-use-lease".into(),
            commitment: Digest::sha256(b"exact views, executable and limits"),
            next: 18,
            ended: false,
        }
    }

    fn launch() -> ServiceControl {
        let expected = fixture();
        ServiceControl {
            version: 1,
            lease_id: expected.lease,
            sequence: expected.next,
            operation: ServiceOperation::Launch {
                commitment: expected.commitment,
            },
        }
    }

    #[test]
    fn cancellation_before_launch_permanently_refuses_startup() {
        let mut gate = fixture();
        let mut cancel = launch();
        cancel.operation = ServiceOperation::Cancel;
        assert_eq!(gate.accept(&cancel), Err(ServiceTermination::Cancelled));
        assert_eq!(gate.accept(&launch()), Err(ServiceTermination::OwnerLost));
    }

    #[test]
    fn only_the_matching_one_use_confirmation_can_release_startup() {
        let mut gate = fixture();
        assert_eq!(gate.accept(&launch()), Ok(19));
        assert_eq!(gate.accept(&launch()), Err(ServiceTermination::OwnerLost));
        for field in [
            "lease",
            "sequence",
            "version",
            "commitment",
            "input",
            "ready",
        ] {
            let mut gate = fixture();
            let mut changed = launch();
            match field {
                "lease" => changed.lease_id = "another".into(),
                "sequence" => changed.sequence -= 1,
                "version" => changed.version += 1,
                "commitment" => {
                    changed.operation = ServiceOperation::Launch {
                        commitment: Digest::sha256(b"changed"),
                    }
                }
                "input" => {
                    changed.operation = ServiceOperation::Input {
                        bytes: b"model text cannot authorize launch".to_vec(),
                    }
                }
                "ready" => changed.operation = ServiceOperation::Ready,
                _ => unreachable!(),
            }
            assert_eq!(
                gate.accept(&changed),
                Err(ServiceTermination::OwnerLost),
                "{field}"
            );
            assert_eq!(
                gate.accept(&launch()),
                Err(ServiceTermination::OwnerLost),
                "{field}"
            );
        }
    }
}
