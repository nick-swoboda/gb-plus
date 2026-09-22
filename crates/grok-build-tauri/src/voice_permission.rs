//! Narrow macOS `AVFoundation` microphone-permission bridge.

#![allow(unsafe_code)]

use std::sync::mpsc;
use std::time::Duration;

use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_av_foundation::{AVAuthorizationStatus, AVCaptureDevice, AVMediaTypeAudio};
use serde::Serialize;

const PERMISSION_WAIT: Duration = Duration::from_mins(2);

/// Honest macOS microphone authorization state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MicrophonePermission {
    NotDetermined,
    Restricted,
    Denied,
    Authorized,
    Unknown,
}

impl MicrophonePermission {
    fn from_av(status: AVAuthorizationStatus) -> Self {
        if status == AVAuthorizationStatus::NotDetermined {
            Self::NotDetermined
        } else if status == AVAuthorizationStatus::Restricted {
            Self::Restricted
        } else if status == AVAuthorizationStatus::Denied {
            Self::Denied
        } else if status == AVAuthorizationStatus::Authorized {
            Self::Authorized
        } else {
            Self::Unknown
        }
    }
}

/// Reads the status without opening a device or presenting UI.
pub(crate) fn microphone_permission() -> Result<MicrophonePermission, String> {
    // SAFETY: the weak-linked extern static is read on the admitted macOS 15
    // target and only Apple's exact AVMediaTypeAudio constant is passed to the
    // documented class method. No object pointer or caller-controlled value
    // crosses this boundary.
    let status = unsafe {
        let media_type = AVMediaTypeAudio
            .ok_or_else(|| "AVFoundation did not expose AVMediaTypeAudio.".to_owned())?;
        AVCaptureDevice::authorizationStatusForMediaType(media_type)
    };
    Ok(MicrophonePermission::from_av(status))
}

/// Presents Apple's microphone prompt only when status is not determined.
pub(crate) fn request_microphone_permission() -> Result<MicrophonePermission, String> {
    let current = microphone_permission()?;
    if current != MicrophonePermission::NotDetermined {
        return Ok(current);
    }
    let (sender, receiver) = mpsc::sync_channel(1);
    let completion = RcBlock::new(move |granted: Bool| {
        let _ = sender.send(granted.as_bool());
    });
    // SAFETY: same fixed AVMediaTypeAudio boundary as the status read. The
    // heap-backed block owns its sender and remains alive while this function
    // waits. This invokes Apple's public permission UI; it does not mutate TCC
    // state except through the user's OS decision.
    unsafe {
        let media_type = AVMediaTypeAudio
            .ok_or_else(|| "AVFoundation did not expose AVMediaTypeAudio.".to_owned())?;
        AVCaptureDevice::requestAccessForMediaType_completionHandler(media_type, &completion);
    }
    let callback_granted = receiver
        .recv_timeout(PERMISSION_WAIT)
        .map_err(|error| match error {
            mpsc::RecvTimeoutError::Timeout => {
                "The macOS microphone permission prompt did not complete within two minutes."
                    .to_owned()
            }
            mpsc::RecvTimeoutError::Disconnected => {
                "The macOS microphone permission callback ended without a decision.".to_owned()
            }
        })?;
    let observed = microphone_permission()?;
    if callback_granted && observed != MicrophonePermission::Authorized {
        return Err(
            "macOS reported microphone permission granted, but the status did not become Authorized."
                .into(),
        );
    }
    if !callback_granted && observed == MicrophonePermission::Authorized {
        return Err(
            "macOS reported microphone permission denied, but the status became Authorized.".into(),
        );
    }
    Ok(observed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_every_documented_av_status_without_red_failure_for_unarmed_state() {
        assert_eq!(
            MicrophonePermission::from_av(AVAuthorizationStatus::NotDetermined),
            MicrophonePermission::NotDetermined
        );
        assert_eq!(
            MicrophonePermission::from_av(AVAuthorizationStatus::Restricted),
            MicrophonePermission::Restricted
        );
        assert_eq!(
            MicrophonePermission::from_av(AVAuthorizationStatus::Denied),
            MicrophonePermission::Denied
        );
        assert_eq!(
            MicrophonePermission::from_av(AVAuthorizationStatus::Authorized),
            MicrophonePermission::Authorized
        );
        assert_eq!(
            MicrophonePermission::from_av(AVAuthorizationStatus(99)),
            MicrophonePermission::Unknown
        );
    }
}
