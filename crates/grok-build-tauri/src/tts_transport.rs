//! Bounded macOS Foundation transport for the single official xAI TTS path.

#![allow(unsafe_code)] // Audited NSURLSession bridge; bearer/audio remain native and bounded.

use core::ffi::c_void;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use block2::RcBlock;
use grok_build_plus_host::{
    PLUS_TTS_ENDPOINT, PLUS_TTS_PATH, PlusHostError, PlusLiveTtsAudio, PlusLiveTtsRequest,
};
use objc2::rc::Retained;
use objc2::runtime::{NSObjectProtocol, ProtocolObject};
use objc2::{AnyThread as _, DefinedClass as _, define_class, msg_send};
use objc2_foundation::{
    NSData, NSError, NSHTTPURLResponse, NSMutableURLRequest, NSObject, NSString, NSURL,
    NSURLRequest, NSURLRequestCachePolicy, NSURLResponse, NSURLSession, NSURLSessionConfiguration,
    NSURLSessionDelegate, NSURLSessionTask, NSURLSessionTaskDelegate,
};

const TTS_RESPONSE_DEADLINE: Duration = Duration::from_mins(3);
const TTS_CANCEL_POLL: Duration = Duration::from_millis(100);
const TTS_MAX_RESPONSE_BYTES: usize = 24 * 1024 * 1024;

#[derive(Debug)]
struct TtsRedirectDelegateIvars {
    redirected: Arc<AtomicBool>,
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements. The sole ivar is an
    // atomic flag and the class implements no custom Drop behavior.
    #[unsafe(super = NSObject)]
    #[ivars = TtsRedirectDelegateIvars]
    struct TtsRedirectDelegate;

    // SAFETY: NSObjectProtocol has no additional implementation requirements.
    unsafe impl NSObjectProtocol for TtsRedirectDelegate {}

    // SAFETY: No NSURLSessionDelegate optional method is claimed here.
    unsafe impl NSURLSessionDelegate for TtsRedirectDelegate {}

    // SAFETY: This one optional method has the exact generated signature. It
    // always supplies nil to the completion block, which is Apple's contract
    // for refusing a redirect before the redirected request begins.
    unsafe impl NSURLSessionTaskDelegate for TtsRedirectDelegate {
        #[allow(non_snake_case, reason = "generated Objective-C protocol method name")]
        #[unsafe(method(URLSession:task:willPerformHTTPRedirection:newRequest:completionHandler:))]
        unsafe fn URLSession_task_willPerformHTTPRedirection_newRequest_completionHandler(
            &self,
            _session: &NSURLSession,
            _task: &NSURLSessionTask,
            _response: &NSHTTPURLResponse,
            _request: &NSURLRequest,
            completion_handler: &block2::DynBlock<dyn Fn(*mut NSURLRequest)>,
        ) {
            self.ivars().redirected.store(true, Ordering::Release);
            completion_handler.call((std::ptr::null_mut(),));
        }
    }
);

impl TtsRedirectDelegate {
    fn new(redirected: Arc<AtomicBool>) -> Retained<Self> {
        let this = Self::alloc().set_ivars(TtsRedirectDelegateIvars { redirected });
        // SAFETY: NSObject's parameterless init signature is fixed.
        unsafe { msg_send![super(this), init] }
    }
}

struct SensitiveHeader(Vec<u8>);

impl Drop for SensitiveHeader {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

type NativeTtsResult = Result<(u16, String, Vec<u8>), String>;

/// Sends one official TTS request through an ephemeral macOS URL session.
/// Redirects, cookies, caches, response bodies on error, and oversized audio
/// are refused. No credential crosses JavaScript, argv, environment, or disk.
pub(crate) fn post_plus_live_tts_macos(
    request: &PlusLiveTtsRequest,
    mut cancelled: impl FnMut() -> bool,
) -> Result<PlusLiveTtsAudio, PlusHostError> {
    if request.endpoint != PLUS_TTS_ENDPOINT || request.path != PLUS_TTS_PATH {
        return Err(PlusHostError::Live(
            "Grok Read Aloud request is not bound to https://api.x.ai/v1/tts".into(),
        ));
    }
    if cancelled() {
        return Err(PlusHostError::LiveCancelled);
    }
    request.with_transport_parts(|body, authorization| {
        post_transport_parts(body, authorization, &mut cancelled)
    })
}

fn post_transport_parts(
    body: &str,
    authorization: &[u8],
    cancelled: &mut impl FnMut() -> bool,
) -> Result<PlusLiveTtsAudio, PlusHostError> {
    let url = NSURL::URLWithString(&NSString::from_str(PLUS_TTS_ENDPOINT))
        .ok_or_else(|| PlusHostError::Live("xAI TTS URL is invalid.".into()))?;
    let request = NSMutableURLRequest::requestWithURL(&url);
    request.setCachePolicy(NSURLRequestCachePolicy::ReloadIgnoringLocalAndRemoteCacheData);
    request.setHTTPShouldHandleCookies(false);
    request.setHTTPMethod(&NSString::from_str("POST"));
    request.setValue_forHTTPHeaderField(
        Some(&NSString::from_str("application/json")),
        &NSString::from_str("Content-Type"),
    );
    request.setValue_forHTTPHeaderField(
        Some(&NSString::from_str("audio/mpeg")),
        &NSString::from_str("Accept"),
    );

    let mut bearer = SensitiveHeader(b"Bearer ".to_vec());
    bearer.0.extend_from_slice(authorization);
    let bearer_text = std::str::from_utf8(&bearer.0)
        .map_err(|_| PlusHostError::LiveSecurity("xAI TTS bearer is not UTF-8.".into()))?;
    request.setValue_forHTTPHeaderField(
        Some(&NSString::from_str(bearer_text)),
        &NSString::from_str("Authorization"),
    );
    // SAFETY: NSData copies exactly `body.len()` bytes from a non-null slice
    // that remains live through this call.
    let body_data = unsafe { NSData::dataWithBytes_length(body.as_ptr().cast(), body.len()) };
    request.setHTTPBody(Some(&body_data));
    drop(bearer);

    let redirected = Arc::new(AtomicBool::new(false));
    let delegate = TtsRedirectDelegate::new(Arc::clone(&redirected));
    let configuration = NSURLSessionConfiguration::ephemeralSessionConfiguration();
    let delegate_object: &ProtocolObject<dyn NSURLSessionDelegate> =
        ProtocolObject::from_ref(&*delegate);
    // SAFETY: The delegate is retained locally and by NSURLSession, implements
    // the exact generated protocols, and the system-created delegate queue is
    // used by passing None.
    let session = unsafe {
        NSURLSession::sessionWithConfiguration_delegate_delegateQueue(
            &configuration,
            Some(delegate_object),
            None,
        )
    };
    let (sender, receiver) = mpsc::sync_channel::<NativeTtsResult>(1);
    let callback_redirected = Arc::clone(&redirected);
    let completion: RcBlock<dyn Fn(*mut NSData, *mut NSURLResponse, *mut NSError)> =
        RcBlock::new(move |data, response, error| {
            let result = capture_completion(data, response, error, &callback_redirected);
            let _ = sender.send(result);
        });
    // SAFETY: The escaping block owns only a sync sender and atomic flag, both
    // Send + Sync. Pointers are retained or copied inside the callback before
    // it returns.
    let task = unsafe { session.dataTaskWithRequest_completionHandler(&request, &completion) };
    task.resume();

    let started = Instant::now();
    let result = loop {
        if cancelled() {
            task.cancel();
            session.invalidateAndCancel();
            return Err(PlusHostError::LiveCancelled);
        }
        let Some(remaining) = TTS_RESPONSE_DEADLINE.checked_sub(started.elapsed()) else {
            task.cancel();
            session.invalidateAndCancel();
            return Err(PlusHostError::LiveTransport(
                "xAI TTS response timed out after three minutes.".into(),
            ));
        };
        match receiver.recv_timeout(remaining.min(TTS_CANCEL_POLL)) {
            Ok(result) => break result,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                task.cancel();
                session.invalidateAndCancel();
                return Err(PlusHostError::LiveTransport(
                    "macOS xAI TTS completion channel closed early.".into(),
                ));
            }
        }
    };
    session.finishTasksAndInvalidate();
    let (status, content_type, bytes) = result.map_err(PlusHostError::LiveTransport)?;
    if redirected.load(Ordering::Acquire) {
        return Err(PlusHostError::Live(
            "xAI TTS returned a redirect; redirects are not followed".into(),
        ));
    }
    if !(200..300).contains(&status) {
        return Err(PlusHostError::LiveHttp { status });
    }
    if content_type.split(';').next().map(str::trim) != Some("audio/mpeg") {
        return Err(PlusHostError::Live(
            "xAI TTS response was not the requested audio/mpeg format".into(),
        ));
    }
    if bytes.is_empty() || bytes.len() > TTS_MAX_RESPONSE_BYTES {
        return Err(PlusHostError::Live(
            "xAI TTS response body was empty or exceeded 24 MiB".into(),
        ));
    }
    Ok(PlusLiveTtsAudio {
        content_type: "audio/mpeg".into(),
        bytes,
    })
}

fn capture_completion(
    data: *mut NSData,
    response: *mut NSURLResponse,
    error: *mut NSError,
    redirected: &AtomicBool,
) -> NativeTtsResult {
    if redirected.load(Ordering::Acquire) {
        return Err("xAI TTS redirect was refused before follow-up.".into());
    }
    if !error.is_null() {
        // SAFETY: NSURLSession supplies a valid NSError for the callback
        // duration. Retaining makes description access lifetime-independent.
        let error = unsafe { Retained::<NSError>::retain(error) }
            .ok_or_else(|| "macOS xAI TTS returned an invalid error pointer.".to_owned())?;
        return Err(bounded_native_error(
            &error.localizedDescription().to_string(),
        ));
    }
    // SAFETY: NSURLSession callback pointers are valid for callback duration;
    // retaining the response and data makes subsequent reads owned.
    let response = unsafe { Retained::<NSURLResponse>::retain(response) }
        .ok_or_else(|| "macOS xAI TTS completed without an HTTP response.".to_owned())?;
    let http = response
        .downcast_ref::<NSHTTPURLResponse>()
        .ok_or_else(|| "macOS xAI TTS response was not HTTP.".to_owned())?;
    let status = u16::try_from(http.statusCode())
        .map_err(|_| "macOS xAI TTS returned an invalid HTTP status.".to_owned())?;
    let content_type = response
        .MIMEType()
        .map(|value| value.to_string())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let data = unsafe { Retained::<NSData>::retain(data) }
        .ok_or_else(|| "macOS xAI TTS completed without response data.".to_owned())?;
    let length = data.length();
    if length == 0 || length > TTS_MAX_RESPONSE_BYTES {
        return Err("macOS xAI TTS returned empty or oversized data.".into());
    }
    let mut bytes = vec![0_u8; length];
    let destination = NonNull::new(bytes.as_mut_ptr().cast::<c_void>())
        .ok_or_else(|| "macOS xAI TTS audio buffer is unavailable.".to_owned())?;
    // SAFETY: `bytes` owns exactly `length` writable bytes and NSData is
    // retained for the duration of the bounded copy.
    unsafe { data.getBytes_length(destination, length) };
    Ok((status, content_type, bytes))
}

fn bounded_native_error(reason: &str) -> String {
    const MAX_ERROR_BYTES: usize = 4096;
    if reason.len() <= MAX_ERROR_BYTES {
        return format!("macOS xAI TTS failed: {reason}");
    }
    let mut end = MAX_ERROR_BYTES;
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    format!("macOS xAI TTS failed: {}…", &reason[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_error_is_bounded_and_contains_no_response_body() {
        let reason = "x".repeat(5000);
        let bounded = bounded_native_error(&reason);
        assert!(bounded.len() <= 4130);
        assert!(bounded.starts_with("macOS xAI TTS failed: "));
    }
}
