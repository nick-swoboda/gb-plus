//! Bounded local multilingual microphone transcription.

use std::collections::HashSet;
use std::fs;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

use cpal::traits::{DeviceTrait as _, HostTrait as _, StreamTrait as _};
use cpal::{FromSample, Sample, SampleFormat, SizedSample, Stream, StreamConfig};
use serde::{Deserialize, Serialize};
use whisper_rs::{FullParams, SamplingStrategy, WhisperContext, WhisperContextParameters};

use crate::asset_download::{AssetManager, AssetSpec, InstalledAsset};
use crate::owner_state::OwnerStateRoot;
use crate::voice_permission::{
    MicrophonePermission, microphone_permission, request_microphone_permission,
};

const VOICE_SETTINGS_SCHEMA: u16 = 1;
const VOICE_SETTINGS_FILE: &str = "voice-settings.json";
const MAX_RECORDING_SECONDS: u64 = 120;
const MAX_INPUT_SAMPLE_RATE: u32 = 96_000;
const MAX_INPUT_CHANNELS: u16 = 2;
const TARGET_SAMPLE_RATE: u32 = 16_000;
const MAX_TRANSCRIPT_BYTES: usize = 12_000;
const RESAMPLE_HALF_TAPS: isize = 16;
const MIN_AUDIO_SECONDS: f64 = 0.25;
const MIN_SIGNAL_PEAK: f32 = 0.003;

const BASE_MODEL: AssetSpec = AssetSpec {
    id: "whisper-base-multilingual",
    filename: "ggml-base.bin",
    url: "https://huggingface.co/ggerganov/whisper.cpp/resolve/5359861c739e955e79d9a303bcbc70fb988958b1/ggml-base.bin",
    byte_len: 147_951_465,
    sha256: "60ed5bc3dd14eea856493d334349b405782ddcaf0028d4b5df4088345fba2efe",
    allowed_hosts: &["huggingface.co", "cdn-lfs.huggingface.co", "*.hf.co"],
};

const SMALL_MODEL: AssetSpec = AssetSpec {
    id: "whisper-small-multilingual",
    filename: "ggml-small.bin",
    url: "https://huggingface.co/ggerganov/whisper.cpp/resolve/5359861c739e955e79d9a303bcbc70fb988958b1/ggml-small.bin",
    byte_len: 487_601_967,
    sha256: "1be3a9b2063867b937e64e2ec7483364a79917e157fa98c5d94b5c1fffea987b",
    allowed_hosts: &["huggingface.co", "cdn-lfs.huggingface.co", "*.hf.co"],
};

/// User-selected multilingual local model.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VoiceModel {
    Base,
    Small,
}

impl VoiceModel {
    pub(crate) const fn event_id(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::Small => "small",
        }
    }

    fn spec(self) -> AssetSpec {
        match self {
            Self::Base => BASE_MODEL,
            Self::Small => SMALL_MODEL,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Base => "Multilingual base",
            Self::Small => "Multilingual small",
        }
    }
}

/// Current non-decorative Voice operation state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VoicePhase {
    Idle,
    Verifying,
    Downloading,
    RequestingPermission,
    Recording,
    Transcribing,
    Failed,
}

/// One model's real local provisioning state.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VoiceModelView {
    model: VoiceModel,
    label: &'static str,
    expected_bytes: u64,
    provisioned: bool,
    verified_this_run: bool,
}

/// Voice state returned to the static frontend.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VoiceView {
    pub(crate) permission: MicrophonePermission,
    pub(crate) phase: VoicePhase,
    pub(crate) selected_model: VoiceModel,
    pub(crate) models: Vec<VoiceModelView>,
    pub(crate) detail: String,
    pub(crate) recorded_milliseconds: u64,
    pub(crate) progress_bytes: Option<u64>,
    pub(crate) progress_total: Option<u64>,
}

/// Download progress without URLs or response headers.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VoiceProgress {
    pub(crate) model: VoiceModel,
    pub(crate) downloaded_bytes: u64,
    pub(crate) total_bytes: u64,
}

/// A transcript is returned to the composer only; it is never persisted here.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VoiceTranscript {
    pub(crate) project_id: String,
    pub(crate) model: VoiceModel,
    pub(crate) duration_milliseconds: u64,
    pub(crate) text: String,
}

#[derive(Clone)]
pub(crate) struct VoiceManager {
    inner: Arc<Mutex<VoiceInner>>,
    assets: AssetManager,
    settings_path: PathBuf,
}

struct VoiceInner {
    selected_model: VoiceModel,
    phase: VoicePhase,
    detail: String,
    verified_models: HashSet<VoiceModel>,
    recording: Option<RecordingSession>,
    progress_bytes: Option<u64>,
    progress_total: Option<u64>,
}

struct RecordingSession {
    project_id: String,
    model: VoiceModel,
    sample_rate: u32,
    channels: u16,
    started: Instant,
    capture: Arc<CaptureState>,
    stream: Stream,
}

struct CaptureState {
    samples: Mutex<Vec<f32>>,
    max_samples: usize,
    dropped_callbacks: AtomicUsize,
    limit_reached: AtomicBool,
    stream_error: Mutex<Option<String>>,
}

impl Drop for CaptureState {
    fn drop(&mut self) {
        if let Ok(samples) = self.samples.get_mut() {
            samples.fill(0.0);
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VoiceSettings {
    schema_version: u16,
    selected_model: VoiceModel,
}

impl VoiceManager {
    pub(crate) fn new(state_root: &Path) -> Self {
        let settings_path = state_root.join(VOICE_SETTINGS_FILE);
        let selected_model = read_settings(&settings_path).unwrap_or(VoiceModel::Base);
        Self {
            inner: Arc::new(Mutex::new(VoiceInner {
                selected_model,
                phase: VoicePhase::Idle,
                detail:
                    "Choose base or small, install it once, then record. Transcripts stay editable."
                        .into(),
                verified_models: HashSet::new(),
                recording: None,
                progress_bytes: None,
                progress_total: None,
            })),
            assets: AssetManager::new(state_root.join("runtime-assets").join("voice")),
            settings_path,
        }
    }

    pub(crate) fn status(&self) -> VoiceView {
        let permission = microphone_permission().unwrap_or(MicrophonePermission::Unknown);
        match self.inner.lock() {
            Ok(inner) => self.view_locked(&inner, permission),
            Err(_) => VoiceView {
                permission,
                phase: VoicePhase::Failed,
                selected_model: VoiceModel::Base,
                models: self.model_views(&HashSet::new()),
                detail: "Voice state is unavailable because its lock was poisoned.".into(),
                recorded_milliseconds: 0,
                progress_bytes: None,
                progress_total: None,
            },
        }
    }

    pub(crate) fn select_model(&self, model: VoiceModel) -> Result<VoiceView, String> {
        {
            let mut inner = self.lock()?;
            ensure_idle(&inner)?;
            inner.selected_model = model;
            inner.detail = format!(
                "{} selected. No prompt will be sent automatically.",
                model.label()
            );
        }
        write_settings(&self.settings_path, model)?;
        Ok(self.status())
    }

    pub(crate) fn install_model<F>(
        &self,
        model: VoiceModel,
        mut progress: F,
    ) -> Result<VoiceView, String>
    where
        F: FnMut(VoiceProgress),
    {
        {
            let mut inner = self.lock()?;
            ensure_idle(&inner)?;
            inner.phase = VoicePhase::Downloading;
            inner.detail = format!("Downloading {} over pinned HTTPS…", model.label());
            inner.progress_bytes = Some(0);
            inner.progress_total = Some(model.spec().byte_len);
        }
        let mut last_emitted = 0_u64;
        let result = self.assets.install(model.spec(), |downloaded, total| {
            if let Ok(mut inner) = self.inner.lock() {
                inner.progress_bytes = Some(downloaded);
                inner.progress_total = Some(total);
            }
            if downloaded == total || downloaded.saturating_sub(last_emitted) >= 4 * 1024 * 1024 {
                last_emitted = downloaded;
                progress(VoiceProgress {
                    model,
                    downloaded_bytes: downloaded,
                    total_bytes: total,
                });
            }
        });
        self.finish_install(model, result)
    }

    pub(crate) fn start_recording(&self, project_id: String) -> Result<VoiceView, String> {
        let model = {
            let mut inner = self.lock()?;
            ensure_idle(&inner)?;
            inner.phase = VoicePhase::Verifying;
            inner.detail = "Verifying the exact local model before microphone access…".into();
            inner.selected_model
        };
        if let Err(error) = self
            .assets
            .verified_path(model.spec())
            .and_then(|path| path.ok_or_else(|| format!("{} is not installed.", model.label())))
        {
            return self.fail(error);
        }
        if let Ok(mut inner) = self.inner.lock() {
            inner.verified_models.insert(model);
            inner.phase = VoicePhase::RequestingPermission;
            inner.detail = "Waiting for the macOS microphone permission decision…".into();
        }
        let permission = match request_microphone_permission() {
            Ok(permission) => permission,
            Err(error) => return self.fail(error),
        };
        if permission != MicrophonePermission::Authorized {
            let message = permission_failure(permission);
            return self.fail(message);
        }
        let session = match build_recording_session(project_id, model) {
            Ok(session) => session,
            Err(error) => return self.fail(error),
        };
        let mut inner = self.lock()?;
        if inner.phase != VoicePhase::RequestingPermission || inner.recording.is_some() {
            drop(session);
            return Err("Voice state changed before recording could start.".into());
        }
        inner.phase = VoicePhase::Recording;
        inner.detail = format!(
            "Recording with {}. Stop to transcribe locally; nothing is sent automatically.",
            model.label()
        );
        inner.recording = Some(session);
        inner.progress_bytes = None;
        inner.progress_total = None;
        Ok(self.view_locked(&inner, permission))
    }

    pub(crate) fn stop_and_transcribe(
        &self,
        active_project_id: &str,
    ) -> Result<VoiceTranscript, String> {
        let session = {
            let mut inner = self.lock()?;
            let session = inner
                .recording
                .take()
                .ok_or_else(|| "No Voice recording is active.".to_owned())?;
            if session.project_id != active_project_id {
                inner.recording = Some(session);
                return Err(
                    "Voice refused to cross the project active when recording began.".into(),
                );
            }
            inner.phase = VoicePhase::Transcribing;
            inner.detail = "Transcribing locally. The result will remain editable.".into();
            session
        };
        let result = transcribe_session(&self.assets, session);
        match result {
            Ok(transcript) => {
                if let Ok(mut inner) = self.inner.lock() {
                    inner.phase = VoicePhase::Idle;
                    inner.detail = "Transcript inserted for review. Voice never sends or enqueues automatically."
                        .into();
                }
                Ok(transcript)
            }
            Err(error) => {
                let _ = self.fail::<()>(error.clone());
                Err(error)
            }
        }
    }

    pub(crate) fn cancel_recording(&self) -> Result<VoiceView, String> {
        let recording = {
            let mut inner = self.lock()?;
            let recording = inner
                .recording
                .take()
                .ok_or_else(|| "No Voice recording is active.".to_owned())?;
            inner.phase = VoicePhase::Idle;
            inner.detail = "Recording discarded from memory. No transcript was created.".into();
            recording
        };
        drop(recording);
        Ok(self.status())
    }

    pub(crate) fn shutdown(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            let recording = inner.recording.take();
            inner.phase = VoicePhase::Idle;
            inner.detail = "Voice stopped during application shutdown.".into();
            drop(recording);
        }
    }

    fn finish_install(
        &self,
        model: VoiceModel,
        result: Result<InstalledAsset, String>,
    ) -> Result<VoiceView, String> {
        match result {
            Ok(installed) => {
                let mut inner = self.lock()?;
                inner.phase = VoicePhase::Idle;
                inner.verified_models.insert(model);
                inner.progress_bytes = None;
                inner.progress_total = None;
                inner.detail = if installed.downloaded {
                    format!("{} installed and SHA-256 verified.", model.label())
                } else {
                    format!(
                        "{} was already installed and SHA-256 verified.",
                        model.label()
                    )
                };
                Ok(self.view_locked(
                    &inner,
                    microphone_permission().unwrap_or(MicrophonePermission::Unknown),
                ))
            }
            Err(error) => self.fail(error),
        }
    }

    fn fail<T>(&self, error: String) -> Result<T, String> {
        if let Ok(mut inner) = self.inner.lock() {
            inner.phase = VoicePhase::Failed;
            inner.detail.clone_from(&error);
            inner.progress_bytes = None;
            inner.progress_total = None;
            inner.recording = None;
        }
        Err(error)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, VoiceInner>, String> {
        self.inner
            .lock()
            .map_err(|_| "Voice state lock is unavailable.".to_owned())
    }

    fn view_locked(&self, inner: &VoiceInner, permission: MicrophonePermission) -> VoiceView {
        VoiceView {
            permission,
            phase: inner.phase,
            selected_model: inner.selected_model,
            models: self.model_views(&inner.verified_models),
            detail: inner.detail.clone(),
            recorded_milliseconds: inner.recording.as_ref().map_or(0, |recording| {
                u64::try_from(recording.started.elapsed().as_millis()).unwrap_or(u64::MAX)
            }),
            progress_bytes: inner.progress_bytes,
            progress_total: inner.progress_total,
        }
    }

    fn model_views(&self, verified: &HashSet<VoiceModel>) -> Vec<VoiceModelView> {
        [VoiceModel::Base, VoiceModel::Small]
            .into_iter()
            .map(|model| {
                let spec = model.spec();
                VoiceModelView {
                    model,
                    label: model.label(),
                    expected_bytes: spec.byte_len,
                    provisioned: provisioned_shape(self.assets.root(), spec),
                    verified_this_run: verified.contains(&model),
                }
            })
            .collect()
    }
}

fn ensure_idle(inner: &VoiceInner) -> Result<(), String> {
    if inner.phase == VoicePhase::Idle || inner.phase == VoicePhase::Failed {
        Ok(())
    } else {
        Err("Finish or cancel the current Voice operation first.".into())
    }
}

#[allow(
    clippy::verbose_bit_mask,
    reason = "the explicit Unix group/other permission mask directly documents the owner-only asset invariant"
)]
fn provisioned_shape(root: &Path, spec: AssetSpec) -> bool {
    let path = root.join(spec.filename);
    fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.len() == spec.byte_len
            && metadata.permissions().mode() & 0o077 == 0
    })
}

fn permission_failure(permission: MicrophonePermission) -> String {
    match permission {
        MicrophonePermission::Denied => "Microphone access is denied. Enable GB Plus in System Settings → Privacy & Security → Microphone, then try again.".into(),
        MicrophonePermission::Restricted => "Microphone access is restricted by macOS policy and cannot be requested by the app.".into(),
        MicrophonePermission::NotDetermined => "The macOS microphone permission prompt ended without a decision.".into(),
        MicrophonePermission::Unknown => "macOS returned an unknown microphone permission state; recording was refused.".into(),
        MicrophonePermission::Authorized => "Microphone authorization failed unexpectedly.".into(),
    }
}

fn build_recording_session(
    project_id: String,
    model: VoiceModel,
) -> Result<RecordingSession, String> {
    let host = cpal::default_host();
    let device = host
        .default_input_device()
        .ok_or_else(|| "No default physical microphone input is available.".to_owned())?;
    let supported = device
        .default_input_config()
        .map_err(|error| format!("Cannot read the default microphone format: {error}"))?;
    let channels = supported.channels();
    let sample_rate = supported.sample_rate();
    if channels == 0 || channels > MAX_INPUT_CHANNELS {
        return Err(format!(
            "The default microphone exposes {channels} channels; Voice admits only one or two."
        ));
    }
    if !(8_000..=MAX_INPUT_SAMPLE_RATE).contains(&sample_rate) {
        return Err(format!(
            "The default microphone sample rate {sample_rate} Hz is outside the admitted 8–96 kHz bound."
        ));
    }
    let max_samples_u64 = u64::from(sample_rate)
        .checked_mul(u64::from(channels))
        .and_then(|value| value.checked_mul(MAX_RECORDING_SECONDS))
        .ok_or_else(|| "Microphone sample bound overflowed.".to_owned())?;
    let max_samples = usize::try_from(max_samples_u64)
        .map_err(|_| "Microphone sample bound exceeds this host.".to_owned())?;
    let capture = Arc::new(CaptureState {
        samples: Mutex::new(Vec::with_capacity(
            usize::try_from(u64::from(sample_rate) * u64::from(channels) * 10)
                .unwrap_or(max_samples)
                .min(max_samples),
        )),
        max_samples,
        dropped_callbacks: AtomicUsize::new(0),
        limit_reached: AtomicBool::new(false),
        stream_error: Mutex::new(None),
    });
    let config: StreamConfig = supported.into();
    let stream = match supported.sample_format() {
        SampleFormat::F32 => build_stream::<f32>(&device, &config, &capture),
        SampleFormat::F64 => build_stream::<f64>(&device, &config, &capture),
        SampleFormat::I8 => build_stream::<i8>(&device, &config, &capture),
        SampleFormat::I16 => build_stream::<i16>(&device, &config, &capture),
        SampleFormat::I32 => build_stream::<i32>(&device, &config, &capture),
        SampleFormat::U8 => build_stream::<u8>(&device, &config, &capture),
        SampleFormat::U16 => build_stream::<u16>(&device, &config, &capture),
        SampleFormat::U32 => build_stream::<u32>(&device, &config, &capture),
        other => Err(format!(
            "The default microphone uses unsupported sample format {other}; no recording started."
        )),
    }?;
    stream
        .play()
        .map_err(|error| format!("Cannot start the microphone input stream: {error}"))?;
    if microphone_permission()? != MicrophonePermission::Authorized {
        drop(stream);
        return Err("Microphone permission changed before recording became active.".into());
    }
    Ok(RecordingSession {
        project_id,
        model,
        sample_rate,
        channels,
        started: Instant::now(),
        capture,
        stream,
    })
}

fn build_stream<T>(
    device: &cpal::Device,
    config: &StreamConfig,
    capture: &Arc<CaptureState>,
) -> Result<Stream, String>
where
    T: SizedSample + Sample + Copy,
    f32: FromSample<T>,
{
    let data_capture = Arc::clone(capture);
    let error_capture = Arc::clone(capture);
    device
        .build_input_stream(
            *config,
            move |data: &[T], _| {
                let Ok(mut samples) = data_capture.samples.try_lock() else {
                    data_capture
                        .dropped_callbacks
                        .fetch_add(1, Ordering::Relaxed);
                    return;
                };
                let remaining = data_capture.max_samples.saturating_sub(samples.len());
                let count = remaining.min(data.len());
                samples.extend(data[..count].iter().copied().map(f32::from_sample));
                if count < data.len() {
                    data_capture.limit_reached.store(true, Ordering::Release);
                }
            },
            move |error| {
                if let Ok(mut slot) = error_capture.stream_error.lock() {
                    *slot = Some(format!("Microphone input stream failed: {error}"));
                }
            },
            None,
        )
        .map_err(|error| format!("Cannot build the microphone input stream: {error}"))
}

fn transcribe_session(
    assets: &AssetManager,
    session: RecordingSession,
) -> Result<VoiceTranscript, String> {
    let duration = session.started.elapsed();
    let project_id = session.project_id.clone();
    let model = session.model;
    let sample_rate = session.sample_rate;
    let channels = session.channels;
    drop(session.stream);
    if let Some(error) = session
        .capture
        .stream_error
        .lock()
        .map_err(|_| "Microphone error state is unavailable.".to_owned())?
        .clone()
    {
        return Err(error);
    }
    let dropped = session.capture.dropped_callbacks.load(Ordering::Acquire);
    if dropped > 0 {
        return Err(format!(
            "Microphone capture dropped {dropped} real-time callbacks; transcription was refused instead of using discontinuous audio."
        ));
    }
    if session.capture.limit_reached.load(Ordering::Acquire) {
        return Err(format!(
            "Recording exceeded the {MAX_RECORDING_SECONDS}-second audio bound; transcription was refused instead of using truncated audio."
        ));
    }
    let mut interleaved = std::mem::take(
        &mut *session
            .capture
            .samples
            .lock()
            .map_err(|_| "Microphone sample buffer is unavailable.".to_owned())?,
    );
    let result = transcribe_samples(
        assets,
        &mut interleaved,
        sample_rate,
        channels,
        project_id,
        model,
        u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
    );
    interleaved.fill(0.0);
    result
}

fn transcribe_samples(
    assets: &AssetManager,
    interleaved: &mut [f32],
    sample_rate: u32,
    channels: u16,
    project_id: String,
    model: VoiceModel,
    duration_milliseconds: u64,
) -> Result<VoiceTranscript, String> {
    let sample_count = u32::try_from(interleaved.len())
        .map_err(|_| "Recording sample count exceeds the admitted duration bound.".to_owned())?;
    let seconds = f64::from(sample_count) / f64::from(sample_rate) / f64::from(channels);
    if seconds < MIN_AUDIO_SECONDS {
        return Err("Recording was too short to transcribe; no transcript was inserted.".into());
    }
    let mut mono = interleaved_to_mono(interleaved, channels)?;
    interleaved.fill(0.0);
    if mono
        .iter()
        .fold(0.0_f32, |peak, sample| peak.max(sample.abs()))
        < MIN_SIGNAL_PEAK
    {
        mono.fill(0.0);
        return Err(
            "Recording contained no detectable speech signal; no transcript was inserted.".into(),
        );
    }
    let mut resampled = resample_to_16khz(&mono, sample_rate)?;
    mono.fill(0.0);
    let model_file = assets
        .open_verified(model.spec())?
        .ok_or_else(|| format!("{} is not installed.", model.label()))?;
    let descriptor_path = format!("/dev/fd/{}", model_file.as_raw_fd());
    let context =
        WhisperContext::new_with_params(&descriptor_path, WhisperContextParameters::default())
            .map_err(|error| format!("Cannot load the verified local model: {error}"))?;
    if !context.is_multilingual() {
        resampled.fill(0.0);
        return Err("The verified model did not identify as multilingual.".into());
    }
    let mut state = context
        .create_state()
        .map_err(|error| format!("Cannot create local transcription state: {error}"))?;
    let mut params = FullParams::new(SamplingStrategy::Greedy { best_of: 1 });
    params.set_language(None);
    params.set_translate(false);
    params.set_no_context(true);
    params.set_no_timestamps(true);
    params.set_print_special(false);
    params.set_print_progress(false);
    params.set_print_realtime(false);
    params.set_print_timestamps(false);
    let threads = std::thread::available_parallelism()
        .map_or(2, usize::from)
        .clamp(1, 8);
    params.set_n_threads(i32::try_from(threads).unwrap_or(2));
    let inference = state.full(params, &resampled);
    resampled.fill(0.0);
    inference.map_err(|error| format!("Local transcription failed: {error}"))?;
    let transcript = state
        .as_iter()
        .map(|segment| segment.to_string())
        .collect::<String>()
        .trim()
        .to_owned();
    if transcript.is_empty() {
        return Err(
            "Local transcription returned an empty transcript; nothing was inserted.".into(),
        );
    }
    if transcript.len() > MAX_TRANSCRIPT_BYTES {
        return Err(
            "Local transcript exceeded the composer byte bound; no partial text was inserted."
                .into(),
        );
    }
    Ok(VoiceTranscript {
        project_id,
        model,
        duration_milliseconds,
        text: transcript,
    })
}

fn interleaved_to_mono(samples: &[f32], channels: u16) -> Result<Vec<f32>, String> {
    let channel_divisor = f32::from(channels);
    let channels = usize::from(channels);
    if channels == 0 || channels > usize::from(MAX_INPUT_CHANNELS) {
        return Err("Microphone channel count is outside the admitted bound.".into());
    }
    if !samples.len().is_multiple_of(channels) {
        return Err("Microphone delivered a partial interleaved frame.".into());
    }
    Ok(samples
        .chunks_exact(channels)
        .map(|frame| frame.iter().sum::<f32>() / channel_divisor)
        .collect())
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    reason = "input/output indices are bounded by five minutes at at most 96 kHz, far below exact integer ranges for f64; the final clamped sample intentionally narrows to the f32 audio contract"
)]
fn resample_to_16khz(input: &[f32], input_rate: u32) -> Result<Vec<f32>, String> {
    if input_rate == TARGET_SAMPLE_RATE {
        return Ok(input.to_vec());
    }
    if !(8_000..=MAX_INPUT_SAMPLE_RATE).contains(&input_rate) {
        return Err("Microphone sample rate is outside the admitted resampler bound.".into());
    }
    let output_len_u128 = (input.len() as u128)
        .checked_mul(u128::from(TARGET_SAMPLE_RATE))
        .ok_or_else(|| "Resampler length overflowed.".to_owned())?
        / u128::from(input_rate);
    let output_len = usize::try_from(output_len_u128)
        .map_err(|_| "Resampler output exceeds this host.".to_owned())?;
    let max_output = usize::try_from(u64::from(TARGET_SAMPLE_RATE) * MAX_RECORDING_SECONDS)
        .map_err(|_| "Resampler bound exceeds this host.".to_owned())?;
    if output_len == 0 || output_len > max_output {
        return Err("Resampler output is outside the admitted duration bound.".into());
    }
    let ratio = f64::from(input_rate) / f64::from(TARGET_SAMPLE_RATE);
    let cutoff = (f64::from(TARGET_SAMPLE_RATE) / f64::from(input_rate)).min(1.0) * 0.94;
    let mut output = Vec::with_capacity(output_len);
    for output_index in 0..output_len {
        let source = output_index as f64 * ratio;
        let center = source.floor() as isize;
        let mut weighted = 0.0_f64;
        let mut weight_sum = 0.0_f64;
        for tap in -RESAMPLE_HALF_TAPS..=RESAMPLE_HALF_TAPS {
            let index = center + tap;
            let Ok(input_index) = usize::try_from(index) else {
                continue;
            };
            if input_index >= input.len() {
                continue;
            }
            let distance = source - index as f64;
            let sinc_argument = std::f64::consts::PI * distance * cutoff;
            let sinc = if sinc_argument.abs() < f64::EPSILON {
                1.0
            } else {
                sinc_argument.sin() / sinc_argument
            };
            let window_position = distance / (RESAMPLE_HALF_TAPS as f64 + 1.0);
            if window_position.abs() > 1.0 {
                continue;
            }
            let window = 0.5 * (1.0 + (std::f64::consts::PI * window_position).cos());
            let weight = cutoff * sinc * window;
            weighted += f64::from(input[input_index]) * weight;
            weight_sum += weight;
        }
        output.push(if weight_sum.abs() < f64::EPSILON {
            0.0
        } else {
            (weighted / weight_sum).clamp(-1.0, 1.0) as f32
        });
    }
    Ok(output)
}

fn read_settings(path: &Path) -> Option<VoiceModel> {
    let parent = path.parent()?;
    let bytes = OwnerStateRoot::new(parent)
        .file(VOICE_SETTINGS_FILE, 4096)
        .ok()?
        .read()
        .ok()??;
    let settings: VoiceSettings = serde_json::from_slice(&bytes).ok()?;
    (settings.schema_version == VOICE_SETTINGS_SCHEMA).then_some(settings.selected_model)
}

fn write_settings(path: &Path, selected_model: VoiceModel) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "Voice settings path has no parent.".to_owned())?;
    let bytes = serde_json::to_vec_pretty(&VoiceSettings {
        schema_version: VOICE_SETTINGS_SCHEMA,
        selected_model,
    })
    .map_err(|error| format!("Cannot encode Voice settings: {error}"))?;
    OwnerStateRoot::new(parent)
        .file(VOICE_SETTINGS_FILE, 4096)
        .and_then(|file| file.replace(&bytes))
        .map_err(|error| format!("Cannot persist Voice settings: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_pcm16_mono_wav(path: &Path) -> Vec<f32> {
        let bytes = fs::read(path).expect("read WAV fixture");
        assert!(bytes.len() >= 44 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WAVE");
        let mut cursor = 12_usize;
        let mut format = None;
        let mut data = None;
        while cursor.checked_add(8).is_some_and(|end| end <= bytes.len()) {
            let id = &bytes[cursor..cursor + 4];
            let length = u32::from_le_bytes(
                bytes[cursor + 4..cursor + 8]
                    .try_into()
                    .expect("WAV chunk length"),
            ) as usize;
            let start = cursor + 8;
            let end = start.checked_add(length).expect("WAV chunk overflow");
            assert!(end <= bytes.len(), "truncated WAV chunk");
            if id == b"fmt " {
                assert!(length >= 16);
                format = Some((
                    u16::from_le_bytes(bytes[start..start + 2].try_into().expect("format tag")),
                    u16::from_le_bytes(bytes[start + 2..start + 4].try_into().expect("channels")),
                    u32::from_le_bytes(
                        bytes[start + 4..start + 8].try_into().expect("sample rate"),
                    ),
                    u16::from_le_bytes(
                        bytes[start + 14..start + 16]
                            .try_into()
                            .expect("sample bits"),
                    ),
                ));
            } else if id == b"data" {
                data = Some(&bytes[start..end]);
            }
            cursor = end + (length & 1);
        }
        assert_eq!(format, Some((1, 1, 16_000, 16)));
        data.expect("WAV data")
            .chunks_exact(2)
            .map(|pair| f32::from(i16::from_le_bytes([pair[0], pair[1]])) / 32768.0)
            .collect()
    }

    #[test]
    fn model_specs_are_exact_multilingual_choices() {
        assert_eq!(BASE_MODEL.byte_len, 147_951_465);
        assert_eq!(SMALL_MODEL.byte_len, 487_601_967);
        assert!(
            BASE_MODEL
                .url
                .contains("/5359861c739e955e79d9a303bcbc70fb988958b1/")
        );
        assert!(
            SMALL_MODEL
                .url
                .contains("/5359861c739e955e79d9a303bcbc70fb988958b1/")
        );
        assert!(!BASE_MODEL.url.contains("main"));
        assert!(!SMALL_MODEL.url.contains("main"));
    }

    #[test]
    fn stereo_is_mixed_without_cross_frame_bleed() {
        let mono = interleaved_to_mono(&[1.0, -1.0, 0.25, 0.75], 2).expect("mix stereo");
        assert_eq!(mono, vec![0.0, 0.5]);
        assert!(interleaved_to_mono(&[1.0, 2.0, 3.0], 2).is_err());
    }

    #[test]
    fn resampler_is_bounded_and_preserves_constant_signal() {
        let input = vec![0.25_f32; 48_000];
        let output = resample_to_16khz(&input, 48_000).expect("resample");
        assert_eq!(output.len(), 16_000);
        assert!(
            output[100..15_900]
                .iter()
                .all(|sample| (*sample - 0.25).abs() < 0.001)
        );
        assert!(resample_to_16khz(&input, 192_000).is_err());
    }

    #[test]
    fn settings_are_versioned_owner_only_and_do_not_contain_audio() {
        let root = std::env::temp_dir().join(format!(
            "grok-voice-settings-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path = root.join(VOICE_SETTINGS_FILE);
        write_settings(&path, VoiceModel::Small).expect("write settings");
        assert_eq!(read_settings(&path), Some(VoiceModel::Small));
        let bytes = fs::read(&path).expect("read settings");
        assert!(!bytes.windows(5).any(|window| window == b"audio"));
        assert_eq!(
            fs::metadata(&path).expect("metadata").permissions().mode() & 0o077,
            0
        );
        fs::remove_dir_all(root).expect("cleanup settings");
    }

    #[test]
    fn transcript_contract_has_no_send_or_enqueue_field() {
        let transcript = VoiceTranscript {
            project_id: "project-1".into(),
            model: VoiceModel::Base,
            duration_milliseconds: 1000,
            text: "editable".into(),
        };
        let value = serde_json::to_value(transcript).expect("serialize transcript");
        assert_eq!(
            value.get("text").and_then(serde_json::Value::as_str),
            Some("editable")
        );
        assert!(value.get("send").is_none());
        assert!(value.get("enqueue").is_none());
    }

    #[test]
    #[ignore = "requires exact admitted base/small model and WAV fixtures outside the repository"]
    fn exact_models_transcribe_english_and_spanish_through_product_path() {
        let root = std::env::var_os("GROK_BUILD_VOICE_FIXTURE_ROOT")
            .map(PathBuf::from)
            .expect("set GROK_BUILD_VOICE_FIXTURE_ROOT to the admitted fixture directory");
        let assets = AssetManager::new(root.clone());

        let mut english = read_pcm16_mono_wav(&root.join("whisper-cpp-vcs/samples/jfk.wav"));
        let english_result = transcribe_samples(
            &assets,
            &mut english,
            16_000,
            1,
            "fixture-project".into(),
            VoiceModel::Base,
            11_000,
        )
        .expect("base English transcription");
        assert!(english.iter().all(|sample| *sample == 0.0));
        assert!(english_result.text.to_ascii_lowercase().contains("ask not"));

        let mut spanish = read_pcm16_mono_wav(&root.join("spanish.wav"));
        let spanish_result = transcribe_samples(
            &assets,
            &mut spanish,
            16_000,
            1,
            "fixture-project".into(),
            VoiceModel::Small,
            3_700,
        )
        .expect("small Spanish transcription");
        assert!(spanish.iter().all(|sample| *sample == 0.0));
        assert!(
            spanish_result
                .text
                .to_ascii_lowercase()
                .contains("transcripción local")
        );
    }

    #[test]
    #[ignore = "downloads the exact admitted 148 MB base model over fixed HTTPS"]
    fn exact_base_model_download_is_verified_before_atomic_promotion() {
        let root = std::env::temp_dir().join(format!(
            "grok-voice-download-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let assets = AssetManager::new(root.clone());
        let mut updates = 0_usize;
        let installed = assets
            .install(BASE_MODEL, |downloaded, total| {
                assert!(downloaded <= total);
                assert_eq!(total, BASE_MODEL.byte_len);
                updates += 1;
            })
            .expect("download and verify exact base model");
        assert!(installed.downloaded);
        assert!(updates > 1);
        assert!(
            assets
                .open_verified(BASE_MODEL)
                .expect("verify model")
                .is_some()
        );
        let entries = fs::read_dir(&root)
            .expect("list asset root")
            .collect::<Result<Vec<_>, _>>()
            .expect("read asset entries");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].file_name(), BASE_MODEL.filename);
        fs::remove_dir_all(root).expect("cleanup downloaded fixture");
    }
}
