"use strict";

const ACTIVE_PHASES = new Set([
  "verifying",
  "downloading",
  "requesting_permission",
  "recording",
  "transcribing",
]);

export function createVoiceInput({
  invoke,
  elements,
  getActiveProjectId,
  onError,
  onNotice,
  onRecordingStart = () => {},
  onTranscriptInserted = () => {},
}) {
  let view = null;
  let localBusy = false;
  let hostBusy = true;
  let pendingTranscript = "";

  elements.voiceModel.addEventListener("change", () => {
    void selectModel(elements.voiceModel.value);
  });
  elements.voiceInstall.addEventListener("click", () => {
    void installModel();
  });
  elements.voiceRecord.addEventListener("click", () => {
    if (view?.phase === "recording") void stopAndTranscribe();
    else void startRecording();
  });
  elements.voiceCancel.addEventListener("click", () => {
    void cancelRecording();
  });
  elements.voiceInsert.addEventListener("click", () => {
    if (insertTranscript(pendingTranscript)) {
      pendingTranscript = "";
      onTranscriptInserted();
      onNotice("Transcript ready");
      render();
    }
  });
  elements.voiceRefresh.addEventListener("click", () => {
    void refresh(false);
  });

  async function refresh(silent = true) {
    if (!invoke) return;
    try {
      view = await invoke("voice_status", {});
      render();
      if (!silent) onNotice("Voice status refreshed");
    } catch (error) {
      if (!silent) onError(message(error));
    }
  }

  async function selectModel(model) {
    if (!invoke || localBusy || ACTIVE_PHASES.has(view?.phase)) return;
    localBusy = true;
    render();
    try {
      view = await invoke("voice_select_model", { model });
      pendingTranscript = "";
      render();
    } catch (error) {
      onError(message(error));
      await refresh();
    } finally {
      localBusy = false;
      render();
    }
  }

  async function installModel() {
    if (!invoke || localBusy || ACTIVE_PHASES.has(view?.phase)) return;
    const model = elements.voiceModel.value;
    localBusy = true;
    view = {
      ...(view || {}),
      phase: "downloading",
      detail: "Downloading the exact model over pinned HTTPS…",
      progressBytes: 0,
      progressTotal: selectedModelView()?.expectedBytes || null,
    };
    render();
    try {
      view = await invoke("voice_install_model", { model });
      onNotice(`${modelLabel(model)} installed and verified`);
    } catch (error) {
      onError(message(error));
      await refresh();
    } finally {
      localBusy = false;
      render();
    }
  }

  async function startRecording() {
    if (!invoke || localBusy || hostBusy || !getActiveProjectId()) return;
    const selected = selectedModelView();
    if (!selected?.provisioned) {
      onError("Install the selected multilingual model before recording.");
      return;
    }
    onRecordingStart();
    localBusy = true;
    view = {
      ...(view || {}),
      phase: "requesting_permission",
      detail: "Waiting for the macOS microphone permission decision…",
    };
    render();
    try {
      view = await invoke("voice_start_recording", {});
      onNotice("Recording locally · Stop to create an editable transcript");
    } catch (error) {
      onError(message(error));
      await refresh();
    } finally {
      localBusy = false;
      render();
    }
  }

  async function stopAndTranscribe() {
    if (!invoke || localBusy || view?.phase !== "recording") return;
    const expectedProject = getActiveProjectId();
    localBusy = true;
    view = {
      ...view,
      phase: "transcribing",
      detail: "Transcribing locally. The result will remain editable.",
    };
    render();
    try {
      const transcript = await invoke("voice_stop_and_transcribe", {});
      if (!transcript || transcript.projectId !== expectedProject) {
        throw new Error("Voice transcript identity did not match the active project.");
      }
      if (!insertTranscript(transcript.text)) {
        pendingTranscript = transcript.text;
        onError("The draft has no room for the transcript. Clear space, then choose Insert transcript.");
      } else {
        pendingTranscript = "";
        onTranscriptInserted();
        onNotice("Transcript ready · not sent");
      }
      await refresh();
    } catch (error) {
      onError(message(error));
      await refresh();
    } finally {
      localBusy = false;
      render();
    }
  }

  async function cancelRecording() {
    if (!invoke || localBusy || view?.phase !== "recording") return;
    localBusy = true;
    render();
    try {
      view = await invoke("voice_cancel_recording", {});
      onNotice("Recording discarded from memory");
    } catch (error) {
      onError(message(error));
      await refresh();
    } finally {
      localBusy = false;
      render();
    }
  }

  function insertTranscript(text) {
    if (typeof text !== "string" || !text.trim()) return false;
    const draft = elements.chatDraft;
    const start = Number.isInteger(draft.selectionStart) ? draft.selectionStart : draft.value.length;
    const end = Number.isInteger(draft.selectionEnd) ? draft.selectionEnd : start;
    const before = draft.value.slice(0, start);
    const after = draft.value.slice(end);
    const prefix = before && !/\s$/.test(before) ? "\n" : "";
    const suffix = after && !/^\s/.test(after) ? "\n" : "";
    const insertion = `${prefix}${text.trim()}${suffix}`;
    const next = `${before}${insertion}${after}`;
    if (next.length > Number(draft.maxLength || 12000)) return false;
    draft.value = next;
    const cursor = before.length + insertion.length;
    draft.setSelectionRange(cursor, cursor);
    draft.dispatchEvent(new Event("input", { bubbles: true }));
    draft.focus();
    return true;
  }

  function handleProgress(progress) {
    if (!progress || progress.model !== view?.selectedModel) return;
    view = {
      ...(view || {}),
      phase: "downloading",
      progressBytes: progress.downloadedBytes,
      progressTotal: progress.totalBytes,
      detail: `Downloading ${formatBytes(progress.downloadedBytes)} of ${formatBytes(progress.totalBytes)}…`,
    };
    render();
  }

  function reset(snapshot) {
    hostBusy = !snapshot?.activeProjectId;
    render();
    if (!view) void refresh();
  }

  function setHostBusy(busy) {
    hostBusy = Boolean(busy);
    render();
  }

  function selectedModelView() {
    return Array.isArray(view?.models)
      ? view.models.find((model) => model.model === view.selectedModel)
      : null;
  }

  function render() {
    const phase = view?.phase || "idle";
    const selected = selectedModelView();
    const active = ACTIVE_PHASES.has(phase);
    const recording = phase === "recording";
    const permission = view?.permission || "unknown";
    if (view?.selectedModel && document.activeElement !== elements.voiceModel) {
      elements.voiceModel.value = view.selectedModel;
    }
    elements.voiceModel.disabled = localBusy || active;
    elements.voiceInstall.hidden = recording || phase === "transcribing" || phase === "requesting_permission";
    elements.voiceInstall.disabled = localBusy || active;
    elements.voiceInstall.textContent = selected?.provisioned
      ? (selected.verifiedThisRun ? "Model verified" : "Verify model")
      : `Install · ${formatBytes(selected?.expectedBytes || 0)}`;
    elements.voiceRecord.textContent = recording ? "Stop & transcribe" : "Record";
    elements.voiceRecord.setAttribute("aria-pressed", String(recording));
    elements.voiceRecord.disabled = localBusy
      || hostBusy
      || (!recording && active)
      || (!recording && !selected?.provisioned)
      || (!recording && ["denied", "restricted", "unknown"].includes(permission));
    elements.voiceCancel.hidden = !recording;
    elements.voiceCancel.disabled = localBusy || !recording;
    elements.voiceInsert.hidden = !pendingTranscript;
    elements.voiceInsert.disabled = localBusy || !pendingTranscript;
    elements.voiceRefresh.disabled = localBusy || active;
    elements.voiceStatus.textContent = voiceStatusText(view, selected);
    elements.voiceStatus.title = view?.detail || elements.voiceStatus.textContent;
    elements.voiceStatus.dataset.kind = view ? statusKind(phase, permission, selected) : "off";
    const total = Number(view?.progressTotal || 0);
    const current = Number(view?.progressBytes || 0);
    elements.voiceProgress.hidden = phase !== "downloading" || total <= 0;
    elements.voiceProgress.max = total > 0 ? total : 1;
    elements.voiceProgress.value = Math.min(total, Math.max(0, current));
  }

  function isRecording() {
    return view?.phase === "recording";
  }

  return { refresh, handleProgress, reset, setHostBusy, isRecording };
}

function voiceStatusText(view, selected) {
  if (!view) return "Checking…";
  const phase = view?.phase || "idle";
  const permission = view?.permission || "unknown";
  if (ACTIVE_PHASES.has(phase) || phase === "failed") {
    return view?.detail || "Working…";
  }
  if (["denied", "restricted", "unknown"].includes(permission)) {
    return view?.detail || "Microphone unavailable";
  }
  if (!selected?.provisioned) return "Not installed";
  return "Ready";
}

function statusKind(phase, permission, selected) {
  if (phase === "failed" || ["denied", "restricted", "unknown"].includes(permission)) return "error";
  if (["recording", "transcribing", "downloading", "verifying", "requesting_permission"].includes(phase)) return "active";
  if (permission === "authorized" && selected?.provisioned) return "ready";
  return "off";
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(bytes >= 100 * 1024 * 1024 ? 0 : 1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${bytes.toLocaleString()} B`;
}

function modelLabel(model) {
  return model === "small" ? "Multilingual small" : "Multilingual base";
}

function message(error) {
  return error instanceof Error ? error.message : String(error);
}
