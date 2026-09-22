"use strict";

import { collectElements } from "./modules/dom.js";
import { renderProjects } from "./modules/projects.js";
import {
  commandOutcomeSummary,
  outcomeClassIsRefusalOrError,
  projectName,
  securityWord,
  viewCopy,
} from "./modules/presentation.js";
import { createChatChanges } from "./modules/review.js";
import { createGitReview } from "./modules/git_review.js";
import { createDiagnostics } from "./modules/diagnostics.js";
import { createChatScheduling } from "./modules/queue.js";
import { activeSessionId } from "./modules/run_status.js";
import { createActivityTimeline } from "./modules/timeline.js";
import { createUsagePresentation } from "./modules/usage.js";
import { createTurnStatus } from "./modules/turn_status.js";
import { createWorkspaceBrowser } from "./modules/workspace.js";
import { createWorktreeManager } from "./modules/worktrees.js";
import { createInteractiveTerminal } from "./modules/terminal.js";
import { createVoiceInput } from "./modules/voice.js";
import { createReadAloud } from "./modules/read_aloud.js";
import { createBrowserControl } from "./modules/browser.js";
import { createCaptureControl } from "./modules/capture.js";
import { createDesktopControl } from "./modules/desktop.js";
import { createNotifications } from "./modules/notifications.js";
import { createCliChat } from "./modules/cli_chat.js";
import { createExtensions } from "./modules/extensions.js";
import { createMcpCallApprovals } from "./modules/mcp_approvals.js";
import { createMcpElicitation } from "./modules/mcp_elicitation.js";
import { createChildActivity } from "./modules/agents.js";
import { createWorkflowActivity } from "./modules/workflows.js";
import { createUpdates } from "./modules/updates.js";

const invoke = window.__TAURI__?.core?.invoke;
const appWindow = window.__TAURI__?.window?.getCurrentWindow?.();

const state = {
  currentView: "chat",
  lastContentView: "chat",
  snapshot: null,
  snapshotRevision: 0,
  busy: false,
  accountBusy: false,
  securityBusy: false,
  toastTimer: null,
  chatScrollTimer: null,
  streamingText: "",
  initialRouteApplied: false,
  highPower: {
    browser: { active: false, busy: false },
    capture: { active: false, busy: false },
    desktop: { active: false, busy: false },
  },
};

const elements = collectElements();
const updates = createUpdates({ invoke, elements, getSnapshot: () => state.snapshot,
  getBusy: () => state.busy || state.accountBusy, setAccountBusy, onSnapshot: applySnapshot });
const cliChat = createCliChat({ invoke, getSnapshot: () => state.snapshot, showToast });
createExtensions({ invoke, getSnapshot: () => state.snapshot, showToast });
createMcpCallApprovals({ invoke, getSnapshot: () => state.snapshot, showToast });
createMcpElicitation({ invoke, getSnapshot: () => state.snapshot, showToast });
const childActivity = createChildActivity({ invoke, getSnapshot: () => state.snapshot, onSnapshot: applySnapshot, showToast });
const workflowActivity = createWorkflowActivity({ invoke, getSnapshot: () => state.snapshot });
let browserSurface = "browser";
const BOOT_MINIMUM_MS = 500;
const bootStartedAt = performance.now();
let finishBootPromise = null;

function finishBoot() {
  finishBootPromise ??= (async () => {
    await document.fonts?.ready;
    await Promise.race([
      new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))),
      new Promise((resolve) => window.setTimeout(resolve, 100)),
    ]);
    const remainingMs = BOOT_MINIMUM_MS - (performance.now() - bootStartedAt);
    if (remainingMs > 0) await new Promise((resolve) => window.setTimeout(resolve, remainingMs));
    document.body.classList.remove("is-booting");
    elements.bootOverlay.hidden = true;
    elements.shell.setAttribute("aria-busy", "false");
  })();
  return finishBootPromise;
}

elements.chatCanvas.addEventListener("scroll", () => {
  elements.chatCanvas.classList.add("is-scrolling");
  window.clearTimeout(state.chatScrollTimer);
  state.chatScrollTimer = window.setTimeout(() => elements.chatCanvas.classList.remove("is-scrolling"), 700);
}, { passive: true });

function setBrowserSurface(surface) {
  if (!["browser", "capture", "desktop"].includes(surface)) return;
  if (browserSurface === "browser" && surface !== "browser") void browserControl?.releaseUserControl?.();
  browserSurface = surface;
  document.querySelectorAll("[data-browser-surface-button]").forEach((button) => {
    button.setAttribute("aria-selected", String(button.dataset.browserSurfaceButton === surface));
  });
  document.querySelectorAll("[data-browser-surface-panel]").forEach((panel) => {
    panel.hidden = panel.dataset.browserSurfacePanel !== surface;
  });
}

document.querySelectorAll("[data-tauri-drag-region]").forEach((region) => {
  region.addEventListener("pointerdown", (event) => {
    if (event.button !== 0 || event.target.closest("button, input, textarea, select, a")) return;
    void appWindow?.startDragging?.();
  });
});

document.querySelectorAll("[data-resize-direction]").forEach((handle) => {
  handle.addEventListener("pointerdown", (event) => {
    if (event.button !== 0) return;
    event.preventDefault();
    void appWindow?.startResizeDragging?.(handle.dataset.resizeDirection);
  });
});
let readAloud = null;
const workspaceBrowser = createWorkspaceBrowser({
  invoke,
  elements,
  onError(message) {
    showToast(message, true);
  },
});
const worktreeManager = createWorktreeManager({
  invoke,
  elements,
  onSnapshot(snapshot) {
    applySnapshot(snapshot);
  },
  onError(message) {
    showToast(message, true);
  },
  onNotice(message) {
    showToast(message);
  },
});
const captureControl = createCaptureControl({
  invoke,
  elements,
  getActiveProjectId() {
    return state.snapshot?.activeProjectId || null;
  },
  onError(message) {
    showToast(message, true);
  },
  onNotice(message) {
    showToast(message);
  },
  onCapabilityState(name, active, busy) {
    setHighPowerState(name, active, busy);
  },
});
const desktopControl = createDesktopControl({
  invoke,
  elements,
  getActiveProjectId() {
    return state.snapshot?.activeProjectId || null;
  },
  onError(message) {
    showToast(message, true);
  },
  onNotice(message) {
    showToast(message);
  },
  onCapabilityState(name, active, busy) {
    setHighPowerState(name, active, busy);
  },
});

elements.globalCapabilityStop.addEventListener("click", () => void stopHighPowerCapabilities());

function setHighPowerState(name, active, busy) {
  if (!state.highPower[name]) return;
  state.highPower[name] = { active: Boolean(active), busy: Boolean(busy) };
  renderHighPowerStop();
}

function renderHighPowerStop() {
  const active = Object.entries(state.highPower).filter(([, value]) => value.active);
  elements.globalCapabilityStop.hidden = active.length === 0;
  elements.globalCapabilityStop.disabled = false;
  const names = active.map(([name]) => name === "desktop" ? "Desktop Control" : `${name[0].toUpperCase()}${name.slice(1)}`);
  elements.globalCapabilityStop.textContent = names.length > 1
    ? "Stop all"
    : (names.length === 1 ? `Stop ${names[0]}` : "Stop capabilities");
  elements.globalCapabilityStop.setAttribute(
    "aria-label",
    names.length ? `Stop ${names.join(" and ")}` : "Stop high-power capabilities",
  );
}

async function stopHighPowerCapabilities() {
  void readAloud?.stop();
  const stops = [];
  if (state.highPower.browser.active) stops.push(browserControl.stop());
  if (state.highPower.capture.active) stops.push(captureControl.stop());
  if (state.highPower.desktop.active) stops.push(desktopControl.stop());
  await Promise.allSettled(stops);
}
const gitReview = createGitReview({
  invoke,
  elements,
  onSnapshot(snapshot) {
    applySnapshot(snapshot);
  },
  onError(message) {
    showToast(message, true);
  },
  onNotice(message) {
    showToast(message);
  },
  onBusy(busy) {
    setBusy(busy);
  },
  onAdd() {
    setView("workspace-browser");
    void worktreeManager.openGitSetup();
  },
});
createDiagnostics({
  invoke,
  elements,
  onBusy(busy) {
    setBusy(busy);
  },
  onError(message) {
    showToast(message, true);
  },
  onNotice(message) {
    showToast(message);
  },
  onCapabilityState(name, active, busy) {
    setHighPowerState(name, active, busy);
  },
});
const chatScheduling = createChatScheduling({
  invoke,
  elements,
  onSnapshot(snapshot) {
    applySnapshot(snapshot);
  },
  onBusy(busy) {
    setBusy(busy);
  },
  onError(message) {
    showToast(message, true);
  },
  onNotice(message) {
    showToast(message);
  },
});
const chatChanges = createChatChanges({
  elements,
  onAccept(binding) {
    void runCommand("accept_all_scoped", binding, "Accepted all pending changes");
  },
  onReject(binding) {
    void runCommand("reject_all_scoped", binding, "Removed all pending changes");
  },
});
const activityTimeline = createActivityTimeline({ elements });
const usagePresentation = createUsagePresentation({ elements });
const turnStatus = createTurnStatus({
  elements,
  onChange(presentation) {
    chatScheduling.setRunPresentation(presentation);
  },
});
const interactiveTerminal = createInteractiveTerminal({
  invoke,
  elements,
  onError(message) {
    showToast(message, true);
  },
  onNotice(message) {
    showToast(message);
  },
});
const voiceInput = createVoiceInput({
  invoke,
  elements,
  getActiveProjectId() {
    return state.snapshot?.activeProjectId || null;
  },
  onError(message) {
    showToast(message, true);
  },
  onNotice(message) {
    showToast(message);
  },
  onRecordingStart() {
    void readAloud?.stop();
  },
  onTranscriptInserted() {
    setView("chat");
  },
});
readAloud = createReadAloud({
  invoke,
  elements,
  isVoiceRecording() {
    return voiceInput.isRecording();
  },
  onError(message) {
    showToast(message, true);
  },
  onNotice(message) {
    showToast(message);
  },
  onMessagesRendered() {
    chatChanges.reattach();
  },
  onConnectRequested() {
    setView("account");
    showToast("Connect Account to use Auto-read.");
  },
});
const browserControl = createBrowserControl({
  invoke,
  elements,
  getActiveProjectId() {
    return state.snapshot?.activeProjectId || null;
  },
  onError(message) {
    showToast(message, true);
  },
  onNotice(message) {
    showToast(message);
  },
  onCapabilityState(name, active, busy) {
    setHighPowerState(name, active, busy);
  },
});
const notificationCenter = createNotifications({
  invoke,
  elements,
  onSnapshot(snapshot) {
    applySnapshot(snapshot);
  },
  async onNavigate(record) {
    if (record.projectId && record.projectId !== state.snapshot?.activeProjectId) {
      await runCommand("switch_project", { id: record.projectId });
    }
    const baseSession = `project-${record.projectId}`;
    if (record.sessionId === baseSession && state.snapshot?.workspaceRef?.worktreeId) {
      await runCommand("activate_workspace", { worktreeId: null });
    } else if (record.sessionId?.startsWith(`${baseSession}-worktree-`)) {
      const worktreeId = record.sessionId.slice(`${baseSession}-worktree-`.length);
      if (state.snapshot?.workspaceRef?.worktreeId !== worktreeId) {
        await runCommand("activate_workspace", { worktreeId });
      }
    }
    setView(record.category === "checks" ? "checks" : "chat");
  },
  onError(message) {
    showToast(message, true);
  },
});

function updateSecurityToggleAccessibility() {
  const showingChecks = state.currentView === "checks";
  const word = securityWord(state.snapshot?.security.kind);
  const returnLabel = viewCopy[state.lastContentView]?.label || "Chat";
  document.querySelectorAll("[data-security-toggle]").forEach((button) => {
    const label = showingChecks
      ? `Return to ${returnLabel}`
      : `Show command security checks: ${word}`;
    button.setAttribute("aria-label", label);
    button.setAttribute("aria-pressed", String(showingChecks));
    button.title = label;
  });
}

function setView(view) {
  if (!viewCopy[view]) return;
  if (state.currentView === "browser" && view !== "browser") void browserControl.releaseUserControl();
  if (view === "checks" && state.currentView !== "checks") {
    state.lastContentView = state.currentView;
  } else if (view !== "checks") {
    state.lastContentView = view;
  }
  state.currentView = view;
  elements.routeLabel.textContent = viewCopy[view].label;
  document.querySelectorAll("[data-view]").forEach((button) => {
    const selected = button.dataset.view === view;
    button.classList.toggle("is-selected", selected);
    if (selected) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  });
  document.querySelectorAll("[data-view-panel]").forEach((panel) => {
    panel.classList.toggle("is-active", panel.dataset.viewPanel === view);
  });
  if (view === "workspace-browser") {
    void workspaceBrowser.ensureRoot();
    void worktreeManager.ensure();
  } else if (view === "review") {
    void gitReview.ensure();
  } else if (view === "terminal") {
    interactiveTerminal.onViewShown();
  } else if (view === "browser") {
    browserControl.onViewShown();
    captureControl.onViewShown();
    desktopControl.onViewShown();
  } else if (view === "account") {
    void updates.refresh();
  }
  updateSecurityToggleAccessibility();
}

function setBusy(busy) {
  state.busy = busy;
  elements.shell.setAttribute("aria-busy", String(busy));
  document.documentElement.classList.toggle("is-busy", busy);
  document.querySelectorAll("button, input, textarea").forEach((control) => {
    if (control.dataset.view || control.dataset.viewJump || control.dataset.busyAllowed !== undefined) return;
    control.disabled = busy;
  });
  workspaceBrowser.setHostBusy(busy || !state.snapshot?.folderPath);
  worktreeManager.setHostBusy(busy || !state.snapshot?.folderPath);
  gitReview.setHostBusy(busy || !state.snapshot?.folderPath);
  chatScheduling.setHostBusy(busy);
  interactiveTerminal.setHostBusy(busy || !state.snapshot?.folderPath);
  voiceInput.setHostBusy(busy || !state.snapshot?.folderPath);
  readAloud.setHostBusy(busy);
  browserControl.setHostBusy(busy || !state.snapshot?.folderPath);
  captureControl.setHostBusy(busy || !state.snapshot?.folderPath);
  desktopControl.setHostBusy(busy || !state.snapshot?.folderPath);
  if (!busy) updateControlAvailability();
}

function setAccountBusy(busy) {
  state.accountBusy = busy;
  document.querySelectorAll("[data-account-action], [data-transport]").forEach((control) => {
    control.disabled = busy;
  });
  if (!busy) updateControlAvailability();
}

function setSecurityBusy(busy, activeControl = null) {
  state.securityBusy = busy;
  elements.terminalCommand.disabled = busy;
  document.querySelectorAll("[data-security-action]").forEach((control) => {
    control.disabled = busy;
    control.setAttribute("aria-busy", String(busy && control === activeControl));
  });
  if (!busy) updateControlAvailability();
}

function updateControlAvailability() {
  updates.render();
  if (!state.snapshot) return;
  const bound = Boolean(state.snapshot.folderPath);
  const account = state.snapshot.account;
  elements.sendButton.disabled = !bound;
  elements.sendMenuToggle.disabled = !bound;
  elements.sendNext.disabled = !bound;
  elements.chatDraft.disabled = !bound;
  const canRunCommands = state.snapshot.security.canRunCommands === true;
  elements.terminalCommand.disabled = !bound || state.securityBusy || !canRunCommands;
  elements.terminalRun.disabled = !bound || state.securityBusy || !canRunCommands;
  elements.runContained.disabled = state.securityBusy || state.snapshot.security.kind === "setting-up" || (canRunCommands && !bound);
  elements.commandSecurityOff.disabled = state.securityBusy;
  const selected = account.selectedTransport;
  const keychainPresence = account.keychainPresence?.state;
  const keychainCanAttempt = keychainPresence
    ? keychainPresence !== "absent"
    : account.keychainConfigured;
  const selectedAvailable = selected === "XaiKeychain"
    ? keychainCanAttempt
    : account.cliAvailable;
  elements.accountRefresh.disabled = state.accountBusy || !selectedAvailable;
  elements.accountDisconnect.disabled = state.accountBusy || account.connection?.state === "disconnected";
  elements.loginGrokCli.disabled = state.accountBusy || account.connected
    && selected === "GrokCliAcp";
  elements.configureXaiKey.disabled = state.accountBusy || account.connected
    && selected === "XaiKeychain";
  elements.replaceXaiKey.disabled = state.accountBusy || !account.keychainConfigured;
  elements.deleteXaiKey.disabled = state.accountBusy || !account.keychainConfigured;
  workspaceBrowser.setHostBusy(state.busy || !bound);
  worktreeManager.setHostBusy(state.busy || !bound);
  gitReview.setHostBusy(state.busy || !bound);
  chatScheduling.setHostBusy(state.busy);
  interactiveTerminal.setHostBusy(state.busy || !bound);
  voiceInput.setHostBusy(state.busy || !bound);
  readAloud.setHostBusy(state.busy);
  browserControl.setHostBusy(state.busy || !bound);
  captureControl.setHostBusy(state.busy || !bound);
  desktopControl.setHostBusy(state.busy || !bound);
  elements.chatDraft.placeholder = bound
    ? "Ask about the project or describe a change…"
    : "Bind a project folder first…";
  elements.terminalCommand.placeholder = bound
    ? "pwd"
    : "Bind a project folder first…";
}

function showToast(message, error = false) {
  window.clearTimeout(state.toastTimer);
  elements.toastMessage.textContent = String(message);
  elements.toast.classList.toggle("is-error", error);
  elements.toast.hidden = false;
  state.toastTimer = window.setTimeout(() => {
    elements.toast.hidden = true;
  }, error ? 6500 : 3200);
}

function setAccountOnboardingStatus(phase, status, detail, sanitizedLog) {
  elements.accountOnboardingStatus.dataset.phase = phase;
  elements.accountOnboardingStatus.dataset.pending = String(
    ["connecting", "opening_browser", "waiting_for_sign_in", "verifying"].includes(phase),
  );
  elements.accountOnboardingStatusTitle.textContent = status;
  elements.accountOnboardingStatusDetail.textContent = detail;
  if (typeof sanitizedLog === "string" && sanitizedLog.trim() !== "") {
    elements.accountCliDetailsOutput.textContent = sanitizedLog;
  }
}

async function runConnectionCommand(command, payload = {}) {
  if (!invoke || state.accountBusy) return null;
  setAccountBusy(true);
  setAccountOnboardingStatus("connecting", "Connecting…", "Checking your account.");
  elements.accountChip.textContent = "Connecting…";
  elements.accountChip.dataset.connected = "false";
  elements.accountChip.dataset.state = "probing";
  await new Promise((resolve) => window.requestAnimationFrame(resolve));
  try {
    const snapshot = await invoke(command, payload);
    applySnapshot(snapshot);
    return snapshot;
  } catch (error) {
    try { applySnapshot(await invoke("bootstrap", {})); } catch {}
    showToast(error instanceof Error ? error.message : String(error), true);
    return null;
  } finally {
    setAccountBusy(false);
  }
}

async function runSecurityCommand(command, payload, activeControl) {
  if (!invoke || state.securityBusy) return null;
  setSecurityBusy(true, activeControl);
  try {
    const snapshot = await invoke(command, payload);
    applySnapshot(snapshot);
    return snapshot;
  } catch (error) {
    try { applySnapshot(await invoke("bootstrap", {})); } catch {}
    showToast(error instanceof Error ? error.message : String(error), true);
    return null;
  } finally {
    setSecurityBusy(false);
  }
}

function reconnectDetail(account) {
  const reconnect = account.reconnectState || { state: "needs_connection" };
  switch (reconnect.state) {
    case "disabled":
      return "Automatic reconnect is Off. Credentials remain in their owning store.";
    case "active": {
      const expiry = new Date(Number(reconnect.expiresAtUtcMs));
      return `Authorized for ${account.selectedTransport} until ${expiry.toLocaleString()}. Background connection checks never extend this time.`;
    }
    case "expired":
      return "The fixed seven-day window expired. Connect explicitly to authorize a new window.";
    case "binding_required":
      return "API-key reconnect needs one verified migration to the stable Keychain broker.";
    case "reconnecting":
      return `Reconnecting through ${reconnect.transport || account.selectedTransport}… Connected remains false until the live connection check passes.`;
    case "suspended_for_lock":
      return "Credentials and active adapters are suspended while macOS is locked.";
    default:
      return "Connect explicitly once to start a fixed seven-day reconnect window.";
  }
}

async function runCommand(command, payload, successMessage) {
  if (!invoke) {
    showToast("Tauri IPC is unavailable in this window.", true);
    return null;
  }
  if (state.busy) return null;
  setBusy(true);
  try {
    const snapshot = await invoke(command, cliChat.prepareInput(command, payload));
    cliChat.inputSent(command);
    applySnapshot(snapshot);
    if (successMessage) showToast(successMessage);
    return snapshot;
  } catch (error) {
    try {
      const current = await invoke("bootstrap", {});
      applySnapshot(current);
    } catch {
      // Preserve the original command failure; bootstrap recovery is best effort.
    }
    showToast(error instanceof Error ? error.message : String(error), true);
    return null;
  } finally {
    setBusy(false);
  }
}

function applySnapshot(snapshot) {
  const revision = Number(snapshot?.snapshotRevision || 0);
  if (revision && revision < state.snapshotRevision) return;
  state.snapshotRevision = Math.max(state.snapshotRevision, revision);
  const previousSnapshot = state.snapshot;
  const previousRoot = state.snapshot?.folderPath || null;
  state.snapshot = snapshot;
  const kind = snapshot.security.kind;
  const word = securityWord(kind);
  const hasChat = (snapshot.chat.trim() !== "" && snapshot.chat !== "No chat yet.")
    || snapshot.staged.length > 0
    || chatScheduling.hasPendingTurns(snapshot);
  const bound = Boolean(snapshot.folderPath);
  const account = snapshot.account ?? {
    connected: false,
    cliAvailable: false,
    keychainConfigured: false,
    keychainPresence: { state: "unchecked" },
    onboardingAcknowledged: false,
    autoReconnectEnabled: true,
    reconnectState: { state: "needs_connection" },
    keychainMigrationState: { state: "unchecked" },
    preferenceIssue: null,
    selectedTransport: "GrokCliAcp",
    connection: { state: "disconnected" },
    status: "Not connected",
    detail: "No live Chat transport has been verified.",
    cliPath: null,
  };
  const activeProjectName = projectName(
    snapshot.workspaceRef?.sourceRoot || snapshot.folderPath,
  );
  const activeWorkspaceLabel = snapshot.workspaceRef?.worktreeTask
    ? `${activeProjectName} · ${snapshot.workspaceRef.worktreeTask}`
    : activeProjectName;
  if (previousRoot !== (snapshot.folderPath || null)) {
    workspaceBrowser.reset(snapshot.folderPath || null);
  }
  worktreeManager.reset(snapshot);
  gitReview.reset(snapshot);
  chatScheduling.render(snapshot);
  activityTimeline.render(snapshot.timeline, snapshot.activeProjectId);
  usagePresentation.render(snapshot.usage);
  turnStatus.renderSnapshot(snapshot);
  interactiveTerminal.reset(snapshot);
  voiceInput.reset(snapshot);
  browserControl.reset(snapshot);
  captureControl.reset(snapshot);
  desktopControl.reset(snapshot);
  notificationCenter.render(snapshot);

  elements.versionLabel.textContent = `v${snapshot.version}`;
  elements.sidebarProject.textContent = activeWorkspaceLabel;
  elements.sidebarProject.title = snapshot.folderPath || "No active project";
  elements.sidebarSecurityDot.dataset.kind = kind;
  elements.sidebarSecurityLabel.textContent = "Command security";
  elements.securityMini.dataset.kind = kind;

  elements.projectStateTitle.textContent = bound ? activeProjectName : "No folder bound";
  elements.projectStateCopy.textContent = snapshot.folderStatus;
  if (document.activeElement !== elements.folderPath) {
    elements.folderPath.value = snapshot.folderPath || "";
  }
  renderProjects(elements, snapshot.projects ?? [], {
    switchProject(project) {
      void readAloud.stop();
      void runCommand("switch_project", { id: project.id }, `Switched to ${project.name}`);
    },
    removeProject(project) {
      void runCommand(
        "remove_project",
        { id: project.id },
        `Removed ${project.name} from the list · files untouched`,
      );
    },
  });

  elements.welcomeState.hidden = hasChat;
  elements.welcomeBindProject.hidden = bound;
  elements.transcript.hidden = !hasChat;
  readAloud.handleSnapshot(snapshot, previousSnapshot);
  chatChanges.render(snapshot.staged, state.busy);
  childActivity.render(snapshot);
  workflowActivity.render(snapshot);
  cliChat.snapshot(snapshot);
  elements.composerContext.textContent = bound ? activeWorkspaceLabel : "Bind a folder to start";
  elements.composerContext.title = snapshot.folderPath || "";
  elements.composerContextDot.classList.toggle("is-bound", bound);

  elements.securityStatus.textContent = snapshot.security.status;
  elements.securityStatus.dataset.kind = kind;
  elements.securityChip.textContent = word;
  elements.securityChip.dataset.kind = kind;
  elements.securityCopy.textContent = snapshot.security.copy;
  elements.securityDetails.textContent = snapshot.security.details;
  elements.runContained.textContent = snapshot.security.actionLabel || "Check for Container";
  elements.commandSecurityOff.hidden = snapshot.security.enabled !== true;
  elements.terminalForm.hidden = snapshot.security.canRunCommands !== true;
  elements.commandOutcomePanel.hidden = snapshot.security.canRunCommands !== true;
  elements.commandOutcomeSummary.textContent = commandOutcomeSummary(snapshot.commandOutcomeClass);
  elements.commandOutcome.textContent = snapshot.commandOutcome;
  elements.commandOutcome.classList.toggle(
    "is-refusal",
    outcomeClassIsRefusalOrError(snapshot.commandOutcomeClass),
  );

  elements.accountStatus.textContent = account.status;
  elements.engineMode.value = account.engine?.mode || "gbPlusContained";
  elements.engineDescription.textContent = account.engine?.mode === "grokCliStandard"
    ? "Uses your Grok CLI and shares its sessions and settings with Terminal."
    : "Uses GB Plus’s existing contained connection.";
  elements.accountChip.textContent = account.status;
  elements.accountChip.dataset.connected = String(account.connected);
  elements.accountChip.dataset.state = account.connection?.state || "disconnected";
  elements.accountDetail.textContent = account.detail;
  elements.accountDisconnect.hidden = !account.connected;
  elements.accountAutoReconnect.checked = account.autoReconnectEnabled !== false;
  elements.accountReconnectDetail.textContent = reconnectDetail(account);
  elements.accountCliPath.textContent = account.cliPath || "Not found";
  elements.accountCliPath.title = account.cliPath || "The grok CLI was not found";
  elements.accountMissing.hidden = account.cliAvailable;
  const keychainState = account.keychainPresence?.state;
  const migrationState = account.keychainMigrationState?.state;
  elements.keychainStatus.textContent = migrationState === "legacy_only"
    ? "Saved API key · one-time migration required"
    : migrationState === "cleanup_pending"
      ? "Saved API key · verified cleanup required"
      : migrationState === "stable_v2"
        ? "Saved API key · one-time stable broker migration required"
        : migrationState === "broker_v3"
          ? "xAI key stored in macOS Keychain · stable broker v3"
          : keychainState === "present"
            ? "xAI key stored in macOS Keychain"
            : keychainState === "unavailable"
              ? "Keychain status unavailable · Connect checks explicitly"
              : keychainState === "unchecked" ? "API key not checked" : "No xAI key stored";
  elements.keychainStatus.title = keychainState === "unavailable"
    ? account.keychainPresence.reason || "Keychain status could not be inspected without interaction"
    : "";
  const hasSavedKey = keychainState === "present"
    || (keychainState !== "absent" && Boolean(account.keychainBrokerSha256));
  const xaiConnected = account.connected && account.selectedTransport === "XaiKeychain";
  elements.configureXaiKey.textContent = xaiConnected
    ? "Connected" : hasSavedKey ? "Connect with saved API key" : "Connect with API key";
  elements.replaceXaiKey.hidden = !hasSavedKey;
  const cliConnected = account.connected && account.selectedTransport === "GrokCliAcp";
  elements.loginGrokCli.textContent = cliConnected ? "Connected" : "Connect with Grok Subscription";
  if (account.connected) {
    elements.loginGrokCli.dataset.connectionRole = account.selectedTransport === "GrokCliAcp"
      ? "connected"
      : "alternate";
    elements.configureXaiKey.dataset.connectionRole = account.selectedTransport === "XaiKeychain"
      ? "connected"
      : "alternate";
  } else {
    delete elements.loginGrokCli.dataset.connectionRole;
    delete elements.configureXaiKey.dataset.connectionRole;
  }
  const friendlyTransport = account.selectedTransport === "XaiKeychain"
    ? "API key"
    : "Grok Subscription";
  elements.accountTransportCopy.textContent = `${friendlyTransport} selected.`;
  document.querySelectorAll("[data-transport]").forEach((button) => {
    const selected = button.dataset.transport === account.selectedTransport;
    button.classList.toggle("is-selected", selected);
    button.setAttribute("aria-checked", String(selected));
  });
  elements.aboutVersion.textContent = `Version ${snapshot.version}`;
  elements.aboutRuntime.textContent = `Tauri ${snapshot.tauriVersion}`;
  const activeRun = snapshot.queue?.runs?.find((run) => (
    run.projectId === snapshot.activeProjectId
    && ["running", "stop_requested"].includes(run.state)
  ));
  const stopRequested = activeRun?.state === "stop_requested";
  elements.cancelChat.hidden = !activeRun;
  elements.cancelChat.disabled = stopRequested;
  elements.cancelChat.setAttribute(
    "aria-label",
    stopRequested ? "Stopping agent run" : "Stop agent run",
  );
  elements.cancelChat.title = stopRequested ? "Stopping…" : "Stop";

  if (account.reconnectState?.state === "reconnecting") {
    setAccountOnboardingStatus(
      "verifying",
      "Connecting…",
      `Verifying the selected ${account.selectedTransport} Chat path.`,
    );
  } else if (account.connection?.state === "connected") {
    setAccountOnboardingStatus("connected", "Connected", account.detail);
  } else if (account.connection?.state === "failed") {
    setAccountOnboardingStatus("failed", "Connection failed", account.detail);
  } else if (account.connection?.state === "probing") {
    setAccountOnboardingStatus("verifying", "Connecting…", account.detail);
  } else if (!account.onboardingAcknowledged && hasSavedKey) {
    setAccountOnboardingStatus(
      "idle",
      "Saved API key found",
      "Connect with the saved API key. The key stays in macOS Keychain and is read only after you choose Connect.",
    );
  } else {
    setAccountOnboardingStatus(
      "idle",
      "Not connected",
      "Choose a connection method when you are ready to use Chat.",
    );
  }

  state.streamingText = "";
  updateControlAvailability();
  updateSecurityToggleAccessibility();
  elements.shell.setAttribute("aria-busy", "false");
  if (state.currentView === "workspace-browser") void workspaceBrowser.ensureRoot();
  state.initialRouteApplied = true;
}

async function chooseAndBindProjectFolder(allowCreate) {
  if (!invoke) {
    showToast("The native folder picker is unavailable outside the Tauri host.", true);
    return;
  }
  if (state.busy) return;
  setBusy(true);
  try {
    const path = await invoke("choose_project_folder", { allowCreate });
    if (!path) return;
    elements.folderPath.value = path;
    const snapshot = await invoke("bind_project", { path });
    applySnapshot(snapshot);
    showToast(allowCreate ? "Project folder selected and added" : "Project added and activated");
  } catch (error) {
    showToast(error instanceof Error ? error.message : String(error), true);
  } finally {
    setBusy(false);
  }
}

document.querySelectorAll("[data-view]").forEach((button) => {
  button.addEventListener("click", () => setView(button.dataset.view));
});

document.querySelectorAll("[data-view-jump]").forEach((button) => {
  button.addEventListener("click", () => setView(button.dataset.viewJump));
});

document.querySelectorAll("[data-browser-surface-button]").forEach((button) => {
  button.addEventListener("click", () => setBrowserSurface(button.dataset.browserSurfaceButton));
});

document.querySelectorAll("[data-browser-surface-jump]").forEach((button) => {
  button.addEventListener("click", () => setBrowserSurface(button.dataset.browserSurfaceJump));
});

document.querySelectorAll("[data-security-toggle]").forEach((button) => {
  button.addEventListener("click", () => {
    setView(state.currentView === "checks" ? state.lastContentView : "checks");
  });
});

elements.chooseFolder.addEventListener("click", () => {
  void chooseAndBindProjectFolder(false);
});

elements.createFolder.addEventListener("click", () => {
  void chooseAndBindProjectFolder(true);
});

elements.folderForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void runCommand("bind_project", { path: elements.folderPath.value }, "Project added and activated");
});

elements.chatForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await readAloud.stop();
  const message = elements.chatDraft.value.trim();
  if (!message) return;
  if (!state.snapshot?.account?.connected) {
    setView("account");
    showToast("Connect Account before sending a message", true);
    return;
  }
  const approval = pendingDecision(message);
  if (approval?.decision) {
    const snapshot = await runCommand(
      approval.decision === "accept" ? "accept_all_scoped" : "reject_all_scoped",
      approval.binding,
      approval.decision === "accept" ? "Accepted all pending changes" : "Removed all pending changes",
    );
    if (snapshot) clearChatDraft();
    return;
  }
  if (approval) {
    showToast(approval.reason, true);
    return;
  }
  state.streamingText = "";
  const activeRun = chatScheduling.activeRun();
  const snapshot = activeRun
    ? await runCommand("send_now", {
      message,
      projectId: activeRun.projectId,
      sessionId: activeRun.sessionId,
      runId: activeRun.id,
    })
    : await runCommand("send_chat", { message });
  if (snapshot) {
    clearChatDraft();
    const awaitingApproval = snapshot.queue?.reviewBlockedProjectIds?.includes(snapshot.activeProjectId);
    showToast(activeRun ? "Will join this run at the next safe step" : awaitingApproval ? "Waiting" : "Message sent");
  }
});

function clearChatDraft() {
  elements.chatDraft.value = "";
  elements.chatDraft.style.height = "auto";
}

function pendingDecision(message) {
  const decision = message === "apply changes"
    ? "accept"
    : ["remove changes", "reject changes"].includes(message) ? "reject" : null;
  if (!decision) return null;
  const staged = state.snapshot?.staged || [];
  if (staged.length === 0) {
    return { reason: "No pending changes are available for this Chat." };
  }
  const binding = chatChanges.binding();
  if (!binding || binding.projectId !== state.snapshot?.activeProjectId) {
    return { reason: "Change approval refused because the active Chat identity is ambiguous." };
  }
  return { binding, decision };
}

elements.sendMenuToggle.addEventListener("click", () => {
  const opening = elements.sendMenu.hidden;
  elements.sendMenu.hidden = !opening;
  elements.sendMenuToggle.setAttribute("aria-expanded", String(opening));
});

elements.sendNext.addEventListener("click", async () => {
  await readAloud.stop();
  const message = elements.chatDraft.value.trim();
  const activeRun = chatScheduling.activeRun();
  if (!message || !activeRun) return;
  elements.sendMenu.hidden = true;
  elements.sendMenuToggle.setAttribute("aria-expanded", "false");
  const snapshot = await runCommand("send_next", { message, runId: activeRun.id });
  if (!snapshot) return;
  clearChatDraft();
  showToast("Will send after this run");
});

document.addEventListener("pointerdown", (event) => {
  if (elements.sendControl.contains(event.target)) return;
  elements.sendMenu.hidden = true;
  elements.sendMenuToggle.setAttribute("aria-expanded", "false");
});
elements.chatDraft.addEventListener("input", () => {
  elements.chatDraft.style.height = "auto";
  elements.chatDraft.style.height = `${Math.min(elements.chatDraft.scrollHeight, 126)}px`;
});
elements.chatDraft.addEventListener("keydown", (event) => {
  if (event.metaKey && event.key === "Enter") {
    event.preventDefault();
    elements.chatForm.requestSubmit();
  }
});

elements.terminalForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const commandLine = elements.terminalCommand.value;
  const snapshot = await runSecurityCommand("run_terminal", { commandLine }, elements.terminalRun);
  if (!snapshot) return;
  const failed = outcomeClassIsRefusalOrError(snapshot.commandOutcomeClass);
  showToast(failed ? "Command refused or failed · see Checks" : "Contained command finished", failed);
});
elements.runContained.addEventListener("click", async () => {
  const action = state.snapshot?.security.action || "check";
  const command = { check: "check_command_security_container", install: "install_command_security_container", setup: "configure_command_security", test: "run_contained_check" }[action];
  elements.runContained.textContent = action === "test" ? "Test contained run" : { check: "Checking...", install: "Installing...", setup: "Setting up..." }[action];
  const snapshot = await runSecurityCommand(command, action === "setup" ? { enabled: true } : {}, elements.runContained);
  if (snapshot) {
    const refused = outcomeClassIsRefusalOrError(snapshot.commandOutcomeClass);
    const installFailed = action === "install" && snapshot.security.actionFailed;
    const notice = action === "check" ? (snapshot.security.action === "install" ? "Colima is not installed" : "Container found") : action === "install" ? (installFailed ? "Colima install failed. Open Details." : "Colima installed") : action === "setup" ? (snapshot.security.kind === "on" ? "Command security is ready" : "Setup needs another step") : (refused ? "Contained run blocked" : "Contained run finished");
    showToast(notice, installFailed || (action === "test" && refused));
  }
});

elements.commandSecurityOff.addEventListener("click", async () => {
  const snapshot = await runSecurityCommand(
    "configure_command_security",
    { enabled: false },
    elements.commandSecurityOff,
  );
  if (snapshot) showToast("Command security turned off");
});

elements.accountRefresh.addEventListener("click", async () => {
  const snapshot = await runConnectionCommand("refresh_account");
  if (snapshot) showToast(`Account: ${snapshot.account.status}`);
});

elements.accountAutoReconnect.addEventListener("change", async () => {
  const enabled = elements.accountAutoReconnect.checked;
  const snapshot = await runCommand("set_auto_reconnect", { enabled });
  if (snapshot) {
    showToast(enabled
      ? (snapshot.account.connected
        ? "Seven-day reconnect window renewed"
        : "Automatic reconnect will start after the next explicit connection")
      : "Automatic reconnect disabled and its grant cleared");
  }
});

elements.resetProviderContext.addEventListener("click", async () => {
  const projectId = state.snapshot?.activeProjectId;
  const sessionId = activeSessionId(state.snapshot);
  if (!projectId || !sessionId) return showToast("Open a project chat first.", true);
  elements.resetProviderContext.disabled = true;
  try {
    applySnapshot(await invoke("reset_provider_context", { projectId, sessionId }));
    showToast("Provider context reset. Earlier Chat remains available.");
  } catch (error) { showToast(String(error), true); }
  finally { elements.resetProviderContext.disabled = false; }
});

elements.engineMode.addEventListener("change", async () => {
  const mode = elements.engineMode.value;
  const snapshot = await runCommand("set_engine_settings", {
    settings: { schemaVersion: 1, mode, developerCli: state.snapshot?.account.engine?.developerCli || null },
  });
  if (snapshot) showToast("Engine selected. Connect when ready.");
  else elements.engineMode.value = state.snapshot?.account.engine?.mode || "gbPlusContained";
});

elements.loginGrokCli.addEventListener("click", async () => {
  const account = state.snapshot?.account;
  const reconnect = account?.onboardingAcknowledged
    && account?.selectedTransport === "GrokCliAcp"
    && (account?.connection?.state !== "failed"
      || account?.reconnectState?.state === "active");
  const snapshot = await runConnectionCommand(reconnect ? "connect_account" : "login_grok_cli");
  if (snapshot) {
    showToast(
      snapshot.account.connected
        ? (reconnect
          ? "Grok Subscription connected"
          : "Grok Subscription sign-in complete")
        : snapshot.account.detail,
      !snapshot.account.connected,
    );
  }
});

document.querySelectorAll("[data-transport]").forEach((button) => {
  button.addEventListener("click", async () => {
    const transport = button.dataset.transport;
    const selected = await runCommand("select_transport", { transport });
    if (!selected) return;
    const command = transport === "XaiKeychain"
      ? "connect_saved_xai_key"
      : "connect_account";
    const snapshot = await runConnectionCommand(command);
    if (snapshot?.account?.connected) {
      showToast(transport === "GrokCliAcp" ? "Grok Subscription connected" : "API key connected");
    }
  });
});

elements.configureXaiKey.addEventListener("click", async () => {
  const wasConfigured = Boolean(state.snapshot?.account?.keychainConfigured);
  const account = state.snapshot?.account;
  const keychainState = account?.keychainPresence?.state;
  const hasSavedKey = keychainState === "present"
    || (keychainState !== "absent" && Boolean(account?.keychainBrokerSha256));
  const snapshot = await runConnectionCommand(
    hasSavedKey ? "connect_saved_xai_key" : "configure_xai_key",
  );
  if (!snapshot) return;
  if (snapshot.account.connected) {
    showToast(hasSavedKey
      ? "Saved API key live path verified"
      : "xAI key stored and live path verified");
  } else if (!wasConfigured && !snapshot.account.keychainConfigured) {
    showToast("Key entry cancelled");
  }
});

elements.replaceXaiKey.addEventListener("click", async () => {
  const snapshot = await runConnectionCommand("configure_xai_key");
  if (snapshot?.account?.connected) showToast("Replacement API key stored and live path verified");
});

elements.deleteXaiKey.addEventListener("click", () => {
  if (!window.confirm("Remove the GB Plus xAI key from macOS Keychain?")) return;
  void runCommand("delete_xai_key", {}, "xAI Keychain item removed");
});

elements.accountDisconnect.addEventListener("click", () => {
  void readAloud.stop();
  void runCommand("disconnect_account", {}, "Disconnected from the selected transport");
});

elements.cancelChat.addEventListener("click", async () => {
  await readAloud.stop();
  try {
    const snapshot = await invoke("cancel_chat", {});
    applySnapshot(snapshot);
    showToast("Stop requested");
  } catch (error) {
    showToast(error instanceof Error ? error.message : String(error), true);
  }
});

function applyRuntimeEvent(event, runId = null) {
  const update = event.payload;
  if (!update || typeof update !== "object") return;
  if (runId) turnStatus.handleRuntimeEvent(update, runId);
  cliChat.update(update, runId);
  if (update.kind === "assistant_delta" && typeof update.payload === "string") {
    if (!state.streamingText) void readAloud.stop();
    state.streamingText += update.payload;
    elements.welcomeState.hidden = true;
    elements.transcript.hidden = false;
    readAloud.renderStreaming(state.streamingText);
  }
  if (update.kind === "tool_refused") {
    showToast(update.payload?.reason || "Agent tool request refused", true);
  }
  if (update.kind === "error") {
    showToast(String(update.payload || "Runtime error"), true);
  }
  if (update.kind === "account_onboarding" && update.payload) {
    const payload = update.payload;
    setAccountOnboardingStatus(
      payload.phase || "idle",
      payload.status || "Not connected",
      payload.detail || "No additional detail was provided.",
      payload.sanitized_log ?? payload.sanitizedLog,
    );
  }
}

function applyWorkspaceEvent(event) {
  workspaceBrowser.handleEvent(event.payload);
}

function applyQueuedRuntimeEvent(event) {
  const envelope = event.payload;
  if (!envelope || envelope.projectId !== state.snapshot?.activeProjectId) return;
  applyRuntimeEvent({ payload: envelope.event }, envelope.runId);
  browserControl.handleAgentEvent(envelope.event);
}

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    elements.toast.hidden = true;
    elements.sendMenu.hidden = true;
    elements.sendMenuToggle.setAttribute("aria-expanded", "false");
  }
  if (event.metaKey && event.altKey && !event.ctrlKey && event.key.toLowerCase() === "l") {
    event.preventDefault();
    readAloud.speakLast();
    return;
  }
  if (event.metaKey && event.altKey && !event.ctrlKey && event.key === ".") {
    event.preventDefault();
    void readAloud.stop();
    return;
  }
  if (!event.metaKey || event.altKey || event.ctrlKey) return;
  const views = ["project", "chat", "workspace-browser", "terminal", "browser", "review", "activity", "checks", "account"];
  const index = Number.parseInt(event.key, 10) - 1;
  if (index >= 0 && index < views.length) {
    event.preventDefault();
    setView(views[index]);
  }
});

async function start() {
  setView("chat");
  if (!invoke) {
    showToast("This interface must run inside the GB Plus Tauri host.", true);
    return;
  }
  if (window.__TAURI__?.event?.listen) {
    try {
      await window.__TAURI__.event.listen("grok-build-plus-runtime-event", applyRuntimeEvent);
    } catch (error) {
      showToast(
        `Live runtime events are unavailable: ${error instanceof Error ? error.message : String(error)}`,
        true,
      );
    }
    try {
      await window.__TAURI__.event.listen("grok-build-plus-workspace-event", applyWorkspaceEvent);
    } catch (error) {
      showToast(
        `Workspace live refresh is unavailable: ${error instanceof Error ? error.message : String(error)}`,
        true,
      );
    }
    try {
      await window.__TAURI__.event.listen("grok-build-plus-queued-runtime-event", applyQueuedRuntimeEvent);
      await window.__TAURI__.event.listen("grok-build-plus-snapshot", (event) => {
        if (event.payload) applySnapshot(event.payload);
      });
    } catch (error) {
      showToast(
        `Queue live updates are unavailable: ${error instanceof Error ? error.message : String(error)}`,
        true,
      );
    }
    try {
      await window.__TAURI__.event.listen("grok-build-plus-activity-event", (event) => {
        activityTimeline.append(event.payload);
      });
    } catch (error) {
      showToast(
        `Activity live updates are unavailable: ${error instanceof Error ? error.message : String(error)}`,
        true,
      );
    }
    try {
      await window.__TAURI__.event.listen("grok-build-plus-pty-event", (event) => {
        interactiveTerminal.handleEvent(event.payload);
      });
    } catch (error) {
      showToast(
        `Interactive Terminal updates are unavailable: ${error instanceof Error ? error.message : String(error)}`,
        true,
      );
    }
    try {
      await window.__TAURI__.event.listen("grok-build-plus-voice-event", (event) => {
        voiceInput.handleProgress(event.payload);
      });
    } catch (error) {
      showToast(
        `Voice progress updates are unavailable: ${error instanceof Error ? error.message : String(error)}`,
        true,
      );
    }
    try {
      await window.__TAURI__.event.listen("grok-build-plus-browser-event", (event) => {
        browserControl.handleProgress(event.payload);
      });
    } catch (error) {
      showToast(
        `Browser progress updates are unavailable: ${error instanceof Error ? error.message : String(error)}`,
        true,
      );
    }
  }
  let initial = null;
  try {
    initial = await invoke("bootstrap", {});
    applySnapshot(initial);
  } catch (error) {
    showToast(`Startup failed: ${error instanceof Error ? error.message : String(error)}`, true);
  } finally {
    await finishBoot();
  }
  if (initial?.account?.connection?.state === "disconnected"
    && initial?.account?.reconnectState?.state === "active") {
    void runConnectionCommand("reconnect_authorized_account");
  }
}

void start().catch((error) => {
  showToast(`Startup failed: ${error instanceof Error ? error.message : String(error)}`, true);
}).finally(finishBoot);
