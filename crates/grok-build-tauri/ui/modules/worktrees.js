"use strict";

function textElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  element.textContent = text;
  return element;
}

function exactConfirmation(kind, worktree) {
  if (kind === "discard") return `DISCARD ${worktree.task}`;
  if (kind === "remove-after-export") return `REMOVE ${worktree.task}`;
  if (kind === "remove-clean") return `REMOVE CLEAN ${worktree.task}`;
  return "";
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

function dirtyCount(dirty) {
  return dirty.staged.length
    + dirty.unstaged.length
    + dirty.conflicted.length
    + dirty.untracked.length
    + (dirty.ignored?.length ?? 0);
}

export function createWorktreeManager({ invoke, elements, onSnapshot, onError, onNotice }) {
  const state = {
    projectId: null,
    workspaceRef: null,
    list: null,
    loading: false,
    hostBusy: false,
    action: null,
    refusal: null,
    refreshWaiters: [],
  };

  function setStatus(message, kind = "idle") {
    elements.worktreeStatus.textContent = message;
    elements.worktreeStatus.title = message;
    elements.worktreeStatus.dataset.kind = kind;
  }

  function updateAvailability() {
    const blocked = state.hostBusy || state.loading || !state.projectId;
    elements.worktreeOpenBase.disabled = blocked
      || !state.workspaceRef?.worktreeId;
    elements.worktreeCreateForm.querySelectorAll("input, button").forEach((control) => {
      control.disabled = blocked || state.list?.available === false;
    });
    elements.worktreeList.querySelectorAll("button").forEach((button) => {
      button.disabled = blocked;
    });
    elements.gitSetupStart.disabled = blocked || !state.list?.setupAvailable;
    elements.gitIdentityForm.querySelectorAll("input, button").forEach((control) => {
      control.disabled = blocked;
    });
  }

  function renderDirtyPaths(container, dirty) {
    if (!dirty?.dirty) return;
    const details = document.createElement("details");
    details.className = "worktree-dirty-details";
    const summary = document.createElement("summary");
    summary.textContent = `${dirtyCount(dirty)} exact dirty path entr${dirtyCount(dirty) === 1 ? "y" : "ies"}`;
    details.append(summary);
    [
      ["Conflicted", dirty.conflicted],
      ["Staged", dirty.staged],
      ["Unstaged", dirty.unstaged],
      ["Untracked", dirty.untracked],
      ["Ignored", dirty.ignored ?? []],
    ].forEach(([label, paths]) => {
      if (paths.length === 0) return;
      const group = document.createElement("section");
      group.append(textElement("strong", "worktree-dirty-label", label));
      const list = document.createElement("ul");
      paths.forEach((path) => {
        const item = document.createElement("li");
        item.textContent = path;
        list.append(item);
      });
      group.append(list);
      details.append(group);
    });
    container.append(details);
  }

  function actionButton(label, kind, worktree, className = "button button-secondary") {
    const button = document.createElement("button");
    button.type = "button";
    button.className = className;
    button.textContent = label;
    button.addEventListener("click", () => {
      void runCardAction(kind, worktree);
    });
    return button;
  }

  function renderWorktree(worktree) {
    const card = document.createElement("article");
    card.className = "worktree-card";
    card.dataset.state = worktree.state;
    if (worktree.active) card.classList.add("is-active");
    if (state.refusal?.id === worktree.id) card.classList.add("is-refused");

    const head = document.createElement("header");
    const copy = document.createElement("div");
    const task = textElement("strong", "worktree-card-title", worktree.task);
    const branch = textElement("code", "worktree-card-branch", worktree.branch);
    task.title = worktree.task;
    branch.title = worktree.branch;
    copy.append(task, branch);
    head.append(copy);
    head.append(textElement(
      "span",
      `worktree-state-chip ${worktree.dirty.dirty ? "is-dirty" : ""}`,
      worktree.active ? "Active" : worktree.dirty.dirty ? "Dirty" : worktree.state,
    ));
    card.append(head);
    const path = textElement("code", "worktree-card-path", worktree.path);
    path.title = worktree.path;
    card.append(path);
    card.append(textElement("p", "worktree-card-detail", worktree.detail));
    if (state.refusal?.id === worktree.id) {
      card.append(textElement("p", "worktree-refusal", state.refusal.detail));
    }
    renderDirtyPaths(card, state.refusal?.id === worktree.id ? state.refusal.dirty : worktree.dirty);

    if (worktree.state === "ready") {
      const actions = document.createElement("div");
      actions.className = "worktree-card-actions";
      if (!worktree.active) actions.append(actionButton("Open", "open", worktree));
      if (worktree.dirty.staged.length > 0) {
        actions.append(actionButton("Commit staged…", "commit", worktree));
      }
      if (worktree.dirty.dirty) {
        actions.append(actionButton("Export recovery…", "export", worktree));
        actions.append(actionButton("Discard…", "discard", worktree, "button button-quiet-danger"));
        if (worktree.recoveryCurrent && worktree.recoveryManifest) {
          actions.append(actionButton(
            "Remove after export…",
            "remove-after-export",
            worktree,
            "button button-quiet-danger",
          ));
        }
      }
      actions.append(actionButton(
        "Remove",
        "remove",
        worktree,
        worktree.dirty.dirty ? "button button-secondary" : "button button-quiet-danger",
      ));
      card.append(actions);
    }
    return card;
  }

  function render() {
    elements.worktreeList.replaceChildren();
    if (!state.projectId) {
      elements.worktreeEmpty.hidden = false;
      elements.worktreeEmpty.textContent = "Bind a base project before managing worktrees.";
      updateAvailability();
      return;
    }
    const worktrees = state.list?.worktrees ?? [];
    elements.worktreeEmpty.hidden = worktrees.length > 0;
    elements.worktreeEmpty.textContent = state.loading
      ? "Refreshing Git…"
      : "No managed worktrees yet.";
    elements.gitSetup.hidden = !state.list?.setupAvailable && elements.gitIdentityForm.hidden;
    if (state.list && !state.list.available) {
      elements.gitSetupDetail.textContent = state.list.status;
    }
    worktrees.forEach((worktree) => elements.worktreeList.append(renderWorktree(worktree)));
    updateAvailability();
  }

  async function refresh() {
    if (!state.projectId || !invoke || state.loading) return;
    state.loading = true;
    setStatus("Refreshing Git…", "loading");
    render();
    try {
      const list = await invoke("list_worktrees", {});
      if (list.projectId !== state.projectId) return;
      state.list = list;
      setStatus(list.available ? list.status : "No managed worktrees yet.", list.available ? "live" : "idle");
    } catch (error) {
      const message = errorMessage(error);
      setStatus(message, "error");
      onError(message);
    } finally {
      state.loading = false;
      render();
      state.refreshWaiters.splice(0).forEach((resolve) => resolve());
    }
  }

  async function runGitSetup(authorName, authorEmail) {
    if (!invoke || state.loading) return;
    state.loading = true;
    updateAvailability();
    try {
      const response = await invoke("initialize_git", {
        authorName: authorName || null,
        authorEmail: authorEmail || null,
      });
      onSnapshot(response.snapshot);
      if (response.result.outcome === "needs_identity") {
        elements.gitSetup.hidden = false;
        elements.gitIdentityForm.hidden = false;
        elements.gitSetupStart.hidden = true;
        elements.gitSetupDetail.textContent = response.result.detail;
        elements.gitAuthorName.focus();
      } else if (response.result.outcome === "committed") {
        elements.gitIdentityForm.hidden = true;
        elements.gitSetupStart.hidden = false;
        onNotice("Git is ready · empty first commit verified");
      } else {
        onError(response.result.detail);
      }
    } catch (error) {
      onError(errorMessage(error));
    } finally {
      state.loading = false;
      await refresh();
    }
  }

  async function invokeSnapshot(command, payload, notice) {
    if (!invoke || state.loading) return false;
    state.loading = true;
    state.refusal = null;
    updateAvailability();
    try {
      const snapshot = await invoke(command, payload);
      onSnapshot(snapshot);
      if (notice) onNotice(notice);
      return true;
    } catch (error) {
      onError(errorMessage(error));
      return false;
    } finally {
      state.loading = false;
      await refresh();
    }
  }

  async function invokeAction(command, payload, notice) {
    if (!invoke || state.loading) return null;
    state.loading = true;
    updateAvailability();
    try {
      const response = await invoke(command, payload);
      onSnapshot(response.snapshot);
      if (response.result?.outcome === "refused") {
        state.refusal = {
          id: payload.worktreeId,
          detail: response.result.detail,
          dirty: response.result.dirty,
        };
        setStatus(response.result.detail, "refused");
        onError(response.result.detail);
      } else {
        state.refusal = null;
        if (notice) onNotice(notice);
      }
      return response;
    } catch (error) {
      onError(errorMessage(error));
      return null;
    } finally {
      state.loading = false;
      await refresh();
    }
  }

  function closeActionSheet() {
    state.action = null;
    elements.worktreeActionSheet.hidden = true;
    elements.worktreeActionField.value = "";
  }

  function openActionSheet(kind, worktree) {
    state.action = { kind, worktree };
    elements.worktreeActionSheet.hidden = false;
    elements.worktreeActionField.hidden = false;
    elements.worktreeActionFieldLabel.hidden = false;
    elements.worktreeActionConfirm.className = "button button-quiet-danger";
    if (kind === "commit") {
      elements.worktreeActionTitle.textContent = `Commit staged changes · ${worktree.task}`;
      elements.worktreeActionDetail.textContent = "Only currently staged Git changes will be committed. Unstaged and untracked paths remain dirty.";
      elements.worktreeActionFieldLabel.textContent = "Commit message";
      elements.worktreeActionField.placeholder = "Describe the staged change";
      elements.worktreeActionConfirm.textContent = "Commit staged";
      elements.worktreeActionConfirm.className = "button button-primary";
    } else {
      const required = exactConfirmation(kind, worktree);
      elements.worktreeActionTitle.textContent = kind === "discard"
        ? `Discard worktree changes · ${worktree.task}`
        : `Remove worktree · ${worktree.task}`;
      elements.worktreeActionDetail.textContent = kind === "discard"
        ? `This deletes tracked and untracked worktree changes. Type ${required} exactly. Removal remains separate.`
        : kind === "remove-after-export"
          ? `This path is dirty but has a matching recovery export. Type ${required} exactly to enter the separate post-export removal flow.`
          : `This clean managed worktree will be removed by Git. Type ${required} exactly.`;
      elements.worktreeActionFieldLabel.textContent = "Exact confirmation";
      elements.worktreeActionField.placeholder = required;
      elements.worktreeActionConfirm.textContent = kind === "discard" ? "Discard changes" : "Remove worktree";
    }
    window.setTimeout(() => elements.worktreeActionField.focus(), 0);
  }

  async function runCardAction(kind, worktree) {
    if (kind === "open") {
      await invokeSnapshot(
        "activate_workspace",
        { worktreeId: worktree.id },
        `Opened worktree ${worktree.task}`,
      );
      return;
    }
    if (kind === "remove") {
      if (!worktree.dirty.dirty) {
        openActionSheet("remove-clean", worktree);
        return;
      }
      await invokeAction(
        "remove_worktree",
        { worktreeId: worktree.id },
        "Managed worktree removed",
      );
      return;
    }
    if (kind === "export") {
      try {
        const destination = await invoke("choose_worktree_recovery_folder", {});
        if (!destination) {
          onNotice("Recovery export cancelled");
          return;
        }
        const response = await invokeAction(
          "export_worktree_recovery",
          { worktreeId: worktree.id, destination },
          "Recovery bundle exported and verified",
        );
        if (response) setStatus(response.result.detail, "live");
      } catch (error) {
        onError(errorMessage(error));
      }
      return;
    }
    openActionSheet(kind, worktree);
  }

  async function confirmAction() {
    const action = state.action;
    if (!action) return;
    const value = elements.worktreeActionField.value;
    closeActionSheet();
    if (action.kind === "commit") {
      await invokeAction(
        "commit_worktree",
        { worktreeId: action.worktree.id, message: value },
        "Staged changes committed",
      );
    } else if (action.kind === "discard") {
      await invokeAction(
        "discard_worktree",
        { worktreeId: action.worktree.id, confirmation: value },
        "Explicitly confirmed worktree changes discarded",
      );
    } else if (action.kind === "remove-after-export") {
      await invokeAction(
        "remove_worktree_after_export",
        {
          worktreeId: action.worktree.id,
          manifestHash: action.worktree.recoveryManifest,
          confirmation: value,
        },
        "Hash-bound exported worktree removed",
      );
    } else if (action.kind === "remove-clean") {
      if (value !== exactConfirmation("remove-clean", action.worktree)) {
        onError(`Clean removal requires the exact confirmation \`${exactConfirmation("remove-clean", action.worktree)}\`.`);
        return;
      }
      await invokeAction(
        "remove_worktree",
        { worktreeId: action.worktree.id },
        "Clean managed worktree removed",
      );
    }
  }

  function reset(snapshot) {
    const nextRef = snapshot?.workspaceRef ?? null;
    const nextProjectId = nextRef?.projectId ?? null;
    if (nextProjectId !== state.projectId) {
      state.list = null;
      state.refusal = null;
    }
    state.projectId = nextProjectId;
    state.workspaceRef = nextRef;
    elements.worktreeCurrent.textContent = nextRef?.worktreeTask
      ? `Worktree · ${nextRef.worktreeTask}`
      : nextRef ? "Base project" : "No active project";
    elements.worktreeCurrent.title = nextRef?.activeRoot ?? "No active project";
    if (!nextRef) {
      setStatus("Bind a base project before managing worktrees.", "idle");
    } else if (!state.list) {
      setStatus("Open to reconcile managed worktrees.", "idle");
    }
    render();
    if (elements.worktreeManager.open) void refresh();
  }

  function setHostBusy(busy) {
    state.hostBusy = busy;
    updateAvailability();
  }

  const advanced = elements.worktreeCreateForm.querySelector(".worktree-advanced");
  let advancedCloseTimer = null;
  const cancelAdvancedClose = () => window.clearTimeout(advancedCloseTimer);
  function scheduleAdvancedClose() {
    cancelAdvancedClose();
    advancedCloseTimer = window.setTimeout(() => {
      if (!advanced.matches(":hover") && !advanced.querySelector("input:focus, :focus-visible")) advanced.open = false;
    }, 3000);
  }

  async function openGitSetup() {
    elements.worktreeManager.open = true;
    if (state.loading) {
      await new Promise((resolve) => state.refreshWaiters.push(resolve));
    } else {
      await refresh();
    }
    const target = elements.gitSetup.hidden
      ? elements.worktreeManager.querySelector("summary")
      : elements.gitSetupStart;
    target?.scrollIntoView({ block: "center", behavior: "smooth" });
    if (!elements.gitSetup.hidden && !elements.gitSetupStart.hidden) {
      elements.gitSetupStart.focus({ preventScroll: true });
    }
  }

  elements.worktreeManager.addEventListener("toggle", () => {
    if (elements.worktreeManager.open) void refresh();
  });
  for (const event of ["pointerenter", "focusin"]) advanced.addEventListener(event, cancelAdvancedClose);
  for (const event of ["pointerleave", "focusout"]) advanced.addEventListener(event, scheduleAdvancedClose);
  elements.worktreeOpenBase.addEventListener("click", () => {
    void invokeSnapshot("activate_workspace", { worktreeId: null }, "Opened base project");
  });
  elements.worktreeCreateForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const task = elements.worktreeTask.value;
    const baseRef = elements.worktreeBaseRef.value;
    void invokeSnapshot(
      "create_worktree",
      { task, baseRef },
      `Created and opened worktree ${task.trim()}`,
    ).then((created) => {
      if (created) elements.worktreeTask.value = "";
    });
  });
  elements.gitSetupStart.addEventListener("click", () => void runGitSetup(null, null));
  elements.gitIdentityForm.addEventListener("submit", (event) => {
    event.preventDefault();
    void runGitSetup(elements.gitAuthorName.value, elements.gitAuthorEmail.value);
  });
  elements.worktreeActionCancel.addEventListener("click", closeActionSheet);
  elements.worktreeActionConfirm.addEventListener("click", () => {
    void confirmAction();
  });
  elements.worktreeActionSheet.addEventListener("click", (event) => {
    if (event.target === elements.worktreeActionSheet) closeActionSheet();
  });

  reset(null);
  return { ensure: refresh, openGitSetup, refresh, reset, setHostBusy };
}
