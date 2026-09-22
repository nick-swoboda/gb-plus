"use strict";

function textElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  element.textContent = text;
  return element;
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

function exactDiscardConfirmation(hunk) {
  return `DISCARD HUNK ${hunk.id.slice(0, 12)}`;
}

export function createGitReview({
  invoke,
  elements,
  onSnapshot,
  onError,
  onNotice,
  onBusy,
  onAdd,
}) {
  const state = {
    projectId: null,
    root: null,
    review: null,
    loading: false,
    hostBusy: false,
    refusal: null,
    discardHunk: null,
    generation: 0,
  };

  function setStatus(message, kind = "idle") {
    elements.gitReviewStatus.textContent = message;
    elements.gitReviewStatus.dataset.kind = kind;
  }

  function updateAvailability() {
    const blocked = state.hostBusy || state.loading || !state.projectId;
    elements.gitReviewAdd.disabled = blocked;
    elements.gitReviewRefresh.disabled = blocked;
    elements.gitReviewStagedList.querySelectorAll("button").forEach((button) => {
      button.disabled = blocked;
    });
    elements.gitReviewUnstagedList.querySelectorAll("button").forEach((button) => {
      button.disabled = blocked;
    });
  }

  function actionButton(label, action, hunk, className = "button button-secondary") {
    const button = document.createElement("button");
    button.type = "button";
    button.className = className;
    button.textContent = label;
    button.addEventListener("click", () => {
      if (action === "discard") openDiscardSheet(hunk);
      else void runAction(action, hunk);
    });
    return button;
  }

  function renderHunk(hunk) {
    const card = document.createElement("article");
    card.className = "git-hunk-card";
    if (state.refusal === hunk.id) card.classList.add("is-refused");

    const head = document.createElement("header");
    const title = document.createElement("div");
    title.append(
      textElement("strong", "git-hunk-header", hunk.header),
      textElement(
        "span",
        "git-hunk-counts",
        `+${hunk.addedLines} −${hunk.removedLines} · ${hunk.id.slice(0, 12)}`,
      ),
    );
    head.append(title, textElement("span", "git-lane-chip", hunk.lane));

    const diff = textElement("pre", "review-diff git-hunk-diff", hunk.diff);
    const foot = document.createElement("footer");
    foot.className = "git-hunk-foot";
    const identity = textElement(
      "span",
      "review-meta",
      "Bound to current index + worktree blobs",
    );
    identity.title = `index ${hunk.indexIdentity} · worktree ${hunk.worktreeIdentity}`;
    const controls = document.createElement("div");
    controls.className = "review-actions";
    if (hunk.lane === "staged") {
      controls.append(actionButton("Unstage", "unstage", hunk));
    } else {
      controls.append(
        actionButton("Discard…", "discard", hunk, "button button-quiet-danger"),
        actionButton("Stage", "stage", hunk, "button button-primary"),
      );
    }
    foot.append(identity, controls);
    card.append(head, diff, foot);
    return card;
  }

  function renderFile(file) {
    const card = document.createElement("article");
    card.className = "git-file-card";
    if (file.binary) card.classList.add("is-binary");
    if (file.conflicted) card.classList.add("is-conflicted");
    const header = document.createElement("header");
    const copy = document.createElement("div");
    const path = textElement("strong", "git-file-path", file.path);
    path.title = file.path;
    copy.append(path, textElement("span", "git-file-detail", file.detail));
    header.append(copy, textElement("span", "git-change-chip", file.changeKind));
    card.append(header);
    if (file.hunks.length === 0) {
      card.append(textElement(
        "p",
        "git-file-unsupported",
        file.conflicted
          ? "Refused while conflicted."
          : file.binary
            ? "Binary change · no per-hunk operation."
            : "No actionable text hunk.",
      ));
    } else {
      const hunks = document.createElement("div");
      hunks.className = "git-file-hunks";
      hunks.append(...file.hunks.map(renderHunk));
      card.append(hunks);
    }
    return card;
  }

  function renderConflicts(review) {
    elements.gitReviewConflicts.replaceChildren();
    const conflicts = review?.conflictPaths ?? [];
    elements.gitReviewConflicts.hidden = conflicts.length === 0;
    if (conflicts.length === 0) return;
    elements.gitReviewConflicts.append(textElement(
      "strong",
      "",
      `${conflicts.length} unresolved conflict ${conflicts.length === 1 ? "path" : "paths"}`,
    ));
    const list = document.createElement("ul");
    conflicts.forEach((path) => list.append(textElement("li", "", path)));
    elements.gitReviewConflicts.append(list);
  }

  function render() {
    const review = state.review;
    const staged = review?.stagedFiles ?? [];
    const unstaged = review?.unstagedFiles ?? [];
    elements.gitReviewStagedList.replaceChildren(...staged.map(renderFile));
    elements.gitReviewUnstagedList.replaceChildren(...unstaged.map(renderFile));
    elements.gitReviewStaged.hidden = staged.length === 0;
    elements.gitReviewUnstaged.hidden = unstaged.length === 0;
    renderConflicts(review);
    const empty = staged.length === 0
      && unstaged.length === 0
      && (review?.conflictPaths?.length ?? 0) === 0;
    elements.gitReviewEmpty.hidden = !empty;
    elements.gitReviewEmpty.textContent = state.loading
      ? "Reading bounded Git state…"
      : !state.projectId
        ? "Bind a project to inspect Git changes."
        : review?.available === false
          ? review.status
          : "Git working tree and index are clean.";
    updateAvailability();
  }

  async function refresh(announce = false) {
    if (!invoke || !state.projectId || state.loading) return;
    const token = state.generation;
    state.loading = true;
    state.refusal = null;
    setStatus(announce ? "Refreshing Git Changes…" : "Reading bounded Git state…", "loading");
    render();
    try {
      const review = await invoke("list_git_review", {});
      if (token !== state.generation || review.projectId !== state.projectId) return;
      state.review = review;
      setStatus(
        review.status,
        review.available ? review.truncated ? "attention" : "live" : "error",
      );
    } catch (error) {
      if (token !== state.generation) return;
      const message = errorMessage(error);
      setStatus(message, "error");
      onError(message);
    } finally {
      state.loading = false;
      render();
    }
  }

  async function runAction(action, hunk, confirmation = null) {
    if (!invoke || state.loading || state.hostBusy) return;
    state.loading = true;
    state.refusal = null;
    onBusy(true);
    render();
    const command = action === "stage"
      ? "stage_git_hunk"
      : action === "unstage"
        ? "unstage_git_hunk"
        : "discard_git_hunk";
    const payload = { hunkId: hunk.id };
    if (confirmation !== null) payload.confirmation = confirmation;
    try {
      const response = await invoke(command, payload);
      onSnapshot(response.snapshot);
      state.review = response.result.review;
      if (response.result.outcome === "refused") {
        state.refusal = hunk.id;
        setStatus(response.result.detail, "refused");
        onError(response.result.detail);
      } else {
        setStatus(response.result.detail, "live");
        onNotice(response.result.detail);
      }
    } catch (error) {
      const message = errorMessage(error);
      setStatus(message, "error");
      onError(message);
    } finally {
      state.loading = false;
      onBusy(false);
      render();
    }
  }

  function openDiscardSheet(hunk) {
    state.discardHunk = hunk;
    const required = exactDiscardConfirmation(hunk);
    elements.gitHunkActionTitle.textContent = `Discard hunk · ${hunk.path}`;
    elements.gitHunkActionDetail.textContent = `This deletes only the selected unstaged worktree hunk and does not change the index. Type ${required} exactly.`;
    elements.gitHunkActionField.value = "";
    elements.gitHunkActionField.placeholder = required;
    elements.gitHunkActionSheet.hidden = false;
    window.setTimeout(() => elements.gitHunkActionField.focus(), 0);
  }

  function closeDiscardSheet() {
    state.discardHunk = null;
    elements.gitHunkActionField.value = "";
    elements.gitHunkActionSheet.hidden = true;
  }

  async function confirmDiscard() {
    const hunk = state.discardHunk;
    if (!hunk) return;
    const confirmation = elements.gitHunkActionField.value;
    closeDiscardSheet();
    await runAction("discard", hunk, confirmation);
  }

  function reset(snapshot) {
    const nextProjectId = snapshot?.workspaceRef?.projectId ?? null;
    const nextRoot = snapshot?.workspaceRef?.activeRoot ?? null;
    if (nextProjectId !== state.projectId || nextRoot !== state.root) {
      state.generation += 1;
      state.review = null;
      state.refusal = null;
    }
    state.projectId = nextProjectId;
    state.root = nextRoot;
    if (!nextProjectId) {
      setStatus("Bind a project to inspect Git changes.", "idle");
    } else if (!state.review) {
      setStatus("Open Review to inspect the active Git workspace.", "idle");
    }
    render();
  }

  function setHostBusy(busy) {
    state.hostBusy = busy;
    updateAvailability();
  }

  elements.gitReviewRefresh.addEventListener("click", () => {
    void refresh(true);
  });
  elements.gitReviewAdd.addEventListener("click", onAdd);
  elements.gitHunkActionCancel.addEventListener("click", closeDiscardSheet);
  elements.gitHunkActionConfirm.addEventListener("click", () => {
    void confirmDiscard();
  });
  elements.gitHunkActionSheet.addEventListener("click", (event) => {
    if (event.target === elements.gitHunkActionSheet) closeDiscardSheet();
  });

  reset(null);
  return { ensure: refresh, refresh, reset, setHostBusy };
}
