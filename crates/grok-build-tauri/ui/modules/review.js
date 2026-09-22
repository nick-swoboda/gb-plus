"use strict";

function friendlyDiff(item) {
  const card = document.createElement("article");
  card.className = "chat-change-file";
  const head = document.createElement("header");
  const path = document.createElement("strong");
  path.className = "chat-file-name";
  path.textContent = item.path;
  path.title = item.path;
  const kind = document.createElement("span");
  kind.textContent = `${item.changeKind} · ${item.groupCount} ${item.groupCount === 1 ? "change" : "changes"}`;
  head.append(path, kind);

  const diff = document.createElement("div");
  diff.className = "friendly-diff";
  for (const line of String(item.diff || "").split("\n")) {
    if (line.startsWith("--- ") || line.startsWith("+++ ") || line === "") continue;
    const row = document.createElement("div");
    if (line.startsWith("@@ group ")) {
      const match = line.match(/^@@ group ([^ ]+) @@$/);
      row.className = "friendly-diff-group";
      row.textContent = `Change ${match?.[1] || ""}`.trim();
    } else {
      row.className = line.startsWith("+")
        ? "friendly-diff-add"
        : line.startsWith("-") ? "friendly-diff-remove" : "friendly-diff-context";
      row.textContent = line;
    }
    diff.append(row);
  }
  card.append(head, diff);
  return card;
}

export function createChatChanges({ elements, onAccept, onReject }) {
  let currentBinding = null;

  function attachToOriginatingReply() {
    if (elements.chatChangeCard.hidden) return;
    const waiting = elements.chatPendingTurns.querySelector(".chat-pending-message");
    if (waiting) {
      waiting.insertAdjacentElement("afterend", elements.chatChangeCard);
      return;
    }
    const reply = [...elements.transcriptBody.querySelectorAll(".chat-message[data-role=\"assistant\"]")].at(-1);
    if (reply) {
      reply.insertAdjacentElement("afterend", elements.chatChangeCard);
      return;
    }
    elements.transcriptBody.append(elements.chatChangeCard);
  }

  function setOpen(open) {
    elements.chatChangeList.hidden = !open;
    elements.chatChangeView.setAttribute("aria-expanded", String(open));
  }

  elements.chatChangeView.addEventListener("click", () => {
    setOpen(elements.chatChangeView.getAttribute("aria-expanded") !== "true");
  });
  elements.chatChangeAccept.addEventListener("click", () => {
    if (currentBinding) onAccept(currentBinding);
  });
  elements.chatChangeReject.addEventListener("click", () => {
    if (currentBinding) onReject(currentBinding);
  });

  function render(staged, busy = false) {
    const items = Array.isArray(staged) ? staged : [];
    const count = items.length;
    const projects = new Set(items.map((item) => item.projectId));
    const sessions = new Set(items.map((item) => item.sessionId));
    const paths = new Set(items.map((item) => item.path));
    const unambiguous = count > 0
      && projects.size === 1
      && sessions.size === 1
      && paths.size === count;
    currentBinding = unambiguous ? {
      projectId: items[0].projectId,
      sessionId: items[0].sessionId,
      proposals: items.map((item) => ({
        path: item.path,
        proposalFingerprint: item.proposalFingerprint,
      })),
    } : null;
    elements.chatChangeCard.hidden = count === 0;
    elements.chatChangeView.textContent = count === 1 ? "Change" : `${count} changes`;
    elements.chatChangeView.title = count === 1
      ? `View pending change to ${items[0].path}`
      : count > 1 ? `View ${count} pending changes` : "No pending changes";
    elements.chatChangeAccept.disabled = busy || !unambiguous;
    elements.chatChangeReject.disabled = busy || !unambiguous;
    elements.chatChangeView.disabled = count === 0;
    elements.chatChangeList.replaceChildren(...items.map(friendlyDiff));
    if (count === 0) {
      setOpen(false);
    } else {
      attachToOriginatingReply();
    }
  }

  return {
    binding() {
      return currentBinding;
    },
    reattach: attachToOriginatingReply,
    render,
  };
}
