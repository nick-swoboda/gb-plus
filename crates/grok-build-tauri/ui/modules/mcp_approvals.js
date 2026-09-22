"use strict";

export function createMcpCallApprovals({ invoke, getSnapshot, showToast }) {
  const parent = document.querySelector("#chat-canvas");
  if (!parent || !invoke) return;
  const section = document.createElement("section");
  section.className = "mcp-call-approvals";
  section.setAttribute("aria-label", "Tool calls awaiting your approval");
  section.setAttribute("aria-live", "polite");
  section.hidden = true;
  parent.append(section);
  let project = null;
  let signature = "";
  let checking = false;
  const busy = new Set();
  const text = (tag, value) => { const node = document.createElement(tag); node.textContent = value; return node; };
  function render(views) {
    const next = JSON.stringify(views);
    if (next === signature) return;
    signature = next;
    section.replaceChildren();
    section.hidden = views.length === 0;
    for (const view of views) {
      const row = document.createElement("article");
      row.append(text("h3", `Allow ${view.tool.wireName}?`), text("p", `${view.server} · ${view.endpoint}`));
      const hookReview = view.kind === "hook";
      row.append(text("p", hookReview
        ? "An enabled project hook requested your review. Normal app permissions still apply after you allow this call."
        : "This server may change data. Review the exact arguments before allowing this one call."));
      const details = document.createElement("details");
      details.open = true;
      details.append(text("summary", hookReview ? "Tool arguments to review" : "Arguments sent to this server"), text("pre", JSON.stringify(view.arguments, null, 2)));
      row.append(details);
      const binding = document.createElement("details");
      binding.append(text("summary", "Tool and run identity"), text("p", `Run: ${view.runId}`), text("code", view.tool.fingerprint), text("pre", JSON.stringify(view.tool.inputSchema, null, 2)));
      row.append(binding);
      for (const [label, allow] of [["Decline", false], ["Allow this call", true]]) {
        const button = text("button", label);
        button.type = "button";
        button.className = "button button-secondary";
        button.dataset.busyAllowed = "";
        button.disabled = busy.has(view.id);
        button.addEventListener("click", async () => {
          if (getSnapshot()?.activeProjectId !== view.projectId || busy.has(view.id)) return;
          busy.add(view.id);
          row.querySelectorAll("button").forEach(item => { item.disabled = true; });
          try {
            await invoke("answer_mcp_call_approval", { projectId: view.projectId, approvalId: view.id, commitment: view.commitment, allow });
            row.remove();
            if (!section.children.length) section.hidden = true;
          } catch (error) { showToast(String(error)); signature = ""; }
          finally { busy.delete(view.id); }
        });
        row.append(button);
      }
      section.append(row);
    }
  }
  async function refresh() {
    const selected = getSnapshot()?.activeProjectId;
    if (project !== selected) { project = selected; signature = ""; section.replaceChildren(); section.hidden = true; }
    if (!selected || checking || document.hidden) return;
    checking = true;
    try {
      const views = await invoke("list_mcp_call_approvals", { projectId: selected });
      if (getSnapshot()?.activeProjectId === selected) render(views);
    } catch { /* A changing project or closed backend supplies no authority. */ }
    finally { checking = false; }
  }
  const timer = window.setInterval(() => { void refresh(); }, 1000);
  window.addEventListener("pagehide", () => { window.clearInterval(timer); section.remove(); }, { once: true });
}
