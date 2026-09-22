"use strict";

import { activeSessionId } from "./run_status.js";

export const visiblePrompt = value => String(value || "").replace(/\n\n\[GB Plus image: [a-f0-9]{64}\]$/, "");

export async function textAttachments(files, remaining) {
  if (files.length > 8) throw new Error("Attach up to eight text files at a time.");
  const parts = [];
  for (const file of files) {
    if (file.type?.startsWith("image/")) throw new Error("The current CLI does not advertise image input. The image was not attached.");
    if (file.size > 12000) throw new Error("Use an @file mention for files larger than this message's text limit.");
    const text = await file.text();
    if (text.includes("\u0000") || text.includes("\ufffd")) throw new Error("Use an @file mention for binary files.");
    parts.push(`\n\nFile: ${file.name}\n${text}`);
  }
  const result = parts.join("");
  if (new TextEncoder().encode(result).length > remaining) throw new Error("These files exceed the message limit. Use an @file mention instead.");
  return result;
}

export function createCliInput({ invoke, getSnapshot, showToast }) {
  const draft = document.querySelector("#chat-draft");
  const chooser = document.createElement("input"); chooser.type = "file"; chooser.multiple = true; chooser.hidden = true;
  const attach = document.createElement("button"); attach.type = "button"; attach.className = "cli-attach-button"; attach.textContent = "+";
  attach.setAttribute("aria-label", "Attach text files"); attach.title = "Attach files or paste text · use @ for a project file"; attach.hidden = true;
  draft?.parentElement.prepend(attach, chooser);
  let enabled = false; let generation = 0; let project = null; let session = null; let imageMarker = null;
  const chip = document.createElement("button"); chip.type = "button"; chip.className = "cli-image-chip"; chip.hidden = true; chip.textContent = "Image attached ×"; chip.setAttribute("aria-label", "Remove attached image");
  draft?.parentElement.before(chip);
  function clearImage(discard) {
    const marker = imageMarker; imageMarker = null; chip.hidden = true;
    if (discard && marker) void invoke("discard_cli_image", { marker }).catch(error => showToast(String(error), true));
  }
  chip.addEventListener("click", () => clearImage(true));
  async function addImage(file, epoch) {
    if (file.size > 16 * 1024 * 1024) throw new Error("Choose an image smaller than 16 MiB.");
    if (imageMarker) throw new Error("Remove the current image before attaching another.");
    const bitmap = await createImageBitmap(file);
    const ratio = Math.min(1, 1280 / bitmap.width, 900 / bitmap.height);
    const canvas = document.createElement("canvas"); canvas.width = Math.max(1, Math.round(bitmap.width * ratio)); canvas.height = Math.max(1, Math.round(bitmap.height * ratio));
    canvas.getContext("2d").drawImage(bitmap, 0, 0, canvas.width, canvas.height); bitmap.close();
    const blob = await new Promise(resolve => canvas.toBlob(resolve, "image/png"));
    if (!blob || epoch !== generation) return;
    const view = getSnapshot();
    const marker = await invoke("stage_cli_image", { projectId: view?.activeProjectId, sessionId: activeSessionId(view), bytes: [...new Uint8Array(await blob.arrayBuffer())] });
    if (epoch !== generation) { await invoke("discard_cli_image", { marker }); return; }
    imageMarker = marker; chip.hidden = false;
  }
  function insert(text) {
    if (new TextEncoder().encode(draft.value + text).length > 12000) throw new Error("Attachments exceed this message's limit.");
    draft.setRangeText(text, draft.selectionStart, draft.selectionEnd, "end"); draft.dispatchEvent(new Event("input", { bubbles: true })); draft.focus();
  }
  async function add(files) {
    const epoch = generation;
    try {
      const images = files.filter(file => file.type?.startsWith("image/"));
      if (images.length > 1 || (images.length && files.length > 1)) throw new Error("Attach one image at a time.");
      if (images.length) { await addImage(images[0], epoch); return; }
      const text = await textAttachments(files, 12000 - new TextEncoder().encode(draft.value).length);
      if (enabled && epoch === generation) insert(text);
    } catch (error) { if (epoch === generation) showToast(String(error), true); }
  }
  attach.addEventListener("click", () => chooser.click());
  chooser.addEventListener("change", () => { void add([...chooser.files]); chooser.value = ""; });
  draft?.addEventListener("paste", event => {
    if (!enabled) return;
    const files = [...(event.clipboardData?.files || [])];
    if (files.length) { event.preventDefault(); void add(files); }
  });
  draft?.addEventListener("dragover", event => { if (enabled) event.preventDefault(); });
  draft?.addEventListener("drop", event => {
    if (enabled && event.dataTransfer?.files?.length) { event.preventDefault(); void add([...event.dataTransfer.files]); }
  });
  document.addEventListener("dragover", event => event.preventDefault());
  document.addEventListener("drop", event => event.preventDefault());
  const window = globalThis.window?.__TAURI__?.window?.getCurrentWindow?.();
  if (window?.onDragDropEvent) void window.onDragDropEvent(event => {
    if (!enabled || event.payload?.type !== "drop" || !draft) return;
    const view = getSnapshot(); if (view?.activeProjectId !== project) return;
    const paths = event.payload.paths || [];
    if (paths.length > 8) { showToast("Drop up to eight files at a time.", true); return; }
    if (paths.some(path => /\.(png|jpe?g|gif|webp|heic|avif)$/i.test(path))) { showToast("The current CLI does not advertise image input. The image was not attached.", true); return; }
    try { insert(paths.map(path => ` @${JSON.stringify(path)}`).join("") + " "); }
    catch (error) { showToast(String(error), true); }
  }).catch(error => showToast(`File drop unavailable: ${error}`, true));
  function snapshot(value) {
    if (enabled && value?.engine?.mode !== "grokCliStandard") { clearImage(true); generation += 1; }
    enabled = value?.engine?.mode === "grokCliStandard"; attach.hidden = !enabled;
    const nextSession = activeSessionId(value);
    if (project !== value?.activeProjectId || session !== nextSession) { clearImage(true); project = value?.activeProjectId; session = nextSession; generation += 1; chooser.value = ""; }
  }
  function prepare(command, payload) {
    if (!imageMarker || !["send_chat", "send_next", "send_now"].includes(command)) return payload;
    if (command === "send_now") throw new Error("Send the image with Send next; the CLI's interjection input is text-only.");
    if (new TextEncoder().encode(payload.message + imageMarker).length > 12000) throw new Error("Shorten the message to make room for its image attachment.");
    return { ...payload, message: payload.message + imageMarker };
  }
  function sent(command) { if (["send_chat", "send_next"].includes(command)) clearImage(false); }
  return { snapshot, prepare, sent };
}
