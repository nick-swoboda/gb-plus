"use strict";

const cache = new Map();
const tags = new Set(["p", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "pre", "ul", "ol", "li", "table", "thead", "tr", "th", "td", "em", "strong", "del", "a", "span"]);
const keywords = new Set("as async await break case catch class const continue def do else enum export false fn for from function if impl import in interface let match mod mut new None null pub raise return self static struct super switch this throw trait true try type use var void while yield".split(" "));

export function highlightCode(target, source) {
  if (source.length > 65536) { target.append(document.createTextNode(source)); return; }
  const pattern = /("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`|\/\/[^\n]*|#[^\n]*|\b[A-Za-z_][A-Za-z_0-9]*\b|\b\d+(?:\.\d+)?\b)/g;
  let cursor = 0; let count = 0;
  for (const match of source.matchAll(pattern)) {
    if (++count > 4096) break;
    target.append(document.createTextNode(source.slice(cursor, match.index)));
    const value = match[0];
    const kind = /^["'`]/.test(value) ? "string" : /^(\/\/|#)/.test(value) ? "comment" : /^\d/.test(value) ? "number" : keywords.has(value) ? "keyword" : null;
    if (kind) { const node = document.createElement("span"); node.className = `syntax-${kind}`; node.textContent = value; target.append(node); }
    else target.append(document.createTextNode(value));
    cursor = match.index + value.length;
  }
  target.append(document.createTextNode(source.slice(cursor)));
}

export function appendMarkdownTokens(root, tokens, onLink) {
  const stack = [root];
  for (const token of tokens) {
    const parent = stack.at(-1);
    if (token.kind === "open") {
      const tag = tags.has(token.tag) ? token.tag : "span";
      const node = document.createElement(tag);
      if (tag === "a" && /^(https?:|mailto:)/i.test(token.href || "")) {
        node.href = token.href; node.title = token.href; node.target = "_blank"; node.rel = "noopener noreferrer";
        if (onLink) node.addEventListener("click", event => { event.preventDefault(); onLink(token.href); });
      }
      if (tag === "ol" && Number.isSafeInteger(token.start)) node.start = token.start;
      if (tag === "th") node.setAttribute("scope", "col");
      if (tag === "pre" && token.language) { node.dataset.language = token.language; node.setAttribute("aria-label", `${token.language} code`); }
      parent.append(node); stack.push(node);
    } else if (token.kind === "close") { if (stack.length > 1) stack.pop(); }
    else if (token.kind === "text") {
      if (parent.tagName === "PRE") highlightCode(parent, token.text);
      else parent.append(document.createTextNode(token.text));
    } else if (token.kind === "code") { const node = document.createElement("code"); node.textContent = token.text; parent.append(node); }
    else if (token.kind === "break") parent.append(document.createElement("br"));
    else if (token.kind === "rule") parent.append(document.createElement("hr"));
  }
}

export async function renderMarkdown(target, text, invoke) {
  target.className = "chat-markdown";
  target.textContent = text;
  if (!invoke) return text;
  try {
    let result = cache.get(text);
    if (!result) {
      result = await invoke("render_chat_markdown", { text });
      if (text.length <= 65536) { cache.set(text, result); if (cache.size > 24) cache.delete(cache.keys().next().value); }
    }
    const fragment = document.createDocumentFragment();
    appendMarkdownTokens(fragment, result.tokens, url => {
      void invoke("open_chat_link", { url }).catch(error => {
        const note = document.createElement("span"); note.setAttribute("role", "alert"); note.textContent = String(error); target.append(note);
      });
    });
    target.replaceChildren(fragment);
    return result.plainText;
  } catch { target.textContent = text; return text; }
}
