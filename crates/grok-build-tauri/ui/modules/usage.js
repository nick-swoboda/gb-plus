"use strict";

const TOKEN_FIELDS = [
  ["Input", "inputTokens"],
  ["Output", "outputTokens"],
  ["Thought", "thoughtTokens"],
  ["Cached", "cachedTokens"],
];

function exactUnsigned(value) {
  return typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value)
    ? BigInt(value)
    : null;
}

function formatUnsigned(value) {
  const exact = exactUnsigned(value);
  return exact === null ? "Unavailable" : exact.toLocaleString("en-US");
}

export function compactContextTokens(value) {
  const exact = exactUnsigned(value);
  if (exact === null) return null;
  if (exact < 1_000n) return exact.toString();
  if (exact < 10_000n) {
    const tenths = (exact + 50n) / 100n;
    return `${tenths / 10n}.${tenths % 10n}K`;
  }
  if (exact < 1_000_000n) return `${exact / 1_000n}K`;
  if (exact < 10_000_000n) {
    const tenths = (exact + 50_000n) / 100_000n;
    return `${tenths / 10n}.${tenths % 10n}M`;
  }
  return `${exact / 1_000_000n}M`;
}

function contextPercentage(basisPoints) {
  const percentage = basisPoints / 100;
  if (percentage >= 100) return "MAX %";
  return percentage < 10 ? `${percentage.toFixed(2)}%` : `${percentage.toFixed(1)}%`;
}

export function relativeBasisPoints(value, maximum) {
  const exact = exactUnsigned(value);
  const max = exactUnsigned(maximum);
  if (exact === null || max === null || max === 0n || exact > max) return 0;
  return Number((exact * 10_000n) / max);
}

function contextState(context) {
  if (!context || typeof context !== "object") {
    return { state: "unknown", basisPoints: null };
  }
  const state = ["known", "unknown", "invalid", "error"].includes(context.state)
    ? context.state
    : "error";
  const basisPoints = Number.isInteger(context.basisPoints)
    && context.basisPoints >= 0
    && context.basisPoints <= 10_000
    ? context.basisPoints
    : null;
  if (state !== "known" || basisPoints === null) {
    return {
      state,
      basisPoints: null,
    };
  }
  const used = compactContextTokens(context.used);
  const size = compactContextTokens(context.size);
  if (used === null || size === null) return { state: "error", basisPoints: null };
  return {
    state,
    label: `${used} / ${size}`,
    fullLabel: `${formatUnsigned(context.used)} / ${formatUnsigned(context.size)} tokens`,
    percentage: contextPercentage(basisPoints),
    basisPoints,
  };
}

function tokenMetrics(usage) {
  const metrics = TOKEN_FIELDS.flatMap(([label, field]) => {
    const value = exactUnsigned(usage?.[field]);
    return value === null ? [] : [{ label, raw: usage[field], value }];
  });
  const maximum = metrics.reduce(
    (current, metric) => metric.value > current ? metric.value : current,
    0n,
  );
  return metrics.map((metric) => ({
    ...metric,
    basisPoints: maximum === 0n
      ? 0
      : Number((metric.value * 10_000n) / maximum),
  }));
}

function tokenRow(metric) {
  const row = document.createElement("div");
  row.className = "usage-token-row";

  const label = document.createElement("span");
  label.className = "usage-token-label";
  label.textContent = metric.label;

  const track = document.createElement("span");
  track.className = "usage-token-track";
  track.setAttribute("aria-hidden", "true");
  const fill = document.createElement("span");
  fill.className = "usage-token-fill";
  fill.style.width = `${metric.basisPoints / 100}%`;
  track.append(fill);

  const value = document.createElement("span");
  value.className = "usage-token-value";
  value.textContent = metric.value.toLocaleString("en-US");

  row.setAttribute("aria-label", `${metric.label} tokens: ${value.textContent}`);
  row.append(label, track, value);
  return row;
}

export function createUsagePresentation({ elements }) {
  function renderContext(context) {
    const view = contextState(context);
    const known = view.state === "known" && view.basisPoints !== null;
    elements.chatContextMeter.dataset.state = view.state;
    elements.chatContextMeter.dataset.tone = known && view.basisPoints >= 8_500 ? "warn" : "normal";
    elements.chatContextMeter.hidden = !known;
    elements.chatContextLabel.textContent = known ? view.label : "";
    elements.chatContextPercent.textContent = known ? view.percentage : "";
    elements.chatContextTrack.hidden = !known;
    if (known) {
      elements.chatContextMeter.setAttribute("aria-label", `Context window: ${view.fullLabel}`);
      elements.chatContextMeter.title = `${view.fullLabel} · ${view.percentage}`;
      elements.chatContextTrack.setAttribute("role", "progressbar");
      elements.chatContextTrack.setAttribute("aria-label", "Context window use");
      elements.chatContextTrack.setAttribute("aria-valuemin", "0");
      elements.chatContextTrack.setAttribute("aria-valuemax", "100");
      elements.chatContextFill.style.width = `${view.basisPoints / 100}%`;
      elements.chatContextTrack.setAttribute("aria-valuenow", String(view.basisPoints / 100));
      elements.chatContextTrack.setAttribute("aria-valuetext", view.fullLabel);
    } else {
      elements.chatContextMeter.removeAttribute("aria-label");
      elements.chatContextMeter.removeAttribute("title");
      elements.chatContextFill.style.width = "0%";
      elements.chatContextTrack.removeAttribute("role");
      elements.chatContextTrack.removeAttribute("aria-label");
      elements.chatContextTrack.removeAttribute("aria-valuemin");
      elements.chatContextTrack.removeAttribute("aria-valuemax");
      elements.chatContextTrack.removeAttribute("aria-valuenow");
      elements.chatContextTrack.removeAttribute("aria-valuetext");
    }
  }

  function render(usage) {
    const view = usage && typeof usage === "object" ? usage : {
      available: false,
      status: "Usage unavailable",
      context: { state: "error", label: "Unknown. Usage unavailable" },
    };
    renderContext(view.context);

    elements.usageStatus.textContent = view.status || "Usage unavailable";
    elements.usageStatus.dataset.kind = !view.available || view.context?.state === "invalid"
      ? "error"
      : view.context?.state === "unknown"
        ? "unknown"
        : "ready";

    const sourceVisible = typeof view.sourceTransport === "string"
      && typeof view.runId === "string";
    elements.usageSource.hidden = !sourceVisible;
    elements.usageSource.textContent = sourceVisible
      ? view.sourceTransport
      : "";
    elements.usageSource.title = sourceVisible ? `Run ${view.runId}` : "";

    const metrics = view.tokensVisible ? tokenMetrics(view) : [];
    elements.usageTokenChart.hidden = metrics.length === 0;
    if (metrics.length === 0) {
      elements.usageTokenChart.removeAttribute("aria-label");
    } else {
      elements.usageTokenChart.setAttribute(
        "aria-label",
        "Provider-reported token categories",
      );
    }
    elements.usageTokenList.replaceChildren(...metrics.map(tokenRow));

    const costVisible = Boolean(
      view.costVisible
      && typeof view.costAmount === "string"
      && typeof view.costCurrency === "string",
    );
    elements.usageCost.hidden = !costVisible;
    elements.usageCostValue.textContent = costVisible
      ? `${view.costAmount} ${view.costCurrency}`
      : "";

    elements.usageEmpty.hidden = metrics.length !== 0 || costVisible;
  }

  return { render };
}
