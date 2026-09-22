"use strict";

const SECURITY_WORDS = { on: "On", unchecked: "Not checked", "setting-up": "Setting up", "needs-attention": "Needs attention" };
const COMMAND_OUTCOME_COPY = {
  idle: "Not run yet. Choose Test contained run.", completed: "Contained run completed. No action needed.",
  timed_out: "Stopped at the time limit. Retry if needed.", refused: "Command blocked. Follow the step above or open Details.",
  error: "Run failed. Open Details before retrying.",
};
export const viewCopy = {
  project: { label: "Projects" },
  chat: { label: "Chat" },
  "workspace-browser": { label: "Workspace" },
  terminal: { label: "Terminal" },
  browser: { label: "Browser" },
  review: { label: "Review" },
  activity: { label: "Activity" },
  checks: { label: "Checks" },
  account: { label: "Account" },
};

export const securityWord = (kind) => SECURITY_WORDS[kind] ?? "Off";

export const commandOutcomeSummary = (outcomeClass) => COMMAND_OUTCOME_COPY[outcomeClass] ?? "Outcome unavailable. Open Details.";

export function projectName(path) {
  if (!path) return "Not bound";
  const segments = path.split("/").filter(Boolean);
  return segments.at(-1) || path;
}

export const outcomeClassIsRefusalOrError = (outcomeClass) => ["timed_out", "refused", "error"].includes(outcomeClass);
