# Security policy

## Reporting vulnerabilities

Use GitHub's private **Report a vulnerability** control when available. If it
is unavailable, request a private contact method from the repository owner
without posting vulnerability details publicly.

Include the affected version, operating system, reproduction steps and impact.
Do not include credentials, personal conversations or private repository data.
We will coordinate a fix and disclosure with the reporter and provide credit
when requested. This preview has no guaranteed response or resolution time.

## Current release

**0.2.2-plus** is an unsigned open-source preview for macOS 15 or later on Apple
Silicon. It is not Developer ID signed or notarized. Full live-account,
VoiceOver and clean-Mac qualification remains open.

Security behavior depends on the selected engine:

- **GB Plus contained:** proposed edits are staged for Accept, which rechecks
  current file contents before applying them.
- **Grok CLI standard:** uses the official CLI, its real home, settings and
  native tools. Edits and commands follow the selected CLI permission mode.
- **Terminal:** runs an interactive shell on the Mac.
- **Command security:** is optional and applies to the separate contained
  Checks path. It does not contain standard CLI commands or Terminal sessions.
- **Browser, Capture and Desktop Control:** require separate project grants,
  with target checks, expiry and visible cancellation.

The queue must never replay interrupted work or uncertain effects automatically.
Repository instructions and model output cannot grant additional permissions.
An unavailable control must produce a refusal or an explicit unavailable state.

## Credentials and local data

CLI sign-in remains in the CLI's own storage. App-managed API-key and MCP
credentials require stable signed Keychain helpers and are unavailable in the
unsigned build. Existing keys are preserved.

Chat and project state are stored locally. Model requests and Read Aloud send
their inputs to the selected provider. Browser profiles contain sensitive local
data and use owner-only filesystem access. GB Plus keeps raw capture and voice
buffers in memory; CLI and provider retention follow their own settings.
Releases must exclude account data, conversations, private projects, browser
profiles, captures and recordings.

Diagnostic exports exclude conversation and credential contents but can contain
project paths and system metadata. Review them before sharing.

## Security scope

Report unauthorized file access, permission bypasses, sandbox escapes, credential
leaks, uncertain-effect replay, incorrect application of reviewed changes,
surviving worker processes, and compromised build or update inputs.

Critical issues include unauthorized execution, credential disclosure,
unrecoverable data loss and false success or rollback claims. High-severity
issues include permission, isolation, recovery or lifecycle failures affecting
a primary workflow. Both block a release until resolved. Bounded issues with a
safe workaround must be documented; cosmetic issues do not lower a security
finding's severity.

Model quality, provider outages and unsupported configurations belong in normal
bug reports unless a security boundary is crossed.

## Containment diagnostics

A contained run is successful only when the installed service verifies all
required controls, issues the matching permit, and reports a known terminal
outcome with cleanup evidence. A fixture pass, native Mac process or nested
Docker test is not a full-isolation claim. The legacy containment diagnostic
remains unqualified for this preview.

Security fixes require regression tests at the affected boundary. Release notes
should identify affected versions, impact and remediation without disclosing
exploit details before users can update.
