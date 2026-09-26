# Changelog

## 0.2.2-plus

- Use Grok CLI standard for new installations and offer a direct switch in
  Account for older installations after CLI updates. Preserve existing engine
  choices, isolated child permissions and queued work.
- Apply model and reasoning choices through the CLI's advertised session
  controls, and verify the active selection before saving it.
- Correct the bundled notice manifest after documentation cleanup and verify
  its file hashes and packaging pin together.
- Exclude local file-owner metadata from the release ZIP.
- Fix clean-runner Linux CI prerequisites and an x86-only test lint.
- Correct CI test isolation and Linux development-probe linkage.
- Speed up large workspace snapshots while retaining existing limits.
- Show source locations when the Linux lint gate fails.
- Keep process-group signals separate from command options on Linux and macOS.
- Replace internal development records with concise public documentation.

## 0.2.1-plus

Unsigned open-source preview for Apple Silicon and macOS 15 or later.

- Failed project commands retain their reason without incorrectly reporting
  that Command security needs repair.
- Terminal white ANSI text uses the dark brand color with contrast protection.
- Account includes a CLI Update button with installed-version and result feedback.
- Chat places new messages at the bottom and includes a compact model and
  reasoning-effort picker.
- The startup window fits the display's usable area; the G+ icon has rounded edges.
- Browser terms remain visible below the page.
- Opt-in Grok CLI standard adds Markdown, streamed activity, permission and
  question dialogs, and attachments. Its full session and settings integration
  remains in development.
- Concurrent child completion no longer causes an incorrect cleanup error.
- Release packaging verifies its contents and includes complete dependency
  notices and required source archives.
- Licensing distinguishes original MIT components from Apache-2.0 Grok Build
  adaptations and other third-party components.

## 0.2.0-plus

- Introduced the GB Plus desktop workspace with projects, persistent Chat,
  Git hunk review, managed worktrees and an interactive Terminal.
- Added durable Send now, Send next and Stop controls with interruption recovery.
- Added optional Browser, Capture, Desktop Control, offline Voice and Read Aloud.
- Added Account connections, notifications, Activity and diagnostic exports.
- Added optional contained execution and review-before-accepting for proposed edits.
