# GB Plus

A coding workspace for macOS, powered by Grok. Keep your projects and chats
together, review changes, and work with Git, Terminal, Browser and Voice in one app.

GB Plus is an independent project and is not an official xAI application.

## Download

[Download GB Plus](https://github.com/nick-swoboda/gb-plus/releases)
for **Apple Silicon and macOS 15 or later**.

The current release, **0.2.1-plus**, is an unsigned open-source preview. It uses
an ad-hoc platform signature and is not Developer ID signed or notarized.

1. Download `gb-plus-macos-arm64-unsigned.zip` and `SHA256SUMS`.
2. Run `shasum -a 256 gb-plus-macos-arm64-unsigned.zip` and compare the result
   with the ZIP's entry in `SHA256SUMS`.
3. Unzip it and move **GB Plus.app** to Applications.
4. If macOS blocks opening it, use **System Settings → Privacy & Security →
   Open Anyway** after verifying the download. See [Apple's guidance](https://support.apple.com/102445).

You do not need the source code to run the prebuilt app.

## Get started

For the unsigned preview, sign in through the official Grok CLI in Terminal.
GB Plus uses the managed installation at `~/.grok/bin/grok`.
Install it using [xAI's instructions](https://github.com/xai-org/grok-build#installing-the-released-binary),
or reuse an existing managed installation. No upstream source checkout is needed.

This preview's standard connection was tested with **Grok CLI 1.0.30**. Standard
mode verifies xAI's publisher signature and has no version cap; compatibility
with later releases is not yet verified. The older contained CLI connection
requires its admitted **1.0.25** binary.

1. Open **Account** and select **Grok CLI standard**, then **Grok Subscription**.
2. Connect and add a project in **Projects**.
3. Open **Chat**. The model button selects the model and reasoning effort.
4. Review the CLI's edit preview and permission request before allowing changes.

New standard chats start in **Ask** mode. The per-chat permission selector also
offers accept edits, Auto and always approve. **Send now** steers active work;
**Send next** queues another turn. **Stop** cancels the active run. Interrupted
work is never restarted automatically.

Use **Account → Updates → Update Grok CLI** to run the CLI's official updater.
GB Plus updates are distributed through this repository's releases.

## Features

- Project workspaces, persistent chat and a compact model/effort picker.
- Git hunk review and managed worktrees.
- An interactive terminal in the selected project or worktree.
- Browser, Capture and Desktop Control with separate project grants.
- Offline Voice transcription and Grok Read Aloud.
- Optional extensions, isolated Grok children, workflows and project memory.

Browser and Voice components download when enabled. Extensions and other
optional capabilities start disabled.

## Preview limitations

**GB Plus contained** remains the default engine; choose **Grok CLI standard**
for the unsigned download. App-managed API-key and MCP credential storage
requires a stable signed build. Existing stored keys are preserved.

Standard CLI commands and the interactive Terminal run on your Mac. Optional
**Command security** applies to the separate contained Checks path. CLI session
and settings integration is still being completed, and full live-account,
VoiceOver and clean-Mac qualification remains open. See [SECURITY.md](SECURITY.md)
for the current security boundaries.

## Build and contribute

The source is a Rust workspace with a Tauri host and bundled HTML, CSS and
JavaScript. No frontend package installation is needed.

Use the pinned Rust toolchain and reviewed prerequisites described in
[CONTRIBUTING.md](CONTRIBUTING.md). Package an ad-hoc signed macOS build with:

```sh
scripts/plus-macos-release.sh --adhoc
```

The packager verifies its native helper and license inputs and reports missing
prerequisites. It produces the app, ZIP, checksums and build receipt under `dist/`.

Contributions require Developer Certificate of Origin sign-off under [DCO](DCO)
and use the license of the component being changed. Please read
[CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## License

Original GB Plus components use [MIT](LICENSE). The adapted Grok Build prompt
and workflow interpreter retain **Apache-2.0**. Other components retain their
own licenses; see [ATTRIBUTION.md](ATTRIBUTION.md). Preserve the applicable
copyright, license and NOTICE files when redistributing.
