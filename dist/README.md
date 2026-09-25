# GB Plus

A project-based coding assistant for macOS 15 or later on Apple Silicon.
This is an independent project, not an official xAI application.

## Install

1. Verify the download with `shasum -a 256 -c SHA256SUMS`.
2. Unzip the app ZIP and move `GB Plus.app` to Applications. The public download
   is `gb-plus-macos-arm64-unsigned.zip`; a GB Plus source checkout is not required.
3. Open GB Plus. This unsigned distribution uses an ad-hoc platform signature,
   with no publisher certificate or notarization. If macOS blocks it, verify
   its checksum, then use System Settings → Privacy & Security → Open Anyway.
   See [Apple's instructions](https://support.apple.com/102445).

## Start

For this unsigned build, sign in with the official Grok CLI in Terminal first.
Add or open a project in Projects, then open Account and choose
**Connect with Grok Subscription**. On an existing installation, choose
**Use Grok CLI standard** under Updates first; finish or remove queued work
before switching. Saved API-key connections and GB Plus-managed MCP credentials
require a stable signed build; this package cannot use those Keychain bindings.
Existing keys remain untouched.

Chat displays the newest
messages at the bottom. Use the small model button above Chat to choose a model
and reasoning effort. Send now steers active work; Send next queues another turn.
Stop cancels the active run. Interrupted work is never replayed automatically.

New installations use Grok CLI standard. Existing engine choices are preserved.
Standard uses the official Grok CLI and shares its normal sessions and
configuration with Terminal. Its full session-management and settings integration is still in
development. Standard commands run on the Mac under the selected CLI permission
mode; new chats begin in Ask. Choose that engine to use a current managed CLI.

## Your data

The download contains application code, public licenses, runtime components and
build metadata. It contains no saved accounts, conversations, projects, browser
profiles, captures or recordings. Your existing local data remains on your Mac.
GB Plus does not export or erase your stored key. CLI sign-in remains in the
CLI's own storage.

## Working with projects

Review proposed changes in Chat before accepting them. In CLI standard mode,
Ask presents the CLI's permission choices and edit preview. Other permission
modes follow the choice you make for that chat.

Workspace browses project files. Review provides Git hunk actions and worktree
controls. Terminal is your interactive shell in the active project or worktree.
Command security is optional and starts Off; its existing contained Checks path
is separate from the user terminal and standard CLI commands.

Browser, Capture and Desktop Control require separate project grants. Capture
and Voice request macOS permissions when enabled. Voice models and the Browser
runtime download only when requested; they are not bundled. Read Aloud uses the
connected account's supported voice service.

Extensions, isolated children, workflows and project memory remain opt-in.
Notifications and Activity show progress. Review a diagnostic export before
sharing it: it excludes conversation and credential contents, but includes
project paths and system metadata.

## License

GB Plus's original components are MIT licensed; see LICENSE.txt. The adapted
Grok Build prompt and workflow interpreter retain Apache-2.0, and other
third-party components retain their respective licenses. See ATTRIBUTION.md
for component scopes and modifications. Preserve the applicable license and
NOTICE material when redistributing. Complete dependency notices and additional
source archives are in RuntimeNotices.tar.gz; copy it
outside the app before unpacking. WorkflowNotices, WebSocketNotices and
BubblewrapSource retain their component notices and source distributions.

## Release status

This is an unsigned open-source preview. Full live-account, clean-Mac and
VoiceOver qualification remains open, as does the complete standard-CLI
integration. Current information is available at
https://github.com/nick-swoboda/gb-plus.
