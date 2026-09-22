# Attribution

GB Plus's original components are licensed under MIT. See [LICENSE](LICENSE)
in the source or `LICENSE.txt` in the app. The root license does not replace the licenses
of the upstream and third-party components below.

The adapted Grok Build system prompt and workflow interpreter remain
Apache-2.0, including the GB Plus adaptations identified in their notices.
Preserve applicable copyright, license, NOTICE and modification notices when
redistributing. GB Plus is independent; these attributions do not imply endorsement.

## Grok Build

The system prompt is adapted from
`crates/codegen/xai-grok-agent/templates/prompt.md` and the workflow interpreter
from `crates/codegen/xai-workflow` at
[upstream commit 3794978](https://github.com/xai-org/grok-build/tree/37949780c144e37df692e3d669051a21fec24f20).
Copyright 2023–2026 SpaceXAI, Apache-2.0. GB Plus adaptations copyright 2026
GB Plus contributors, Apache-2.0.

The prompt describes the desktop host, Grok identity, app-managed memory and
delegation, authorized tools and proposal acceptance. The interpreter retains
the Rhai language and workflow operations with app-controlled execution,
bounded host calls and durable recovery. Detailed modification notices remain
in `crates/grok-build-plus-host/prompts/NOTICE.md` and
`crates/grok-build-workflow/NOTICE.md`.

The complete Apache-2.0 license is in
`vendor/workflow-notices/xai-workflow-LICENSE.txt` and the app's
`Contents/Resources/WorkflowNotices/` directory.

## Desktop and terminal

- [Tauri](https://tauri.app/) 2.11.5 and Wry 0.55.1: Apache-2.0 OR MIT.
  The macOS host uses the operating system's WKWebView.
- [portable-pty](https://crates.io/crates/portable-pty) 0.9.0: MIT.
- [xterm.js](https://xtermjs.org/) 6.0.0 and addon-fit 0.11.0: MIT.
  Original license files accompany the vendored frontend assets.
- [Slint](https://slint.dev/) 1.17.1: Royalty-free 2.0 for the separately gated
  legacy window. Slint is a product of SixtyFPS GmbH. That window includes
  `AboutSlint` and the attribution `Slint Royalty-free 2.0 attribution: AboutSlint above.`
  The shipped Tauri app does not link Slint. Its license is not replaced by MIT.

## Voice

- [whisper-rs](https://codeberg.org/tazz4843/whisper-rs) 0.16.0: Unlicense.
- [whisper.cpp](https://github.com/ggml-org/whisper.cpp) 1.8.3: MIT.
  GB Plus carries a build patch to `whisper-rs-sys 0.15.0`; the vendored source
  retains both upstream license texts.
- [CPAL](https://github.com/RustAudio/cpal) 0.18.1: Apache-2.0.
  Microphone input also uses Apple's AVFoundation and CoreAudio frameworks.

Optional `base` and `small` model files download from a pinned revision of
`ggerganov/whisper.cpp` on Hugging Face. Its model card declares MIT and
identifies the files as converted OpenAI Whisper models. They are not bundled
or rehosted by GB Plus.

## Optional Command security

[Colima](https://github.com/abiosoft/colima) 0.10.3 (MIT) and
[Lima](https://github.com/lima-vm/lima) 2.2.0 (Apache-2.0) download when the user
requests setup; they are not bundled with the app.

The Linux runner payload includes [Bubblewrap](https://github.com/containers/bubblewrap)
0.9.0-1ubuntu0.1 for arm64 under LGPL-2+ as a separate executable. Its upstream
and Debian packaging source, detached signature, source descriptor and copyright
notice accompany the app in `Contents/Resources/BubblewrapSource`.

## Other components and bundled notices

Exact Rust dependency versions are recorded in `Cargo.lock`.

- Diagnostics use zip 8.6.0 (MIT), zlib-rs 0.6.7 (zlib), and typed-path 0.12.3
  (MIT OR Apache-2.0).
- The workflow engine uses Rhai 1.25.1. Its dependencies' selected license
  texts are in `vendor/workflow-notices`. The unmodified Smartstring 1.0.1
  source archive and MPL-2.0 license are included there and in the app.
- The optional Responses WebSocket transport uses tokio-tungstenite and
  tungstenite 0.28.0. Its added dependencies' MIT licenses are retained in
  `vendor/websocket-notices` and the app's `WebSocketNotices` directory.
- Markdown rendering uses pulldown-cmark 0.13.4, copyright 2015 Google Inc.,
  under MIT. Its unicase 2.9.0 dependency is used under MIT, copyright
  2014–2026 Sean McArthur. Both license texts ship in `WorkflowNotices`.

Complete dependency and Rust standard-library notices, plus corresponding MPL
source archives, are included in `Contents/Resources/RuntimeNotices.tar.gz`.
The inventory and hashes are in `vendor/runtime-notices/`. Copy the archive
outside the app before unpacking it. The separate WorkflowNotices,
WebSocketNotices and BubblewrapSource materials must also be preserved.
