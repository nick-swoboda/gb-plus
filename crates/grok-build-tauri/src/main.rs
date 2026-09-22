//! Process entry point for the Tauri 2 GB Plus shell.

use std::env;

#[cfg(target_os = "macos")]
fn main() {
    let mut arguments = env::args_os().skip(1);
    let result = match arguments.next() {
        Some(flag) if flag == "--tauri-smoke" && arguments.next().is_none() => {
            grok_build_tauri::smoke_tauri_host().map(|report| println!("{report}"))
        }
        Some(flag) if (flag == "--version" || flag == "-V") && arguments.next().is_none() => {
            println!("GB Plus {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some(flag) if flag == "--chrome-pipe-launcher" => {
            grok_build_tauri::run_chrome_pipe_launcher(arguments)
        }
        Some(flag) if flag == "--cli-standard-smoke" => {
            match (arguments.next(), arguments.next()) {
                (Some(root), None) => grok_build_tauri::smoke_cli_standard(std::path::Path::new(&root))
                    .map(|report| println!("{report}")),
                _ => Err("--cli-standard-smoke requires one new absolute fixture directory".into()),
            }
        }
        Some(flag) if flag == "--browser-smoke" => match (arguments.next(), arguments.next()) {
            (Some(state_root), None) => {
                let state_root = std::path::PathBuf::from(state_root);
                grok_build_tauri::smoke_browser(&state_root).map(|report| println!("{report}"))
            }
            (None, _) => {
                Err("--browser-smoke requires one absolute pre-provisioned state root".into())
            }
            (Some(_), Some(_)) => Err("--browser-smoke accepts exactly one state root".into()),
        },
        Some(flag) if flag == "--browser-network-smoke" => {
            match (arguments.next(), arguments.next()) {
                (Some(state_root), None) => {
                    let state_root = std::path::PathBuf::from(state_root);
                    grok_build_tauri::smoke_browser_network(&state_root)
                        .map(|report| println!("{report}"))
                }
                (None, _) => Err(
                    "--browser-network-smoke requires one absolute pre-provisioned state root"
                        .into(),
                ),
                (Some(_), Some(_)) => {
                    Err("--browser-network-smoke accepts exactly one state root".into())
                }
            }
        }
        None => grok_build_tauri::run(),
        Some(_) => Err(
            "usage: grok-build-tauri [--tauri-smoke|--browser-smoke STATE_ROOT|--browser-network-smoke STATE_ROOT|--version|-V]"
                .into(),
        ),
    };

    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    let mut arguments = env::args_os().skip(1);
    if arguments
        .next()
        .is_some_and(|flag| flag == "--version" || flag == "-V")
        && arguments.next().is_none()
    {
        println!("GB Plus {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    eprintln!("GB Plus requires macOS 15 or later.");
    std::process::exit(78);
}
