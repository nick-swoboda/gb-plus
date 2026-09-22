//! Development example used only through an admitted contained-service lease.
//!
//! `--mcp` reports a bounded workspace inventory. `--hook` protects Cargo.lock.
//! Neither mode accepts a command, accesses credentials or starts a process.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::Path;

use serde_json::{Value, json};

const MAX_INPUT: usize = 64 * 1024;

fn line(input: &mut impl std::io::BufRead) -> Result<Option<Value>, String> {
    let mut bytes = Vec::new();
    loop {
        let buffer = input.fill_buf().map_err(|error| error.to_string())?;
        if buffer.is_empty() {
            return if bytes.is_empty() {
                Ok(None)
            } else {
                Err("Input ended inside a JSON line.".into())
            };
        }
        let count = buffer
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(buffer.len(), |n| n + 1);
        if bytes.len() + count > MAX_INPUT {
            return Err("Input exceeds 64 KiB.".into());
        }
        bytes.extend_from_slice(&buffer[..count]);
        input.consume(count);
        if bytes.last() == Some(&b'\n') {
            return serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|error| error.to_string());
        }
    }
}

fn write(output: &mut impl std::io::Write, value: &Value) -> Result<(), String> {
    let mut bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    output
        .write_all(&bytes)
        .and_then(|()| output.flush())
        .map_err(|error| error.to_string())
}

fn inventory() -> Result<Value, String> {
    let mut directories = vec![std::path::PathBuf::from("/workspace")];
    let mut files = 0_usize;
    let mut entries = 0_usize;
    let mut bytes = 0_u64;
    let mut suffixes = BTreeMap::<String, usize>::new();
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(directory).map_err(|error| error.to_string())? {
            entries += 1;
            if entries > 16_384 {
                return Err("Workspace inventory exceeds 16,384 entries.".into());
            }
            let entry = entry.map_err(|error| error.to_string())?;
            let metadata = entry
                .path()
                .symlink_metadata()
                .map_err(|error| error.to_string())?;
            if metadata.is_dir() {
                directories.push(entry.path());
            } else if metadata.is_file() {
                files += 1;
                bytes = bytes
                    .checked_add(metadata.len())
                    .ok_or("Inventory byte count overflowed.")?;
                let suffix = entry
                    .path()
                    .extension()
                    .and_then(std::ffi::OsStr::to_str)
                    .filter(|s| s.len() <= 24 && s.bytes().all(|b| b.is_ascii_alphanumeric()))
                    .unwrap_or("other")
                    .to_ascii_lowercase();
                if suffixes.len() >= 128 && !suffixes.contains_key(&suffix) {
                    return Err("Workspace inventory exceeds 128 suffixes.".into());
                }
                *suffixes.entry(suffix).or_default() += 1;
            } else {
                return Err("Workspace view contains a link or special file.".into());
            }
        }
    }
    Ok(json!({"files":files,"bytes":bytes,"suffixCounts":suffixes}))
}

fn serve(
    input: &mut impl std::io::BufRead,
    output: &mut impl std::io::Write,
) -> Result<(), String> {
    let mut initialized = false;
    for _ in 0..256 {
        let Some(message) = line(input)? else {
            return Ok(());
        };
        if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") || !message.is_object() {
            return Err("Expected JSON-RPC 2.0.".into());
        }
        let method = message
            .get("method")
            .and_then(Value::as_str)
            .ok_or("Method is absent.")?;
        let Some(id) = message.get("id") else {
            if !matches!(
                method,
                "notifications/initialized" | "notifications/cancelled"
            ) {
                return Err("Unsupported notification.".into());
            }
            continue;
        };
        if !(id.is_i64() || id.is_u64() || id.as_str().is_some_and(|s| s.len() <= 128)) {
            return Err("Invalid request ID.".into());
        }
        let result = match method {
            "initialize" if !initialized => {
                let version = message
                    .pointer("/params/protocolVersion")
                    .and_then(Value::as_str);
                if !matches!(version, Some("2025-11-25" | "2025-06-18")) {
                    return Err("Unsupported MCP protocol version.".into());
                }
                initialized = true;
                Ok(
                    json!({"protocolVersion":version,"capabilities":{"tools":{}},
                    "serverInfo":{"name":"gbplus-contained-inventory","version":"1.0.0"}}),
                )
            }
            "ping" => Ok(json!({})),
            "tools/list" if initialized => Ok(json!({"tools":[{
                "name":"workspace_inventory","description":"Count regular files and bytes in the captured read-only workspace, grouped by file suffix. Does not read file contents.",
                "inputSchema":{"type":"object","properties":{},"additionalProperties":false},
                "annotations":{"readOnlyHint":true,"destructiveHint":false,"openWorldHint":false}
            }]})),
            "tools/call"
                if initialized
                    && message.pointer("/params/name").and_then(Value::as_str)
                        == Some("workspace_inventory")
                    && message
                        .pointer("/params/arguments")
                        .and_then(Value::as_object)
                        .is_some_and(serde_json::Map::is_empty) =>
            {
                let result = inventory();
                Ok(json!({"content":[{"type":"text","text":match &result {
                        Ok(value) => value.to_string(), Err(error) => error.clone()
                    }}],"isError":result.is_err()}))
            }
            _ => Err("Unsupported or uninitialized request."),
        };
        write(
            output,
            &match result {
                Ok(result) => json!({"jsonrpc":"2.0","id":id,"result":result}),
                Err(message) => {
                    json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":message}})
                }
            },
        )?;
    }
    Err("Example server reached its 256-message limit.".into())
}

fn hook(input: &mut impl std::io::BufRead, output: &mut impl std::io::Write) -> Result<(), String> {
    let message = line(input)?.ok_or("Hook input is absent.")?;
    if message.get("hook_event_name").and_then(Value::as_str) != Some("PreToolUse") {
        return Err("This example supports only PreToolUse.".into());
    }
    let tool = message
        .get("tool_name")
        .and_then(Value::as_str)
        .ok_or("Tool name is absent.")?;
    let path = message.pointer("/tool_input/path").and_then(Value::as_str);
    if matches!(tool, "propose_write" | "propose_replace")
        && path.is_some_and(|path| {
            Path::new(path).file_name() == Some(std::ffi::OsStr::new("Cargo.lock"))
        })
    {
        write(
            output,
            &json!({"hookSpecificOutput":{"hookEventName":"PreToolUse",
            "permissionDecision":"deny","permissionDecisionReason":"The enabled example hook protects Cargo.lock; review dependency changes separately."}}),
        )?;
    }
    Ok(()) // Successful hooks are quiet; normal app authority still applies.
}

fn main() -> std::process::ExitCode {
    let mode = std::env::args().skip(1).collect::<Vec<_>>();
    let result = match mode.as_slice() {
        [mode] if mode == "--mcp" => {
            serve(&mut std::io::stdin().lock(), &mut std::io::stdout().lock())
        }
        [mode] if mode == "--hook" => {
            hook(&mut std::io::stdin().lock(), &mut std::io::stdout().lock())
        }
        _ => Err("Select exactly --mcp or --hook.".into()),
    };
    if let Err(error) = result {
        let _ = writeln!(std::io::stderr(), "Contained extension refused: {error}");
        return std::process::ExitCode::from(2);
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_and_catalog_require_initialization_without_reading_the_workspace() {
        let messages = [
            json!({"jsonrpc":"2.0","id":0,"method":"tools/list","params":{}}),
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"shell","arguments":{}}}),
        ];
        let input = messages
            .iter()
            .map(|message| format!("{message}\n"))
            .collect::<String>();
        let mut output = Vec::new();
        serve(&mut std::io::Cursor::new(input), &mut output).unwrap();
        let replies = output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(replies.len(), 4);
        assert!(replies[0].get("error").is_some());
        assert_eq!(replies[1]["result"]["protocolVersion"], "2025-11-25");
        assert_eq!(
            replies[2]["result"]["tools"][0]["name"],
            "workspace_inventory"
        );
        assert!(replies[3].get("error").is_some());
    }

    #[test]
    fn the_hook_denies_dependency_lock_changes_and_keeps_success_quiet() {
        for (tool, path, denied) in [
            ("propose_write", "Cargo.lock", true),
            ("propose_replace", "nested/Cargo.lock", true),
            ("read_file", "Cargo.lock", false),
            ("propose_write", "src/main.rs", false),
        ] {
            let input = format!(
                "{}\n",
                json!({"hook_event_name":"PreToolUse","tool_name":tool,"tool_input":{"path":path}})
            );
            let mut output = Vec::new();
            hook(&mut std::io::Cursor::new(input), &mut output).unwrap();
            if denied {
                let result: Value = serde_json::from_slice(&output).unwrap();
                assert_eq!(result["hookSpecificOutput"]["permissionDecision"], "deny");
            } else {
                assert!(output.is_empty());
            }
        }
    }

    #[test]
    fn partial_and_oversized_input_refuses_without_waiting_for_another_line() {
        for input in [b"{\"incomplete\":".to_vec(), vec![b'x'; MAX_INPUT + 1]] {
            assert!(line(&mut std::io::Cursor::new(input)).is_err());
        }
        assert!(line(&mut std::io::Cursor::new(b"")).unwrap().is_none());
    }
}
