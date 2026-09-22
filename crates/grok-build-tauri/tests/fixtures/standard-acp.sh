#!/bin/sh
printf '%s\n' "$*" >> starts.txt
printf '%s\n' "$HOME" "$GROK_HOME" > launch-home.txt
write_effect() {
  printf '%s' "$2" > "$1.tmp" && /bin/mv "$1.tmp" "$1"
}
outer=9000
while IFS= read -r line; do
  printf '%s\n' "$line" >> requests.jsonl
  id=$(printf '%s' "$line" | /usr/bin/sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  case "$line" in
    *'"method":"initialize"'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":'"$id"',"result":{"protocolVersion":1,"agentCapabilities":{"promptCapabilities":{"image":true}},"authMethods":[{"id":"cached_token"}],"_meta":{"agentVersion":"9.7.6","x.ai/mcp/sdk":true,"mcpServers":[{"name":"user-configured"}],"modelState":{"currentModelId":"custom/model"}}}}'
      ;;
    *'"method":"authenticate"'*)
      printf '%s\n' '{"jsonrpc":"2.0","id":'"$id"',"result":{}}'
      ;;
    *'"method":"session/new"'*|*'"method":"session/load"'*)
      server=$(printf '%s' "$line" | /usr/bin/sed -n 's/.*"serverId":"\([^"]*\)".*/\1/p')
      outer=$((outer + 1))
      printf '%s\n' '{"jsonrpc":"2.0","id":'"$outer"',"method":"_x.ai/mcp/sdk_call","params":{"serverId":"'"$server"'","message":{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}}}'
      IFS= read -r reply
      printf '%s\n' '{"jsonrpc":"2.0","method":"_x.ai/mcp_initialized","params":{"sessionId":"shared-session","mcpToolCount":40}}'
      if [ -f ask-on-start ]; then
        startup_id=$id
        printf '%s\n' '{"jsonrpc":"2.0","id":9901,"method":"session/request_permission","params":{"sessionId":"shared-session","toolCall":{"toolCallId":"startup-edit","title":"Session-start edit","kind":"edit","content":[{"type":"diff","path":"startup-effect.txt","oldText":null,"newText":"accepted"}]},"options":[{"optionId":"yes","name":"Allow once","kind":"allow_once"},{"optionId":"no","name":"Reject","kind":"reject_once"}]}}'
        continue
      fi
      printf '%s\n' '{"jsonrpc":"2.0","id":'"$id"',"result":{"sessionId":"shared-session"}}'
      ;;
    *'"method":"session/prompt"'*)
      case "$line" in *'wait-forever'*) waiting_id=$id; continue ;; esac
      case "$line" in *'continuation-fixture'*)
        continuation=working
        printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"shared-session","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"First reply. "}}}}'
        printf '%s\n' '{"jsonrpc":"2.0","id":'"$id"',"result":{"stopReason":"end_turn"}}'
        continue ;;
      esac
      case "$line" in *'background-fixture'*)
        background=ready
        printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"shared-session","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"Background started"}}}}'
        printf '%s\n' '{"jsonrpc":"2.0","id":'"$id"',"result":{"stopReason":"end_turn"}}'
        continue ;;
      esac
      case "$line" in *'permission-fixture'*)
        waiting_id=$id
        printf '%s\n' '{"jsonrpc":"2.0","id":'"$id"',"method":"session/request_permission","params":{"sessionId":"shared-session","toolCall":{"toolCallId":"edit-1","title":"Edit fixture","kind":"edit","content":[{"type":"diff","path":"permission-effect.txt","oldText":null,"newText":"accepted"}]},"options":[{"optionId":"allow-edits-session","name":"Allow all edits this session","kind":"allow_always"},{"optionId":"yes","name":"Allow once","kind":"allow_once"},{"optionId":"no","name":"Reject","kind":"reject_once"}]}}'
        continue ;;
      esac
      count=0
      while [ "$count" -lt 9 ]; do
        outer=$((outer + 1))
        printf '%s\n' '{"jsonrpc":"2.0","id":'"$outer"',"method":"_x.ai/mcp/sdk_call","params":{"serverId":"'"$server"'","message":{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"fact.txt"}}}}}'
        IFS= read -r reply
        case "$reply" in *'"isError":true'*|*'"error":'*) exit 31 ;; esac
        count=$((count + 1))
      done
      printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"shared-session","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"native and app tools ready"}}}}'
      printf '%s\n' '{"jsonrpc":"2.0","id":'"$id"',"result":{"stopReason":"end_turn"}}'
      ;;
    *'"outcome":"selected"'*)
      if [ -n "$startup_id" ]; then
        case "$line" in *'"optionId":"yes"'*) write_effect startup-effect.txt accepted || exit 1 ;; esac
        printf '%s\n' '{"jsonrpc":"2.0","id":'"$startup_id"',"result":{"sessionId":"shared-session"}}'
        startup_id=''
        continue
      fi
      if [ "$background" = waiting ]; then
        case "$line" in *'"optionId":"yes"'*) write_effect background-effect.txt 'background accepted' || exit 1 ;; esac
        background=completed
        printf '%s\n' '{"jsonrpc":"2.0","method":"_x.ai/session/update","params":{"sessionId":"shared-session","update":{"sessionUpdate":"background_tasks","tasks":[],"truncated":false}}}'
        printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"shared-session","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"Background finished"}}}}'
        continue
      fi
      if [ -z "$waiting_id" ]; then continue; fi
      case "$line" in *'"optionId":"yes"'*|*'"optionId":"allow-edits-session"'*) write_effect permission-effect.txt accepted || exit 1 ;; esac
      printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"shared-session","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"permission finished"}}}}'
      printf '%s\n' '{"jsonrpc":"2.0","id":'"$waiting_id"',"result":{"stopReason":"end_turn"}}'
      waiting_id=''
      ;;
    *'"method":"_x.ai/sessions/list"'*)
      if [ "$continuation" = working ]; then
        continuation=finished
        printf '%s\n' '{"jsonrpc":"2.0","id":'"$id"',"result":{"result":{"sessions":[{"sessionId":"shared-session","cwd":"'"$(pwd)"'","activity":"working","resident":true,"yolo":false}]}}}'
        printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"shared-session","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"CLI continuation."}}}}'
        continue
      fi
      printf '%s\n' '{"jsonrpc":"2.0","id":'"$id"',"result":{"result":{"sessions":[{"sessionId":"shared-session","cwd":"'"$(pwd)"'","activity":"idle","resident":true,"yolo":false}]}}}'
      if [ -f crash-after-idle ]; then /bin/rm crash-after-idle; exit 0; fi
      if [ "$background" = ready ]; then
        background=waiting
        printf '%s\n' '{"jsonrpc":"2.0","method":"_x.ai/session/update","params":{"sessionId":"shared-session","update":{"sessionUpdate":"background_tasks","tasks":[{"task_id":"task-1","description":"Fixture background task","status":"running"}],"truncated":false}}}'
        printf '%s\n' '{"jsonrpc":"2.0","id":9900,"method":"session/request_permission","params":{"sessionId":"shared-session","toolCall":{"toolCallId":"background-edit","title":"Background edit","kind":"edit","content":[{"type":"diff","path":"background-effect.txt","oldText":null,"newText":"background accepted"}]},"options":[{"optionId":"yes","name":"Allow once","kind":"allow_once"},{"optionId":"no","name":"Reject","kind":"reject_once"}]}}'
      fi
      ;;
    *'"method":"_x.ai/session/close"'*)
      printf '%s\n' 'closed' >> closed-sessions.txt
      printf '%s\n' '{"jsonrpc":"2.0","id":'"$id"',"result":{"result":{"success":true,"outcome":"closed"}}}'
      ;;
    *'"method":"session/cancel"'*)
      if [ -n "$waiting_id" ]; then
        printf '%s\n' '{"jsonrpc":"2.0","id":'"$waiting_id"',"result":{"stopReason":"cancelled"}}'
        waiting_id=''
      fi
      ;;
  esac
done
