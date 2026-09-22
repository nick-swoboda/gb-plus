#!/bin/sh
# Fixed offline protocol fixture: an interjection races the original turn end.
if [ "$1" = "--version" ]; then /usr/bin/printf 'grok 1.0.25 (fixture) [stable]\n'; exit 0; fi
history=0
while IFS= read -r line; do
  id=$(printf '%s' "$line" | /usr/bin/sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  case "$line" in
    *'"method":"initialize"'*)
      result='{"protocolVersion":1,"authMethods":[{"id":"cached_token"}],"_meta":{"x.ai/mcp/sdk":true,"mcpServers":[],"modelState":{"currentModelId":"fixture-model"}}}' ;;
    *'"method":"authenticate"'*) result='{}' ;;
    *'"method":"session/new"'*|*'"method":"session/load"'*) result='{"sessionId":"fixture-session"}' ;;
    *'"method":"_x.ai/session/rename"'*) result='{"success":true}' ;;
    *'"method":"_x.ai/session/info"'*)
      result='{"sessionId":"fixture-session","cwd":"'"$(pwd)"'","agentName":"grok-build-plus-gui","context":{"toolDefinitionsCount":2}}' ;;
    *'"method":"_x.ai/mcp/list"'*) result='{"servers":[{"name":"gbplus","source":"local","type":"stdio","command":"","session":{"enabled":true,"status":"ready","tools":[{"name":"browser_click","enabled":true},{"name":"browser_inspect","enabled":true},{"name":"browser_key","enabled":true},{"name":"browser_navigate","enabled":true},{"name":"browser_screenshot","enabled":true},{"name":"browser_scroll","enabled":true},{"name":"browser_type","enabled":true},{"name":"desktop_click","enabled":true},{"name":"desktop_key","enabled":true},{"name":"desktop_scroll","enabled":true},{"name":"desktop_type","enabled":true},{"name":"glob","enabled":true},{"name":"grep","enabled":true},{"name":"list_dir","enabled":true},{"name":"propose_replace","enabled":true},{"name":"propose_write","enabled":true},{"name":"read_file","enabled":true},{"name":"run_contained","enabled":true},{"name":"todo_write","enabled":true}]}}]}' ;;
    *'"method":"session/prompt"'*)
      /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"fixture-session","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"Original completion. "}}}}'
      result='{"stopReason":"end_turn"}' ;;
    *'"method":"_x.ai/interject"'*)
      # Queue echo is duplicated and does not prove model consumption.
      echo='{"jsonrpc":"2.0","method":"_x.ai/session/interjection","params":{"sessionId":"fixture-session","interjectionId":"steer-one","text":"GB Plus steering [steer-one]:\nFinish the follow-up."}}'
      /usr/bin/printf '%s\n' "$echo" "$echo"
      result='{"status":"queued"}' ;;
    *'"method":"_x.ai/session/updates"'*)
      history=$((history + 1))
      user='{"method":"session/update","params":{"sessionId":"fixture-session","update":{"sessionUpdate":"user_message_chunk","content":{"type":"text","text":"GB Plus steering [steer-one]:\nFinish the follow-up."}}}}'
      if [ "$history" -eq 1 ]; then
        result='{"updates":['"$user"'],"totalCount":1,"hasMore":false}'
      else
        /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"fixture-session","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"Follow-up completed."}}}}'
        terminal='{"method":"_x.ai/session/update","params":{"sessionId":"fixture-session","update":{"sessionUpdate":"turn_completed","prompt_id":"interject-fallback-fixture","stop_reason":"end_turn"}}}'
        result='{"updates":['"$user"','"$terminal"'],"totalCount":2,"hasMore":false}'
      fi ;;
    *'"method":"_x.ai/sessions/list"'*)
      if [ "$history" -eq 1 ]; then activity=working; else activity=idle; fi
      result='{"sessions":[{"sessionId":"fixture-session","cwd":"'"$(pwd)"'","yolo":false,"activity":"'"$activity"'"}]}' ;;
    *'"method":"_x.ai/session/close"'*)
      /usr/bin/printf 'closed\n' > close-observed.txt
      result='{"success":true,"outcome":"closed"}' ;;
    *) exit 17 ;;
  esac
  case "$line" in
    *'"method":"_x.ai/session/info"'*|*'"method":"_x.ai/mcp/list"'*|*'"method":"_x.ai/interject"'*|*'"method":"_x.ai/sessions/list"'*|*'"method":"_x.ai/session/close"'*) result='{"result":'"$result"'}' ;;
  esac
  /usr/bin/printf '%s\n' '{"jsonrpc":"2.0","id":'"$id"',"result":'"$result"'}'
done
