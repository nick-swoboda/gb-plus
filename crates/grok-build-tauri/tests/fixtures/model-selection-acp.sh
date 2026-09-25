#!/bin/sh
effort=xhigh
while IFS= read -r line; do
  printf '%s\n' "$line" >> requests.jsonl
  id=$(printf '%s' "$line" | /usr/bin/sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  case "$line" in
    *'"method":"_x.ai/models/list"'*)
      result='{"result":{"availableModels":[{"modelId":"grok-4.7","_meta":{"reasoningEfforts":[{"value":"high"},{"value":"xhigh"}]}}]}}' ;;
    *'"method":"session/new"'*)
      if [ -f legacy ]; then result='{"sessionId":"model-session"}'; else
        result='{"sessionId":"model-session","configOptions":[{"id":"model","type":"select","currentValue":"grok-4.7"},{"id":"reasoning_effort","type":"select","currentValue":"xhigh"}]}'
      fi ;;
    *'"method":"session/set_model"'*)
      if [ -f legacy ]; then effort=high; fi
      result='{"_meta":{"model":{"Ok":"grok-4.7"}}}' ;;
    *'"method":"session/set_config_option"'*)
      case "$line" in *'"configId":"reasoning_effort"'*) effort=high ;; esac
      if [ -f wrong-effort ]; then effort=xhigh; fi
      result='{"configOptions":[{"id":"model","type":"select","currentValue":"grok-4.7"},{"id":"reasoning_effort","type":"select","currentValue":"'"$effort"'"}]}' ;;
    *'"method":"_x.ai/session/info"'*)
      result='{"result":{"model":"grok-4.7"}}'
      if [ -f wrong-model ]; then result='{"result":{"model":"different-model"}}'; fi ;;
    *'"method":"_x.ai/session/state"'*)
      saved=xhigh
      if [ -f legacy ]; then saved=$effort; fi
      result='{"summary":{"reasoning_effort":"'"$saved"'"}}' ;;
    *) result='{}' ;;
  esac
  printf '%s\n' '{"jsonrpc":"2.0","id":'"$id"',"result":'"$result"'}'
done
