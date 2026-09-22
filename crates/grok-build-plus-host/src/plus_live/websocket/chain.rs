//! Memory-only continuation. Every caller still supplies its full local context.
use serde_json::{Map, Value};
const MAX_BODY: usize = 12 * 1024 * 1024;
const MAX_ITEMS: usize = 8192;

#[derive(Default)]
pub(super) struct Chain {
    previous: Option<String>,
    input: Vec<Value>,
    parameters: Map<String, Value>,
}
impl Chain {
    pub(super) fn prepare(&self, body: &str) -> Result<Prepared, &'static str> {
        if body.len() > MAX_BODY {
            return Err("WebSocket input exceeds its bound.");
        }
        let value: Value =
            serde_json::from_str(body).map_err(|_| "Invalid local conversation request.")?;
        let mut object = value
            .as_object()
            .cloned()
            .ok_or("Conversation request is not an object.")?;
        if object.get("store") != Some(&Value::Bool(false))
            || object.contains_key("previous_response_id")
            || object.contains_key("type")
            || object.contains_key("generate")
        {
            return Err("WebSocket requires a complete local context with store:false.");
        }
        object.remove("stream");
        object.remove("background");
        let input = object
            .remove("input")
            .and_then(|v| v.as_array().cloned())
            .ok_or("Conversation input is not an array.")?;
        if input.len() > MAX_ITEMS {
            return Err("WebSocket input-item bound exceeded.");
        }
        let parameters = object.clone();
        // The admitted xAI endpoint rejects instructions together with a
        // previous_response_id. App instructions must remain explicit, so
        // start a fresh connection with full input instead of omitting them.
        let continuation = !parameters.contains_key("instructions")
            && self.previous.is_some()
            && self.parameters == parameters
            && input.starts_with(&self.input);
        let send = if continuation {
            object.insert(
                "previous_response_id".into(),
                Value::String(
                    self.previous
                        .clone()
                        .ok_or("Missing continuation identity.")?,
                ),
            );
            input[self.input.len()..].to_vec()
        } else {
            input.clone()
        };
        object.insert("input".into(), Value::Array(send));
        object.insert("type".into(), Value::String("response.create".into()));
        let wire =
            serde_json::to_string(&object).map_err(|_| "WebSocket request encoding failed.")?;
        if wire.len() > MAX_BODY {
            return Err("WebSocket wire request exceeds its bound.");
        }
        Ok(Prepared {
            wire,
            input,
            parameters,
            fresh_connection: self.previous.is_some() && !continuation,
        })
    }
    pub(super) fn completed(
        &mut self,
        prepared: Prepared,
        response: &Value,
    ) -> Result<(), &'static str> {
        let id = response
            .get("id")
            .and_then(Value::as_str)
            .ok_or("Completion lacks identity.")?;
        let output = response
            .get("output")
            .and_then(Value::as_array)
            .ok_or("Completion lacks output.")?;
        if id.is_empty()
            || id.len() > 256
            || id.chars().any(char::is_control)
            || response["status"] != "completed"
            || prepared.input.len() + output.len() > MAX_ITEMS
        {
            return Err("Completion cannot establish a bounded continuation.");
        }
        let mut input = prepared.input;
        input.extend(output.iter().cloned());
        if serde_json::to_vec(&input)
            .map_err(|_| "Continuation encoding failed.")?
            .len()
            > MAX_BODY
        {
            return Err("WebSocket continuation exceeds its bound.");
        }
        self.previous = Some(id.into());
        self.input = input;
        self.parameters = prepared.parameters;
        Ok(())
    }
}
pub(super) struct Prepared {
    pub(super) wire: String,
    pub(super) fresh_connection: bool,
    input: Vec<Value>,
    parameters: Map<String, Value>,
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn body(input: Value) -> String {
        let mut request = json!({"model":"synthetic","store":false,"tools":[]});
        request["input"] = input;
        request.to_string()
    }
    #[test]
    fn exact_prefix_uses_delta_but_reconnection_and_compaction_rebuild_locally() {
        let user = json!({"role":"user","content":"artificial fact"});
        let call =
            json!({"type":"function_call","call_id":"call-1","name":"read_file","arguments":"{}"});
        let result =
            json!({"type":"function_call_output","call_id":"call-1","output":"exact result"});
        let mut chain = Chain::default();
        let initial = chain.prepare(&body(json!([user]))).unwrap();
        assert!(!initial.wire.contains("previous_response_id"));
        chain
            .completed(
                initial,
                &json!({"id":"response-1","status":"completed","output":[call]}),
            )
            .unwrap();
        let full = body(json!([user, call, result]));
        let delta: Value = serde_json::from_str(&chain.prepare(&full).unwrap().wire).unwrap();
        assert_eq!(delta["input"], json!([result]));
        assert_eq!(delta["previous_response_id"], "response-1");
        let rebuilt: Value =
            serde_json::from_str(&Chain::default().prepare(&full).unwrap().wire).unwrap();
        assert_eq!(rebuilt["input"], json!([user, call, result]));
        assert!(rebuilt.get("previous_response_id").is_none());
        let compact = json!([{"type":"compaction","encrypted_content":"OPAQUE"},result]);
        let reset: Value =
            serde_json::from_str(&chain.prepare(&body(compact.clone())).unwrap().wire).unwrap();
        assert_eq!(reset["input"], compact);
        assert!(reset.get("previous_response_id").is_none());
    }
    #[test]
    fn changed_context_parameters_and_foreign_response_ids_never_reuse_a_chain() {
        let mut chain = Chain::default();
        let request = chain
            .prepare(&body(json!([{"role":"user","content":"old"}])))
            .unwrap();
        chain
            .completed(request, &json!({"id":"r","status":"completed","output":[]}))
            .unwrap();
        let mut changed: Value = serde_json::from_str(&body(
            json!([{"role":"user","content":"old"},{"role":"user","content":"new"}]),
        ))
        .unwrap();
        changed["model"] = json!("changed");
        assert!(
            !chain
                .prepare(&changed.to_string())
                .unwrap()
                .wire
                .contains("previous_response_id")
        );
        changed["previous_response_id"] = json!("foreign");
        assert!(chain.prepare(&changed.to_string()).is_err());
        changed
            .as_object_mut()
            .unwrap()
            .remove("previous_response_id");
        changed["store"] = json!(true);
        assert!(chain.prepare(&changed.to_string()).is_err());
    }

    #[test]
    fn explicit_app_instructions_always_reconstruct_the_full_local_context() {
        let user = json!({"role":"user","content":"fictional inventory"});
        let call =
            json!({"type":"function_call","call_id":"read-1","name":"read_file","arguments":"{}"});
        let output =
            json!({"type":"function_call_output","call_id":"read-1","output":"recorded fact"});
        let mut request: Value = serde_json::from_str(&body(json!([user]))).unwrap();
        request["instructions"] = json!("Explicit application policy");
        let mut chain = Chain::default();
        chain
            .completed(
                chain.prepare(&request.to_string()).unwrap(),
                &json!({"id":"r1","status":"completed","output":[call]}),
            )
            .unwrap();
        request["input"] = json!([user, call, output]);
        let wire: Value =
            serde_json::from_str(&chain.prepare(&request.to_string()).unwrap().wire).unwrap();
        assert!(wire.get("previous_response_id").is_none());
        assert!(
            chain
                .prepare(&request.to_string())
                .unwrap()
                .fresh_connection
        );
        assert_eq!(wire["instructions"], request["instructions"]);
        assert_eq!(wire["input"], request["input"]);
        assert_eq!(wire["store"], false);
    }
}
