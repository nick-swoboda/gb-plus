use super::cli_interactions::*;
use serde_json::json;

fn permission() -> serde_json::Value {
    json!({"sessionId":"session-a","toolCall":{"toolCallId":"edit-1","kind":"edit","content":[{"type":"diff","path":"fact.txt","oldText":"before","newText":"after"}]},"options":[{"optionId":"yes","kind":"allow_once","name":"Allow once"},{"optionId":"no","kind":"reject_once","name":"Reject"}]})
}

#[test]
fn permission_selection_is_offered_exactly_once_and_cancel_overrides_ready_allow() {
    let hub = CliInteractions::default();
    let view = hub
        .register("session/request_permission", &json!(1), &permission())
        .unwrap();
    assert!(
        hub.answer(
            view.id,
            CliAnswer::Permission {
                option_id: "invented".into()
            }
        )
        .is_err()
    );
    assert!(hub.take_ready(false).unwrap().is_empty());
    hub.answer(
        view.id,
        CliAnswer::Permission {
            option_id: "yes".into(),
        },
    )
    .unwrap();
    assert!(
        hub.answer(
            view.id,
            CliAnswer::Permission {
                option_id: "yes".into()
            }
        )
        .is_err()
    );
    let response = hub.take_ready(true).unwrap();
    assert_eq!(
        response[0].response,
        json!({"outcome":{"outcome":"cancelled"}})
    );
    assert!(hub.take_ready(false).unwrap().is_empty());
    hub.close();
    assert!(
        hub.register("session/request_permission", &json!(2), &permission())
            .is_err()
    );
}

#[test]
fn permission_request_ids_can_collide_with_client_requests_but_not_each_other() {
    let hub = CliInteractions::default();
    let view = hub
        .register("session/request_permission", &json!(1), &permission())
        .unwrap();
    assert!(
        hub.register("session/request_permission", &json!(1), &permission())
            .is_err()
    );
    hub.answer(
        view.id,
        CliAnswer::Permission {
            option_id: "yes".into(),
        },
    )
    .unwrap();
    assert_eq!(
        hub.take_ready(false).unwrap()[0].response,
        json!({"outcome":{"outcome":"selected","optionId":"yes"}})
    );
    let mut malformed = permission();
    malformed["options"][1]["optionId"] = json!("yes");
    assert!(
        hub.register("session/request_permission", &json!(2), &malformed)
            .is_err()
    );
}

#[test]
fn question_answers_validate_choices_notes_and_plan_actions() {
    let hub = CliInteractions::default();
    let view = hub.register("_x.ai/ask_user_question", &json!("question"), &json!({"sessionId":"session-a","mode":"default","questions":[{"question":"Which?","options":[{"label":"Blue","description":"Cool","preview":"blue preview"}],"multiSelect":false}]})).unwrap();
    assert!(hub.answer(view.id, CliAnswer::SkipInterview).is_err());
    assert!(
        hub.answer(
            view.id,
            CliAnswer::Questions {
                answers: [("Which?".into(), vec!["Red".into()])].into(),
                notes: std::collections::BTreeMap::default()
            }
        )
        .is_err()
    );
    hub.answer(
        view.id,
        CliAnswer::Questions {
            answers: [("Which?".into(), vec!["Blue".into()])].into(),
            notes: [("Which?".into(), "Agreed".into())].into(),
        },
    )
    .unwrap();
    let result = hub.take_ready(false).unwrap().remove(0).response;
    assert_eq!(result["answers"]["Which?"], json!(["Blue"]));
    assert_eq!(result["annotations"]["Which?"]["preview"], "blue preview");
    assert_eq!(result["annotations"]["Which?"]["notes"], "Agreed");
}
