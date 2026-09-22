use super::*;
use serde_json::json;
use std::cell::RefCell;
use std::fmt::Write as _;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Default)]
struct Host {
    calls: RefCell<Vec<(u64, HostCall)>>,
    refuse: bool,
    output: Value,
}
impl WorkflowHost for Host {
    fn call(&self, sequence: u64, request: HostCall, _: &CancelCheck) -> Result<HostReply, String> {
        self.calls.borrow_mut().push((sequence, request));
        if self.refuse {
            Err("Uncertain effect refuses replay".into())
        } else {
            Ok(HostReply {
                value: self.output.clone(),
                replayed: false,
            })
        }
    }
}
fn run(script: &str) -> WorkflowOutcome {
    run_workflow(
        script,
        &json!({"a":19,"b":23}),
        Rc::new(Host::default()),
        Arc::new(|| false),
    )
}
fn failed(outcome: &WorkflowOutcome) -> bool {
    matches!(outcome, WorkflowOutcome::Failed { .. })
}

#[test]
fn pure_language_and_explicit_complete_preserve_exact_json() {
    assert_eq!(
        run("#{answer: args.a + args.b, labels:[\"one\",\"two\"]}"),
        WorkflowOutcome::Completed {
            result: json!({"answer":42,"labels":["one","two"]})
        }
    );
    assert_eq!(
        run("complete(42); agent(\"unreachable\")"),
        WorkflowOutcome::Completed { result: json!(42) }
    );
    assert_eq!(
        run("pause(\"verification\",\"Review the child proposal\");"),
        WorkflowOutcome::Paused {
            kind: "verification".into(),
            message: "Review the child proposal".into()
        }
    );
    assert!(failed(&run("pause(\"automatic_retry\",\"wrong\")")));
}

#[test]
fn ambient_io_dynamic_code_clocks_sleep_and_unknown_hosts_refuse() {
    for script in [
        "eval(\"42\")",
        "Fn(\"eval\").call(\"42\")",
        "import \"fixture.rhai\" as f;",
        "read_file(\"/etc/passwd\")",
        "write_file(\"fixture\",\"x\")",
        "timestamp()",
        "sleep(1)",
        "sleep(0.001)",
        "Fn(\"sleep\").call(1)",
        "1.sleep()",
        "git_diff_since(\"HEAD\")",
        "telemetry(\"event\",#{})",
        "render_template(\"file\",#{})",
        "exit()",
    ] {
        assert!(failed(&run(script)), "{script}");
    }
}

#[test]
fn independent_operation_recursion_variable_and_collection_limits_apply() {
    for script in [
        "loop {}",
        "fn f() { f() } f()",
        "let a=[]; loop {a.push(0);}",
        "let s=\"abcdefghijklmnop\"; loop {s+=s;}",
    ] {
        assert!(failed(&run(script)));
    }
    assert!(failed(&run(&format!(
        "{}1{}",
        "(".repeat(100),
        ")".repeat(100)
    ))));
    let mut variables = String::new();
    let mut functions = String::new();
    for i in 0..160 {
        write!(variables, "let v{i}={i};").unwrap();
    }
    for i in 0..40 {
        writeln!(functions, "fn f{i}() {{ {i} }}").unwrap();
    }
    assert!(failed(&run(&variables)));
    assert!(failed(&run(&functions)));
    assert!(failed(&run(&"let x=1;".repeat(9000))));
    let mut nested = json!(0);
    for _ in 0..25 {
        nested = json!([nested]);
    }
    for args in [nested, json!(vec![0; 1025]), json!("x".repeat(MAX_BYTES))] {
        assert!(matches!(
            run_workflow("args", &args, Rc::new(Host::default()), Arc::new(|| false)),
            WorkflowOutcome::Failed { .. }
        ));
    }
}

#[test]
fn host_requests_are_typed_sequenced_and_do_not_accept_authority_fields() {
    let host = Rc::new(Host {
        output: json!({"success":true}),
        ..Host::default()
    });
    let result = run_workflow(
        "phase(\"Inspect\"); let a=agent(\"read\",#{agent_type:\"plan\"}); log(\"done\"); a",
        &json!({}),
        host.clone(),
        Arc::new(|| false),
    );
    assert_eq!(
        result,
        WorkflowOutcome::Completed {
            result: json!({"success":true})
        }
    );
    assert_eq!(
        host.calls.borrow().iter().map(|c| c.0).collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    for extra in [
        "model:\"foreign\"",
        "workspace:\"/\"",
        "fork_context:true",
        "resume_from:\"foreign\"",
        "agent_type:\"parent\"",
        "permission:\"allow\"",
    ] {
        let host = Rc::new(Host::default());
        assert!(failed(&run_workflow(
            &format!("agent(\"read\",#{{{extra}}})"),
            &json!({}),
            host.clone(),
            Arc::new(|| false)
        )));
        assert!(host.calls.borrow().is_empty());
    }
}

#[test]
fn parallel_preflight_is_all_or_none_and_bounded() {
    let host = Rc::new(Host {
        output: json!(["first", "second"]),
        ..Host::default()
    });
    let result = run_workflow(
        "parallel([#{prompt:\"one\",agent_type:\"explore\"},#{prompt:\"two\",agent_type:\"worker\"}])",
        &json!({}),
        host.clone(),
        Arc::new(|| false),
    );
    assert_eq!(
        result,
        WorkflowOutcome::Completed {
            result: json!(["first", "second"])
        }
    );
    assert_eq!(host.calls.borrow().len(), 1);
    for script in [
        "parallel([])",
        "parallel([#{prompt:\"ok\"},#{prompt:\"bad\",model:\"foreign\"}])",
        "let xs=[]; for n in 0..9 {xs.push(#{prompt:\"x\"});} parallel(xs)",
    ] {
        let host = Rc::new(Host::default());
        assert!(failed(&run_workflow(
            script,
            &json!({}),
            host.clone(),
            Arc::new(|| false)
        )));
        assert!(host.calls.borrow().is_empty());
    }
}

#[test]
fn effect_failure_cannot_be_caught_to_continue_uncertain_work() {
    let host = Rc::new(Host {
        refuse: true,
        ..Host::default()
    });
    assert!(failed(&run_workflow(
        "try {agent(\"first\");} catch (e) {agent(\"second\");} agent(\"third\");",
        &json!({}),
        host.clone(),
        Arc::new(|| false)
    )));
    assert_eq!(host.calls.borrow().len(), 1);
}

#[test]
fn host_call_count_output_and_scratch_contract_are_bounded() {
    let host = Rc::new(Host::default());
    assert!(failed(&run_workflow(
        "for n in 0..300 {budget();}",
        &json!({}),
        host.clone(),
        Arc::new(|| false)
    )));
    assert_eq!(host.calls.borrow().len(), 256);
    let host = Rc::new(Host {
        output: json!("x".repeat(MAX_BYTES)),
        ..Host::default()
    });
    assert!(failed(&run_workflow(
        "agent(\"read\")",
        &json!({}),
        host,
        Arc::new(|| false)
    )));
    for script in [
        "read_scratch_file(\"../file\")",
        "write_scratch_file(\"/tmp/x\",\"a\")",
        "read_scratch_file(\"..\")",
    ] {
        assert!(failed(&run(script)));
    }
}

#[test]
fn cancellation_applies_before_and_after_the_bounded_host_boundary() {
    struct CancelHost(Arc<AtomicBool>);
    impl WorkflowHost for CancelHost {
        fn call(&self, _: u64, _: HostCall, _: &CancelCheck) -> Result<HostReply, String> {
            self.0.store(true, Ordering::Release);
            Ok(HostReply {
                value: json!("completed before cancel"),
                replayed: false,
            })
        }
    }
    assert_eq!(
        run_workflow(
            "42",
            &json!({}),
            Rc::new(Host::default()),
            Arc::new(|| true)
        ),
        WorkflowOutcome::Cancelled
    );
    let flag = Arc::new(AtomicBool::new(false));
    let observed = flag.clone();
    assert_eq!(
        run_workflow(
            "agent(\"read\"); agent(\"never\");",
            &json!({}),
            Rc::new(CancelHost(flag)),
            Arc::new(move || observed.load(Ordering::Acquire))
        ),
        WorkflowOutcome::Cancelled
    );
}
