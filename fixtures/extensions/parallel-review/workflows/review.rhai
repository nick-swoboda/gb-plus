phase("Reviewing the same captured workspace in two isolated Grok children");
let question = if args.contains("question") { args.question } else { "Identify the main implementation risks and the relevant source files." };
let results = parallel([
    #{prompt: "Inspect this workspace for correctness concerns. " + question, agent_type: "explore", label: "Correctness"},
    #{prompt: "Inspect this workspace for regression risks and missing validation. " + question, agent_type: "plan", label: "Validation"}
]);
pause("user", "Review both child observations before completing this workflow.");
complete(results);
