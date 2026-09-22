# Parallel review example

Preview this local directory in Extensions, inspect the immutable inventory and
script, and enable the workflow component for the selected project. Enabling it
does not run it. In Automations choose Run, optionally supplying JSON such as
`{"question":"Review the recovery paths."}`. Default maximum is eight Grok calls;
this example requests two read-only children.

The engine pauses after recording both results. Explicit Resume reuses completed
journal entries. Child proposals, when a different reviewed script uses Worker,
remain separate for review. Extensions, native machine tools, Browser, Capture,
Desktop and credentials are not inherited by these children. Project hook
restrictions remain in force. Temporary input/results cannot resume after app
restart. Non-Git projects execute their child models serially.

This example remains disabled until explicitly enabled for a project.
