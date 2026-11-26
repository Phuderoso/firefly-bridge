"""What the retrieved public documents actually establish.

This module is a citation record, not a capability probe of a running agent.
"""

from __future__ import annotations

RETRIEVED = "2026-11-08"

CITATIONS = (
    {
        "id": "docs-headless",
        "title": "Headless & Scripting",
        "url": "https://docs.x.ai/build/cli/headless-scripting",
        "anchor": "published page, no git SHA; retrieved 2026-11-08",
        "establishes": (
            "grok agent stdio is JSON-RPC on stdin/stdout. The published example "
            "sends initialize (protocolVersion 1), authenticate, session/new, then "
            "session/prompt. Assistant text arrives as session/update chunks. "
            "session/prompt returns completion metadata. Headless --resume / --continue "
            "and --session-id are separate CLI session controls. --session-id on that "
            "page is described as create or resume; the user guide corrects -s to create-only."
        ),
    },
    {
        "id": "docs-sessions",
        "title": "Sessions",
        "url": "https://docs.x.ai/build/features/sessions",
        "anchor": "published page, no git SHA; retrieved 2026-11-08",
        "establishes": (
            "Sessions are stored under ~/.grok/sessions and 'work the same' in the TUI, "
            "headless mode, and over ACP. Resume is grok --resume or /resume. "
            "--fork-session branches a copy. Nothing on this page describes a second "
            "client joining a running TUI turn."
        ),
    },
    {
        "id": "docs-cli-ref",
        "title": "CLI Reference",
        "url": "https://docs.x.ai/build/cli/reference",
        "anchor": "published page, no git SHA; retrieved 2026-11-08",
        "establishes": (
            "Documents grok version, grok sessions list|search|delete, grok inspect, "
            "and grok agent stdio. Does not document a grok leader subcommand."
        ),
    },
    {
        "id": "docs-mcp",
        "title": "MCP Servers",
        "url": "https://docs.x.ai/build/features/mcp-servers",
        "anchor": "published page, no git SHA; retrieved 2026-11-08",
        "establishes": (
            "MCP exposes tools to Grok. It is not a channel for posting a peer "
            "message into an existing conversation."
        ),
    },
    {
        "id": "docs-hooks",
        "title": "Hooks",
        "url": "https://docs.x.ai/build/features/hooks",
        "anchor": "published page, no git SHA; retrieved 2026-11-08",
        "establishes": (
            "Hooks observe lifecycle events. They do not inject a peer turn. "
            "PreToolUse is fail-open except for an explicit deny. Not used here."
        ),
    },
    {
        "id": "guide-agent",
        "title": "User guide 15 — Agent mode",
        "url": "https://github.com/xai-org/grok-build/blob/main/crates/codegen/xai-grok-pager/docs/user-guide/15-agent-mode.md",
        "anchor": (
            "blob c025513e2821768e826ccdaec7eb77bb806a3337; "
            "last commit touching the path 72a61251fcffb464bcc687aeb5a998e5a98ec0c9 "
            "(2026-09-01, source revision a549186d9d39311f2d3ee4208db62af8c65aa476); "
            "contents API ref=main retrieved 2026-11-08"
        ),
        "establishes": (
            "--leader / --no-leader connects to a shared leader process or forces a "
            "local agent. Leader mode snoops configId model so each client's "
            "default_model stays in sync. That is not a session-join or busy-queue "
            "contract. x.ai/* methods are non-exhaustive and are not called here. "
            "The guide tells automation to start with --always-approve; this bridge "
            "never does that."
        ),
    },
    {
        "id": "guide-sessions",
        "title": "User guide 17 — Sessions",
        "url": "https://github.com/xai-org/grok-build/blob/main/crates/codegen/xai-grok-pager/docs/user-guide/17-sessions.md",
        "anchor": "blob 93b190805b0c2f0dfad58f130799348e33ae1b1b; contents API ref=main retrieved 2026-11-08",
        "establishes": (
            "ACP session/new creates a session. session/load loads an existing id. "
            "The guide says clients can reconnect and load previous sessions by ID, "
            "and that updates.jsonl drives /resume and session restore. Concurrent "
            "same-ID headless use is described as best-effort. grok sessions list "
            "prints id, dates, source status, and summary for the current directory. "
            "grok sessions search also uses remote results and is not part of the preflight."
        ),
    },
    {
        "id": "shell-readme",
        "title": "xai-grok-shell README",
        "url": "https://github.com/xai-org/grok-build/blob/main/crates/codegen/xai-grok-shell/README.md",
        "anchor": "blob 8fea7538fc7d1dee1cfb70df9ccbc18dcd70635e; contents API ref=main retrieved 2026-11-08",
        "establishes": (
            "Same session/new and session/load examples: load previous sessions by ID "
            "after automatic persistence. Not a statement that a second process "
            "attaches to a live TUI composer."
        ),
    },
    {
        "id": "acp-v1-load",
        "title": "ACP v1 session setup",
        "url": "https://agentclientprotocol.com/protocol/v1/session-setup",
        "anchor": "published page; retrieved 2026-11-08",
        "establishes": (
            "session/load is allowed only when initialize advertises loadSession. "
            "The agent MUST replay the conversation as session/update notifications. "
            "The page calls this persistence and sharing across client instances. "
            "Replay of stored history is not, by itself, attachment to a running turn."
        ),
    },
    {
        "id": "acp-prompt",
        "title": "ACP prompt turn",
        "url": "https://agentclientprotocol.com/protocol/prompt-turn",
        "anchor": "published page; retrieved 2026-11-08",
        "establishes": (
            "session/prompt carries sessionId and prompt content blocks. "
            "session/update may include an agent messageId; that id is assigned by "
            "the agent, not by the peer. session/cancel aborts the turn. "
            "session/request_permission is how a tool asks to proceed. "
            "No composer-buffer field and no peer-speaker field appear."
        ),
    },
    {
        "id": "acp-v1-permission",
        "title": "ACP v1 tool calls",
        "url": "https://agentclientprotocol.com/protocol/v1/tool-calls",
        "anchor": "published page; retrieved 2026-11-08",
        "establishes": (
            "Permission response is outcome selected plus optionId, or outcome "
            "cancelled. Kinds include allow_once, allow_always, reject_once, "
            "reject_always. Cancelled means the operation must not proceed."
        ),
    },
    {
        "id": "acp-v2-draft-prompt",
        "title": "ACP v2 draft prompt lifecycle",
        "url": "https://agentclientprotocol.com/protocol/v2/prompt-lifecycle",
        "anchor": "draft page; retrieved 2026-11-08; not Grok's published protocolVersion",
        "establishes": (
            "Draft text says a client MAY send session/prompt while foreground work "
            "is running, and that an agent MUST NOT reject a prompt only because "
            "work is active. Inserting during active work may steer the current "
            "turn or start the next one, and that choice is up to the agent. "
            "Grok's published example uses protocolVersion 1. This draft is not a "
            "queue guarantee and is not implemented by this bridge."
        ),
    },
)


def live_blockers() -> list[dict]:
    return [
        {
            "id": "attach",
            "status": "missing",
            "detail": (
                "No retrieved page states that an additional ACP client attaches to "
                "the in-memory session already open in the interactive TUI. "
                "session/load and grok --resume load persisted history (updates.jsonl / "
                "~/.grok/sessions). That is a copy or a restore, not live attachment."
            ),
        },
        {
            "id": "noninterruption",
            "status": "missing",
            "detail": (
                "No retrieved page documents a busy query or a queue that waits "
                "behind a human turn without steering it. session/cancel is specified "
                "as abort. The v2 draft, which Grok has not published as its version, "
                "explicitly allows a prompt during active work to steer the turn. "
                "Busy cannot be inferred. Non-interruption is not guaranteed."
            ),
        },
        {
            "id": "composer",
            "status": "missing",
            "detail": (
                "No retrieved page mentions the TUI draft line. Nothing establishes "
                "that a programmatic prompt leaves partially typed text untouched."
            ),
        },
        {
            "id": "speaker",
            "status": "missing",
            "detail": (
                "session/prompt is a user message. No documented field marks the "
                "sender as agent-a rather than the user. Attribution in this "
                "prototype stays on the local receipt."
            ),
        },
        {
            "id": "acceptance_ack",
            "status": "missing",
            "detail": (
                "Grok's headless page says session/prompt returns completion "
                "metadata at the end of the turn. There is no documented intermediate "
                "transport-accepted frame. The mock ack agent.mock/accepted is "
                "synthetic and is rejected as a reason to enable the live transport."
            ),
        },
        {
            "id": "leader_semantics",
            "status": "incomplete",
            "detail": (
                "--leader means connect to a shared leader process. The model-config "
                "snoop shows the proxy can see more than one client's model default. "
                "It does not name the RPC that selects the TUI's current session, "
                "and the docs.x.ai CLI reference does not document grok leader list. "
                "A previous empty leader list proved nothing was discovered then; "
                "it is not current availability and not impossibility."
            ),
        },
    ]
