# Reply recovery seam — RC4

No real Grok `chat_history` API has been proven in this repository. The shipping
`UnavailableChatHistory` adapter is explicitly unavailable and performs **no RPC,
file read, screen scrape or prompt**. This is an interface + safe stub, not a
claim of live reply recovery. Tests use synthetic adapters only.

`AcpSession(chat_history=...)` accepts a `ChatHistory` implementation. A separately
proven and authorized read-only implementation must declare `proven_read_only=True`
and implement `recover_reply(ReplyLocator) -> HistoryReply | None`. No config
option bypasses API proof or builds a URL/method out of user text.

Locator pins session ID, incarnation, initiator-issued turn ID and nonce,
message ID, authenticated sender and byte limit. A result must echo the exact
locator. Wrong origin, missing evidence, exceptions and oversized content are
rejected without echoing raw errors. A real adapter must also enforce these
constraints server-side, including permitted offsets/digests if its documented
API needs them, and may not search or export another session's history. Do not
install an adapter before that API and authorization have actually been verified.

Recovery is attempted once per verified terminal when:
- no complete reply was captured;
- a correlated chunk failed parsing, had a sequence gap/invalid 1-based start,
  or an attested terminal chunkCount mismatched (or the RPC parser saw malformed frames);
- captured content failed redaction or hit the reply limit.

Only **after terminal ownership is already attested** does history run. A malformed
or unverified terminal stays unknown; history cannot fabricate completion, take a
turn, approve tools, cancel, release the queue, or resend. Duplicate terminal reads
reuse an in-memory result rather than querying repeatedly.

Recovered text must pass the same redactor. Successfully rendered content carries
an internal typed marker so later serialization does not reparse it or confuse
content-rendering failure with typed protocol metadata. If the redactor still fails, content
is `[REDACTION_FAILED]`, `reply_verified=false`; no raw fallback. Unavailable or
unproven adapters yield `reply_recovery_unavailable`. Successful synthetic/proven
adapter results use `recovered_chat_history`. Core protocol metadata is validated
and preserved separately: original ID, sender, turn ID, terminal state and consumed
claim survive redactor failure and restart. Ledger lookups reconstruct these from
columns even if an RC1 receipt JSON contains failed-redaction markers.

Replies remain owner-only and bounded in memory, not a persisted history cache.
The interface does not itself provide restart-time history lookup or a real
scheduler API. Those operational capabilities remain open pending proven APIs.

RC4 separates reply_origin_verified, reply_stream_contiguous and reply_complete.
A contiguous rendered stream with no terminal count may remain reply_verified
(origin/content check), but reply_complete is false/unproven. An attested matching
chunkCount or a trusted adapter returning the entire logical reply is required
for reply_complete=true. The adapter's promise of full content is part of its
trusted contract, not a capability manufactured by a model or user text. The
shipping stub cannot fulfill it. No unseen tail can be ruled out from monotonic
chunk IDs alone. Recovery never alters remote terminal/claim evidence.

## Authority loss (RC5)

A missing/replaced/generation-changed/non-exclusive authority lock latches the
incarnation closed. It cannot silently reacquire or approve; only an offered
reject_once may be selected on an exactly owned permission, otherwise silence.
A committed/ambiguous turn remains consumed and unresolved until real terminal
proof; losing a filesystem lock is not delivery failure or cancellation proof.
Stop the affected broker and reconcile through authorized procedures, preserving
the same DB. Never delete lock files or start with another DB to bypass unknowns.
Both stable and runtime lock files remain on normal close; descriptor close releases
the locks. Cross-version/live handoff and real Mac behavior are unvalidated.
