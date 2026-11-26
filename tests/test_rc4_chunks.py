"""agent-c's chunk-gap regression: verified origin is not complete content."""

import pytest
from test_rc2 import ProvenSyntheticHistory, begin, chunk
from test_rc2 import make_broker as make_broker


@pytest.mark.parametrize("sequences", [(1, 3), (3,), (1, 3, 2), (0,), (-1,), (True,)])
def test_chunk_gaps_or_invalid_start_never_claim_verified_complete_reply(make_broker, sequences):
    d = make_broker()
    begin(d)
    for seq in sequences:
        chunk(d.session, text=f"partial-{seq}", seq=seq)
    d.session.conn.finish()
    assert d.pump_once().state == "delivered"
    r = d.receipt("agent-a", "message-1")
    assert r["reply_origin_verified"] is True
    assert not r["reply_verified"] and not r["reply_complete"]
    assert not r["reply_stream_contiguous"]
    assert r["reply_recovery"] == "reply_recovery_unavailable"
    assert "partial" not in r["reply_redacted"]
    assert r["attempt_committed"] and len(d.session.conn.calls) == 1


def test_chunk_gap_can_only_recover_via_exact_bounded_history(make_broker):
    d = make_broker()
    d.session.chat_history = ProvenSyntheticHistory()
    begin(d)
    chunk(d.session, "partial-first", seq=1)
    chunk(d.session, "partial-third", seq=3)
    d.session.conn.finish()
    d.pump_once()
    r = d.receipt("agent-a", "message-1")
    assert r["reply_verified"] and r["reply_complete"]
    assert not r["reply_stream_contiguous"]
    assert r["reply_recovery"] == "recovered_chat_history"
    assert len(d.session.chat_history.calls) == 1
    assert len(d.session.conn.calls) == 1


@pytest.mark.parametrize(
    "count,complete,verified",
    [
        (None, False, True),
        (2, True, True),
        (3, False, False),
        (1, False, False),
        (True, False, False),
    ],
)
def test_terminal_count_distinguishes_contiguous_prefix_from_complete_answer(
    make_broker, count, complete, verified
):
    d = make_broker()
    begin(d)
    chunk(d.session, "first ", seq=1)
    chunk(d.session, "second", seq=2)
    d.session.conn.finish()
    if count is not None:
        d.session.active_call.result["_meta"]["agentBridge"]["chunkCount"] = count
    d.pump_once()
    r = d.receipt("agent-a", "message-1")
    assert r["reply_verified"] is verified
    assert r["reply_complete"] is complete
    assert r["reply_origin_verified"]
    assert len(d.session.conn.calls) == 1


def test_duplicate_chunk_does_not_duplicate_reply_or_create_a_gap(make_broker):
    d = make_broker()
    begin(d)
    chunk(d.session, "one ", seq=1)
    chunk(d.session, "duplicate", seq=1)
    chunk(d.session, "two", seq=2)
    d.session.conn.finish()
    d.session.active_call.result["_meta"]["agentBridge"]["chunkCount"] = 2
    d.pump_once()
    r = d.receipt("agent-a", "message-1")
    assert r["reply_redacted"] == "one two"
    assert r["reply_complete"] and r["reply_stream_contiguous"]
