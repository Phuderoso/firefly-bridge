"""B1: signed trailers never provide the receive clock or erase replay history."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from firefly_bridge import presence as pr
from firefly_bridge import speaker as sp
from firefly_bridge.presence_nonces import nonce_transaction
from firefly_bridge.queue import Outbox
from tests.hmac_fixtures import SIG_TS, make_keyring, signed_body

NOW = float(SIG_TS)
ROOT = Path(__file__).resolve().parents[1]


def iso(ts):
    return datetime.fromtimestamp(ts, UTC).isoformat()


@pytest.fixture
def channel(tmp_path):
    sp.use_config(ROOT / 'examples/config.example.toml')
    ring = make_keyring(tmp_path)
    cfg = pr.PresenceConfig(terminals={'peerb': str(tmp_path / 'heartbeat.json')})
    store = tmp_path / 'nonces.json'
    base = dict(
        target='peerb', own_aliases=['peerb'], roster=['agent-a', 'agent-b'],
        now=NOW, sources=[lambda n: pr.PresenceRecord(n, NOW, 'idle')],
        cfg=cfg, keyring=ring['ring'], nonce_store=store, claim=True,
    )
    yield ring, base, store
    sp.use_config(None)


def decide(channel, body=None, **kw):
    ring, base, _ = channel
    return pr.wake_decision('agent-a', **dict(base, body=body or signed_body(ring, 'agent-a'), **kw))


@pytest.mark.parametrize('age', [30 * 86400, 601, -601])
@pytest.mark.parametrize('transport', [False, True])
def test_old_or_future_body_is_stale_not_wake(channel, age, transport):
    ring, _, _ = channel
    body = signed_body(ring, 'agent-a', ts=int(NOW - age))
    for _ in range(2):
        d = decide(channel, body, created_at=iso(NOW) if transport else '')
        assert (d.action, d.reason, d.presence) == (sp.GATED_NON_VIP, 'stale', '')


def test_no_created_at_uses_receive_now_and_fresh_body_wakes(channel):
    assert decide(channel, created_at='').action == sp.WAKE


@pytest.mark.parametrize('offset', [-601, 601])
def test_transport_time_is_checked_in_both_directions(channel, offset):
    d = decide(channel, created_at=iso(NOW + offset))
    assert (d.action, d.reason) == (sp.GATED_NON_VIP, 'stale')


@pytest.mark.parametrize('offset', [-600, 600])
def test_transport_window_boundaries_are_inclusive(channel, offset):
    assert decide(channel, created_at=iso(NOW + offset)).action == sp.WAKE


def test_original_old_transport_time_does_not_allow_ancient_body(channel):
    ring, _, _ = channel
    ts = int(NOW - 30 * 86400)
    body = signed_body(ring, 'agent-a', ts=ts)
    d = decide(channel, comment={'id': 17, 'created_at': iso(ts), 'body': body})
    assert (d.action, d.reason) == (sp.GATED_NON_VIP, 'stale')


def test_invalid_explicit_transport_time_is_not_replaced(channel):
    d = decide(channel, created_at='not-a-date')
    assert (d.action, d.reason) == (sp.GATED_NON_VIP, 'stale')


def test_repeat_same_comment_id_is_also_a_replay(channel):
    ring, _, path = channel
    c = dict(id=8, created_at=iso(NOW), body=signed_body(ring, 'agent-a'))
    original = dict(c)
    assert decide(channel, comment=c).action == sp.WAKE
    d = decide(channel, comment=c)
    assert (d.action, d.reason) == (sp.GATED_NON_VIP, 'replayed_nonce')
    assert c == original  # transport object is not mutated
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.with_name(path.name + '.lock').stat().st_mode & 0o777 == 0o600


def test_repeated_nonce_is_scoped_by_signer(channel):
    ring, base, _ = channel
    nonce = os.urandom(8).hex()
    for sender in ('agent-a', 'agent-b'):
        text = f'para: peerb\n\noi\n\n— {sender}\n'
        body = sp.sign_body(text, sender, ring['key'](sender), ts=int(NOW), nonce=nonce)
        assert pr.wake_decision(sender, body=body, **base).action == sp.WAKE
        d = pr.wake_decision(sender, body=body, **base)
        assert (d.action, d.reason) == (sp.GATED_NON_VIP, 'replayed_nonce')


def test_bad_mac_cannot_poison_nonce_history(channel):
    ring, _, path = channel
    body = signed_body(ring, 'agent-a')
    assert decide(channel, body.replace('oi peerb', 'altered')).action != sp.WAKE
    assert json.loads(path.read_text())['nonces'] == {}
    assert decide(channel, body).action == sp.WAKE


def test_deferred_turn_can_retry_until_grant_then_is_consumed(channel):
    ring, base, _ = channel
    body = signed_body(ring, 'agent-a')
    d = decide(channel, body, sources=[lambda n: pr.PresenceRecord(n, NOW, 'busy')])
    assert d.action == pr.DEFERRED_BUSY
    assert decide(channel, body).action == sp.WAKE
    assert decide(channel, body).reason == 'replayed_nonce'


def test_asserted_auth_does_not_bypass_verification_or_ledger(channel):
    _, base, _ = channel
    d = pr.wake_decision('agent-a', **base, auth='verified', signed_by='agent-a', sender_verified=True)
    assert d.action != sp.WAKE


def make_gate(channel):
    _, base, _ = channel
    kw = {k: v for k, v in base.items() if k != 'claim'}  # queue_gate always claims
    return pr.queue_gate(**dict(kw, now=lambda: NOW))


@pytest.mark.parametrize('old', [False, True])
def test_queue_gate_thirty_day_repro_and_repeat_across_gate_restart(channel, old):
    ring, _, _ = channel
    body = signed_body(ring, 'agent-a', ts=int(NOW - (30 * 86400 if old else 0)))
    turn = SimpleNamespace(body=body, outbound_text=body, sender='agent-a')
    first = make_gate(channel)(turn)
    second = make_gate(channel)(turn)  # new gate, same persisted ledger
    if old:
        assert (first.action, first.reason) == (sp.GATED_NON_VIP, 'stale')
        assert second.reason == 'stale' and second.action != sp.WAKE
    else:
        assert first.action == sp.WAKE
        assert (second.action, second.reason) == (sp.GATED_NON_VIP, 'replayed_nonce')


def test_queue_outbox_does_not_dispatch_copied_body(channel):
    ring, _, _ = channel
    body = signed_body(ring, 'agent-a')
    calls = []
    box = Outbox(lambda turn: calls.append(turn.message_id), presence_gate=make_gate(channel))
    first = box.enqueue('m1', 's', 'oi', body)
    box.pump_once()
    second = box.enqueue('m2', 's', 'oi', body)
    box.pump_once()
    assert first.state == 'delivered' and first.route == ''
    assert second.state == 'failed' and second.reason.endswith(':replayed_nonce')
    assert second.route == 'inbox'  # replayed copy is not lost, only never wakes
    assert calls == ['m1']


def run_knock(channel, body, created_at='', *extra, store_arg=True, env=None):
    ring, base, store = channel
    root = store.parent
    cfg = root / 'config.toml'
    hb = root / 'heartbeat.json'
    hb.write_text(json.dumps(dict(name='peerb', ts=NOW, state='idle')))
    cfg.write_text(
        '[channel_roster]\nvip = ["agent-a"]\n'
        f'[channel_keyring]\ndir = "{ring["dir"]}"\n'
        f'[channel_presence.terminals]\nPeerb = "{hb}"\n'
    )
    return subprocess.run(
        [sys.executable, str(ROOT / 'scripts/channel-knock'), '--presence',
         '--from', 'agent-a', '--config', str(cfg), '--now', str(NOW),
         '--body', body, '--created-at', created_at, *extra,
         *(['--nonce-store', str(store)] if store_arg else [])],
        capture_output=True, text=True, cwd=ROOT,
        env=dict(env or os.environ, PYTHONPATH=str(ROOT)), check=True,
    ).stdout


@pytest.mark.parametrize('transport', [False, True])
def test_knock_thirty_day_repro_is_stale_in_two_processes(channel, transport):
    ring, _, _ = channel
    body = signed_body(ring, 'agent-a', ts=int(NOW - 30 * 86400))
    for _ in range(2):
        out = run_knock(channel, body, iso(NOW) if transport else '')
        assert 'action=gated_non_vip' in out and 'reason=stale' in out
        assert 'session/prompt' not in out


def test_knock_repeat_is_persisted_between_processes(channel):
    ring, _, _ = channel
    body = signed_body(ring, 'agent-a')
    assert 'action=wake ' in run_knock(channel, body, '', '--claim')
    out = run_knock(channel, body, '', '--claim')
    assert 'action=gated_non_vip' in out and 'reason=replayed_nonce' in out
    assert 'session/prompt' not in out


def test_parallel_wake_grants_are_atomic(channel):
    ring, _, _ = channel
    body = signed_body(ring, 'agent-a')
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _: decide(channel, body), range(8)))
    assert sum(d.action == sp.WAKE for d in outcomes) == 1
    assert sum(d.reason == 'replayed_nonce' for d in outcomes) == 7


@pytest.mark.parametrize('fault', ['corrupt', 'bad-version', 'bad-data', 'bad-mode', 'symlink', 'directory', 'lock-symlink'])
def test_unsafe_nonce_store_fails_closed_without_overwrite(channel, fault):
    _, _, path = channel
    path.write_text('{}')
    path.chmod(0o600)
    if fault == 'corrupt':
        path.write_text('not json')
    elif fault == 'bad-version':
        path.write_text('{"v": 2, "nonces": {}}')
    elif fault == 'bad-data':
        path.write_text('{"v": 1, "nonces": {"fake": "expiry"}}')
    elif fault == 'bad-mode':
        path.chmod(0o644)
    elif fault == 'symlink':
        target = path.with_name('target')
        target.write_text('do not overwrite')
        path.unlink()
        path.symlink_to(target)
    elif fault == 'directory':
        path.unlink()
        path.mkdir()
    elif fault == 'lock-symlink':
        path.with_name(path.name + '.lock').symlink_to(path)
    before = path.read_bytes() if path.is_file() else None
    d = decide(channel)
    assert (d.action, d.reason) == (sp.GATED_NON_VIP, 'nonce_store_error')
    if before is not None:
        assert path.read_bytes() == before


def test_nonce_save_failure_cannot_return_wake(channel):
    with mock.patch('firefly_bridge.presence_nonces.os.replace', side_effect=OSError('disk full')):
        d = decide(channel)
    assert (d.action, d.reason) == (sp.GATED_NON_VIP, 'nonce_store_error')
    assert list(channel[2].parent.glob('*.tmp')) == []


def test_expired_records_pruned_but_current_or_future_kept(channel):
    _, _, path = channel
    with nonce_transaction(path, NOW) as records:
        records.update(old=NOW - 1, boundary=NOW, future=NOW + 1200)
    with nonce_transaction(path, NOW) as records:
        assert records == dict(boundary=NOW, future=NOW + 1200)


def test_pruning_never_revives_old_message_with_original_transport_time(channel):
    ring, base, _ = channel
    body = signed_body(ring, 'agent-a')
    assert decide(channel, body).action == sp.WAKE
    later = dict(base, now=NOW + 601, sources=[lambda n: pr.PresenceRecord(n, NOW + 601, 'idle')])
    d = pr.wake_decision('agent-a', body=body, created_at=iso(NOW), **later)
    assert (d.action, d.reason) == (sp.GATED_NON_VIP, 'stale')


# --- follow-up: inbox routing, read-only dry-run, one default ledger, ledger NITs -------------


def test_queue_gated_non_vip_turn_goes_to_inbox(channel):
    ring, _, _ = channel
    body = signed_body(ring, 'agent-c')  # valid key, but not in this roster
    calls = []
    box = Outbox(lambda turn: calls.append(turn.message_id), presence_gate=make_gate(channel))
    t = box.enqueue('m1', 's', 'oi', body, sender='agent-c')
    box.pump_once()
    assert (t.state, t.route, t.presence_action) == ('failed', 'inbox', sp.GATED_NON_VIP)
    assert calls == []


def test_busy_refused_after_wake_releases_nonce_so_retry_is_delivered(channel):
    """#17: BusyRefused means nothing was sent, so the grant is given back and the retry wakes."""
    from firefly_bridge.queue import BusyRefused

    ring, _, path = channel
    body = signed_body(ring, 'agent-a')
    calls = []

    def runner(turn):
        calls.append(turn.message_id)
        if len(calls) == 1:
            raise BusyRefused('peer_busy')
        return {'stop_reason': 'end_turn'}

    clock = [1000.0]
    box = Outbox(runner, presence_gate=make_gate(channel), now=lambda: clock[0])
    t = box.enqueue('m1', 's', 'oi', body)
    box.pump_once()  # wake granted, runner refuses busy -> deferred, nonce released
    assert t.state == 'deferred' and calls == ['m1']
    assert json.loads(path.read_text())['nonces'] == {}
    clock[0] = t.next_attempt_at
    box.pump_once()
    assert t.state == 'delivered' and calls == ['m1', 'm1']
    assert len(json.loads(path.read_text())['nonces']) == 1  # spent by the delivered grant
    # a copy of the delivered body is still a replay
    t2 = box.enqueue('m2', 's', 'oi', body)
    box.pump_once()
    assert t2.state == 'failed' and t2.reason.endswith(':replayed_nonce') and calls == ['m1', 'm1']


def test_release_only_applies_to_a_grant_made_by_this_gate(channel):
    ring, _, path = channel
    body = signed_body(ring, 'agent-a')
    gate = make_gate(channel)
    turn = SimpleNamespace(body=body, outbound_text=body, sender='agent-a')
    assert gate.release(turn) is False  # nothing granted yet
    assert gate(turn).action == sp.WAKE
    other = SimpleNamespace(body=body, outbound_text=body, sender='agent-a')
    assert gate.release(other) is False  # a different turn cannot un-claim it
    assert len(json.loads(path.read_text())['nonces']) == 1
    assert gate.release(turn) is True and gate.release(turn) is False


def test_wake_decision_claim_false_reads_without_writing(channel):
    _, _, path = channel
    ring = channel[0]
    body = signed_body(ring, 'agent-a')
    for _ in range(2):
        assert decide(channel, body, claim=False).action == sp.WAKE
    assert not path.exists() and not path.with_name(path.name + '.lock').exists()
    assert decide(channel, body).action == sp.WAKE  # first real claim still works
    before = path.read_bytes()
    d = decide(channel, body, claim=False)
    assert (d.action, d.reason) == (sp.GATED_NON_VIP, 'replayed_nonce')
    assert path.read_bytes() == before


def test_knock_dry_run_is_read_only_by_default(channel):
    ring, _, path = channel
    body = signed_body(ring, 'agent-a')
    for _ in range(2):
        out = run_knock(channel, body)
        assert 'action=wake ' in out and 'ledger=read_only' in out
    assert not path.exists()
    assert 'ledger=claimed' in run_knock(channel, body, '', '--claim')
    before = path.read_bytes()
    out = run_knock(channel, body)
    assert 'reason=replayed_nonce' in out and 'ledger=read_only' in out
    assert path.read_bytes() == before


def test_queue_and_knock_share_the_default_ledger(channel, tmp_path):
    ring, base, _ = channel
    shared = tmp_path / 'state' / 'presence-nonces.json'
    env = dict(os.environ, CHANNEL_PRESENCE_NONCES=str(shared))
    body = signed_body(ring, 'agent-a')
    assert 'action=wake ' in run_knock(channel, body, '', '--claim', store_arg=False, env=env)
    assert shared.exists()
    with mock.patch.dict(os.environ, {'CHANNEL_PRESENCE_NONCES': str(shared)}):
        kw = {k: v for k, v in base.items() if k != 'claim'}
        gate = pr.queue_gate(**dict(kw, nonce_store=None, now=lambda: NOW))
        d = gate(SimpleNamespace(body=body, outbound_text=body, sender='agent-a'))
    assert (d.action, d.reason) == (sp.GATED_NON_VIP, 'replayed_nonce')
    assert (shared.parent.stat().st_mode & 0o777) == 0o700


def test_oversized_ledger_fails_closed_without_overwrite(channel):
    from firefly_bridge import presence_nonces as pn

    _, _, path = channel
    path.write_bytes(b' ' * (pn.MAX_LEDGER_BYTES + 1))
    path.chmod(0o600)
    before = path.read_bytes()
    d = decide(channel)
    assert (d.action, d.reason) == (sp.GATED_NON_VIP, 'nonce_store_error')
    assert path.read_bytes() == before


def test_group_writable_ledger_dir_fails_closed(channel, tmp_path):
    ring, base, _ = channel
    shared = tmp_path / 'open'
    shared.mkdir()
    shared.chmod(0o777)
    d = pr.wake_decision('agent-a', **dict(base, nonce_store=shared / 'n.json',
                                           body=signed_body(ring, 'agent-a')))
    assert (d.action, d.reason) == (sp.GATED_NON_VIP, 'nonce_store_error')
    assert list(shared.iterdir()) == []


def test_presence_errors_are_not_reported_as_ledger_errors(channel):
    ring, _, _ = channel
    body = signed_body(ring, 'agent-a')
    box = Outbox(lambda turn: None, presence_gate=make_gate(channel))
    with mock.patch.object(pr.sp, 'wake_gate', side_effect=RuntimeError('config')):
        t = box.enqueue('m1', 's', 'oi', body)
        box.pump_once()
    assert t.presence_action == 'deferred_unknown'
    assert t.reason == 'deferred_unknown:presence_gate_error:RuntimeError'


def test_ledger_key_is_alias_independent_base_name():
    from firefly_bridge.presence_nonces import ledger_key

    assert ledger_key('agent-a', 'ab') == ledger_key('agent-a[x]', 'ab') == 'agent-a\nab'
    sp.use_config(ROOT / 'examples/config.example.toml')
    try:
        assert ledger_key('agent-d-alt', 'ab') == 'agent-d-alt\nab'  # alias map not applied
    finally:
        sp.use_config(None)
