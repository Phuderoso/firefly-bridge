"""Presence/occupancy gate: fake sources only; no process, socket, tmux, launchd or TUI."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from firefly_bridge import presence as pr
from firefly_bridge import speaker as sp
from tests.hmac_fixtures import make_keyring, signed_kwargs

ROOT = Path(__file__).resolve().parents[1]
OWNER = "owner"
ROSTER = ["agent-a", "agent-b", "agent-c", "agent-d", OWNER, "peerx"]
OWN = ["peerb"]
TARGET = "peerb"
NOW = 1_763_130_000.0


def fake(state=None, *, age=5.0, name=TARGET, task="", busy=None):
    calls: list[str] = []

    def src(n):
        calls.append(n)
        if state is None and busy is None:
            return None
        obj = {"name": name, "ts": NOW - age, "state": state or "", "task": task}
        if busy is not None:
            obj["busy"] = busy
        return pr.record_from_mapping(obj, source="fake")

    src.calls = calls  # type: ignore[attr-defined]
    return src


class Base(unittest.TestCase):
    def setUp(self):
        sp.use_config(ROOT / "examples" / "config.example.toml")  # aliases: ownernick/ownerlogin, agent-d-alt, peerx
        self._keys = tempfile.TemporaryDirectory()
        self.ring = make_keyring(Path(self._keys.name))

    def tearDown(self):
        self._keys.cleanup()
        sp.use_config(None)

    def decide(self, sender, src, cfg=None, *, signed=True, legacy_unsigned=None):
        extra = signed_kwargs(self.ring, sender) if signed else {}
        return pr.wake_decision(
            sender,
            target=TARGET,
            own_aliases=OWN,
            roster=ROSTER,
            now=NOW,
            sources=[src],
            cfg=cfg,
            legacy_unsigned=legacy_unsigned,
            **extra,
        )


class PresenceStates(Base):
    def test_idle_busy_absent(self):
        self.assertEqual(pr.presence(TARGET, NOW, [fake("idle")]).state, pr.IDLE)
        self.assertEqual(pr.presence(TARGET, NOW, [fake("busy")]).state, pr.BUSY)
        self.assertEqual(pr.presence(TARGET, NOW, [fake("absent")]).state, pr.ABSENT)

    def test_task_or_busy_flag_means_busy(self):
        self.assertEqual(pr.presence(TARGET, NOW, [fake("idle", task="draft")]).state, pr.BUSY)
        self.assertEqual(pr.presence(TARGET, NOW, [fake("idle", busy=True)]).state, pr.BUSY)

    def test_unknown_cases(self):
        cfg = pr.PresenceConfig(max_age_s=60, future_skew_s=10)
        cases = {
            "no_source": [],
            "no_record": [fake(None)],
            "stale": [fake("idle", age=61)],
            "future": [fake("idle", age=-11)],
            "foreign_name": [fake("idle", name="agent-b")],
            "bad_state": [fake("sleeping")],
        }
        for label, srcs in cases.items():
            with self.subTest(label):
                self.assertEqual(pr.presence(TARGET, NOW, srcs, cfg).state, pr.UNKNOWN)

    def test_broken_source_is_unknown_not_crash(self):
        def boom(_):
            raise RuntimeError("x")

        p = pr.presence(TARGET, NOW, [boom])
        self.assertEqual((p.state, p.reason), (pr.UNKNOWN, "source_error"))

    def test_conservative_merge(self):
        self.assertEqual(pr.presence(TARGET, NOW, [fake("idle"), fake("busy")]).state, pr.BUSY)
        self.assertEqual(pr.presence(TARGET, NOW, [fake("idle"), fake("absent")]).state, pr.ABSENT)
        self.assertEqual(pr.presence(TARGET, NOW, [fake("idle", age=999), fake("idle")]).state, pr.IDLE)


class WakeDecision(Base):
    def test_vip_idle_wakes(self):
        d = self.decide("agent-a", fake("idle"))
        self.assertEqual((d.action, d.presence), (sp.WAKE, pr.IDLE))

    def test_busy_defers(self):
        d = self.decide("agent-a", fake("busy", task="notes"))
        self.assertEqual((d.action, d.presence), (pr.DEFERRED_BUSY, pr.BUSY))

    def test_absent_defers(self):
        self.assertEqual(self.decide("agent-b", fake("absent")).action, pr.DEFERRED_ABSENT)

    def test_stale_and_unknown_fail_closed(self):
        self.assertEqual(self.decide("agent-a", fake("idle", age=10_000)).action, pr.DEFERRED_UNKNOWN)
        self.assertEqual(self.decide("agent-a", fake(None)).action, pr.DEFERRED_UNKNOWN)
        d = pr.wake_decision(
            "agent-a", target=TARGET, own_aliases=OWN, roster=ROSTER, now=NOW, sources=[],
            **signed_kwargs(self.ring, "agent-a"),
        )
        self.assertEqual(d.action, pr.DEFERRED_UNKNOWN)

    def test_non_vip_gated_before_presence(self):
        for who in ("peerd", "peerc", "random-login", ""):
            with self.subTest(who):
                src = fake("idle")
                d = self.decide(who, src, signed=False)
                self.assertEqual(d.action, sp.GATED_NON_VIP)
                self.assertEqual(d.presence, "")
                self.assertEqual(src.calls, [], "presence must not be read for non-VIP")

    def test_self_echo_suppressed_before_presence(self):
        src = fake("idle")
        d = self.decide("peerb", src, signed=False)
        self.assertEqual(d.action, sp.SUPPRESSED_SELF_ECHO)
        self.assertEqual(src.calls, [])

    def test_unsigned_vip_never_wakes_even_with_legacy_opt_in(self):
        # #11: an unsigned body has no nonce, so the replay ledger cannot make it one-shot;
        # behind the presence gate legacy_unsigned does not apply.
        for legacy in (None, False, True):
            with self.subTest(legacy=legacy):
                src = fake("idle")
                d = self.decide("agent-a", src, signed=False, legacy_unsigned=legacy)
                self.assertEqual(d.action, sp.GATED_NON_VIP)
                self.assertEqual(d.reason, "signature_required")
                self.assertEqual(src.calls, [])

    def test_owner_busy_default_flag_false_defers(self):
        for spelled in (OWNER, "ownernick", "ownerlogin"):
            with self.subTest(spelled):
                self.assertEqual(self.decide(spelled, fake("busy")).action, pr.DEFERRED_BUSY)

    def test_owner_busy_flag_on_but_unverified_still_defers(self):
        cfg = pr.PresenceConfig(allow_busy_override=True, busy_override_principals=(OWNER,))
        for spelled in (OWNER, "ownernick", "ownerlogin"):
            with self.subTest(spelled):
                # Unsigned / sender_verified flag: R3 gates before presence (no override bypass).
                src = fake("busy")
                d = self.decide(spelled, src, cfg, signed=False)
                self.assertEqual(d.action, sp.GATED_NON_VIP)
                self.assertEqual(d.reason, "owner_unverified")
                self.assertEqual(src.calls, [])
                d = pr.wake_decision(
                    spelled, target=TARGET, own_aliases=OWN, roster=ROSTER, now=NOW,
                    sources=[fake("busy")], cfg=cfg, sender_verified=True,
                )
                self.assertEqual(d.action, sp.GATED_NON_VIP)

    def test_verified_hook_only_when_flag_and_list_and_verified(self):
        def go(cfg, who=OWNER, src=None, signed=True):
            extra = signed_kwargs(self.ring, who) if signed else {}
            return pr.wake_decision(
                who, target=TARGET, own_aliases=OWN, roster=ROSTER, now=NOW,
                sources=[src or fake("busy")], cfg=cfg, **extra,
            ).action

        on = pr.PresenceConfig(allow_busy_override=True, busy_override_principals=(OWNER,))
        self.assertEqual(go(on), sp.WAKE)  # HMAC-verified owner: the only path through busy
        self.assertEqual(go(pr.PresenceConfig(busy_override_principals=(OWNER,))), pr.DEFERRED_BUSY)
        self.assertEqual(go(pr.PresenceConfig(allow_busy_override=True)), pr.DEFERRED_BUSY)
        self.assertEqual(go(on, signed=False), sp.GATED_NON_VIP)  # flag cannot bypass a missing sig
        self.assertEqual(go(on, who="agent-a"), pr.DEFERRED_BUSY)
        self.assertEqual(go(on, src=fake("absent")), pr.DEFERRED_ABSENT)
        self.assertEqual(go(on, src=fake(None)), pr.DEFERRED_UNKNOWN)

    def test_default_config_never_overrides_even_verified(self):
        d = pr.wake_decision(
            OWNER, target=TARGET, own_aliases=OWN, roster=ROSTER, now=NOW,
            sources=[fake("busy")], **signed_kwargs(self.ring, OWNER),
        )
        self.assertEqual(d.action, pr.DEFERRED_BUSY)

    def test_flag_true_with_empty_list_overrides_nobody(self):
        cfg = pr.PresenceConfig(allow_busy_override=True)
        self.assertEqual(self.decide(OWNER, fake("busy"), cfg).action, pr.DEFERRED_BUSY)

    def test_list_without_flag_overrides_nobody(self):
        cfg = pr.PresenceConfig(allow_busy_override=False, busy_override_principals=(OWNER,))
        self.assertEqual(self.decide(OWNER, fake("busy"), cfg).action, pr.DEFERRED_BUSY)


class StateFileAndConfig(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, obj):
        p = self.dir / name
        p.write_text(obj if isinstance(obj, str) else json.dumps(obj), encoding="utf-8")
        return p

    def test_state_file_roundtrip_and_iso_ts(self):
        p = self.write("peerb.json", {"name": TARGET, "ts": "2025-11-14T14:33:20Z", "state": "idle"})
        rec = pr.read_state_file(p)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.state, "idle")
        cfg = pr.PresenceConfig(terminals={"peerb": str(p)})
        self.assertEqual(pr.presence(TARGET, rec.ts + 1, [pr.state_file_source(cfg)], cfg).state, pr.IDLE)

    def test_bad_files_are_none(self):
        self.assertIsNone(pr.read_state_file(self.dir / "missing.json"))
        self.assertIsNone(pr.read_state_file(self.write("garbage.json", "{not json")))
        self.assertIsNone(pr.read_state_file(self.write("list.json", "[1,2]")))
        self.assertIsNone(pr.read_state_file(self.write("nots.json", {"name": TARGET, "state": "idle"})))
        self.assertIsNone(pr.read_state_file(self.write("big.json", " " * (pr.MAX_STATE_BYTES + 1))))
        self.assertIsNone(pr.read_state_file(self.dir))

    def test_symlink_refused(self):
        real = self.write("real.json", {"name": TARGET, "ts": NOW, "state": "idle"})
        link = self.dir / "link.json"
        os.symlink(real, link)
        self.assertIsNone(pr.read_state_file(link))

    def test_unconfigured_terminal_unknown(self):
        cfg = pr.PresenceConfig()
        self.assertEqual(pr.presence(TARGET, NOW, [pr.state_file_source(cfg)], cfg).state, pr.UNKNOWN)

    def test_config_parse_and_defaults(self):
        cfg = pr.parse_presence_config_text(
            '[channel_presence]\nmax_age_s = 90\nallow_busy_override = true\n'
            'busy_override_principals = ["X"]\n[channel_presence.terminals]\nPeerb = "/tmp/n.json"\n'
        )
        self.assertEqual((cfg.max_age_s, cfg.allow_busy_override, cfg.busy_override_principals), (90.0, True, ("X",)))
        self.assertEqual(cfg.terminals, {sp.norm_name("peerb"): "/tmp/n.json"})
        d = pr.parse_presence_config_text("")
        self.assertFalse(d.allow_busy_override)
        self.assertEqual(d.busy_override_principals, ())
        self.assertEqual(pr.load_presence_config(self.dir / "absent.toml"), pr.PresenceConfig())
        with self.assertRaises(ValueError):
            pr.parse_presence_config_text('[channel_presence]\nallow_busy_override = "yes"\n')

    def test_shipped_examples_default_override_off(self):
        for rel in ("examples/config.example.toml", "config/example.toml"):
            with self.subTest(rel):
                cfg = pr.load_presence_config(ROOT / rel)
                self.assertFalse(cfg.allow_busy_override)
                self.assertEqual(cfg.busy_override_principals, ())
                self.assertEqual(len(cfg.terminals), 1)


class DryRunOnly(unittest.TestCase):
    def test_module_never_spawns_or_connects(self):
        src = (ROOT / "firefly_bridge" / "presence.py").read_text(encoding="utf-8")
        for bad in ("subprocess", "socket", "tmux", "launchctl", "os.kill", "Popen", "--live", ".sock"):
            self.assertFalse(bad in src.split('"""', 2)[2], bad)

    def test_decision_runs_with_process_and_socket_blocked(self):
        ring = make_keyring(Path(tempfile.mkdtemp()))
        with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("spawn")), \
             mock.patch.object(socket, "socket", side_effect=AssertionError("socket")):
            d = pr.wake_decision(
                "agent-a", target=TARGET, own_aliases=OWN, roster=ROSTER, now=NOW,
                sources=[fake("idle")], **signed_kwargs(ring, "agent-a"),
            )
        self.assertEqual(d.action, sp.WAKE)


if __name__ == "__main__":
    unittest.main()
