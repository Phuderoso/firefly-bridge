"""scripts/channel-keygen + scripts/channel-keygen-smoke (roteiro de keygen do canal).

Offline. Toda chave é efêmera em tmp_path; nenhuma é commitada. Os testes conferem que o
segredo nunca aparece em stdout/stderr e que o formato é o que firefly_bridge.speaker lê.
"""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from firefly_bridge import speaker as sp

ROOT = Path(__file__).resolve().parents[1]
KEYGEN = ROOT / "scripts" / "channel-keygen"
SMOKE = ROOT / "scripts" / "channel-keygen-smoke"
EXAMPLE = ROOT / "examples" / "config.example.toml"
_loader = importlib.machinery.SourceFileLoader("channel_keygen_t", str(KEYGEN))
_spec = importlib.util.spec_from_loader("channel_keygen_t", _loader)
kg = importlib.util.module_from_spec(_spec)
_loader.exec_module(kg)

BASE = ('[github_canal]\nrepo = "example-owner/agent-channel"\npr = "1"\n\n'
        '[channel_roster]\nvip = ["agent-a", "peerb", "owner"]\nowner = "owner"\n'
        'pending = ["peerb", "peera", "peera-peerb"]\n'
        '[channel_roster.aliases]\nowner = ["ownernick"]\n')


_NO_HOME = str(Path(__file__).resolve().parent / "_no_such_home_for_keygen_tests")  # never read a real config
_BASE_ENV = {k: v for k, v in os.environ.items() if k != "FIREFLY_BRIDGE_CONFIG"}
_BASE_ENV["HOME"] = _NO_HOME
_ENV: dict[str, str] = dict(_BASE_ENV)


@pytest.fixture(autouse=True)
def roster_config(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Every subprocess gets a roster (owner owner, alias ownernick) via $FIREFLY_BRIDGE_CONFIG, like the Mac."""
    cfg = tmp_path_factory.mktemp("roster") / "config.toml"
    cfg.write_text(BASE)
    _ENV.clear()
    _ENV.update(_BASE_ENV, FIREFLY_BRIDGE_CONFIG=str(cfg))
    return cfg


def run(*args: str, umask: int | None = None, cwd: Path | None = None,
        env: dict | None = None) -> subprocess.CompletedProcess:
    pre = (lambda: os.umask(umask)) if umask is not None else None
    return subprocess.run([sys.executable, str(KEYGEN), *args], capture_output=True, text=True,
                          preexec_fn=pre, cwd=cwd, timeout=60, env=env or _ENV)


def secrets_in(ring: Path) -> list[str]:
    return [f.read_text(encoding="ascii").strip() for f in ring.glob("*.key")]


def assert_no_secret(ring: Path, *texts: str) -> None:
    blob = "\n".join(texts).lower()
    for h in secrets_in(ring):
        assert h not in blob
        assert not any(h[i:i + 16] in blob for i in range(len(h) - 15))


@pytest.fixture()
def ring(tmp_path: Path) -> Path:
    return tmp_path / "keyring"


def test_gen_format_is_what_speaker_reads(ring: Path) -> None:
    p = run("gen", "--keyring", str(ring), "agent-a", "peerb", "agent-c", "--allow-pending-identity")
    assert p.returncode == 0, p.stderr
    recs = [json.loads(line) for line in p.stdout.splitlines()]
    assert [r["name"] for r in recs] == ["agent-a", "peerb", "agent-c"]
    assert all(r["mode"] == "0600" and r["key_material_printed"] is False for r in recs)
    assert all(len(r["fingerprint"]) == 16 and int(r["fingerprint"], 16) >= 0 for r in recs)
    assert oct(ring.stat().st_mode & 0o777) == "0o700"
    assert sorted(f.name for f in ring.iterdir()) == ["agent-a.key", "agent-c.key", "peerb.key"]
    for f in ring.glob("*.key"):
        assert oct(f.stat().st_mode & 0o777) == "0o600"
        assert len(sp.load_key(f)) == 32
    loaded = sp.load_keyring_dir(ring)
    assert set(loaded) == {"agent-a", "agent-c", "peerb"}
    for r in recs:
        assert kg.fingerprint(sp.load_key(r["path"])) == r["fingerprint"]
    assert_no_secret(ring, p.stdout, p.stderr)
    assert len(set(secrets_in(ring))) == 3  # independent keys


def test_umask_000_still_yields_0600(ring: Path) -> None:
    assert run("gen", "--keyring", str(ring), "peerb", "--allow-pending-identity", umask=0).returncode == 0
    assert oct((ring / "peerb.key").stat().st_mode & 0o777) == "0o600"
    assert oct(ring.stat().st_mode & 0o777) == "0o700"


def test_refuses_overwrite_without_force_and_batch_is_all_or_nothing(ring: Path) -> None:
    assert run("gen", "--keyring", str(ring), "peerb", "--allow-pending-identity").returncode == 0
    before = (ring / "peerb.key").read_bytes()
    p = run("gen", "--keyring", str(ring), "agent-a", "peerb", "--allow-pending-identity")
    assert p.returncode == 3 and "chave_existe" in p.stderr
    assert (ring / "peerb.key").read_bytes() == before
    assert not (ring / "agent-a.key").exists()  # nothing written when any target exists
    assert_no_secret(ring, p.stdout, p.stderr)


def test_force_rotates_atomically_and_reports_old_fingerprint(ring: Path) -> None:
    run("gen", "--keyring", str(ring), "peerb", "--allow-pending-identity")
    old = kg.fingerprint(sp.load_key(ring / "peerb.key"))
    p = run("gen", "--keyring", str(ring), "peerb", "--force", "--allow-pending-identity")
    rec = json.loads(p.stdout)
    assert p.returncode == 0 and rec["replaced_fingerprint"] == old and rec["fingerprint"] != old
    assert rec["fingerprint"] == kg.fingerprint(sp.load_key(ring / "peerb.key"))
    assert sorted(f.name for f in ring.iterdir()) == ["peerb.key"]
    assert_no_secret(ring, p.stdout, p.stderr)


@pytest.mark.parametrize("bad", ["peera peerb", "../x", "<x>", "", "a/b", "-x"])
def test_rejects_unsafe_names(ring: Path, bad: str) -> None:
    p = run("gen", "--keyring", str(ring), "--", bad)
    assert p.returncode != 0
    assert not list(ring.glob("*.key")) if ring.exists() else True


def test_symlink_target_is_never_followed(ring: Path, tmp_path: Path) -> None:
    ring.mkdir(mode=0o700)
    victim = tmp_path / "victim.txt"
    victim.write_text("nao toque\n")
    (ring / "peerb.key").symlink_to(victim)
    assert run("gen", "--keyring", str(ring), "peerb", "--allow-pending-identity").returncode == 3
    assert run("gen", "--keyring", str(ring), "peerb", "--force", "--allow-pending-identity").returncode == 4
    assert victim.read_text() == "nao toque\n"


def test_refuses_keyring_inside_a_git_worktree(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    p = run("gen", "--keyring", str(repo / "keys"), "peerb", "--allow-pending-identity")
    assert p.returncode == 4 and "keyring_dentro_de_repo_git" in p.stderr
    assert not (repo / "keys").exists()


def test_bad_key_content_is_never_echoed(ring: Path) -> None:
    ring.mkdir(mode=0o700)
    fake = "segredo-nao-hex-" + "z" * 40
    f = ring / "peerb.key"
    f.write_text(fake)
    f.chmod(0o600)
    p = run("fingerprint", "--keyring", str(ring))
    assert "chave_nao_hex" in p.stdout and fake not in p.stdout + p.stderr


def test_check_flags_open_mode_tmp_legacy_and_missing_owner(ring: Path, tmp_path: Path) -> None:
    run("gen", "--keyring", str(ring), "peerb", "agent-a", "--allow-pending-identity")
    base = tmp_path / "base.toml"
    base.write_text(BASE)
    cfgp = tmp_path / "peerb.toml"
    assert run("render-config", "--base", str(base), "--name", "peerb", "--keyring", str(ring),
               "--out", str(cfgp), "--allow-pending-identity").returncode == 0
    assert run("check", "--keyring", str(ring), "--config", str(cfgp), "--allow-pending-identity").returncode == 0
    (ring / "agent-a.key").chmod(0o644)
    (ring / ".x.key.tmp").write_text("")
    bad = tmp_path / "bad.toml"
    bad.write_text('[channel_roster]\nvip = ["peerb"]\n[channel_wake]\nlegacy_unsigned_wake = true\n')
    p = run("check", "--keyring", str(ring), "--config", str(bad))
    assert p.returncode == 4
    for needle in ("chave_permissao_aberta", "tmp_orfao", "legacy_unsigned_wake_ligado", "config_sem_owner",
                   "config_sem_keyring"):
        assert needle in p.stderr
    assert_no_secret(ring, p.stdout, p.stderr)


def test_render_config_is_paths_only_and_bound_identity_reads_it(ring: Path, tmp_path: Path) -> None:
    run("gen", "--keyring", str(ring), "peerb", "--allow-pending-identity")
    base = tmp_path / "base.toml"
    base.write_text(BASE)
    out = tmp_path / "terminals" / "peerb.toml"
    p = run("render-config", "--base", str(base), "--name", "peerb", "--keyring", str(ring), "--out", str(out),
            "--allow-pending-identity")
    assert p.returncode == 0 and json.loads(p.stdout)["problems"] == []
    assert oct(out.stat().st_mode & 0o777) == "0o600"
    assert_no_secret(ring, out.read_text(), p.stdout, p.stderr)
    name, key = sp.bound_identity(out)
    assert name == "peerb" and key == sp.load_key(ring / "peerb.key")
    assert sp.load_keyring(out) == sp.load_keyring_dir(ring)
    assert sp.load_owner(out) == ["owner"] and sp.load_legacy_unsigned_wake(out) is False
    again = run("render-config", "--base", str(base), "--name", "peerb", "--keyring", str(ring), "--out", str(out),
                "--allow-pending-identity")
    assert again.returncode == 3
    ident = tmp_path / "ident.toml"
    ident.write_text(BASE + '\n[channel_identity]\nname = "X"\nkey_file = "/x"\n')
    assert run("render-config", "--base", str(ident), "--name", "peerb", "--keyring", str(ring),
               "--out", str(tmp_path / "o2.toml")).returncode == 2
    legacy = tmp_path / "legacy.toml"
    legacy.write_text(BASE + "\n[channel_wake]\nlegacy_unsigned_wake = true\n")
    assert run("render-config", "--base", str(legacy), "--name", "peerb", "--keyring", str(ring),
               "--out", str(tmp_path / "o3.toml"), "--allow-pending-identity").returncode == 4


def test_revoke_removes_key_and_verification_becomes_unknown_key(ring: Path) -> None:
    run("gen", "--keyring", str(ring), "agent-a", "peerb", "--allow-pending-identity")
    key = sp.load_key(ring / "agent-a.key")
    fp = kg.fingerprint(key)
    body = sp.sign_body("para: peerb\n\noi\n\n— agent-a\n", "agent-a", key, ts=1_800_000_000)
    c = {"id": 1, "body": body, "created_at": "2027-01-15T08:00:00Z"}
    assert sp.verify_comment(c, sp.load_keyring_dir(ring)).auth == "verified"
    assert run("revoke", "--keyring", str(ring), "agent-a").returncode == 2  # needs --yes
    p = run("revoke", "--keyring", str(ring), "agent-a", "--yes")
    assert p.returncode == 0 and json.loads(p.stdout)["revoked_fingerprint"] == fp
    assert not (ring / "agent-a.key").exists()
    assert sp.verify_comment(c, sp.load_keyring_dir(ring)).auth == "unknown_key"
    assert key.hex() not in p.stdout + p.stderr


def test_fallback_toml_parser_reads_the_example_config() -> None:
    data = kg._toml_fallback(EXAMPLE.read_text(encoding="utf-8"))
    assert data["channel_roster"]["owner"] == "owner"
    assert "channel_wake" not in data  # commented out in the example: strict default


def test_smoke_script_passes_and_leaks_nothing(tmp_path: Path) -> None:
    env = dict(os.environ, TMPDIR=str(tmp_path))
    p = subprocess.run([sys.executable, str(SMOKE)], capture_output=True, text=True, timeout=120, env=env)
    lines = [json.loads(line) for line in p.stdout.splitlines() if line.strip()]
    assert p.returncode == 0, p.stdout[-2000:] + p.stderr[-2000:]
    checks = {r["check"]: r["ok"] for r in lines if "check" in r}
    for must in ("assinado_valido_acorda", "sem_assinatura_nao_acorda", "forjado_corpo_adulterado_nao_acorda",
                 "forjado_chave_errada_nao_acorda", "forjado_signatario_errado_nao_acorda",
                 "forjado_relay_forjado_sem_assinatura_nao_acorda", "replay_de_nonce_rejeitado",
                 "fora_da_janela_600s_rejeitado", "nenhum_output_ou_arquivo_contem_segredo",
                 "keygen_sob_bash_x", "tmpdir_apagado", "legacy_desligado",
                 "keygen_recusa_owner_mesmo_com_flag", "keygen_recusa_peerb_sem_flag"):
        assert checks.get(must) is True, must
    assert lines[-1]["smoke"] == "ok"
    assert list(tmp_path.iterdir()) == []  # ephemeral dir removed, nothing left behind


def test_render_config_from_shared_config_that_already_has_the_keyring(ring: Path, tmp_path: Path) -> None:
    """Mac layout: shared config.toml (roster + owner + keyring, no identity; used by wake_watch)
    -> per-terminal config adds only [channel_identity]."""
    run("gen", "--keyring", str(ring), "agent-a")
    shared = tmp_path / "config.toml"
    shared.write_text(BASE + f'\n[channel_keyring]\ndir = "{ring}"\n')
    out = tmp_path / "terminals" / "agent.toml"
    p = run("render-config", "--base", str(shared), "--name", "agent-a", "--keyring", str(ring), "--out", str(out))
    assert p.returncode == 0, p.stderr
    assert out.read_text().count("[channel_keyring]") == 1
    assert sp.bound_identity(out)[0] == "agent-a" and sp.load_keyring(out) == sp.load_keyring_dir(ring)
    other = tmp_path / "other"
    p = run("render-config", "--base", str(shared), "--name", "agent-a", "--keyring", str(other),
            "--out", str(tmp_path / "x.toml"))
    assert p.returncode == 2 and "keyring_divergente" in p.stderr


def test_phase1_no_owner_key_check_flags_it_and_render_refuses_owner_identity(ring: Path, tmp_path: Path) -> None:
    """Fase 1: não existe chave do dono; o dono fala por relay assinado pela agent-a."""
    run("gen", "--keyring", str(ring), "agent-a")
    shared = tmp_path / "config.toml"
    shared.write_text(BASE + f'\n[channel_keyring]\ndir = "{ring}"\n')
    assert run("check", "--keyring", str(ring), "--config", str(shared)).returncode == 0
    for owner_name in ("owner", "ownernick"):  # owner and its roster alias
        p = run("render-config", "--base", str(shared), "--name", owner_name, "--keyring", str(ring),
                "--out", str(tmp_path / f"{owner_name}.toml"))
        assert p.returncode == 4 and "identidade_do_owner_recusada" in p.stderr
        assert not (tmp_path / f"{owner_name}.toml").exists()
    kg.ensure_keyring_dir(ring)  # an owner key that slipped in by hand (gen itself refuses it)
    kg.write_key_atomic(kg.key_path(ring, "ownernick"), os.urandom(32), force=False)
    p = run("check", "--keyring", str(ring), "--config", str(shared))
    assert p.returncode == 4 and "chave_bloqueada: ownernick.key: identidade_do_owner_recusada" in p.stderr
    assert_no_secret(ring, p.stdout, p.stderr)
    assert "identidade_do_owner_recusada" in " ".join(kg.check_config(shared))  # keyring taken from the config
    data = kg._toml_fallback(shared.read_text())
    assert kg._owner_names(data) == {"owner", "ownernick"}  # py3.9 fallback parser path


@pytest.mark.parametrize("owner", ["owner", "ownernick", "OWNER", "ownernick"])
def test_gen_refuses_owner_and_aliases_before_any_write(ring: Path, owner: str) -> None:
    p = run("gen", "--keyring", str(ring), owner)
    assert p.returncode == 4 and "identidade_do_owner_recusada" in p.stderr and "Nada foi escrito" in p.stderr
    assert not ring.exists()  # refused before even creating the keyring dir


@pytest.mark.parametrize("owner", ["owner", "ownernick", "OWNER"])
def test_gen_owner_stays_refused_even_with_the_pending_flag(ring: Path, owner: str) -> None:
    p = run("gen", "--keyring", str(ring), owner, "--allow-pending-identity")
    assert p.returncode == 4 and "identidade_do_owner_recusada" in p.stderr
    assert not ring.exists()


def test_gen_batch_with_owner_writes_nothing(ring: Path) -> None:
    ring.mkdir(mode=0o700)
    p = run("gen", "--keyring", str(ring), "agent-a", "owner")
    assert p.returncode == 4 and list(ring.iterdir()) == []


@pytest.mark.parametrize("name", ["peerb", "peerb", "peera", "PEERA", "peera-peerb"])
def test_gen_refuses_pending_peerb_without_flag(ring: Path, name: str) -> None:
    p = run("gen", "--keyring", str(ring), name)
    assert p.returncode == 4 and "identidade_pendente_recusada" in p.stderr and "--allow-pending-identity" in p.stderr
    assert not ring.exists()


def test_gen_peerb_with_flag_generates(ring: Path) -> None:
    p = run("gen", "--keyring", str(ring), "peerb", "--allow-pending-identity")
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout)["name"] == "peerb" and len(sp.load_key(ring / "peerb.key")) == 32
    assert_no_secret(ring, p.stdout, p.stderr)


def test_gen_denylist_follows_roster_owner_and_aliases_from_config(ring: Path, tmp_path: Path) -> None:
    cfg = tmp_path / "config.toml"
    cfg.write_text('[channel_roster]\nowner = "Chefe"\npending = ["Peerb"]\n'
                   '[channel_roster.aliases]\n'
                   'chefe = ["Boss"]\nPeerb = ["Noite"]\n')
    for name in ("Chefe", "boss", "BOSS"):
        p = run("gen", "--keyring", str(ring), name, "--config", str(cfg), "--allow-pending-identity")
        assert p.returncode == 4 and "identidade_do_owner_recusada" in p.stderr, name
    p = run("gen", "--keyring", str(ring), "noite", "--config", str(cfg))
    assert p.returncode == 4 and "identidade_pendente_recusada" in p.stderr
    env = dict(_ENV, FIREFLY_BRIDGE_CONFIG=str(cfg))  # same config picked up from the environment
    assert run("gen", "--keyring", str(ring), "Boss", env=env).returncode == 4
    assert not ring.exists()
    assert run("gen", "--keyring", str(ring), "agent-a", "--config", str(tmp_path / "nope.toml")).returncode == 4
    assert not ring.exists()  # explicit unreadable config fails closed
    data = kg._toml_fallback(cfg.read_text())  # py3.9 path
    assert kg._owner_names(data) == {"chefe", "boss"}
    assert kg._pending_names(data)["peerb"] == {"peerb", "noite"}


# --- falha fechada sem roster, NAME_RE antes de escrever, check/render com a mesma política ---------


def test_gen_without_any_config_fails_closed(ring: Path) -> None:
    """Sem config não há como saber o owner: recusa (antes, um owner só do roster passava)."""
    for name in ("Chefe", "agent-a"):
        p = run("gen", "--keyring", str(ring), name, env=_BASE_ENV)  # no env config, HOME without config
        assert p.returncode == 4 and "config_ausente" in p.stderr and "Nada foi escrito" in p.stderr
    assert not ring.exists()


def test_gen_env_config_that_does_not_exist_fails_closed(ring: Path, tmp_path: Path) -> None:
    env = dict(_BASE_ENV, FIREFLY_BRIDGE_CONFIG=str(tmp_path / "sumiu.toml"))
    p = run("gen", "--keyring", str(ring), "agent-a", env=env)
    assert p.returncode == 4 and "config_ausente" in p.stderr and "FIREFLY_BRIDGE_CONFIG" in p.stderr
    assert not ring.exists()


def test_gen_config_without_owner_fails_closed(ring: Path, tmp_path: Path) -> None:
    cfg = tmp_path / "sem-owner.toml"
    cfg.write_text('[channel_roster]\nvip = ["agent-a", "Chefe"]\n')
    p = run("gen", "--keyring", str(ring), "agent-a", "--config", str(cfg))
    assert p.returncode == 4 and "owner_desconhecido" in p.stderr
    assert not ring.exists()


def test_gen_home_default_config_supplies_the_roster_owner(ring: Path, tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / ".config" / "firefly-bridge").mkdir(parents=True)
    (home / ".config" / "firefly-bridge" / "config.toml").write_text('[channel_roster]\nowner = "Chefe"\n')
    env = dict(_BASE_ENV, HOME=str(home))
    p = run("gen", "--keyring", str(ring), "Chefe", env=env)
    assert p.returncode == 4 and "identidade_do_owner_recusada" in p.stderr and not ring.exists()
    assert run("gen", "--keyring", str(ring), "agent-a", env=env).returncode == 0


@pytest.mark.parametrize("bad", ["../escape", "a b", "", "-x"])
def test_gen_invalid_name_leaves_no_keyring_dir(ring: Path, bad: str) -> None:
    p = run("gen", "--keyring", str(ring), "agent-a", "--", bad)
    assert p.returncode == 2 and "nome_invalido" in p.stderr
    assert not ring.exists()


def test_check_without_config_flag_uses_env_then_home(ring: Path, tmp_path: Path) -> None:
    run("gen", "--keyring", str(ring), "agent-a")
    legacy = tmp_path / "legacy.toml"
    legacy.write_text(BASE + "\n[channel_wake]\nlegacy_unsigned_wake = true\n")
    p = run("check", "--keyring", str(ring), env=dict(_BASE_ENV, FIREFLY_BRIDGE_CONFIG=str(legacy)))
    assert p.returncode == 4 and "legacy_unsigned_wake_ligado" in p.stderr
    home = tmp_path / "home"
    (home / ".config" / "firefly-bridge").mkdir(parents=True)
    (home / ".config" / "firefly-bridge" / "config.toml").write_text(BASE + f'\n[channel_keyring]\ndir = "{ring}"\n')
    assert run("check", "--keyring", str(ring), env=dict(_BASE_ENV, HOME=str(home))).returncode == 0
    p = run("check", "--keyring", str(ring), env=_BASE_ENV)
    assert p.returncode == 4 and "config_ausente" in p.stderr


def test_render_config_and_check_share_the_gen_policy(ring: Path, tmp_path: Path) -> None:
    run("gen", "--keyring", str(ring), "agent-a", "peerb", "--allow-pending-identity")
    shared = tmp_path / "config.toml"
    shared.write_text(BASE + f'\n[channel_keyring]\ndir = "{ring}"\n')
    for name in ("peerb", "peera"):
        p = run("render-config", "--base", str(shared), "--name", name, "--keyring", str(ring),
                "--out", str(tmp_path / "n.toml"))
        assert p.returncode == 4 and "identidade_pendente_recusada" in p.stderr
        assert not (tmp_path / "n.toml").exists()
    p = run("render-config", "--base", str(shared), "--name", "owner", "--keyring", str(ring),
            "--out", str(tmp_path / "p.toml"), "--allow-pending-identity")
    assert p.returncode == 4 and "identidade_do_owner_recusada" in p.stderr
    assert run("render-config", "--base", str(shared), "--name", "peerb", "--keyring", str(ring),
               "--out", str(tmp_path / "n.toml"), "--allow-pending-identity").returncode == 0
    p = run("check", "--keyring", str(ring), "--config", str(shared))
    assert p.returncode == 4 and "chave_bloqueada: peerb.key: identidade_pendente_recusada" in p.stderr
    assert run("check", "--keyring", str(ring), "--config", str(shared), "--allow-pending-identity").returncode == 0
    no_owner = tmp_path / "no-owner.toml"
    no_owner.write_text('[channel_roster]\nvip = ["agent-a"]\n')
    p = run("render-config", "--base", str(no_owner), "--name", "agent-a", "--keyring", str(ring),
            "--out", str(tmp_path / "f.toml"))
    assert p.returncode == 4 and "owner_desconhecido" in p.stderr
