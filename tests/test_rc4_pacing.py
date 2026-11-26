"""60/600 defaults are now enforced floors unless the user opts out."""

import pytest
from test_rc2 import make_broker as make_broker

from firefly_bridge.config import BridgeConfig, ConfigError, load_config


@pytest.mark.parametrize(
    "field,value",
    [
        ("post_turn_interval_s", 0),
        ("post_turn_interval_s", 59),
        ("target_interval_s", 0),
        ("target_interval_s", 599),
    ],
)
def test_below_minimum_requires_explicit_flag_direct_toml_env(tmp_path, field, value):
    with pytest.raises(ConfigError, match="explicit_optout"):
        BridgeConfig(**{field: value}).validate(require_target=False)
    path = tmp_path / "below-floor.toml"
    path.write_text(f"{field}={value}\n")
    with pytest.raises(ConfigError, match="explicit_optout"):
        load_config(path, env={}, require_target=False)
    with pytest.raises(ConfigError, match="explicit_optout"):
        load_config(env={"FIREFLY_BRIDGE_" + field.upper(): str(value)}, require_target=False)
    path.write_text(f"{field}={value}\npacing_minimums_enabled=false\n")
    assert getattr(load_config(path, env={}, require_target=False), field) == value


def test_optout_is_not_a_numeric_bounds_or_nonfinite_bypass():
    for value in (-1, float("nan"), float("inf")):
        with pytest.raises(ConfigError):
            BridgeConfig(pacing_minimums_enabled=False, post_turn_interval_s=value).validate(
                require_target=False
            )
    with pytest.raises(ConfigError, match="not_bool"):
        BridgeConfig(pacing_minimums_enabled="false").validate(require_target=False)


def test_default_floors_and_explicit_optout_are_visible_in_status(make_broker):
    defaults = make_broker(_defaults=True)
    assert defaults.snapshot()["pacing"]["minimums_enabled"] is True
    assert defaults.cfg.post_turn_interval_s >= 60 and defaults.cfg.target_interval_s >= 600
    optout = make_broker(
        pacing_minimums_enabled=False, post_turn_interval_s=0, target_interval_s=0
    )
    assert optout.snapshot()["pacing"]["minimums_enabled"] is False
