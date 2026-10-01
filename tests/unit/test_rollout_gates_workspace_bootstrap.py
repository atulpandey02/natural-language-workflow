"""B01: the rollout refuses a host whose bootstrap does not enforce grants."""

import pytest

from nlw.ops.rollout import gates
from nlw.ops.rollout.gates import GateError


def test_gated_single_bootstrap_passes() -> None:
    gates.check_workspace_bootstrap_gated(1, True, [])


@pytest.mark.parametrize(
    ("overloads", "gated", "access", "match"),
    [
        (0, False, [], "0 create_workspace_for_current_user overloads"),
        (2, True, [], "2 create_workspace_for_current_user overloads"),
        (1, False, [], "does not enforce creation grants"),
        (1, True, ["nlw_app"], "runtime roles can access"),
        (1, True, ["public"], "runtime roles can access"),
    ],
)
def test_ungated_or_exposed_bootstrap_is_no_go(
    overloads: int, gated: bool, access: list[str], match: str
) -> None:
    with pytest.raises(GateError, match=match):
        gates.check_workspace_bootstrap_gated(overloads, gated, access)
