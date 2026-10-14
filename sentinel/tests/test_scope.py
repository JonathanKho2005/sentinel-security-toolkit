import pytest
from sentinel.network.scope import validate_ports, validate_target

def test_loopback_target():
    assert validate_target("127.0.0.1") == "127.0.0.1"

def test_target_outside_scope():
    with pytest.raises(PermissionError):
        validate_target("192.0.2.10")

@pytest.mark.parametrize(
    "host",
    ["", "   ", "not-ip", "example.com", 123, None],
)
def test_invalid_target_is_rejected(host):
    with pytest.raises(ValueError):
        validate_target(host)


def test_explicitly_allowed_network_is_accepted():
    result = validate_target(
        "192.168.56.10",
        allowed_targets=["192.168.56.0/24"],
    )

    assert result == "192.168.56.10"


# ---------- Port validation ----------

def test_valid_ports_are_accepted_and_deduplicated():
    assert validate_ports([53, 80, 443, 80]) == [53, 80, 443]


@pytest.mark.parametrize(
    "ports",
    [
        [],
        "80",
        80,
        None,
        [0],
        [-1],
        [65536],
        [80.0],
        [True],
        [80, False],
    ],
)
def test_invalid_ports_are_rejected(ports):
    with pytest.raises(ValueError):
        validate_ports(ports)


def test_maximum_port_count_is_enforced():
    with pytest.raises(ValueError):
        validate_ports([22, 80], max_ports=1)


@pytest.mark.parametrize("limit", [0, -1, True, 1.5, "100"])
def test_invalid_maximum_port_count_is_rejected(limit):
    with pytest.raises(ValueError):
        validate_ports([80], max_ports=limit)