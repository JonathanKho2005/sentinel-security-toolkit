import json
import pytest
import argparse

from sentinel import cli

# Port argument parsing
def test_parse_valid_ports():
    assert cli.parse_ports("22,80,443") == [22, 80, 443]
@pytest.mark.parametrize(
    "value",
    [
        "",
        "22,,80",
        "22,abc,80",
        "22,80,",
    ],
)

def test_parse_invalid_ports(value):
    with pytest.raises(argparse.ArgumentTypeError):
        cli.parse_ports(value)

# Argument parser
def test_cli_help_lists_scan_commands():
    parser = cli.build_parser()

    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["--help"])

    assert exc_info.value.code == 0

def test_cli_error_requires_scan_type():
    parser = cli.build_parser()

    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args([])

    assert exc_info.value.code == 2


def test_cli_error_rejects_missing_required_arguments():
    parser = cli.build_parser()

    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["syn"])

    assert exc_info.value.code == 2


# TCP scan dispatch
@pytest.mark.parametrize(
    ("command", "function_name"),
    [
        ("syn", "syn_scan"),
        ("ack", "ack_scan"),
        ("xmas", "xmas_scan"),
    ],
)
def test_cli_dispatches_tcp_scan(
    monkeypatch, capsys, command, function_name
):
    calls = []

    def fake_scan(host, ports, allowed_targets=None):
        calls.append((host, ports, allowed_targets))

        return [
            {
                "port": 80,
                "protocol": "TCP",
                "scan": command.upper(),
                "status": "open",
            }
        ]

    monkeypatch.setattr(
        cli.scanner,
        function_name,
        fake_scan,
    )

    exit_code = cli.main([
        command,
        "--host", "127.0.0.1",
        "--ports", "22,80",
    ])

    assert exit_code == 0
    assert calls == [
        ("127.0.0.1", [22, 80], None)
    ]

    output = capsys.readouterr().out
    results = json.loads(output)

    assert results[0]["port"] == 80
    assert results[0]["status"] == "open"


def test_cli_passes_explicit_allowed_target(monkeypatch, capsys):
    calls = []

    def fake_scan(host, ports, allowed_targets=None):
        calls.append(allowed_targets)
        return []

    monkeypatch.setattr(
        cli.scanner,
        "syn_scan",
        fake_scan,
    )

    exit_code = cli.main([
        "syn",
        "--host", "192.0.2.10",
        "--ports", "80",
        "--allow-target", "192.0.2.0/24",
    ])

    assert exit_code == 0
    assert calls == [["192.0.2.0/24"]]



# DNS scan dispatch
def test_cli_dispatches_dns_scan(monkeypatch, capsys):
    calls = []

    def fake_dns_scan(host, domain, allowed_targets=None):
        calls.append((host, domain, allowed_targets))

        return [
            {
                "host": host,
                "domain": domain,
                "protocol": "DNS",
                "scan": "DNS",
                "status": "responded",
                "response_code": 0,
                "answer_count": 1,
            }
        ]

    monkeypatch.setattr(
        cli.scanner,
        "dns_scan",
        fake_dns_scan,
    )

    exit_code = cli.main([
        "dns",
        "--host", "127.0.0.1",
        "--domain", "example.com",
    ])

    assert exit_code == 0
    assert calls == [
        ("127.0.0.1", "example.com", None)
    ]

    output = capsys.readouterr().out
    results = json.loads(output)

    assert results[0]["domain"] == "example.com"
    assert results[0]["status"] == "responded"



# Error handling
@pytest.mark.parametrize(
    "error",
    [
        ValueError("Invalid input"),
        PermissionError("Target outside permitted scope"),
    ],
)
def test_cli_handles_scanner_errors(
    monkeypatch, capsys, error
):
    def fake_scan(*args, **kwargs):
        raise error

    monkeypatch.setattr(
        cli.scanner,
        "syn_scan",
        fake_scan,
    )

    exit_code = cli.main([
        "syn",
        "--host", "127.0.0.1",
        "--ports", "80",
    ])

    captured = capsys.readouterr()

    assert exit_code == 1
    assert str(error) in captured.err
    assert captured.out == ""


def test_cli_error_rejects_malformed_port_argument():
    with pytest.raises(SystemExit) as exc_info:
        cli.main([
            "syn",
            "--host", "127.0.0.1",
            "--ports", "22,,80",
        ])

    assert exc_info.value.code == 2
