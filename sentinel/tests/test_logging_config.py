import json

import pytest

from sentinel import cli
from sentinel.logging_config import configure_logging

@pytest.fixture
def configured_logger(tmp_path):
    # Use a temporary log file and clean up its handler afterwards.

    log_path = tmp_path / "logs" / "sentinel.log"
    logger = configure_logging(log_path=log_path)

    yield logger, log_path

    # Close the file handler so it does not affect other tests.
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        handler.close()


def read_log(logger, log_path):
    # Flush pending messages before reading the log file.

    for handler in logger.handlers:
        handler.flush()

    return log_path.read_text(encoding="utf-8")


# Logging configuration
def test_logging_creates_file_and_records_message(configured_logger):
    logger, log_path = configured_logger

    logger.info("Sentinel logging test message")

    content = read_log(logger, log_path)

    assert log_path.exists()
    assert "INFO sentinel: Sentinel logging test message" in content


def test_logging_includes_timestamp_and_level(configured_logger):
    logger, log_path = configured_logger

    logger.warning("Test warning")

    content = read_log(logger, log_path)

    assert "WARNING sentinel: Test warning" in content
    assert len(content.splitlines()[0]) > 20


def test_reconfiguring_logging_does_not_duplicate_messages(
    configured_logger,
):
    logger, log_path = configured_logger

    # Configure the same logger and file again.
    logger = configure_logging(log_path=log_path)
    logger.info("Single log entry")

    content = read_log(logger, log_path)

    assert len(logger.handlers) == 1
    assert content.count("Single log entry") == 1


# CLI logging integration
def test_cli_logs_successful_scan(
    monkeypatch, capsys, configured_logger
):
    logger, log_path = configured_logger

    # Make the CLI use our temporary logger.
    monkeypatch.setattr(
        cli,
        "configure_logging",
        lambda: logger,
    )

    # Mock the scanner so no network packets are sent.
    def fake_scan(host, ports, allowed_targets=None):
        return [
            {
                "port": 80,
                "protocol": "TCP",
                "scan": "SYN",
                "status": "open",
            }
        ]

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

    assert exit_code == 0

    # Check the usual CLI JSON output is still available.
    output = json.loads(capsys.readouterr().out)
    assert output[0]["status"] == "open"

    # Check that the request and completion were logged.
    content = read_log(logger, log_path)

    assert "Scan requested: type=syn target=127.0.0.1" in content
    assert "Scan completed: type=syn target=127.0.0.1 results=1" in content


def test_cli_logs_scan_failure(
    monkeypatch, capsys, configured_logger
):
    logger, log_path = configured_logger

    monkeypatch.setattr(
        cli,
        "configure_logging",
        lambda: logger,
    )

    def failing_scan(*args, **kwargs):
        raise PermissionError("Target outside permitted scope")

    monkeypatch.setattr(
        cli.scanner,
        "syn_scan",
        failing_scan,
    )

    exit_code = cli.main([
        "syn",
        "--host", "127.0.0.1",
        "--ports", "80",
    ])

    assert exit_code == 1

    captured = capsys.readouterr()
    assert "Target outside permitted scope" in captured.err
    assert captured.out == ""

    content = read_log(logger, log_path)

    assert "Scan requested: type=syn target=127.0.0.1" in content
    assert "Operation failed: type=syn target=127.0.0.1" in content

