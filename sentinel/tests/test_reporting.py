import csv
import json
import pytest

from sentinel.reporting import validate_results,save_json,save_csv,save_report

# Result validation
def test_validate_results_accepts_list_of_dictionaries():
    results = [
        {"port": 80, "status": "open"},
        {"port": 443, "status": "closed"},
    ]
    validate_results(results)

@pytest.mark.parametrize(
    "results",
    [
        None,
        "not a list",
        {"port": 80},
        [{"port": 80}, "invalid row"],
        [None],
    ],
)

def test_validate_results_rejects_invalid_data(results):
    with pytest.raises(ValueError):
        validate_results(results)

# JSON reporting
def test_save_json_creates_file_and_preserves_results(tmp_path):
    results = [
        {
            "port": 80,
            "protocol": "TCP",
            "scan": "SYN",
            "status": "open",
        },
        {
            "port": 443,
            "protocol": "TCP",
            "scan": "SYN",
            "status": "closed",
        },
    ]

    output_path = tmp_path / "reports" / "scan.json"

    returned_path = save_json(results, output_path)

    assert returned_path == output_path
    assert output_path.exists()

    with output_path.open(encoding="utf-8") as file:
        saved_results = json.load(file)

    assert saved_results == results


def test_save_json_handles_empty_results(tmp_path):
    output_path = tmp_path / "empty.json"

    save_json([], output_path)

    with output_path.open(encoding="utf-8") as file:
        saved_results = json.load(file)

    assert saved_results == []


def test_save_json_rejects_invalid_results(tmp_path):
    output_path = tmp_path / "invalid.json"

    with pytest.raises(ValueError):
        save_json([{"port": 80}, "invalid row"], output_path)

    assert not output_path.exists()


# CSV reporting
def test_save_csv_writes_headers_and_rows(tmp_path):
    results = [
        {
            "port": 80,
            "protocol": "TCP",
            "status": "open",
        },
        {
            "port": 443,
            "protocol": "TCP",
            "status": "closed",
        },
    ]

    output_path = tmp_path / "scan.csv"

    returned_path = save_csv(results, output_path)

    assert returned_path == output_path
    assert output_path.exists()

    with output_path.open(
        newline="",
        encoding="utf-8",
    ) as file:
        rows = list(csv.DictReader(file))

    assert len(rows) == 2
    assert rows[0]["port"] == "80"
    assert rows[0]["status"] == "open"
    assert rows[1]["port"] == "443"
    assert rows[1]["status"] == "closed"


def test_save_csv_handles_mixed_tcp_and_dns_results(tmp_path):
    results = [
        {
            "port": 80,
            "protocol": "TCP",
            "status": "open",
        },
        {
            "domain": "example.com",
            "protocol": "DNS",
            "response_code": 0,
            "answer_count": 1,
        },
    ]

    output_path = tmp_path / "mixed.csv"

    save_csv(results, output_path)

    with output_path.open(
        newline="",
        encoding="utf-8",
    ) as file:
        reader = csv.DictReader(file)
        rows = list(reader)

    assert "port" in reader.fieldnames
    assert "domain" in reader.fieldnames
    assert "response_code" in reader.fieldnames

    assert rows[0]["port"] == "80"
    assert rows[0]["domain"] == ""

    assert rows[1]["domain"] == "example.com"
    assert rows[1]["port"] == ""


def test_save_csv_serialises_nested_values(tmp_path):
    results = [
        {
            "domain": "example.com",
            "answers": [
                {"type": 1, "data": "192.0.2.44"}
            ],
        }
    ]

    output_path = tmp_path / "dns.csv"

    save_csv(results, output_path)

    with output_path.open(
        newline="",
        encoding="utf-8",
    ) as file:
        row = next(csv.DictReader(file))

    # Nested data is stored as JSON text inside the CSV cell.
    answers = json.loads(row["answers"])

    assert answers[0]["type"] == 1
    assert answers[0]["data"] == "192.0.2.44"


def test_save_csv_converts_none_to_empty_cell(tmp_path):
    results = [
        {
            "port": None,
            "status": "no_response",
        }
    ]

    output_path = tmp_path / "scan.csv"

    save_csv(results, output_path)

    with output_path.open(
        newline="",
        encoding="utf-8",
    ) as file:
        row = next(csv.DictReader(file))

    assert row["port"] == ""


# Reporting format selection
def test_save_report_selects_json(tmp_path):
    results = [{"port": 80, "status": "open"}]
    output_path = tmp_path / "scan.json"

    returned_path = save_report(results, output_path)

    assert returned_path == output_path

    with output_path.open(encoding="utf-8") as file:
        assert json.load(file) == results


def test_save_report_selects_csv(tmp_path):
    results = [{"port": 80, "status": "open"}]
    output_path = tmp_path / "scan.csv"

    returned_path = save_report(results, output_path)

    assert returned_path == output_path
    assert output_path.exists()

    with output_path.open(
        newline="",
        encoding="utf-8",
    ) as file:
        rows = list(csv.DictReader(file))

    assert rows[0]["port"] == "80"


def test_save_report_accepts_uppercase_extension(tmp_path):
    output_path = tmp_path / "scan.JSON"

    save_report([{"status": "open"}], output_path)

    assert output_path.exists()


def test_save_report_rejects_unsupported_extension(tmp_path):
    output_path = tmp_path / "scan.txt"

    with pytest.raises(ValueError, match="Unsupported report format"):
        save_report([], output_path)

    assert not output_path.exists()
