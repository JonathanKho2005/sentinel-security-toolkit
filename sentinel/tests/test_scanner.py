
import pytest

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR

from sentinel.network import scanner


# Helpers
def mock_sr(monkeypatch, answered=None, unanswered=None):
    # Replace scanner.sr() with a fake function so no real network packets are sent.

    calls = []

    def fake_sr(packet, **kwargs):
        calls.append((packet, kwargs))
        return list(answered or []), list(unanswered or [])

    monkeypatch.setattr(scanner, "sr", fake_sr)
    return calls


def block_sr(monkeypatch):
    # Fail if a scanner attempts to send packets.

    def fail_if_called(*args, **kwargs):
        pytest.fail("sr() must not be called for invalid input.")

    monkeypatch.setattr(scanner, "sr", fail_if_called)


def make_tcp_pair(port, sent_flags, response_flags, source_port=40000):
    """Construct a simulated TCP request and response."""

    sent = (
        IP(src="127.0.0.1", dst="127.0.0.1")
        / TCP(
            sport=source_port,
            dport=port,
            flags=sent_flags,
        )
    )

    received = (
        IP(src="127.0.0.1", dst="127.0.0.1")
        / TCP(
            sport=port,
            dport=source_port,
            flags=response_flags,
        )
    )

    return sent, received


def make_dns_pair(domain="example.com", rcode=0, answer_count=1):
    """Construct a simulated DNS query and response."""

    sent = (
        IP(src="127.0.0.1", dst="127.0.0.1")
        / UDP(sport=53000, dport=53)
        / DNS(
            id=1234,
            rd=1,
            qd=DNSQR(qname=domain, qtype="A"),
        )
    )

    answer = None

    if answer_count > 0:
        answer = DNSRR(
            rrname=domain,
            type="A",
            ttl=60,
            rdata="192.0.2.44",
        )

    received = (
        IP(src="127.0.0.1", dst="127.0.0.1")
        / UDP(sport=53, dport=53000)
        / DNS(
            id=1234,
            qr=1,
            rd=1,
            ra=1,
            rcode=rcode,
            qd=DNSQR(qname=domain, qtype="A"),
            an=answer,
            ancount=answer_count,
        )
    )

    return sent, received

# Scope validation integration
@pytest.mark.parametrize(
    ("scan_function", "args"),
    [
        (scanner.syn_scan, ("192.0.2.10", [80])),
        (scanner.xmas_scan, ("192.0.2.10", [80])),
        (scanner.ack_scan, ("192.0.2.10", [80])),
        (scanner.dns_scan, ("192.0.2.10", "example.com")),
    ],
)

def test_scanners_reject_out_of_scope_targets(
    monkeypatch, scan_function, args
):
    block_sr(monkeypatch)

    with pytest.raises(PermissionError):
        scan_function(*args)


@pytest.mark.parametrize(
    "scan_function",
    [
        scanner.syn_scan,
        scanner.xmas_scan,
        scanner.ack_scan,
    ],
)
def test_tcp_scanners_reject_invalid_ports(
    monkeypatch, scan_function
):
    block_sr(monkeypatch)

    with pytest.raises(ValueError):
        scan_function("127.0.0.1", [70000])


@pytest.mark.parametrize(
    "scan_function",
    [
        scanner.syn_scan,
        scanner.xmas_scan,
        scanner.ack_scan,
    ],
)
def test_tcp_scanners_enforce_maximum_port_count(
    monkeypatch, scan_function
):
    block_sr(monkeypatch)

    with pytest.raises(ValueError):
        scan_function("127.0.0.1", [80, 443], max_ports=1)


def test_explicitly_allowed_target_can_be_scanned_with_mock(
    monkeypatch,
):
    calls = mock_sr(monkeypatch, answered=[], unanswered=[])

    results = scanner.syn_scan(
        "192.0.2.10",
        [80],
        allowed_targets=["192.0.2.0/24"],
    )

    assert results == []
    assert len(calls) == 1

# SYN scan tests
def test_syn_scan_classifies_open_closed_and_unanswered(
    monkeypatch,
):
    open_pair = make_tcp_pair(80, "S", "SA")
    closed_pair = make_tcp_pair(81, "S", "RA", source_port=40001)

    unanswered_packet = (
        IP(dst="127.0.0.1")
        / TCP(sport=40002, dport=443, flags="S")
    )

    mock_sr(
        monkeypatch,
        answered=[open_pair, closed_pair],
        unanswered=[unanswered_packet],
    )

    results = scanner.syn_scan(
        "127.0.0.1",
        [80, 81, 443],
    )

    assert len(results) == 3

    by_port = {item["port"]: item for item in results}

    assert by_port[80]["status"] == "open"
    assert by_port[81]["status"] == "closed"
    assert by_port[443]["status"] == "filtered"

    assert all(item["protocol"] == "TCP" for item in results)
    assert all(item["scan"] == "SYN" for item in results)


def test_syn_scan_handles_all_unanswered_probes(monkeypatch):
    unanswered = [
        IP(dst="127.0.0.1") / TCP(sport=40000, dport=80, flags="S"),
        IP(dst="127.0.0.1") / TCP(sport=40001, dport=443, flags="S"),
    ]

    mock_sr(monkeypatch, unanswered=unanswered)

    results = scanner.syn_scan("127.0.0.1", [80, 443])

    assert len(results) == 2
    assert {item["port"] for item in results} == {80, 443}
    assert all(item["status"] == "filtered" for item in results)

# XMAS scan tests
def test_xmas_scan_classifies_rst_as_closed(monkeypatch):
    pair = make_tcp_pair(80, "FPU", "R")

    mock_sr(monkeypatch, answered=[pair])

    results = scanner.xmas_scan("127.0.0.1", [80])

    assert len(results) == 1
    assert results[0]["port"] == 80
    assert results[0]["protocol"] == "TCP"
    assert results[0]["scan"] == "XMAS"
    assert results[0]["status"] == "closed"


def test_xmas_scan_classifies_icmp_unreachable_as_filtered(
    monkeypatch,
):
    sent = (
        IP(src="127.0.0.1", dst="127.0.0.1")
        / TCP(sport=40000, dport=80, flags="FPU")
    )

    received = (
        IP(src="127.0.0.1", dst="127.0.0.1")
        / ICMP(type=3, code=13)
    )

    mock_sr(monkeypatch, answered=[(sent, received)])

    results = scanner.xmas_scan("127.0.0.1", [80])

    assert len(results) == 1
    assert results[0]["status"] == "filtered"
    assert results[0]["protocol"] == "ICMP"


def test_xmas_scan_labels_unanswered_probe_open_or_filtered(
    monkeypatch,
):
    unanswered = (
        IP(dst="127.0.0.1")
        / TCP(sport=40000, dport=443, flags="FPU")
    )

    mock_sr(monkeypatch, unanswered=[unanswered])

    results = scanner.xmas_scan("127.0.0.1", [443])

    assert len(results) == 1
    assert results[0]["status"] == "open/filtered"

# ACK scan tests
def test_ack_scan_classifies_rst_as_unfiltered(monkeypatch):
    rst_pair = make_tcp_pair(22, "A", "R")
    rst_ack_pair = make_tcp_pair(
        80, "A", "RA", source_port=40001
    )

    mock_sr(monkeypatch, answered=[rst_pair, rst_ack_pair])

    results = scanner.ack_scan("127.0.0.1", [22, 80])

    assert len(results) == 2
    assert all(item["status"] == "unfiltered" for item in results)
    assert all(item["scan"] == "ACK" for item in results)


def test_ack_scan_classifies_icmp_unreachable_as_filtered(
    monkeypatch,
):
    sent = (
        IP(src="127.0.0.1", dst="127.0.0.1")
        / TCP(sport=40000, dport=80, flags="A")
    )

    received = (
        IP(src="127.0.0.1", dst="127.0.0.1")
        / ICMP(type=3, code=13)
    )

    mock_sr(monkeypatch, answered=[(sent, received)])

    results = scanner.ack_scan("127.0.0.1", [80])

    assert len(results) == 1
    assert results[0]["status"] == "filtered"
    assert results[0]["protocol"] == "ICMP"


def test_ack_scan_labels_unanswered_probe_filtered(monkeypatch):
    unanswered = (
        IP(dst="127.0.0.1")
        / TCP(sport=40000, dport=443, flags="A")
    )

    mock_sr(monkeypatch, unanswered=[unanswered])

    results = scanner.ack_scan("127.0.0.1", [443])

    assert len(results) == 1
    assert results[0]["status"] == "filtered"

# DNS scan tests
def test_dns_scan_records_successful_response(monkeypatch):
    sent, received = make_dns_pair(
        domain="example.com",
        rcode=0,
        answer_count=1,
    )

    mock_sr(monkeypatch, answered=[(sent, received)])

    results = scanner.dns_scan(
        "127.0.0.1",
        "example.com",
    )

    assert len(results) == 1

    result = results[0]

    assert result["host"] == "127.0.0.1"
    assert result["domain"] == "example.com"
    assert result["protocol"] == "DNS"
    assert result["scan"] == "DNS"
    assert result["status"] == "responded"
    assert result["response_code"] == 0
    assert result["answer_count"] == 1


def test_dns_scan_records_nxdomain_response_code(monkeypatch):
    sent, received = make_dns_pair(
        domain="example.com",
        rcode=3,
        answer_count=0,
    )

    mock_sr(monkeypatch, answered=[(sent, received)])

    results = scanner.dns_scan("127.0.0.1", "example.com")

    assert len(results) == 1
    assert results[0]["status"] == "responded"
    assert results[0]["response_code"] == 3
    assert results[0]["answer_count"] == 0


def test_dns_scan_handles_unexpected_response(monkeypatch):
    sent = (
        IP(dst="127.0.0.1")
        / UDP(sport=53000, dport=53)
        / DNS(
            rd=1,
            qd=DNSQR(qname="example.com", qtype="A"),
        )
    )

    received = (
        IP(src="127.0.0.1", dst="127.0.0.1")
        / UDP(sport=53, dport=53000)
    )

    mock_sr(monkeypatch, answered=[(sent, received)])

    results = scanner.dns_scan("127.0.0.1", "example.com")

    assert len(results) == 1
    assert results[0]["status"] == "unexpected_response"
    assert results[0]["response_code"] is None
    assert results[0]["answer_count"] == 0


def test_dns_scan_handles_no_response(monkeypatch):
    unanswered = (
        IP(dst="127.0.0.1")
        / UDP(sport=53000, dport=53)
        / DNS(
            rd=1,
            qd=DNSQR(qname="example.com", qtype="A"),
        )
    )

    mock_sr(
        monkeypatch,
        answered=[],
        unanswered=[unanswered],
    )

    results = scanner.dns_scan("127.0.0.1", "example.com")

    assert len(results) == 1
    assert results[0]["status"] == "no_response"
    assert results[0]["response_code"] is None
    assert results[0]["answer_count"] == 0

