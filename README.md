# Sentinel — Python Network Reconnaissance Toolkit

Sentinel is a Python-based network reconnaissance toolkit built with [Scapy](https://scapy.net/). It provides a command-line interface for running basic TCP SYN, ACK and XMAS scans, alongside a UDP-based DNS query. Scan results can be displayed as JSON or exported to JSON and CSV files.

The project focuses on practical network programming, input validation, controlled scan scope, automated testing and structured reporting. It is an educational portfolio project, not a replacement for professional network-scanning or security-assessment tools.

## Features

- **TCP SYN scan** — sends TCP SYN probes and classifies responses as open, closed or filtered.
- **TCP ACK scan** — uses TCP ACK probes to distinguish unfiltered responses from responses that appear to be filtered.
- **TCP XMAS scan** — sends TCP packets with FIN, PSH and URG flags and classifies the responses.
- **DNS query** — sends a UDP DNS A-record query to a specified DNS server and reports whether a response was received.
- **Target-scope validation** — limits scans to loopback addresses by default. Additional targets must be explicitly allow-listed.
- **Port validation** — checks port values, removes duplicates and limits each TCP scan to 100 unique ports.
- **Command-line interface** — provides separate commands for each scan type.
- **Report export** — supports JSON and CSV output.
- **Application logging** — records scan requests, completions and errors in a rotating log file.
- **Automated tests** — uses `pytest` and mocked Scapy responses to test validation, scan-response handling, CLI behaviour, reporting and logging.

## Project structure

```text
sentinel_cyber_project/
├── sentinel/
│   ├── __init__.py
│   ├── cli.py
│   ├── logging_config.py
│   ├── reporting.py
│   ├── network/
│   │   ├── __init__.py
│   │   ├── scanner.py
│   │   └── scope.py
│   └── tests/
│       ├── test_cli.py
│       ├── test_logging_config.py
│       ├── test_reporting.py
│       ├── test_scanner.py
│       └── test_scope.py
├── requirements.txt
└── README.md
```

The exact test filenames may differ slightly depending on the current repository contents.

## Requirements

- Python 3
- The dependencies listed in `requirements.txt`
- Elevated privileges may be required by Scapy to send and receive raw network packets.

## Installation

Clone the repository and move into the project directory:

```bash
git clone <YOUR-REPOSITORY-URL>
cd sentinel_cyber_project
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the project dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Run commands from the repository's root directory so that Python can locate the `sentinel` package.

## Usage

Display the available commands:

```bash
python -m sentinel.cli --help
```

Display help for an individual scan:

```bash
python -m sentinel.cli syn --help
python -m sentinel.cli ack --help
python -m sentinel.cli xmas --help
python -m sentinel.cli dns --help
```

### Target scope

Sentinel permits loopback targets by default:

- `127.0.0.0/8` for IPv4 loopback addresses
- `::1/128` for IPv6 loopback

For a non-loopback target, you must explicitly add an authorised IP address or network using `--allow-target`. The target supplied with `--host` must be an IP address within the allowed scope.

For example, the following uses a documentation-only example address. Replace it with a target you are explicitly authorised to assess:

```bash
sudo "$(which python)" -m sentinel.cli syn \
  --host 192.0.2.10 \
  --ports 22,80,443 \
  --allow-target 192.0.2.0/24
```

Allow-listing a target in Sentinel does not itself grant permission to scan it. You are responsible for obtaining authorisation before testing any system or network.

### TCP SYN scan

A SYN scan sends TCP SYN probes to the specified ports. It uses the responses to make a basic assessment of port state.

```bash
sudo "$(which python)" -m sentinel.cli syn \
  --host 127.0.0.1 \
  --ports 22,80,443
```

### TCP ACK scan

An ACK scan sends TCP ACK probes. A returned RST is classified as **unfiltered**; relevant ICMP destination-unreachable responses are classified as **filtered**.

```bash
sudo "$(which python)" -m sentinel.cli ack \
  --host 127.0.0.1 \
  --ports 22,80,443
```

### TCP XMAS scan

An XMAS scan sends TCP packets with the FIN, PSH and URG flags set. The response-based classifications are limited and can vary depending on the target operating system and network configuration.

```bash
sudo "$(which python)" -m sentinel.cli xmas \
  --host 127.0.0.1 \
  --ports 22,80,443
```

### DNS query

The DNS command sends a UDP query for an A record to the DNS server specified by `--host`.

```bash
sudo "$(which python)" -m sentinel.cli dns \
  --host <AUTHORISED_DNS_SERVER_IP> \
  --domain example.com \
  --allow-target <AUTHORISED_DNS_SERVER_IP>
```

Replace the placeholder with the IP address of a DNS server you are permitted to query. The DNS command is a basic query/response check; it is not a DNS vulnerability scanner or a DNS threat-detection system.

### Running a controlled local demonstration

You can demonstrate the SYN scan against a service running on your own machine without scanning an external host.

In Terminal 1, start a temporary HTTP server on the loopback interface:

```bash
python -m http.server 8000 --bind 127.0.0.1
```

In Terminal 2, run a scan against the open local port and a second port where no service is expected to be listening:

```bash
sudo "$(which python)" -m sentinel.cli syn \
  --host 127.0.0.1 \
  --ports 8000,8001
```

Stop the temporary HTTP server with `Ctrl+C` when you have finished.

## Saving reports

Each scan command accepts `--output`. The file extension determines the report format: `.json` or `.csv`.

Save a JSON report:

```bash
sudo "$(which python)" -m sentinel.cli syn \
  --host 127.0.0.1 \
  --ports 8000,8001 \
  --output reports/syn-scan.json
```

Save a CSV report:

```bash
sudo "$(which python)" -m sentinel.cli syn \
  --host 127.0.0.1 \
  --ports 8000,8001 \
  --output reports/syn-scan.csv
```

Sentinel creates the parent output directory when necessary. If `--output` is omitted, the results are printed to the terminal as JSON. Unsupported output extensions are rejected.

## Logging

Sentinel writes application logs to:

```text
logs/sentinel.log
```

The logging configuration uses a rotating file handler to limit log-file size and retain a small number of backups. The log records scan requests, successful completion and handled errors. Generated logs should not normally be committed to the repository.

## Running the tests

From the project root, run the complete test suite:

```bash
python -m pytest -q
```

The tests use mocked Scapy responses where appropriate, so most tests validate the program's logic without sending real network packets. They cover areas including:

- Target and port validation
- TCP SYN, ACK and XMAS response classification
- DNS query response handling
- CLI argument parsing and command dispatch
- JSON and CSV report generation
- Logging configuration and CLI logging behaviour

## Interpreting results and limitations

Network scan results are observations based on the packets received during a scan. They are not guarantees about the actual state of a service.

- **SYN scan:** a SYN/ACK response is treated as open, a RST response as closed, and a lack of response may be reported as filtered by the current implementation.
- **ACK scan:** a RST response is treated as unfiltered, while relevant ICMP unreachable responses and a lack of response are treated as filtered by the current implementation. An ACK scan does not determine whether a port is open.
- **XMAS scan:** a RST response is treated as closed; ICMP unreachable responses can indicate filtering; a lack of response is ambiguous and may be reported as open/filtered.
- **DNS query:** reports whether a DNS response was received and includes basic response information. A response does not establish that the DNS server is secure or correctly configured.

This project currently has several deliberate limitations:

- It implements basic packet-based scans rather than the full feature set of tools such as Nmap.
- It does not perform service/version detection, operating-system fingerprinting, vulnerability identification or exploitation.
- It does not implement comprehensive retransmission, timing adaptation or firewall-evasion techniques.
- Scan results can be inconclusive because of packet loss, host configuration, firewalls and network conditions.
- The DNS functionality is a basic A-record query, not DNS enumeration, anomaly detection or threat intelligence.

## Responsible use

Sentinel is intended for learning and for testing systems that you own or have explicit permission to assess. Do not scan networks, devices or services without authorisation. Keep scans narrow and within the intended scope. The built-in target allow-list and port limit are safeguards, not a substitute for responsible use.

## Future improvements

Potential future extensions include more robust packet-response validation, configurable scan timing, additional unit and integration tests, richer report metadata, and defensive monitoring features such as log analysis and alerting. These are not part of the current scanner-focused implementation unless they are added and tested separately.


