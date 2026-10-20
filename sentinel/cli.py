import argparse
import json
import sys

from sentinel.network import scanner


def parse_ports(value):
    # Convert comma-separated port numbers into a list of integers.
    parts = value.split(",")

    if not parts or any(not prt.strip() for prt in parts):
        raise argparse.ArgumentTypeError(
            "Provide comma-separated ports, e.g. 22,80,443."
        )

    try:
        return [int(prt.strip()) for prt in parts]
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "Ports must be integers, e.g. 22,80,443."
        ) from exc


def build_parser():
    # Build cli argument parser.
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel - Python Network Reconnaissance Toolkit",
    )

    subparsers = parser.add_subparsers(
        dest="scan_type",
        required=True,
        help="Type of scan to perform",
    )

    # Commands for the TCP scans.
    for scan_name in ("syn", "ack", "xmas"):
        scan_parser = subparsers.add_parser(
            scan_name,
            help=f"Perform a TCP {scan_name.upper()} scan",
        )

        scan_parser.add_argument(
            "--host",
            required=True,
            help="Target IP address",
        )

        scan_parser.add_argument(
            "--ports",
            required=True,
            type=parse_ports,
            help="Comma-separated TCP ports, e.g. 22,80,443",
        )

        scan_parser.add_argument(
            "--allow-target",
            dest="allowed_targets",
            action="append",
            default=None,
            help=(
                "Explicitly authorised IP address or CIDR network. "
                "May be supplied more than once."
            ),
        )

    # DNS requires a DNS server IP and a domain but not TCP ports.
    dns_parser = subparsers.add_parser(
        "dns",
        help="Send a DNS A-record query",
    )

    dns_parser.add_argument(
        "--host",
        required=True,
        help="IP address of the DNS server",
    )

    dns_parser.add_argument(
        "--domain",
        required=True,
        help="Domain name to query",
    )

    dns_parser.add_argument(
        "--allow-target",
        dest="allowed_targets",
        action="append",
        default=None,
        help=(
            "Explicitly authorised DNS server IP or CIDR network. "
            "May be supplied more than once."
        ),
    )

    return parser


def main(argv=None):
    # Parse CLI arguments, run a scan, and display the results.
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.scan_type == "syn":
            results = scanner.syn_scan(
                args.host,
                args.ports,
                allowed_targets=args.allowed_targets,
            )

        elif args.scan_type == "ack":
            results = scanner.ack_scan(
                args.host,
                args.ports,
                allowed_targets=args.allowed_targets,
            )

        elif args.scan_type == "xmas":
            results = scanner.xmas_scan(
                args.host,
                args.ports,
                allowed_targets=args.allowed_targets,
            )

        elif args.scan_type == "dns":
            results = scanner.dns_scan(
                args.host,
                args.domain,
                allowed_targets=args.allowed_targets,
            )

        else:
            parser.error("Unsupported scan type.")

        # Print the results as readable JSON.
        print(json.dumps(results, indent=2, default=str))
        return 0

    except (ValueError, PermissionError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
