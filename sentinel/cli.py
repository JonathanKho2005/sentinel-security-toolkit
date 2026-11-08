
import argparse
import json
import sys
from pathlib import Path

from sentinel.network import scanner
from sentinel import reporting
from sentinel.logging_config import configure_logging


def parse_ports(value):
    """Convert comma-separated port numbers into a list of integers."""

    parts = value.split(",")

    if not parts or any(not part.strip() for part in parts):
        raise argparse.ArgumentTypeError(
            "Provide comma-separated ports, e.g. 22,80,443."
        )

    try:
        return [int(part.strip()) for part in parts]
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "Ports must be integers, e.g. 22,80,443."
        ) from exc


def build_parser():
    """Build the CLI argument parser."""

    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel - Python Network Reconnaissance Toolkit",
    )

    subparsers = parser.add_subparsers(
        dest="scan_type",
        required=True,
        help="Type of scan to perform",
    )

    # Commands for TCP scans.
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
            help="Explicitly authorised IP address or CIDR network.",
        )

        scan_parser.add_argument(
            "--output",
            help="Save results to a .json or .csv file.",
        )

    # DNS command.
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
        help="Explicitly authorised DNS server IP or CIDR network.",
    )

    dns_parser.add_argument(
        "--output",
        help="Save results to a .json or .csv file.",
    )

    return parser


def main(argv=None):
    """Parse CLI arguments, execute a scan and handle its output."""

    parser = build_parser()
    args = parser.parse_args(argv)

    # Reject unsupported report formats before scanning.
    if args.output:
        extension = Path(args.output).suffix.lower()

        if extension not in {".json", ".csv"}:
            parser.error("Output filename must end in .json or .csv.")

    # Configure application logging.
    logger = configure_logging()

    logger.info(
        "Scan requested: type=%s target=%s",
        args.scan_type,
        args.host,
    )

    try:
        # Execute the selected scanner.
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

        # Record successful scan completion.
        logger.info(
            "Scan completed: type=%s target=%s results=%d",
            args.scan_type,
            args.host,
            len(results),
        )

        # Save results if an output path was provided.
        if args.output:
            saved_path = reporting.save_report(
                results,
                args.output,
            )

            logger.info(
                "Report saved: path=%s format=%s records=%d",
                saved_path,
                saved_path.suffix.lower(),
                len(results),
            )

            print(f"Report successfully saved to: {saved_path}")

        else:
            # Otherwise, display results in Terminal.
            print(json.dumps(results, indent=2, default=str))

        return 0

    except (ValueError, OSError) as exc:
        logger.error(
            "Operation failed: type=%s target=%s error=%s",
            args.scan_type,
            args.host,
            exc,
        )

        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
