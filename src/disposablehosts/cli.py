"""Command-line interface for disposable email domain generator."""

import argparse
import sys

from .generator import disposableHostGenerator


def main() -> None:
    """Main entry point for the disposable email domain generator."""
    exit_status = 1
    parser = argparse.ArgumentParser(description="Generate list of disposable mail hosts.")
    parser.add_argument(
        "--dns-verify",
        action="store_true",
        dest="dns_verify",
        help="validate if valid MX / A record is present for hosts",
    )
    parser.add_argument(
        "--source-map",
        action="store_true",
        dest="source_map",
        help="generate source map",
    )
    parser.add_argument(
        "--src",
        dest="src_filter",
        help="only request entries for given source",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_false",
        dest="verbose",
        help="hide verbose output",
    )
    parser.add_argument(
        "-D",
        "--debug",
        action="store_true",
        dest="debug",
        help="show debug output and exit on warn/error",
    )
    parser.add_argument(
        "--max-retry",
        type=int,
        dest="max_retry",
        help="maximum count of retries to fetch an url, default: 150",
        default=150,
    )
    parser.add_argument(
        "--dns-threads",
        type=int,
        dest="dns_threads",
        help="count of threads to use for dns resolving, default:10",
        default=10,
    )
    parser.add_argument(
        "--dns-timeout",
        type=float,
        dest="dns_timeout",
        help="timeout for dns request, default: 20",
        default=20.0,
    )
    parser.add_argument(
        "--ns",
        action="append",
        dest="nameservers",
        help="set custom resolver for dns-verify",
    )
    parser.add_argument(
        "--dnsport",
        type=int,
        dest="dnsport",
        help="set custom resolver port for dns-verify",
    )
    parser.add_argument(
        "--list-sources",
        action="store_true",
        dest="list_sources",
        help="list all sources",
    )
    parser.add_argument(
        "--list-no-mx",
        action="store_true",
        dest="list_no_mx",
        help="list domains without valid mx",
    )
    parser.add_argument(
        "--whitelist",
        dest="whitelist",
        help="custom whitelist to load - all domains listed in that file are removed from output",
    )
    parser.add_argument(
        "--greylist",
        dest="greylist",
        help="custom greylist to load - all domains listed in that file are removed from output if not --strict is set",
    )
    parser.add_argument(
        "--add-free-mailservices",
        action="store_true",
        dest="free_mailservices",
        help="list free mail services",
    )
    parser.add_argument(
        "--file",
        dest="file",
        help="custom file to load - add custom domains to local result",
    )
    parser.add_argument(
        "--skip-scrape",
        dest="skip_scrape",
        action="store_true",
        help="skip domain scraping - only use static sources",
    )
    parser.add_argument(
        "--skip-src",
        dest="skip_src",
        action="append",
        help="skip given src - can be set multiple times",
    )
    parser.add_argument(
        "--strict",
        dest="strict",
        action="store_true",
        help="remove domains with anonymous signup methods - see greylist.txt",
    )
    parser.add_argument(
        "--dedicated-strict",
        dest="dedicated_strict",
        action="store_true",
        help="create additional file including domains skipped in strict mode",
    )

    options = parser.parse_args()
    dhg = disposableHostGenerator(vars(options))
    if options.list_sources:
        dhg.list_sources()
    elif dhg.generate() or options.src_filter is not None:
        exit_status = 0
        dhg.write_to_file()
        if options.dedicated_strict:
            dhg.add_greylist()
            dhg.out_file = "domains_strict"
            dhg.write_to_file()
    sys.exit(exit_status)
