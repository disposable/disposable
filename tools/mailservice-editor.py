import json
import argparse
import os
import sys
from typing import List, Optional

from verify_data import ALLOWED_TYPES, ALLOWED_VERIFICATIONS


def load_json(file_path):
    """Load JSON file or return an empty dict if file doesn't exist."""
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_json(file_path, data):
    """Save data to JSON file."""
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def update_json(
    file_path: str,
    service: str,
    hosts: Optional[List[str]] = None,
    mx_hosts: Optional[List[str]] = None,
    account_type: Optional[str] = None,
    signup_verification: Optional[str] = None
) -> None:
    """Update or add a domain entry in the JSON file.

    Args:
        file_path: Path to the JSON file.
        domain: Domain name to update/add.
        hosts: List of hostnames.
        mx_hosts: List of MX hostnames.
        account_type: Type of the account.
        signup_verification: Verification method used during signup.
    """
    data = load_json(file_path)

    if service in data:
        # Update existing entry
        new_hosts = set(data[service].get("hosts", []))
        new_mx_hosts = set(data[service].get("mx_hosts", []))

        if hosts:
            new_hosts = new_hosts.union(set(hosts))

        if mx_hosts:
            new_mx_hosts = new_mx_hosts.union(set(mx_hosts))

        data[service]["hosts"] = list(new_hosts)

        if new_mx_hosts:
            data[service]["mx_hosts"] = list(new_mx_hosts)
    else:
        # Add new entry
        data[service] = {
            "hosts": hosts,
        }
        if mx_hosts:
            data[service]["mx_hosts"] = mx_hosts

    if account_type:
        if account_type not in ALLOWED_TYPES:
            print(f"Invalid account type: {account_type}")
            sys.exit(1)
        data[service]["type"] = account_type

    if signup_verification:
        if signup_verification not in ALLOWED_VERIFICATIONS:
            print(f"Invalid signup verification: {signup_verification}")
            sys.exit(1)
        data[service]["signup_verification"] = signup_verification

    save_json(file_path, data)
    print(f"Updated {service} in {file_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Update JSON file with service details.")

    parser.add_argument("--file", default="mailservices.json", help="Path to the JSON file.")
    parser.add_argument("--service", required=True, help="Service name to update/add.")
    parser.add_argument("--host", action="append", default=[], help="Hostnames (can be used multiple times).")
    parser.add_argument("--mx-host", action="append", default=[], help="MX Hostnames (can be used multiple times).")
    parser.add_argument("--stdin", action="store_true", help="Read hosts from stdin (line by line).")
    parser.add_argument("--type", choices=ALLOWED_TYPES, help="Account type (free or paid).")
    parser.add_argument("--verify", choices=ALLOWED_VERIFICATIONS, help="Signup verification type.")

    args = parser.parse_args()

    # Collect hosts from stdin if enabled
    stdin_hosts = []
    if args.stdin:
        stdin_hosts = [line.strip() for line in sys.stdin if line.strip()]

    # Combine hosts from CLI args and stdin
    all_hosts = args.host + stdin_hosts
    all_mx_hosts = args.mx_host  # MX hosts are not read from stdin

    update_json(args.file, args.service, all_hosts, all_mx_hosts, args.type, args.verify)
