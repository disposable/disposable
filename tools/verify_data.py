#!env python3

import json
import sys
import argparse
import re

ALLOWED_TYPES = ['free', 'paid', 'forwarding']
ALLOWED_VERIFICATIONS = ['none', 'email', 'mobile', 'payment', 'other']


# Regular expression for validating domain names
HOSTNAME_RE = re.compile(
    r"^(?!-)[A-Za-z0-9\-]{1,255}(?<!-)(\.[A-Za-z0-9\-]{2,64})+$"
)


def validate_mailservices(filename: str):
    """
    Validate the structure of a mail services data file.

    Check that the JSON is valid and that the content matches the expected structure.
    The expected structure is a dictionary with service names as keys. Each service
    has a dictionary with the following keys:
        hosts: a list of strings representing the hostnames of the service.
        type: a string indicating the type of the service. Possible values are
            'free' and 'paid'.
        signup_verification: a string indicating the verification method used
            during signup. Possible values are 'none', 'email', 'mobile', 'payment',
            and 'other'.
        mx_hosts: a list of strings representing the MX hosts of the service. This
            key is optional.

    The function will print an error message for each invalid or missing entry
    and exit with code 1 if there are any errors. If no errors are found, it will
    print a success message and exit with code 0.

    Args:
        filename: Path to the JSON file.

    Returns:
        True if the JSON is valid and the content matches the expected structure,
        False otherwise.
    """
    data = {}
    errors = []
    with open(filename) as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print(f"Failed to decode {filename}")
            return False

    if not isinstance(data, dict):
        print(f"Invalid JSON: {filename} must contain an object (dictionary)")
        return False

    all_hosts = set()
    mx_hosts = set()
    for service_name, service_options in data.items():
        if not type(service_options) is dict:
            errors.append("Service {} is not a dictionary.".format(service_name))
            continue

        if not type(service_options.get('hosts')) is list:
            errors.append("Service {} has no hosts.".format(service_name))
            continue

        for host in service_options['hosts']:
            if not type(host) is str:
                errors.append("Host {} is not a string.".format(host))
                continue

            if not HOSTNAME_RE.match(host):
                errors.append("Host {} is not a valid domain name.".format(host))
                continue

            if host in all_hosts:
                errors.append("Duplicate host {} in service {}.".format(host, service_name))
                continue

            all_hosts.add(host)

        if "mx_hosts" in service_options:
            if not isinstance(service_options["mx_hosts"], list):
                errors.append("MX hosts for service {} are not a list.".format(service_name))
                continue

            for mx in service_options["mx_hosts"]:
                if not isinstance(mx, str):
                    errors.append("MX host {} in service {} is not a string.".format(mx, service_name))
                    continue

                if not HOSTNAME_RE.match(mx):
                    errors.append("Invalid MX host {} in service {}.".format(mx, service_name))
                    continue

                if mx in mx_hosts:
                    errors.append("Duplicate MX host {} in service {}.".format(mx, service_name))
                    continue

                mx_hosts.add(mx)

        if service_options.get('type') and service_options['type'] not in ALLOWED_TYPES:
            errors.append("Type {} for service {} is unknown.".format(service_options['type'], service_name))

        if service_options.get('signup_verification') and service_options['signup_verification'] not in ALLOWED_VERIFICATIONS:
            errors.append("Verification {} for service {} is unknown.".format(service_options['signup_verification'], service_name))

        if service_options.get('mx_hosts') and type(service_options['mx_hosts']) is not list:
            errors.append("MX hosts for service {} are not a list.".format(service_name))

    if errors:
        print(f"Verification for {filename} failed:")
        for error in errors:
            print(error)
        return False

    print("%s is valid." % filename)
    return True


def validate_hostname_file(filename: str) -> bool:
    errors = []
    with open(filename) as f:
        x = 0
        for line in f:
            x += 1
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if not HOSTNAME_RE.match(line):
                errors.append(f"Line {x}: {line} is not a valid domain name.")

    if errors:
        print(f"Verification for {filename} failed:")
        for error in errors:
            print(error)
        return False

    print(f"{filename} is valid")
    return True


def main():
    parser = argparse.ArgumentParser(description="Verify structur of all data files")

    parser.add_argument("--github", action="store_true", help="Validate all files.")
    parser.add_argument("--mailservices", help="Path to the mailservices JSON file.")
    parser.add_argument("--whitelist", help="Path to the whiliste file.")

    args = parser.parse_args()
    error = False

    if args.github:
        args.mailservices = "mailservices.json"
        args.whitelist = "whitelist.txt"

    if args.whitelist and not validate_hostname_file(args.whitelist):
        error = True

    if args.mailservices and not validate_mailservices(args.mailservices):
        error = True

    if error:
        sys.exit(1)


if __name__ == "__main__":
    main()
