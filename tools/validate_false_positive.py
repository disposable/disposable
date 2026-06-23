#!/usr/bin/env python3
"""Validate a false-positive issue and post an automated response."""

import argparse
import re
import subprocess
import sys
from urllib.request import urlopen


def parse_section(body: str, heading: str) -> str:
    """Extract the value of a markdown section by its heading."""
    pattern = re.compile(
        rf"^### {re.escape(heading)}\s*\n\s*(.+?)(?=\n### |\Z)",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(body)
    if match:
        return match.group(1).strip()
    return ""


def get_managed_sources(generator_path: str) -> set:
    """Parse generator.py and return URLs of sources managed by this repository."""
    managed = set()
    with open(generator_path, "r") as f:
        content = f.read()
    for block in re.finditer(r"\{[^{}]*?\}", content):
        block_text = block.group()
        if '"src"' not in block_text and "'src'" not in block_text:
            continue
        if '"external": False' not in block_text and "'external': False" not in block_text:
            continue
        src_match = re.search(r'["\']src["\']:\s*["\']([^"\']+)["\']', block_text)
        if src_match:
            managed.add(src_match.group(1))
    return managed


def fetch_lines(url: str) -> set[str]:
    """Fetch a text file from a URL and return its lines as a set."""
    with urlopen(url) as response:
        return {line.decode("utf-8").strip() for line in response}


def format_source_line(url: str) -> str:
    """Format a source URL as a markdown line with optional GitHub issue link."""
    if url.startswith("https://raw.githubusercontent.com/"):
        parts = url.split("/")
        user, repo, branch = parts[3], parts[4], parts[5]
        file_path = "/".join(parts[6:])
        blob_url = f"https://github.com/{user}/{repo}/blob/{branch}/{file_path}"
        issue_url = f"https://github.com/{user}/{repo}/issues/new"
        return f"- [{user}/{repo}/{file_path}]({blob_url}) ([report false positive to source]({issue_url}))"
    return f"- [{url}]({url})"


def validate(
    domains_url: str,
    source_map_url: str,
    generator_path: str,
    issue_body: str,
) -> tuple[bool, bool, str, str, list[str]]:
    """
    Validate a false-positive report.

    Returns:
        domain_found: whether the domain is in the blocklist
        has_managed_source: whether any source for the domain is managed by this repo
        domain: the parsed domain name
        claimed_source: the parsed claimed source URL
        actual_sources: list of actual source URLs for the domain
    """
    domain = parse_section(issue_body, "Domain name")
    claimed_source = parse_section(issue_body, "Source list")

    domains = fetch_lines(domains_url)
    domain_found = domain in domains

    actual_sources = []
    if domain_found:
        with urlopen(source_map_url) as response:
            for line in response:
                line = line.decode("utf-8").strip()
                if line.endswith(f":{domain}"):
                    actual_sources.append(line.rsplit(":", 1)[0])

    managed_sources = get_managed_sources(generator_path)
    has_managed_source = any(src in managed_sources for src in actual_sources)

    return domain_found, has_managed_source, domain, claimed_source, actual_sources


def build_comment(
    domain_found: bool,
    has_managed_source: bool,
    domain: str,
    claimed_source: str,
    actual_sources: list[str],
) -> str:
    """Build the appropriate comment based on validation results."""
    sources_block = "\n".join(format_source_line(src) for src in actual_sources) if actual_sources else "_No sources found._"

    if not domain_found:
        return (
            f"Thank you for your message!\n\n"
            f"To confirm the status of your domain, please use the following lookup link:\n"
            f"https://disposable.github.io/disposable-email-domains/lookup\n\n"
            f"Your domain **{domain}** does not appear to be currently listed in our blocklist.\n\n"
            f"This issue will remain closed. Please reply to this ticket if you need it reopened."
        )

    if not has_managed_source:
        return (
            f"Thank you for your message!\n\n"
            f"To confirm the status of your domain, please use the following lookup link:\n"
            f"https://disposable.github.io/disposable-email-domains/lookup\n\n"
            f"Your domain **{domain}** is listed from the following external source(s). "
            f"We are an aggregator and do **not** manage these sources. "
            f"To have your domain removed, you must report the false positive to each source directly:\n\n"
            f"{sources_block}\n\n"
            f"Once the source(s) remove your domain, it will automatically disappear from our list at the next update.\n\n"
            f"This issue will remain closed. Please reply if you need it reopened after the source(s) have been updated."
        )

    return (
        f"✅ Validation passed\n\n"
        f"- **Domain**: {domain}\n"
        f"- **Claimed source**: {claimed_source or '(not provided)'}\n"
        f"- **Actual source(s)**:\n\n"
        f"{sources_block}\n\n"
        f"This domain is listed from a source managed by this repository. "
        f"A maintainer will review this request."
    )


def post_comment(issue_number: str, comment: str) -> None:
    """Post a comment on the issue using the GitHub CLI."""
    subprocess.run(
        ["gh", "issue", "comment", issue_number, "--body", comment],
        check=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate a false-positive issue and post an automated response.",
    )
    parser.add_argument("--issue-number", required=True, help="GitHub issue number")
    parser.add_argument("--issue-body", required=True, help="GitHub issue body text")
    parser.add_argument(
        "--domains-url",
        default="https://raw.githubusercontent.com/disposable/disposable-email-domains/master/domains.txt",
        help="URL to domains.txt",
    )
    parser.add_argument(
        "--source-map-url",
        default="https://raw.githubusercontent.com/disposable/disposable-email-domains/master/domains_source_map.txt",
        help="URL to domains_source_map.txt",
    )
    parser.add_argument("--generator-file", default="src/disposablehosts/generator.py", help="Path to generator.py")

    args = parser.parse_args()

    domain_found, has_managed_source, domain, claimed_source, actual_sources = validate(
        args.domains_url,
        args.source_map_url,
        args.generator_file,
        args.issue_body,
    )

    if not domain:
        print("Could not parse domain from issue body; skipping validation.")
        sys.exit(0)

    comment = build_comment(domain_found, has_managed_source, domain, claimed_source, actual_sources)
    post_comment(args.issue_number, comment)


if __name__ == "__main__":
    main()
