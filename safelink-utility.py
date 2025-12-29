#!/usr/bin/env python3


"""
Advanced Threat Protection (ATP) Safe Links URL Encoder / Decoder
By Rick Pelletier (galigante@gmail.com), 21 March 2025
Last Update: 29 December 2025

Supports:
- Microsoft Safe Links: All regions
- Barracuda: 'a=' wrappers
- Proofpoint v1/v2: 'u=' decoding
- Proofpoint v3: '__URL__' extraction
- Mimecast: 'url=' and 'domain='
- Generic A: 'a=' extractions
- Generic URL: 'url=' extraction

Regex-free decoding:
- RFC-compliant parsing
- Resistant to parameter reordering
- Handles nested encoding

Correct Safe Links encoding:
- Validates input URL
- Canonical formatting
- Region-agnostic

Security improvements:
- Structural validation
- No regex parsing of attacker-controlled URLs
- No silent exception swallowing

Linter: ruff check safelink-utility.py --extend-select F,B,UP
"""


from __future__ import annotations
import argparse
import sys
from typing import Callable
from urllib.parse import (
    parse_qs,
    quote,
    unquote,
    urlparse,
)


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
def _validate_url(url: str) -> None:
    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Invalid URL")


def _is_valid_url(url: str) -> bool:
    try:
        _validate_url(url)
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# Encoding functions
# --------------------------------------------------------------------------- #
def encode_safelinks(url: str, prefix: str) -> str:
    _validate_url(url)
    return f"{prefix.rstrip('/')}/?url={quote(url, safe='')}"


def encode_barracuda(url: str, prefix: str) -> str:
    _validate_url(url)
    return f"{prefix.rstrip('/')}/?a={quote(url, safe='')}"


def encode_proofpoint_v2(url: str, prefix: str) -> str:
    _validate_url(url)
    encoded = (
        url.replace(":", "-3A")
           .replace("/", "_")
    )
    return f"{prefix.rstrip('/')}/v2/url?u={encoded}"


def encode_proofpoint_v3(url: str, prefix: str) -> str:
    _validate_url(url)
    return f"{prefix.rstrip('/')}/v3/__{url}__;!!"


def encode_mimecast_url(url: str, prefix: str) -> str:
    _validate_url(url)
    return f"{prefix.rstrip('/')}/s/placeholder?url={quote(url, safe='')}"


def encode_mimecast_domain(url: str, prefix: str) -> str:
    parsed = urlparse(url)
    _validate_url(url)
    return f"{prefix.rstrip('/')}/s/placeholder?domain={parsed.netloc}"


def encode_generic_url(url: str, prefix: str) -> str:
    _validate_url(url)
    return f"{prefix.rstrip('/')}/?url={quote(url, safe='')}"


def encode_generic_a(url: str, prefix: str) -> str:
    _validate_url(url)
    return f"{prefix.rstrip('/')}/?a={quote(url, safe='')}"


ENCODERS: dict[str, Callable[[str, str], str]] = {
    "safelinks": encode_safelinks,
    "barracuda": encode_barracuda,
    "proofpoint-v2": encode_proofpoint_v2,
    "proofpoint-v3": encode_proofpoint_v3,
    "mimecast-url": encode_mimecast_url,
    "mimecast-domain": encode_mimecast_domain,
    "generic-url": encode_generic_url,
    "generic-a": encode_generic_a,
}

FORMAT_DESCRIPTIONS: dict[str, str] = {
    "safelinks": "Microsoft Safe Links (?url=)",
    "barracuda": "Barracuda linkprotect (?a=)",
    "proofpoint-v2": "Proofpoint URL Defense v1/v2 (u=)",
    "proofpoint-v3": "Proofpoint URL Defense v3 (__URL__)",
    "mimecast-url": "Mimecast (?url=)",
    "mimecast-domain": "Mimecast (?domain=)",
    "generic-url": "Generic wrapper (?url=)",
    "generic-a": "Generic wrapper (?a=)",
}


# --------------------------------------------------------------------------- #
# Decoding
# --------------------------------------------------------------------------- #
def decode_protected_url(protected_url: str) -> str | None:
    parsed = urlparse(protected_url)
    host = parsed.netloc.lower()
    query = parse_qs(parsed.query)

    # Proofpoint v3
    if "urldefense" in host and "__" in parsed.path:
        try:
            start = parsed.path.index("__") + 2
            end = parsed.path.index("__", start)
            candidate = parsed.path[start:end]
            return candidate if _is_valid_url(candidate) else None
        except ValueError:
            return None

    # Proofpoint v1/v2
    if "urldefense" in host and "u" in query:
        decoded = (
            query["u"][0]
            .replace("-3A", ":")
            .replace("_", "/")
        )
        return decoded if _is_valid_url(decoded) else None

    # Mimecast
    if "mimecast" in host:
        if "url" in query:
            decoded = unquote(query["url"][0])
            return decoded if _is_valid_url(decoded) else None

        if "domain" in query:
            return f"https://{query['domain'][0]}"

    # Generic / Safe Links / Barracuda
    for key in ("url", "a"):
        if key in query:
            decoded = unquote(query[key][0])

            return decoded if _is_valid_url(decoded) else None

    return None


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Encode or decode protected email security URLs"
    )

    parser.add_argument(
        "--list-formats",
        action="store_true",
        help="List supported encoding formats and exit",
    )

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("-e", "--encode", action="store_true")
    mode.add_argument("-d", "--decode", action="store_true")

    parser.add_argument("-u", "--url", help="URL to process")

    parser.add_argument(
        "--format",
        choices=sorted(ENCODERS),
        help="Encoding format (required for --encode)",
    )

    parser.add_argument(
        "--prefix",
        default="https://na01.safelinks.protection.outlook.com",
        help="Base service URL",
    )

    return parser


def _list_formats() -> None:
    print("Available encoding formats:\n")

    for name in sorted(ENCODERS):
        description = FORMAT_DESCRIPTIONS.get(name, "")
        print(f"  {name:<17} {description}")


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.list_formats:
        _list_formats()
        return 0

    try:
        if args.encode:
            if not args.url or not args.format:
                raise ValueError("--encode requires --url and --format")

            encoder = ENCODERS[args.format]
            print(encoder(args.url, args.prefix))

            return 0

        if args.decode:
            if not args.url:
                raise ValueError("--decode requires --url")

            decoded = decode_protected_url(args.url)
            if decoded:
                print(decoded)

                return 0

            print("Error: Unsupported or invalid protected URL", file=sys.stderr)

            return 1

        parser.error("One of --encode, --decode, or --list-formats is required")

    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)

        return 1


if __name__ == "__main__":
    sys.exit(main())

# end of script
