#!/usr/bin/env python3
# -*- coding: utf-8 -*-


"""
Advanced Threat Protection (ATP) Safe Links URL Encoder/Decoder
By Rick Pelletier (galigante@gmail.com), 21 March 2025
Last Update: 21 March 2025

Also see:
- https://digital.va.gov/employee-resource-center/safe-link-decoder/
- https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-office-365
"""


import sys
import re
import urllib.parse
import argparse


def encode_atp_safe_links(url):
    encoded_url = urllib.parse.quote(url)
    atp_safe_links_url = f'https://na01.safelinks.protection.outlook.com/?url={encoded_url}&data=04...'

    return atp_safe_links_url


def decode_atp_safe_links(url):
    match = re.search(r'url=([^&]+)', url)

    if match:
        encoded_url = match.group(1)
        decoded_url = urllib.parse.unquote(encoded_url)

        return decoded_url
    else:
        return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    command_group_two = parser.add_mutually_exclusive_group(required=True)
    command_group_two.add_argument('-e', '--encode', action='store_true')
    command_group_two.add_argument('-d', '--decode', action='store_true')
    parser.add_argument('--url', '-u', type=str, required=True)
    args = parser.parse_args()

    if args.encode:
        if (encoded_url := encode_atp_safe_links(args.url)):
            print(f'{encoded_url}')

    if args.decode:
        if (decoded_url := decode_atp_safe_links(args.url)):
            print(f'{decoded_url}')
        else:
            print('Invalid Safelink (or unable to decode)')

        sys.exit(1)

    sys.exit(0)
else:
    sys.exit(1)

# end of script
