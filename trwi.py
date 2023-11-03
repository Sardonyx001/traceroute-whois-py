#!usr/bin/env python3

import re
import subprocess
import argparse
from ipwhois import IPWhois


def run_traceroute(destination: str) -> str: 
    try:
        result = subprocess.run(
            ["traceroute", destination],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        if result.returncode == 0:
            return result.stdout
        else:
            return f"Traceroute error: {result.stderr}"
    except Exception as e:
        return f"An error occurred: {str(e)}"


def extract_ip_addresses(traceroute_output: str) -> list[str]:
    # Regular expression pattern for matching IP addresses
    ip_address_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ip_addresses: list[str] = re.findall(ip_address_pattern, traceroute_output)

    unique_ip_addresses: list[str] = []
    seen = set()
    for ip in ip_addresses:
        if ip not in seen:
            unique_ip_addresses.append(ip)
            seen.add(ip)

    return unique_ip_addresses


def get_whois_info(ip_address: str) -> dict[str, None] | str:
    try:
        return IPWhois(ip_address).lookup_whois()
    except Exception as e:
        return f"Error: {str(e)}" 


def main():
    parser = argparse.ArgumentParser(
        description="Print Ip Addresses and their respective organization of each IP passes through traceroute"
    )
    parser.add_argument(
        "-i", dest="ip_address", required=True, help="IP address to lookup"
    )

    args = parser.parse_args()
    ip_address: str = args.ip_address

    traceroute_output = run_traceroute(ip_address)
    ip_addresses = extract_ip_addresses(traceroute_output)

    for ip in ip_addresses:
        whois_info = get_whois_info(ip)
        if isinstance(whois_info, dict):
            print(f'{ip}: {whois_info["asn_description"]}')
        else:
            print("Something went wrong.")


if __name__ == "__main__":
    main()
