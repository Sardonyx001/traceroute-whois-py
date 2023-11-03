#!usr/bin/env python3
'''
    This is Python script that performs a traceroute to a specified destination, extracts
    the unique IP addresses from the traceroute output, and retrieves WHOIS information for each IP
    address.

    Parameters
    ----------
    destination : str
        The `destination` parameter is the address or hostname to trace the route to. It is the target
    destination for the traceroute command.

    Returns
    -------
        The code returns the IP addresses and their respective organization of each IP that is passed
    through the traceroute.

'''

import re
import subprocess
import argparse
from ipwhois import IPWhois
from halo import Halo

@Halo(text='Loading', spinner='bouncingBar')
def run_traceroute(destination: str) -> str: 
    """
    Runs a traceroute to the specified destination and returns the output.

    Args:
        destination (str): The destination address or hostname to trace the route to.

    Returns:
        str: The output of the traceroute command if successful, or an error message if an error occurs.

    Raises:
        None

    Examples:
        >>> run_traceroute("www.example.com")
        'traceroute to www.example.com (93.184.216.34), 30 hops max, 60 byte packets\n 1  192.168.1.1 (192.168.1.1)  1.234 ms  1.345 ms  1.456 ms\n 2  10.0.0.1 (10.0.0.1)  2.345 ms  2.456 ms  2.567 ms\n 3  203.0.113.1 (203.0.113.1)  3.456 ms  3.567 ms  3.678 ms\n ...'
    """

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
    """
    Extracts unique IP addresses from the given traceroute output.

    Args:
        traceroute_output (str): The output of the traceroute command.

    Returns:
        list[str]: A list of unique IP addresses extracted from the traceroute output.

    Raises:
        None
    """
    # Regular expression pattern for matching IP addresses
    ip_address_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ip_addresses: list[str] = re.findall(ip_address_pattern, traceroute_output)

    unique_ip_addresses: list[str] = []
    seen = set()
    for ip in ip_addresses:
        if ip not in seen and "192.168" not in ip:
            unique_ip_addresses.append(ip)
            seen.add(ip)

    return unique_ip_addresses

@Halo(text='Tracing', spinner='bouncingBar')
def get_whois_info(ip_address: str) -> dict[str, None] | str:
    """
    Retrieves WHOIS information for the specified IP address.

    Args:
        ip_address (str): The IP address to retrieve WHOIS information for.

    Returns:
        Union[dict[str, None], str]: A dictionary containing WHOIS information if successful, or an error message if an error occurs.

    Raises:
        None
    """
    try:
        return IPWhois(ip_address).lookup_whois()
    except Exception as e:
        return f"Error: {str(e)}" 


def main():
    parser = argparse.ArgumentParser(
        description="Print Ip Addresses and their respective organization of each IP passes through traceroute"
    )
    parser.add_argument(
        "-t", dest="destinations", nargs='+', required=True, help="IP address or hostname to lookup. It can also be a list"
    )

    args = parser.parse_args()
    destinations: list[str] = args.destinations
    for dest in destinations:
        traceroute_output = run_traceroute(dest)
        ip_addresses = extract_ip_addresses(traceroute_output)

        print(f"Traceroute and Whois info for {dest}")
        i: int = 0
        for i,ip in enumerate(ip_addresses):
            whois_info = get_whois_info(ip)
            if isinstance(whois_info, dict):
                print(f'{i+1}* {ip}: {whois_info["asn_description"]}')
            else:
                print(whois_info)
        print("-"*80)


if __name__ == "__main__":
    main()
