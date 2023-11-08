#!/usr/bin/env python3
from __future__ import annotations

import socket
import sys
import time
from typing import Optional
from collections.abc import Generator
from contextlib import ExitStack


def traceroute(
    dest_addr: str, max_hops: int = 64, timeout: float = 2
) -> Generator[tuple[Optional[str] , Optional[float] ], None, None]:
    """Traceroute implementation using UDP packets.

    Args:
        dest_addr (str): The destination address.
        max_hops (int, optional): The maximum number of hops.
        Defaults to 64.
        timeout (float, optional): The timeout for receiving packets.
        Defaults to 2.

    Yields:
        Generator[tuple[str | None , float | None ], None, None]: A generator that
        yields the current address and elapsed time for each hop.

    """
    # ExitStack allows us to avoid multiple nested contextmanagers
    with ExitStack() as stack:
        # Create an ICMP socket connection for receiving packets
        rx = stack.enter_context(
            socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
            )
        )

        # Create a UDP socket connection for sending packets
        tx = stack.enter_context(
            socket.socket(
                socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP
            )
        )

        # Set the timeout for receiving packets
        rx.settimeout(timeout)

        # Bind the receiver socket to any available port
        rx.bind(("", 0))

        # Iterate over the TTL values
        for ttl in range(1, max_hops + 1):
            # Set the TTL value in the sender socket
            tx.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

            # Send an empty UDP packet to the destination address
            tx.sendto(b"", (dest_addr, 33434))

            try:
                # Start the timer
                start_time = time.perf_counter_ns()

                # Receive the response packet and extract the source address
                _, curr_addr = rx.recvfrom(512)
                curr_addr = curr_addr[0]

                # Stop the timer and calculate the elapsed time
                end_time = time.perf_counter_ns()
                elapsed_time = (end_time - start_time) / 1e6
            except socket.error:
                # If an error occurs while receiving the packet, set the
                # address and elapsed time as None
                curr_addr = None
                elapsed_time = None

            # Yield the current address and elapsed time
            yield curr_addr, elapsed_time

            # Break the loop if the destination address is reached
            if curr_addr == dest_addr:
                break


def main() -> None:
    # Get the destination address from command-line argument
    dest_name = sys.argv[1]
    dest_addr = socket.gethostbyname(dest_name)

    # Print the traceroute header
    print(f"Traceroute to {dest_name} ({dest_addr})")
    print(
        f"{'Hop':<5s}{'IP Address':<20s}{'Hostname':<50s}{'Time (ms)':<10s}"
    )
    print("-" * 90)

    # Iterate over the traceroute results and print each hop information
    for i, (addr, elapsed_time) in enumerate(traceroute(dest_addr)):
        if addr is not None:
            try:
                # Get the hostname corresponding to the IP address
                host = socket.gethostbyaddr(addr)[0]
            except socket.error:
                host = ""
            # Print the hop information
            print(
                f"{i+1:<5d}{addr:<20s}{host:<50s}{elapsed_time:<10.3f} ms"
            )
        else:
            # Print "*" for hops with no response
            print(f"{i+1:<5d}{'*':<20s}{'*':<50s}{'*':<10s}")


if __name__ == "__main__":
    main()
