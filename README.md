# Traceroute IP Address Parser

## Overview

This Python script allows you to run the traceroute from Python and extract a list of IP addresses from the output while preserving the order of appearance. It can be useful for analyzing the route taken by network packets when trying to reach a specific host or IP address.

## Features

- Run traceroute from Python using the subprocess module.
- Extract a list of IP addresses from the traceroute output.
- Remove duplicate IP addresses while preserving the order of appearance.
- Print the list of unique IP addresses and a description of their respective organizations

## Usage

1. Install the required packages if you haven't already:

```bash
pip install subprocess
pip install re
```

1. Run the script by providing the destination host or IP address as a command-line argument:

```bash
python trwi.py -i example.com
```

The script will execute the traceroute command and display a list of unique IP addresses in the order they were encountered and which organization or company they belong too.

## TODO

- The script depends on the traceroute program already installed on the system so it is kinda very slow. Maybe using another language like go or rust might make it faster.
- Also I wanna add a loading spinner or something.
