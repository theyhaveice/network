# network

A lightweight macOS command-line tool for resolving and scanning network devices. Query a single IP, sweep a subnet, or inspect your own machine — with output in plain text, JSON, or XML.

---

## Table of Contents

- [About](#about)
- [Installation](#installation)
- [Usage](#usage)
  - [Commands](#commands)
  - [Flags](#flags)
- [Examples](#examples)
- [License](#license)

---

## About

`network` is a C++ command-line utility for macOS that resolves detailed information about devices on your local network. Given one or more IP addresses, a CIDR subnet, or an IP range, it probes each host and returns:

- **Hostname** — resolved via mDNS, ARP, NSHost, and `getnameinfo` (tried in order)
- **IPv4 / IPv6** addresses
- **MAC address** — from the ARP table
- **Vendor** — looked up against a local OUI database (`arp-scan`) with a fallback to the [macvendors.com](https://macvendors.com) API
- **TTL** — ARP expiry time

Results are cached to `/tmp/network_tool_cache.tsv` for one hour to keep repeated queries fast. Non-responding devices are never written to cache.

The scanner uses a concurrent thread pool (default 64 threads) to sweep subnets quickly.

> **Platform:** macOS only. The tool depends on `Foundation.framework`, `dns_sd`, and macOS-specific ARP/interface APIs.

---

## Installation
to install `network`. run this in `Terminal`
```bash
curl -fsSL "https://raw.githubusercontent.com/theyhaveice/network/main/install.sh"

# Downloading network v0.1.0...
# network v0.1.0 installed successfully!
# You can run it using: network
```

## Usage

```
network [command] [flags]
```

### Commands

| Command | Description |
|---|---|
| `get` | Resolve and display info for one or more IP addresses |
| `current` | Show network info for this device |
| `clear-cache` | Delete all cached device results |
| `help` | Show help |

Run `network [command] --help` for command-specific details.

---

### Flags

#### `get` — Input flags

| Flag | Description |
|---|---|
| `-ip <ip>[,<ip>...]` | One or more individual IP addresses |
| `-subnet <ip/prefix>` | All host IPs in a CIDR subnet (e.g. `192.168.1.0/24`) |
| `-range <minIp>,<maxIp>` | Inclusive IP range (e.g. `192.168.1.1,192.168.1.64`) |

#### Output flags (all commands)

| Flag | Description |
|---|---|
| `-o <field>[,<field>...]` | Fields to display: `hostname`, `ipv4`, `ipv6`, `macaddress`, `vendor`, `ttl` |
| `--xml` | Output as XML |
| `--json` | Output as JSON |

#### Filter flags

| Flag | Description |
|---|---|
| `--R` | Include all responding devices |
| `--A` | Include every IP in the range, responding or not |

#### Cache flags

| Flag | Description |
|---|---|
| `--nocache` | Skip cache read/write for this run (always re-probe) |

---

## Examples

```bash
# Look up a single IP
network get -ip 192.168.1.1

# Look up multiple IPs, showing only hostname and IPv4 as JSON
network get -ip 192.168.1.1,192.168.1.2 -o hostname,ipv4 --json

# Scan a full subnet, showing all responding devices
network get -subnet 192.168.1.0/24 --R

# Scan an IP range and output as XML
network get -range 192.168.1.1,192.168.1.50 --xml

# Show info for the current machine
network current

# Show only the current machine's MAC address and vendor
network current -o macaddress,vendor

# Clear the on-disk cache
network clear-cache
```

---

## License

MIT License — [LICENSE](LICENSE)
