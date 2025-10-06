# Network Scanner

A simple network scanning CLI tool written in C.

## Features

- Scan IP addresses and check open ports
- Support for network ranges with subnet masks
- Configurable port scanning
- Default scanning on ports 80 and 443
- Excludes reserved addresses (network and broadcast)

## Usage

```bash
# Scan a specific IP on default ports (80, 443)
./network-scanner 192.168.1.1

# Scan a network range
./network-scanner 192.168.1.0/24

# Specify custom ports
./network-scanner 192.168.1.1 -p 22,80,443,8080
```

## Building

```bash
gcc -o network-scanner *.c
```

## Note

This is a learning project. For production use, consider established tools like `nmap`.

## TO-DO List

### High Priority

- [X] Accept command-line arguments
- [X] Support for netmask -> Set first IP to "zero"
- [X] Process command-line arguments
  - [X] Scan the network associated with an IP address
  - [X] Specify ports to scan
  - [X] Scan a specific IP
- [X] Correctly iterate over IP addresses
- [X] Function that scans a list of ports

### Medium Priority

- [X] Exclude reserved addresses (e.g., 192.168.31.0 and 192.168.31.255)
- [X] Default address scan on ports 80, 443
- [X] Comment the code
- [ ] Return lists for results
- [ ] Write a scan report

### Low Priority

- [ ] Option to set timeout
- [ ] Multi-process
- [ ] ping_address function
- [X] Fix error with "0.0.0.0"
- [ ] Write scan results to JSON
