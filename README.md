**Network-Analyzer** is a Python-based terminal tool that captures and analyzes live network traffic using [Scapy](https://scapy.net/). It displays real-time packet details like source/destination IPs, protocols, ports, and service names — all with clean, colorized output. Ideal for beginners learning network security, or anyone needing a quick packet-sniffing utility.

## Features

- Live capture of TCP, UDP, ICMP, and IP packets
- Automatic detection of common services (HTTP, SSH, DNS, etc.)
- Verbose mode for packet payload previews and TCP flag inspection


## Installation
```bash
git clone https://github.com/ameer-rah/Network-Analyzer.git
cd Network-Analyzer
````

### Install Dependencies
Make sure to have Python 3 and pip installed, then run:
```bash
pip install -r requirements.txt
```

**Note:** To capture packets, you should run this script with root or administrator privileges.

### 1. Run with Root/Administrator Privileges
To capture network packets, the script must be run with elevated privileges:

```bash
sudo python analyzer.py [options]
```

### 2. Basic Command Syntax
```bash
python analyzer.py -i <interface> -c <packet_count> -f "<filter>" -v
```

* `-i` / `--interface`: Network interface to listen on (e.g., `eth0`, `wlan0`)
* `-c` / `--count`: Number of packets to capture (`0` = infinite)
* `-f` / `--filter`: (Optional) BPF-style filter (e.g., `"tcp port 80"`)
* `-v` / `--verbose`: (Optional) Displays extra details like TCP flags and payload preview

### 3. Examples

#### Capture 50 HTTP packets on eth0

```bash
sudo python analyzer.py -i eth0 -f "tcp port 80" -c 50
```

#### Capture indefinitely with verbose output on `wlan0`

```bash
sudo python analyzer.py -i wlan0 -v
```

#### Filter for DNS (UDP port 53) and show verbose info

```bash
sudo python analyzer.py -i eth0 -f "udp port 53" -v
```

### 4. Interpreting the Output
* Each packet is timestamped and color-coded.
* You’ll see:

  ```
  [timestamp] PROTOCOL - SRC_IP:SRC_PORT -> DST_IP:DST_PORT - Service: SERVICE_NAME Flags: ...
  ```
* TCP flags like SYN, ACK, and FIN are highlighted to help analyze connection behavior.

### 5. Stopping the Capture

To stop the program at any time, use:

```
Ctrl + C
```

## Troubleshooting

* Make sure you’re using **sudo/root** if packet capture isn't working.
* If an interface name isn't accepted, use `ifconfig` or `ip link` to check names.
* Some systems may block raw sockets — check OS/firewall permissions.

## Contributing

Contributions are welcome! Here's how:

1. Fork this repo
2. Create your branch (`git checkout -b feature/___`)
3. Commit your changes (`git commit -m 'Add some ___'`)
4. Push to your branch (`git push origin feature/____`)
5. Open a Pull Request 

## License
This project is open-source and available under the [MIT License](LICENSE)
