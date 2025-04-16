# VulnScan
![Vulnerability Scanner Logo](https://i.postimg.cc/26w6XXJ7/image-2025-04-14-13-42-14.png)

A powerful tool for scanning IPs and identifying CVE vulnerabilities using Shodan InternetDB

## Features

- Scan single IP or IP range
- Support for IP lists from file
- Scan for one or multiple CVEs simultaneously
- Support for CVE lists from file
- Save results with full details
- Smart proxy management system
- Concurrent high-speed execution
- JSON and text output formats

## Prerequisites Installation

```bash
pip install -r requirements.txt
```

## Usage

### Basic Scan:

```bash
python vulnscan.py -i 192.168.1.1 -c CVE-2022-27502
```

### Advanced Scan:

```bash
python vulnscan.py -if targets.txt -cf cves.txt -p -o results.json -w 20
```

### Available Parameters:

```
usage: vulnscan.py [-i IP] [-if IP_FILE] [-c CVE [CVE ...]] [-cf CVE_FILE] [-p] [-pf PROXY_FILE] [-pt PROXY_THREADS] [-o OUTPUT]
                   [-t TIMEOUT] [-r RETRIES] [-w WORKERS] [-v] [-h]

Target Options:
  -i, --ip IP           Single IP or IP range (e.g., 192.168.1.1 or 192.168.1.1-192.168.1.100)
  -if, --ip-file IP_FILE
                        File containing list of IPs or IP ranges (one per line)

Vulnerability Options:
  -c, --cve CVE [CVE ...]
                        One or more CVE IDs (e.g., CVE-2022-27502)
  -cf, --cve-file CVE_FILE
                        File containing list of CVE IDs (one per line)

Proxy Options:
  -p, --use-proxy       Use automatic proxy rotation (download proxies from online sources)
  -pf, --proxy-file PROXY_FILE
                        File containing list of proxies (one per line)
                        Formats: http[s]://[user:pass@]host:port or socks[4|5]://[user:pass@]host:port
  -pt, --proxy-threads PROXY_THREADS
                        Number of threads for proxy checking (default: 100)

General Options:
  -o, --output OUTPUT   Output file (default: vulnerable.txt)
  -t, --timeout TIMEOUT
                        Timeout in seconds for each request (default: 10)
  -r, --retries RETRIES
                        Max retries for failed requests (default: 3)
  -w, --workers WORKERS
                        Number of concurrent workers (default: 10)
  -v, --verbose         Enable verbose output with detailed information
  -h, --help            Show this help message and exit
```

## Usage Examples

1. Scan an IP range for two CVEs:

```bash
python vulnscan.py -i 10.0.0.1-10.0.0.100 -c CVE-2021-41380 CVE-2022-27502 -o results.txt
```

2. Scan IP list from file with proxies:

```bash
python vulnscan.py -if targets.txt -C vulnerabilities.txt -p -w 15
```

3. Fast scan with short timeout:

```bash
python vulnscan.py -i 192.168.1.1-192.168.1.254 -c CVE-2020-3452 -t 3 -r 2 -w 30
```

## File Formats

### IP File:
```
192.168.1.1
10.0.0.1-10.0.0.50
172.16.0.1
```

### CVE File:
```
CVE-2022-27502
CVE-2021-41380
CVE-2020-3452
```

### Proxy File:
```
http://proxy1.example.com:8080
socks5://proxy2.example.com:1080
https://proxy3.example.com:3128
```

## Output

Results are saved in two formats:

1. Simple text file (`vulnerable.txt`):
```
192.168.1.15 - CVE-2022-27502
10.0.0.23 - CVE-2021-41380, CVE-2020-3452
```

2. Complete JSON file (`vulnerable.json`):
```json
[
  {
    "ip": "192.168.1.15",
    "ports": [80, 443, 8080],
    "cpes": ["cpe:/a:microsoft:iis", "cpe:/a:apache:http_server"],
    "hostnames": ["webserver.example.com"],
    "tags": ["web", "https"],
    "vulns": ["CVE-2022-27502"],
    "all_vulns": ["CVE-2022-27502", "CVE-2021-44228"]
  }
]
```

## Limitations

- Requires internet access to query Shodan InternetDB
- Rate limiting from Shodan API
- Valid proxies recommended for large-scale scans

## Contributing

Suggestions and contributions via Pull Requests are welcome.

## License

This project is licensed under the MIT License.
