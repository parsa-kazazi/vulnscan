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

### Available Parameters:

```
usage: vulnscan.py [-i IP] [-if IP_FILE] [-c CVE [CVE ...]] [-cf CVE_FILE] [-p] [-pf PROXY_FILE] [-pc] [-o OUTPUT] [-w WORKERS]
                   [-t TIMEOUT] [-r RETRIES] [-v] [-h]

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
  -p, --use-proxy       Use automatic proxy rotation
  -pf, --proxy-file PROXY_FILE
                        File containing list of proxies
  -pc, --proxy-check    Check and filter working proxies before use

General Options:
  -o, --output OUTPUT   Output file (default: vulnerable.txt)
  -w, --workers WORKERS
                        Number of concurrent workers (default: 30)
  -t, --timeout TIMEOUT
                        Timeout in seconds for each request (default: 5)
  -r, --retries RETRIES
                        Max retries for failed requests (default: 3)
  -v, --verbose         Enable verbose output for detailed information
  -h, --help            Show this help message and exit
```

### Usage Examples

1. Basic scan:
```
python vulnscan.py -i 192.168.1.1 -c CVE-2022-27502 CVE-2021-41380
```
2. Scan IP range from file:
```
python vulnscan.py -if ips.txt -c CVE-2022-27502 -o results.txt
```
3. Scan with CVEs from file:
```
python vulnscan.py -i 10.0.0.1-10.0.0.100 -cf cves.txt
```
4. Scan with automatic proxies:
```
python vulnscan.py -i 192.168.1.1 -c CVE-2022-1234 -p
```
5. Scan with custom proxy file:
```
python vulnscan.py -if targets.txt -cf vulnerabilities.txt -pf proxies.txt
```
6. Scan with proxy checking:
```
python vulnscan.py -i 10.0.0.1-10.0.0.100 -c CVE-2022-1234 -p -pc
```
7. Advanced scan with all options:
```
python vulnscan.py -if targets.txt -cf cves.txt -pf proxies.txt -o output.json -t 3 -r 5 -w 300 -pc -v
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
192.168.1.15 is vulnerable to CVE-2022-27502
10.0.0.23 is vulnerable to CVE-2021-41380, CVE-2020-3452
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
