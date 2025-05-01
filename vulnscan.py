import sys
import argparse
import asyncio
from colorama import Fore, init
from core.scanner import scan_targets
from core.utils import (
    log, 
    load_ips_from_file, 
    get_ip_list, 
    load_cves_from_file,
    clean_cve_list, 
    save_results,
    set_verbose
)

init(autoreset=True)

def print_banner():
    print(Fore.LIGHTBLUE_EX + r"""
  _____     _     _____
 |  |  |_ _| |___|   __|___ ___ ___
 |  |  | | | |   |__   |  _| .'|   |
  \___/|___|_|_|_|_____|___|__,|_|_|

""" + Fore.RESET + "   [ Mass Vulnerability Scanner ]\n")

def usage(parser):
    parser.print_help()
    print("\n\nExamples:")
    print("  Basic scan:")
    print("    python vulnscan.py -i 192.168.1.1 -c CVE-2022-27502 CVE-2021-41380")
    print("  Scan IP range from file:")
    print("    python vulnscan.py -if ips.txt -c CVE-2022-27502 -o results.txt")
    print("  Scan with CVEs from file:")
    print("    python vulnscan.py -i 10.0.0.1-10.0.0.100 -cf cves.txt")
    print("  Scan with automatic proxies:")
    print("    python vulnscan.py -i 192.168.1.1 -c CVE-2022-1234 -p")
    print("  Scan with custom proxy file:")
    print("    python vulnscan.py -if targets.txt -cf vulnerabilities.txt -pf proxies.txt")
    print("  Scan with proxy checking:")
    print("    python vulnscan.py -i 10.0.0.1-10.0.0.100 -c CVE-2022-1234 -p -pc")
    print("  Advanced scan with all options:")
    print("    python vulnscan.py -if targets.txt -cf cves.txt -pf proxies.txt -o output.json -t 20 -r 5 -w 50 -pt 200 -pc -v\n")


def parse_arguments():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )
    
    target_group = parser.add_argument_group('Target Options')
    target_group.add_argument('-i', '--ip', type=str,
                              help='Single IP or IP range (e.g., 192.168.1.1 or 192.168.1.1-192.168.1.100)')
    target_group.add_argument('-if', '--ip-file', type=str,
                              help='File containing list of IPs or IP ranges (one per line)')
    
    vuln_group = parser.add_argument_group('Vulnerability Options')
    vuln_group.add_argument('-c', '--cve', nargs='+',
                            help='One or more CVE IDs (e.g., CVE-2022-27502)')
    vuln_group.add_argument('-cf', '--cve-file', type=str,
                            help='File containing list of CVE IDs (one per line)')

    proxy_group = parser.add_argument_group('Proxy Options')
    proxy_group.add_argument('-p', '--use-proxy', action='store_true', 
                             help='Use automatic proxy rotation')
    proxy_group.add_argument('-pf', '--proxy-file', type=str, 
                             help='File containing list of proxies')
    proxy_group.add_argument('-pc', '--proxy-check', action='store_true',
                             help='Check and filter working proxies before use')

    general_group = parser.add_argument_group('General Options')
    general_group.add_argument('-o', '--output', type=str, default="vulnerable.txt", 
                             help=f'Output file (default: vulnerable.txt)')
    general_group.add_argument('-w', '--workers', type=int, default=30,
                             help='Number of concurrent workers (default: 30)')
    general_group.add_argument('-t', '--timeout', type=int, default=5, 
                             help='Timeout in seconds for each request (default: 5)')
    general_group.add_argument('-r', '--retries', type=int, default=3, 
                             help='Max retries for failed requests (default: 3)')
    general_group.add_argument('-v', '--verbose', action='store_true', 
                             help='Enable verbose output for detailed information')
    general_group.add_argument('-h', '--help', action='store_true', help='Show this help message and exit')
    
    args, unknown = parser.parse_known_args()
    
    if unknown:
        log(f"Unknown arguments: {' '.join(unknown)}\n", "e")
        usage(parser)
        sys.exit(1)
    
    if args.help:
        usage(parser)
        sys.exit(0)
    
    if not args.ip and not args.ip_file:
        log("You must specify either an IP/range (-i) or a file with IPs (-if)\n", "e")
        usage(parser)
        sys.exit(1)
        
    if not args.cve and not args.cve_file:
        log("You must specify either CVE IDs (-c) or a file with CVEs (-cf)\n", "e")
        usage(parser)
        sys.exit(1)
    
    return args

def main():
    print_banner()
    args = parse_arguments()
    set_verbose(args.verbose)
    
    if args.ip_file:
        ip_list = load_ips_from_file(args.ip_file)
    else:
        ip_list = get_ip_list(args.ip)
    
    if not ip_list:
        log("No valid IP addresses found to scan", "e")
        sys.exit(1)
        
    if args.cve_file:
        cves = load_cves_from_file(args.cve_file)
    else:
        cves = args.cve
    
    cves = clean_cve_list(cves)
    
    if not cves:
        log("No valid CVE IDs provided", "e")
        sys.exit(1)
    
    if args.proxy_file and args.use_proxy:
        log("Both proxy options specified (-p and -pf), using proxy file (-pf) takes precedence", "w")
        args.use_proxy = False
    
    log(f"Target: {args.ip_file if args.ip_file else args.ip}", "i")
    log(f"CVEs: {args.cve_file if args.cve_file else ', '.join(args.cve)}", "i")
    log(f"Output file: {args.output}", "i")
    log(f"Timeout: {args.timeout}s", "i")
    log(f"Retries: {args.retries}", "i")
    log(f"Workers: {args.workers}", "i")
    log(f"Proxy: {'Enabled (file)' if args.proxy_file else 'Enabled (auto)' if args.use_proxy else 'Disabled'}", "i")
    if args.proxy_file or args.use_proxy:
        log(f"Proxy checking: {'Enabled' if args.proxy_check else 'Disabled'}", "i")
        if args.proxy_file:
            log(f"Proxy file: {args.proxy_file}", "i")
    log(f"Verbose: {'Enabled' if args.verbose else 'Disabled'}")
    print()
    
    try:
        vulnerable_hosts = asyncio.run(
            scan_targets(
                ip_list=ip_list,
                cves=cves,
                output_file=args.output,
                use_proxy=args.use_proxy,
                proxy_file=args.proxy_file,
                proxy_check=args.proxy_check,
                concurrency=args.workers,
                timeout=args.timeout,
                max_retries=args.retries,
                verbose_output=args.verbose
            )
        )
        
        log("Scan results:", "i")
        if vulnerable_hosts:
            save_results(vulnerable_hosts, args.output)
        else:
            log("No vulnerable IPs found", "i")
            
    except KeyboardInterrupt:
        print()
        log("Scan cancelled by user", "w")
        sys.exit(0)
    except Exception as e:
        log(f"Error: {str(e)}", "e")

if __name__ == "__main__":
    main()
