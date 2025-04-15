
import argparse
import asyncio
import sys
from colorama import Fore, Style, init
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
    print("  Scan single IP for multiple CVEs:")
    print("    python vulnscan.py -i 192.168.1.1 -c CVE-2022-27502 CVE-2021-41380")
    print("  Scan IP range from file:")
    print("    python vulnscan.py -if ips.txt -c CVE-2022-27502 -o results.txt")
    print("  Scan with multiple CVEs from file:")
    print("    python vulnscan.py -i 10.0.0.1-10.0.0.100 -cf cves.txt -p")
    print("  Full scan with all options:")
    print("    python vulnscan.py -if targets.txt -cf vulnerabilities.txt -p -o output.txt -t 20 -r 5\n")

def parse_arguments():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )
    
    target_group = parser.add_argument_group('Target Options')
    target_group.add_argument('-i', '--ip', type=str, help='Single IP or IP range (e.g., 192.168.1.1 or 192.168.1.1-192.168.1.100)')
    target_group.add_argument('-if', '--ip-file', type=str, help='File containing list of IPs or IP ranges (one per line)')
    
    vuln_group = parser.add_argument_group('Vulnerability Options')
    vuln_group.add_argument('-c', '--cve', nargs='+', help='One or more CVE IDs (e.g., CVE-2022-27502)')
    vuln_group.add_argument('-cf', '--cve-file', type=str, help='File containing list of CVE IDs (one per line)')
    
    general_group = parser.add_argument_group('General Options')
    general_group.add_argument('-o', '--output', type=str, default="vulnerable.txt", 
                             help=f'Output file (default: vulnerable.txt)')
    general_group.add_argument('-p', '--use-proxy', action='store_true', 
                             help='Use automatic proxy rotation to bypass rate limits')
    general_group.add_argument('-pt', '--proxy-threads', type=int, default=100,
                             help='Number of threads for proxy checking (default: 100)')
    general_group.add_argument('-t', '--timeout', type=int, default=10, 
                             help='Timeout in seconds for each request (default: 10)')
    general_group.add_argument('-r', '--retries', type=int, default=3, 
                             help='Max retries for failed requests (default: 3)')
    general_group.add_argument('-w', '--workers', type=int, default=10, 
                             help='Number of concurrent workers (default: 10)')
    general_group.add_argument('-v', '--verbose', action='store_true', 
                             help='Enable verbose output with detailed information')
    general_group.add_argument('-h', '--help', action='store_true', help='Show this help message and exit')
    
    args, unknown = parser.parse_known_args()
    
    if unknown:
        log(f"Error: Unknown arguments: {' '.join(unknown)}\n", "error")
        usage(parser)
        sys.exit(1)
    
    if args.help:
        usage(parser)
        sys.exit(0)
    
    if not args.ip and not args.ip_file:
        log("Error: You must specify either an IP/range (-i) or a file with IPs (-if)\n", "error")
        usage(parser)
        sys.exit(1)
        
    if not args.cve and not args.cve_file:
        log("Error: You must specify either CVE IDs (-c) or a file with CVEs (-cf)\n", "error")
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
        log("Error: No valid IP addresses found to scan", "error")
        sys.exit(1)
        
    if args.cve_file:
        cves = load_cves_from_file(args.cve_file)
    else:
        cves = args.cve
    

    if args.cve_file:
        with open(args.cve_file, 'r') as f:
            cves = [line.strip() for line in f if line.strip()]
    else:
        cves = args.cve
    
    cves = clean_cve_list(cves)
    
    if not cves:
        log("Error: No valid CVE IDs provided", "error")
        sys.exit(1)
    
    log(f"Target: {args.ip_file if args.ip_file else args.ip}", "info")
    log(f"CVEs: {args.cve_file if args.cve_file else ', '.join(args.cve)}", "info")
    log(f"Output file: {args.output}", "info")
    log(f"Timeout: {args.timeout}s", "info")
    log(f"Retries: {args.retries}", "info")
    log(f"Workers: {args.workers}", "info")
    log(f"Proxy: {'Enabled' if args.use_proxy else 'Disabled'}", "info")
    if args.use_proxy:
        log(f"Proxy threads: {args.proxy_threads}", "info")
    log(f"Verbose: {'Enabled' if args.verbose else 'Disabled'}")
    print()
    
    try:
        vulnerable_hosts = asyncio.run(
            scan_targets(
                ip_list=ip_list,
                cves=cves,
                output_file=args.output,
                use_proxy=args.use_proxy,
                timeout=args.timeout,
                max_retries=args.retries,
                concurrency=args.workers,
                proxy_threads=args.proxy_threads
            )
        )
        
        log("Scan results:", "info")
        if vulnerable_hosts:
            save_results(vulnerable_hosts, args.output)
        else:
            log("No vulnerable IPs found", "info")
            
    except KeyboardInterrupt:
        print()
        log("Scan cancelled by user", "warning")
        sys.exit(0)
    except Exception as e:
        log(f"Unexpected error: {str(e)}", "error")

if __name__ == "__main__":
    main()