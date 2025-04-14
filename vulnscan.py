import aiohttp
import asyncio
import sys
import random
import argparse
from netaddr import IPAddress, IPRange
from colorama import Fore, Style, init
from urllib.parse import urlparse
from typing import List, Optional, Dict, Set, Tuple
import time
import json
import os

init(autoreset=True)

print(Fore.LIGHTBLUE_EX + r"""
  _____     _     _____
 |  |  |_ _| |___|   __|___ ___ ___
 |  |  | | | |   |__   |  _| .'|   |
  \___/|___|_|_|_|_____|___|__,|_|_|

""" + Fore.RESET + "   [ Mass Vulnerability Scanner ]\n")

class RateLimitException(Exception):
    pass

class ProxyManager:
    def __init__(self, proxy_list: List[str]):
        self.proxies = proxy_list
        self.working_proxy: Optional[str] = None
        self.bad_proxies: Dict[str, float] = {}
        self.rate_limited_proxies: Set[str] = set()
        self.proxy_test_interval = 300
        self.proxy_retry_threshold = 3
        self.proxy_fail_counts: Dict[str, int] = {}
        self.current_proxy_index = 0
        
    async def get_working_proxy(self, session: aiohttp.ClientSession) -> Optional[str]:
        if self.working_proxy and self.working_proxy not in self.rate_limited_proxies:
            if self.proxy_fail_counts.get(self.working_proxy, 0) < self.proxy_retry_threshold:
                return self.working_proxy
            else:
                self.working_proxy = None
                
        for _ in range(len(self.proxies)):
            proxy = self.proxies[self.current_proxy_index % len(self.proxies)]
            self.current_proxy_index += 1
            
            if self._is_proxy_bad(proxy):
                continue
                
            if await self.test_proxy(proxy, session):
                self.working_proxy = proxy
                self.proxy_fail_counts[proxy] = 0
                if proxy in self.rate_limited_proxies:
                    self.rate_limited_proxies.remove(proxy)
                return proxy
                
        for proxy, fail_time in list(self.bad_proxies.items()):
            if time.time() - fail_time > self.proxy_test_interval:
                if await self.test_proxy(proxy, session):
                    self.working_proxy = proxy
                    del self.bad_proxies[proxy]
                    self.proxy_fail_counts[proxy] = 0
                    if proxy in self.rate_limited_proxies:
                        self.rate_limited_proxies.remove(proxy)
                    return proxy
                    
        return None
        
    def _is_proxy_bad(self, proxy: str) -> bool:
        if proxy in self.rate_limited_proxies:
            return True
        if proxy in self.bad_proxies:
            return time.time() - self.bad_proxies[proxy] < self.proxy_test_interval
        return False
        
    async def test_proxy(self, proxy: str, session: aiohttp.ClientSession) -> bool:
        try:
            test_urls = ["http://httpbin.org/ip", "https://httpbin.org/ip"]
            
            for test_url in test_urls:
                try:
                    async with session.get(test_url, timeout=TIMEOUT, proxy=proxy) as response:
                        if response.status != 200:
                            raise Exception(f"Status {response.status}")
                        await response.read()
                except Exception as e:
                    log(f"Proxy test failed for {proxy}: {str(e)}", "warning")
                    raise
                    
            log(f"Proxy working: {proxy}", "success")
            return True
            
        except Exception as e:
            current_fails = self.proxy_fail_counts.get(proxy, 0) + 1
            self.proxy_fail_counts[proxy] = current_fails
            
            if current_fails >= self.proxy_retry_threshold:
                log(f"Proxy marked as bad: {proxy}", "warning")
                self.bad_proxies[proxy] = time.time()
                if proxy == self.working_proxy:
                    self.working_proxy = None
            return False

    def mark_proxy_failed(self, proxy: str, rate_limit: bool = False):
        if proxy == self.working_proxy:
            self.working_proxy = None
            
        if rate_limit:
            log(f"Proxy rate limited: {proxy}", "warning")
            self.rate_limited_proxies.add(proxy)
        else:
            log(f"Proxy failed: {proxy}", "warning")
            self.bad_proxies[proxy] = time.time()

def log(message, level="info"):
    levels = {
        "info": f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL}",
        "success": f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL}",
        "warning": f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL}",
        "error": f"{Fore.LIGHTRED_EX}[-]{Style.RESET_ALL}",
    }
    print(f"{levels.get(level, levels['info'])} {message}")

def usage(parser):
    parser.print_help()
    print("\nExamples:")
    print("  Scan single IP for multiple CVEs:")
    print("    python vulnscan.py -i 192.168.1.1 -c CVE-2022-27502 CVE-2021-41380")
    print("  Scan IP range from file:")
    print("    python vulnscan.py -I ips.txt -c CVE-2022-27502 -o results.txt")
    print("  Scan with multiple CVEs from file:")
    print("    python vulnscan.py -i 10.0.0.1-10.0.0.100 -C cves.txt -p proxies.txt")
    print("  Full scan with all options:")
    print("    python vulnscan.py -I targets.txt -C vulnerabilities.txt -p proxy_list.txt -o output.txt -t 20 -r 5")
    print("\nProxy file format:")
    print("  http://proxy1:port")
    print("  socks5://proxy2:port")
    print("  https://proxy3:port\n")

def validate_ip(ip: str) -> bool:
    try:
        IPAddress(ip)
        return True
    except Exception:
        return False

def validate_ip_range(ip_range: str) -> bool:
    try:
        if '-' in ip_range:
            start, end = ip_range.split('-')
            IPAddress(start)
            IPAddress(end)
            return True
        return validate_ip(ip_range)
    except Exception:
        return False

def get_ip_list(target: str) -> List[str]:
    if os.path.exists(target):
        return load_ips_from_file(target)
    
    if '-' in target:
        start, end = target.split('-')
        return get_range(start, end)
    
    return [target] if validate_ip(target) else []

def get_range(start_ip: str, end_ip: str) -> List[str]:
    start = IPAddress(start_ip)
    end = IPAddress(end_ip)
    return [str(ip) for ip in IPRange(start, end)]

def load_ips_from_file(file_path: str) -> List[str]:
    with open(file_path, 'r') as f:
        ips = []
        for line in f:
            line = line.strip()
            if validate_ip(line):
                ips.append(line)
            elif '-' in line and validate_ip_range(line):
                start, end = line.split('-')
                ips.extend(get_range(start, end))
        return ips

def load_cves_from_file(file_path: str) -> List[str]:
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip() and line.strip().startswith('CVE-')]

def load_proxies(proxy_file: str) -> List[str]:
    with open(proxy_file, "r") as file:
        proxies = [line.strip() for line in file if line.strip()]
    for proxy in proxies:
        if not validate_proxy(proxy):
            log(f"Invalid proxy format: {proxy}\n", "error")
            sys.exit(1)
    return proxies

def validate_proxy(proxy: str) -> bool:
    try:
        result = urlparse(proxy)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

async def handle_response(response, ip: str, cves: List[str], proxy_manager: Optional[ProxyManager]) -> Tuple[Optional[Dict], bool]:
    try:
        response_data = await response.json() if response.status != 204 else {}
        
        if response.status == 200:
            if not response_data:
                log(f"Empty response from {ip}", "warning")
                return None, False
            
            if "detail" in response_data and response_data["detail"] == "No information available":
                log(f"{ip} not found in Shodan database", "warning")
                return None, False
                
            if "vulns" in response_data:
                found_vulns = [vuln for vuln in cves if vuln in response_data["vulns"]]
                if found_vulns:
                    result = {
                        "ip": ip,
                        "ports": response_data.get("ports", []),
                        "cpes": response_data.get("cpes", []),
                        "hostnames": response_data.get("hostnames", []),
                        "tags": response_data.get("tags", []),
                        "vulns": found_vulns,
                        "all_vulns": response_data.get("vulns", [])
                    }
                    log(f"{ip} is vulnerable to {', '.join(found_vulns)}", "success")
                    return result, False
            return None, False
                
        elif response.status == 429:
            error_msg = response_data.get("error", "Rate limit exceeded")
            log(f"Rate limit on {ip}: {error_msg}", "warning")
            if not proxy_manager:
                raise RateLimitException()
            return None, True
            
        elif response.status == 403:
            log(f"Access forbidden on {ip}", "error")
            return None, False
            
        elif response.status == 401:
            log(f"Unauthorized access on {ip}", "error")
            return None, False
            
        else:
            log(f"{ip} not found in shodan", "warning")
            return None, False
            
    except ValueError:
        log(f"Invalid JSON from {ip}", "error")
        return None, False
        
    except Exception as e:
        log(f"Error processing {ip}: {str(e)}", "error")
        return None, False

async def scan(ip: str, cves: List[str], session: aiohttp.ClientSession, 
              semaphore: asyncio.Semaphore, exit_event: asyncio.Event, 
              proxy_manager: Optional[ProxyManager]) -> Optional[Dict]:
    try:
        async with semaphore:
            for retry in range(MAX_RETRIES):
                if exit_event.is_set():
                    return None
                    
                try:
                    proxy = await proxy_manager.get_working_proxy(session) if proxy_manager else None
                    log(f"Scanning {ip} with {'proxy ' + proxy if proxy else 'direct connection'}")
                    
                    async with session.get("https://internetdb.shodan.io/{ip}".format(ip=ip), 
                                        timeout=TIMEOUT, 
                                        proxy=proxy) as response:
                        result, rate_limit = await handle_response(response, ip, cves, proxy_manager)
                        
                        if rate_limit and proxy_manager:
                            proxy_manager.mark_proxy_failed(proxy, rate_limit=True)
                            await asyncio.sleep(5)
                            
                        if result or response.status in [200, 404]:
                            return result

                except asyncio.TimeoutError:
                    log(f"Timeout on {ip} (attempt {retry + 1}/{MAX_RETRIES})", "warning")
                    if proxy_manager and proxy:
                        proxy_manager.mark_proxy_failed(proxy)
                    await asyncio.sleep(random.uniform(1, 3))
                    continue
                    
                except aiohttp.ClientError as e:
                    log(f"Connection error on {ip}: {str(e)}", "error")
                    if proxy_manager and proxy:
                        proxy_manager.mark_proxy_failed(proxy)
                    await asyncio.sleep(random.uniform(0.5, 1.5))
                    continue
                    
                except RateLimitException:
                    exit_event.set()
                    raise
                    
                except Exception as e:
                    log(f"Unexpected error scanning {ip}: {str(e)}", "error")
                    await asyncio.sleep(random.uniform(0.5, 1.5))
                    continue

            log(f"Max retries reached for {ip}", "warning")
            return None
            
    except asyncio.CancelledError:
        return None

async def get_cve_info(cve_id: str, session: aiohttp.ClientSession) -> Optional[Dict]:
    try:
        async with session.get("https://cvedb.shodan.io/cve/{cve_id}".format(cve_id=cve_id), timeout=TIMEOUT) as response:
            if response.status == 200:
                return await response.json()
            elif response.status == 404:
                log(f"No information available for {cve_id}", "warning")
            else:
                log(f"Failed to get CVE info (Status: {response.status})", "warning")
    except Exception as e:
        log(f"Error fetching CVE info: {str(e)}", "error")
    return None

def display_cve_info(cve_info: Dict):
    log(f"CVE Information for {cve_info.get('cve_id', 'N/A')}:", "info")
    print(f" - Summary: {cve_info.get('summary', 'N/A')}")
    print(f" - CVSS Score: {cve_info.get('cvss_v3', cve_info.get('cvss', 'N/A'))}")
    print(f" - Published: {cve_info.get('published_time', 'N/A')}")
    print(f" - Known Exploited: {'Yes' if cve_info.get('kev', False) else 'No'}")
    
    print(" - References:")
    references = cve_info.get('references', ['N/A'])
    for ref in references[:5]:
        print(f"     {ref}")
    if len(references) > 5:
        print(f"     (+ {len(references)-5} more references)")
    print()

async def scan_targets(ip_list: List[str], cves: List[str], output_file: str, 
                      proxy_file: Optional[str], timeout: int, max_retries: int, 
                      concurrency: int) -> List[Dict]:
    global TIMEOUT, MAX_RETRIES, CONCURRENT_REQUESTS
    TIMEOUT = timeout
    MAX_RETRIES = max_retries
    CONCURRENT_REQUESTS = concurrency
    
    proxy_manager = ProxyManager(load_proxies(proxy_file)) if proxy_file else None
    semaphore = asyncio.Semaphore(CONCURRENT_REQUESTS)
    exit_event = asyncio.Event()
    vulnerable_hosts = []

    json_output = output_file.replace('.txt', '.json') if output_file.endswith('.txt') else output_file + '.json'
    with open(output_file, 'w') as f:
        pass
    with open(json_output, 'w') as f:
        json.dump([], f)

    try:
        async with aiohttp.ClientSession() as session:
            for cve in cves:
                cve_info = await get_cve_info(cve, session)
                if cve_info:
                    display_cve_info(cve_info)
            
            time.sleep(3)
            
            tasks = [scan(ip, cves, session, semaphore, exit_event, proxy_manager) for ip in ip_list]
            
            for task in asyncio.as_completed(tasks):
                try:
                    result = await task
                    if result:
                        vulnerable_hosts.append(result)
                        save_immediate_result(result, output_file, json_output)
                except RateLimitException:
                    log("Stopping scan due to rate limit", "error")
                    break
                except Exception as e:
                    log(f"Error in task: {str(e)}", "error")
                    
    except Exception as e:
        log(f"Fatal error: {str(e)}", "error")
        
    return vulnerable_hosts

def save_immediate_result(result: Dict, txt_file: str, json_file: str):
    try:
        with open(txt_file, 'a') as f:
            f.write(f"{result['ip']} - {', '.join(result['vulns'])}\n")
        
        with open(json_file, 'r+') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = []
            data.append(result)
            f.seek(0)
            json.dump(data, f, indent=2)
            f.truncate()
            
        log(f"Saved result for {result['ip']}", "success")
    except Exception as e:
        log(f"Failed to save immediate result: {str(e)}", "error")

def save_results(vulnerable_hosts: List[Dict], output_file: str):
    """Final save of all results (for completeness)"""
    try:
        json_output = output_file.replace('.txt', '.json') if output_file.endswith('.txt') else output_file + '.json'
        
        with open(json_output, 'w') as f:
            json.dump(vulnerable_hosts, f, indent=2)
        
        with open(output_file, 'w') as f:
            for host in vulnerable_hosts:
                f.write(f"{host['ip']} - {', '.join(host['vulns'])}\n")
        
        log(f"Found {len(vulnerable_hosts)} vulnerable IPs", "success")
        log(f"Final results saved to {output_file} and {json_output}", "info")
    except Exception as e:
        log(f"Failed to save final results: {str(e)}", "error")

def parse_arguments():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )
    
    target_group = parser.add_argument_group('Target Options')
    target_group.add_argument('-i', '--ip', type=str, help='Single IP or IP range (e.g., 192.168.1.1 or 192.168.1.1-192.168.1.100)')
    target_group.add_argument('-I', '--ip-file', type=str, help='File containing list of IPs or IP ranges (one per line)')
    
    vuln_group = parser.add_argument_group('Vulnerability Options')
    vuln_group.add_argument('-c', '--cve', nargs='+', help='One or more CVE IDs (e.g., CVE-2022-27502)')
    vuln_group.add_argument('-C', '--cve-file', type=str, help='File containing list of CVE IDs (one per line)')
    
    general_group = parser.add_argument_group('General Options')
    general_group.add_argument('-o', '--output', type=str, default="vulnerable.txt", 
                             help=f'Output file (default: vulnerable.txt)')
    general_group.add_argument('-p', '--proxy-file', type=str, help='File containing list of proxies')
    general_group.add_argument('-t', '--timeout', type=int, default=5, 
                             help='Timeout in seconds for each request (default: 5)')
    general_group.add_argument('-r', '--retries', type=int, default=3, 
                             help='Max retries for failed requests (default: 3)')
    general_group.add_argument('-w', '--workers', type=int, default=10, 
                             help='Number of concurrent workers (default: 10)')
    general_group.add_argument('-h', '--help', action='store_true', help='Show this help message and exit')
    
    args = parser.parse_args()
    
    if args.help:
        usage(parser)
        sys.exit(0)
    
    if not args.ip and not args.ip_file:
        log("Error: You must specify either an IP/range (-i) or a file with IPs (-I)\n", "error")
        usage(parser)
        sys.exit(1)
        
    if not args.cve and not args.cve_file:
        log("Error: You must specify either CVE IDs (-c) or a file with CVEs (-cf)", "error")
        usage(parser)
        sys.exit(1)
    
    return args

def main():
    args = parse_arguments()
    
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
    
    if not cves:
        log("Error: No valid CVE IDs found to scan for", "error")
        sys.exit(1)
    
    log(f"Starting scan with the following parameters:", "info")
    log(f"Targets: {len(ip_list)} IPs ({'from file' if args.ip_file else args.ip})", "info")
    log(f"Vulnerabilities: {len(cves)} CVEs ({'from file' if args.cve_file else 'manual'})", "info")
    log(f"Concurrent workers: {args.workers}", "info")
    log(f"Timeout: {args.timeout}s, Max retries: {args.retries}", "info")
    if args.proxy_file:
        log(f"Proxies: {len(load_proxies(args.proxy_file))} loaded", "info")
    log(f"Output file: {args.output}\n", "info")
    
    try:
        vulnerable_hosts = asyncio.run(
            scan_targets(
                ip_list=ip_list,
                cves=cves,
                output_file=args.output,
                proxy_file=args.proxy_file,
                timeout=args.timeout,
                max_retries=args.retries,
                concurrency=args.workers
            )
        )
        
        if vulnerable_hosts:
            save_results(vulnerable_hosts, args.output)
        else:
            log("No vulnerable IPs found", "info")
            
    except KeyboardInterrupt:
        log("Scan cancelled by user", "warning")
    except Exception as e:
        log(f"Unexpected error: {str(e)}", "error")

if __name__ == "__main__":
    main()
