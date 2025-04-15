import aiohttp
import asyncio
import random
import time
import json
import sys
from .proxy import get_fresh_proxies
from .utils import log, save_results, save_immediate_result

TIMEOUT = 5
MAX_RETRIES = 3
CONCURRENT_REQUESTS = 10

async def handle_response(response, ip: str, cves: list, proxy_manager: dict) -> tuple:
    try:
        response_data = await response.json() if response.status != 204 else {}
        
        if response.status == 200:
            if not response_data:
                log(f"Empty response from {ip}", "warning", verbose=True)
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
                    if len(found_vulns) == 1:
                        log(f"{ip} is vulnerable to {found_vulns[0]}", "success")
                    else:
                        log(f"{ip} is vulnerable to {', '.join(found_vulns)}", "success")
                    return result, False
            return None, False
        
        elif response.status == 404:
            log(f"{ip} not found in shodan", "warning", verbose=True)
            return None, False
        
        if response.status == 429:
            if not proxy_manager:
                log("API rate limit reached. Exiting.", "error")
                log("Use proxies (-p option) or try again later.", "error")
                sys.exit(1)
            return None, True
        
        elif response.status == 403:
            log(f"Access forbidden on {ip}", "error")
            return None, False
        
        elif response.status == 401:
            log(f"Unauthorized access on {ip}", "error")
            return None, False
        
        else:
            log(f"Failed to scan (Status: {response.status})", "error")
            return None, False
            
    except ValueError:
        log(f"Invalid JSON from {ip}", "error")
        return None, False
    
    except Exception as e:
        log(f"Error processing {ip}: {str(e)}", "error")
        return None, False

async def scan(ip: str, cves: list, session: aiohttp.ClientSession, 
              semaphore: asyncio.Semaphore, exit_event: asyncio.Event, 
              proxy_manager: dict) -> dict:
    try:
        async with semaphore:
            for retry in range(MAX_RETRIES):
                if exit_event.is_set():
                    return None
                    
                try:
                    proxy = None
                    if proxy_manager:
                        if not proxy_manager['proxies'] or time.time() - proxy_manager['last_refresh'] > 3600:
                            log("Proxy list empty or expired, refreshing...", "info")
                            proxy_manager['proxies'] = await get_fresh_proxies(
                                proxy_manager.get('threads', 100)
                            )
                            proxy_manager['last_refresh'] = time.time()
                            proxy_manager['current_index'] = 0
                        
                        if proxy_manager['proxies']:
                            proxy = proxy_manager['proxies'][proxy_manager['current_index'] % len(proxy_manager['proxies'])]
                            proxy_manager['current_index'] += 1
                    
                    log(f"Scanning {ip} with {'proxy ' + proxy if proxy else 'direct connection'}", "info", verbose=True)
                    
                    async with session.get(f"https://internetdb.shodan.io/{ip}", 
                                        timeout=TIMEOUT, 
                                        proxy=proxy) as response:
                        result, rate_limit = await handle_response(response, ip, cves, proxy_manager)
                        
                        if rate_limit and proxy_manager and proxy:
                            log(f"Proxy rate limited: {proxy}", "warning", verbose=True)
                            proxy_manager['proxies'].remove(proxy)
                            await asyncio.sleep(5)
                            
                        if result or response.status in [200, 404]:
                            return result

                except asyncio.TimeoutError:
                    log(f"Timeout on {ip} (attempt {retry + 1}/{MAX_RETRIES})", "warning", verbose=True)
                    if proxy_manager and proxy:
                        proxy_manager['proxies'].remove(proxy)
                    await asyncio.sleep(random.uniform(1, 3))
                    continue
                    
                except aiohttp.ClientError as e:
                    log(f"Connection error on {ip}: {str(e)}", "error", verbose=True)
                    if proxy_manager and proxy:
                        proxy_manager['proxies'].remove(proxy)
                    await asyncio.sleep(random.uniform(0.5, 1.5))
                    continue
                    
                except Exception as e:
                    log(f"Unexpected error scanning {ip}: {str(e)}", "error")
                    await asyncio.sleep(random.uniform(0.5, 1.5))
                    continue

            log(f"Max retries reached for {ip}", "warning")
            return None
            
    except asyncio.CancelledError:
        return None

async def get_cve_info(cve_id: str, session: aiohttp.ClientSession) -> dict:
    try:
        async with session.get(f"https://cvedb.shodan.io/cve/{cve_id}", timeout=TIMEOUT) as response:
            if response.status == 200:
                return await response.json()
            elif response.status == 404:
                log(f"No information available for {cve_id}", "warning")
            else:
                log(f"Failed to get CVE info (Status: {response.status})", "warning")
    except Exception as e:
        log(f"Error fetching CVE info: {str(e)}", "error")
    return None

def display_cve_info(cve_info: dict):
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

async def scan_targets(ip_list: list, cves: list, output_file: str, 
                      use_proxy: bool, timeout: int, max_retries: int, 
                      concurrency: int, proxy_threads: int = 100) -> list:
    global TIMEOUT, MAX_RETRIES, CONCURRENT_REQUESTS
    TIMEOUT = timeout
    MAX_RETRIES = max_retries
    CONCURRENT_REQUESTS = concurrency
    
    proxy_manager = None
    if use_proxy:
        fresh_proxies = await get_fresh_proxies(proxy_threads)
        proxy_manager = {
            'proxies': fresh_proxies,
            'current_index': 0,
            'last_refresh': time.time(),
            'threads': proxy_threads
        }
    
    semaphore = asyncio.Semaphore(CONCURRENT_REQUESTS)
    exit_event = asyncio.Event()
    vulnerable_hosts = []

    json_output = output_file.replace('.txt', '.json') if output_file.endswith('.txt') else output_file + '.json'
    file_created = False

    try:
        async with aiohttp.ClientSession() as session:
            for cve in cves:
                cve_info = await get_cve_info(cve, session)
                if cve_info:
                    display_cve_info(cve_info)

            await asyncio.sleep(3)
            log("Scan started", "info")
            
            tasks = [asyncio.create_task(scan(ip, cves, session, semaphore, exit_event, proxy_manager)) for ip in ip_list]
            
            try:
                for task in asyncio.as_completed(tasks):
                    try:
                        result = await task
                        if result:
                            vulnerable_hosts.append(result)
                            if len(result['vulns']) == 1:
                                log(f"{result['ip']} is vulnerable to {result['vulns'][0]}", "success")
                            else:
                                log(f"{result['ip']} is vulnerable to {', '.join(result['vulns'])}", "success")
                            
                            if not file_created:
                                with open(output_file, 'w') as f:
                                    pass
                                with open(json_output, 'w') as f:
                                    json.dump([], f)
                                file_created = True
                            
                            save_immediate_result(result, output_file, json_output, vulnerable_hosts)
                    except Exception as e:
                        log(f"Unexpected error: {str(e)}", "error")
            except Exception as e:
                log(f"Scan interrupted: {str(e)}", "error")
                exit_event.set()
                for t in tasks:
                    t.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                raise
            
    except Exception as e:
        log(f"Fatal error: {str(e)}", "error")
        sys.exit(1)
        
    if vulnerable_hosts:
        save_results(vulnerable_hosts, output_file)
    else:
        log("No vulnerable IPs found", "info")
        if file_created:
            import os
            if os.path.exists(output_file):
                os.remove(output_file)
            if os.path.exists(json_output):
                os.remove(json_output)
        
    return vulnerable_hosts