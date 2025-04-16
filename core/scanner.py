import sys
import time
import random
import aiohttp
import asyncio
from .proxy import load_proxies, download_proxies
from .utils import (
    log,
    save_immediate_result,
    get_cve_info,
    display_cve_info
)

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
                            proxy_manager['proxies'] = await load_proxies(
                                timeout=TIMEOUT,
                                threads=proxy_manager.get('threads', 100)
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

            log(f"Max retries reached for {ip}", "warning", verbose=True)
            return None
            
    except asyncio.CancelledError:
        return None

async def scan_targets(ip_list: list, cves: list, output_file: str, 
                      timeout: int, max_retries: int, 
                      concurrency: int, proxy_threads: int = 100,
                      use_proxy: bool = False, proxy_file: str = None,
                      proxy_check: bool = False,
                      verbose_output: bool = False) -> list:
    global TIMEOUT, MAX_RETRIES, CONCURRENT_REQUESTS
    TIMEOUT = timeout
    MAX_RETRIES = max_retries
    CONCURRENT_REQUESTS = concurrency
    
    if verbose_output:
        for cve in cves:
            cve_info = await get_cve_info(cve)
            if cve_info:
                display_cve_info(cve_info)

    proxy_manager = None
    if use_proxy or proxy_file:
        if proxy_check:
            fresh_proxies = await load_proxies(
                proxy_file=proxy_file,
                timeout=timeout,
                threads=proxy_threads
            )
        else:
            if proxy_file:
                with open(proxy_file, 'r') as f:
                    fresh_proxies = [line.strip() for line in f if line.strip()]
            else:
                fresh_proxies = await download_proxies()
        
        if fresh_proxies:
            proxy_manager = {
                'proxies': fresh_proxies,
                'current_index': 0,
                'last_refresh': time.time(),
                'threads': proxy_threads,
                'failed_proxies': {}
            }
            log(f"Using {len(fresh_proxies)} {'working ' if proxy_check else ''}proxies\n", "success")
        else:
            log("No proxies available, aborting scan", "error")
            return []
    
    semaphore = asyncio.Semaphore(CONCURRENT_REQUESTS)
    exit_event = asyncio.Event()
    vulnerable_hosts = []
    total_ips = len(ip_list)
    scanned_ips = 0
    last_progress_update = 0

    json_output = output_file.replace('.txt', '.json') if output_file.endswith('.txt') else output_file + '.json'

    try:
        async with aiohttp.ClientSession() as session:
            await asyncio.sleep(3)
            log("Scan started", "info")
            
            tasks = []
            for ip in ip_list:
                if exit_event.is_set():
                    break
                
                task = asyncio.create_task(scan(ip, cves, session, semaphore, exit_event, proxy_manager))
                tasks.append(task)
            
            async def report_progress():
                nonlocal scanned_ips, last_progress_update
                while scanned_ips < total_ips and not exit_event.is_set():
                    current_time = time.time()
                    if (current_time - last_progress_update > 5) or (scanned_ips % max(1, total_ips//10)) == 0:
                        progress = (scanned_ips / total_ips) * 100
                        log(f"Scan progress: {progress:.1f}% ({scanned_ips}/{total_ips} IPs)", "info")
                        last_progress_update = current_time
                    await asyncio.sleep(1)
            
            progress_task = asyncio.create_task(report_progress())
            
            try:
                for task in asyncio.as_completed(tasks):
                    try:
                        result = await task
                        scanned_ips += 1
                        if result:
                            vulnerable_hosts.append(result)
                            save_immediate_result(result, output_file, json_output, vulnerable_hosts)
                    except Exception as e:
                        log(f"Unexpected error: {str(e)}", "error")
                        scanned_ips += 1
            finally:
                progress_task.cancel()
                try:
                    await progress_task
                except asyncio.CancelledError:
                    pass
                
    except Exception as e:
        log(f"Fatal error: {str(e)}", "error")
        sys.exit(1)
        
    return vulnerable_hosts
