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
        content_type = response.headers.get('Content-Type', '')
        
        if 'text/html' in content_type:
            if response.status == 403:
                log(f"Access forbidden on {ip}", "w", True)
                return None, False
            return None, False
        
        try:
            response_data = await response.json() if response.status != 204 else {}
        except ValueError:
            if response.status == 200:
                log(f"Invalid JSON from {ip}", "w", True)
            return None, False
        
        if response.status == 200:
            if not response_data:
                log(f"Empty response from {ip}", "w", True)
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
                        log(f"{ip} is vulnerable to {found_vulns[0]}", "s")
                    else:
                        log(f"{ip} is vulnerable to {', '.join(found_vulns)}", "s")
                    return result, False
            return None, False
        
        elif response.status == 404:
            log(f"{ip} not found in shodan", "w", True)
            return None, False
        
        elif response.status == 429:
            if not proxy_manager:
                if not hasattr(handle_response, 'rate_limit_reported'):
                    log("API rate limit reached. Stopping scan.", "e")
                    log("Use proxies or try again later.", "e")
                    handle_response.rate_limit_reported = True
                raise asyncio.CancelledError("Rate limit reached")
            return None, True
        
        elif response.status == 403:
            log(f"Access forbidden on {ip}", "w", True)
            return None, False
        
        elif response.status == 401:
            log(f"Unauthorized access on {ip}", "e", True)
            return None, False
        
        else:
            log(f"Failed to scan {ip} (Status: {response.status})", "e", True)
            return None, False
            
    except Exception as e:
        log(f"Error processing {ip}: {str(e)}", "e", True)
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
                        async with proxy_manager['lock']:
                            if not proxy_manager['proxies'] or time.time() - proxy_manager['last_refresh'] > 3600:
                                log("Proxy list empty or expired, refreshing...", "i")
                                proxy_manager['proxies'] = await load_proxies(
                                    timeout=TIMEOUT,
                                    workers=proxy_manager.get('workers', 100)
                                )
                                proxy_manager['last_refresh'] = time.time()
                                proxy_manager['current_index'] = 0
                            
                            if proxy_manager['proxies']:
                                proxy = proxy_manager['proxies'][proxy_manager['current_index'] % len(proxy_manager['proxies'])]
                                proxy_manager['current_index'] += 1
                    
                    log(f"Scanning {ip} with {'proxy ' + proxy if proxy else 'direct connection'}", "i", True)
                    
                    async with session.get(f"https://internetdb.shodan.io/{ip}", 
                                        timeout=TIMEOUT, 
                                        proxy=proxy,
                                        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}) as response:
                        result, rate_limit = await handle_response(response, ip, cves, proxy_manager)
                        
                        if rate_limit and proxy_manager and proxy:
                            log(f"Proxy rate limited: {proxy}", "w", True)
                            async with proxy_manager['lock']:
                                if proxy in proxy_manager['proxies']:
                                    proxy_manager['proxies'].remove(proxy)
                            await asyncio.sleep(5)
                            
                        if result or response.status in [200, 404]:
                            return result

                except asyncio.CancelledError:
                    exit_event.set()
                    return None
                except asyncio.TimeoutError:
                    log(f"Timeout on {ip} (attempt {retry + 1}/{MAX_RETRIES})", "w", True)
                    if proxy_manager and proxy:
                        async with proxy_manager['lock']:
                            if proxy in proxy_manager['proxies']:
                                proxy_manager['proxies'].remove(proxy)
                    await asyncio.sleep(random.uniform(1, 3))
                    continue
                    
                except aiohttp.ClientError as e:
                    log(f"Connection error on {ip}: {str(e)}", "e", True)
                    if proxy_manager and proxy:
                        async with proxy_manager['lock']:
                            if proxy in proxy_manager['proxies']:
                                proxy_manager['proxies'].remove(proxy)
                    await asyncio.sleep(random.uniform(0.5, 1.5))
                    continue
                    
                except Exception as e:
                    log(f"Error scanning {ip}: {str(e)}", "e", True)
                    await asyncio.sleep(random.uniform(0.5, 1.5))
                    continue

            log(f"Max retries reached for {ip}", "w", True)
            return None
            
    except asyncio.CancelledError:
        return None

async def process_batch(
    batch: list,
    cves: list,
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    exit_event: asyncio.Event,
    proxy_manager: dict
) -> list:
    vulnerable_hosts = []
    tasks = []

    for ip in batch:
        if exit_event.is_set():
            break
        task = asyncio.create_task(scan(ip, cves, session, semaphore, exit_event, proxy_manager))
        tasks.append(task)

    try:
        for task in asyncio.as_completed(tasks):
            try:
                result = await task
                if result:
                    vulnerable_hosts.append(result)
            except Exception as e:
                if not exit_event.is_set():
                    log(f"Error in batch processing: {str(e)}", "e")
    except asyncio.CancelledError:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        exit_event.set()

    return vulnerable_hosts

async def scan_targets(ip_list, cves: list,
                       output_file: str, timeout: int,
                       max_retries: int, concurrency: int,
                       use_proxy: bool = False, proxy_file: str = None,
                       proxy_check: bool = False,
                       verbose_output: bool = False) -> list:
    global TIMEOUT, MAX_RETRIES
    TIMEOUT = timeout
    MAX_RETRIES = max_retries
    
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
                workers=concurrency
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
                'workers': concurrency,
                'failed_proxies': {},
                'lock': asyncio.Lock()
            }
            log(f"Using {len(fresh_proxies)} {'working ' if proxy_check else ''}proxies\n", "s")
        else:
            log("No proxies available, aborting scan", "e")
            return []
    
    BATCH_SIZE = 100
    vulnerable_hosts = []
    exit_event = asyncio.Event()
    semaphore = asyncio.Semaphore(concurrency)
    json_output = output_file.replace('.txt', '.json') if output_file.endswith('.txt') else output_file + '.json'
    actually_scanned = 0
    last_report_time = time.time()
    report_interval = 30

    ip_list = list(ip_list)
    total_ips = len(ip_list)
    log(f"Total IPs to scan: {total_ips}", "i")

    async def progress_reporter():
        nonlocal actually_scanned, last_report_time
        while not exit_event.is_set() and actually_scanned < total_ips:
            await asyncio.sleep(1)
            current_time = time.time()
            if current_time - last_report_time >= report_interval:
                percentage = (actually_scanned / float(total_ips)) * 100 if total_ips > 0 else 0
                log(f"Progress: {actually_scanned}/{total_ips} IPs scanned ({percentage:.2f}%)", "i")
                last_report_time = current_time

    try:
        async with aiohttp.ClientSession() as session:
            log("Scan started", "i")
            batch = []

            progress_task = asyncio.create_task(progress_reporter())

            for ip in ip_list:
                if exit_event.is_set():
                    break

                batch.append(ip)
                if len(batch) >= BATCH_SIZE:
                    batch_results = await process_batch(batch, cves, session, semaphore, exit_event, proxy_manager)
                    vulnerable_hosts.extend(batch_results)
                    actually_scanned += len(batch)
                    batch = []

                    if vulnerable_hosts:
                        save_immediate_result(batch_results, output_file, json_output, vulnerable_hosts)

            if batch and not exit_event.is_set():
                batch_results = await process_batch(batch, cves, session, semaphore, exit_event, proxy_manager)
                vulnerable_hosts.extend(batch_results)
                actually_scanned += len(batch)
                if vulnerable_hosts:
                    save_immediate_result(batch_results, output_file, json_output, vulnerable_hosts)

            progress_task.cancel()
            try:
                await progress_task
            except asyncio.CancelledError:
                pass

    except KeyboardInterrupt:
        log("Scan cancelled by user", "w")
    except Exception as e:
        log(f"Error: {str(e)}", "e")
    finally:
        if actually_scanned > 0:
            percentage = (actually_scanned / total_ips) * 100 if total_ips > 0 else 0
            log(f"Scan completed: {actually_scanned}/{total_ips} IPs scanned ({percentage:.1f}%)", "i")

    return vulnerable_hosts
