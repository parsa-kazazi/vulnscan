import requests
import time
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor, as_completed
from .utils import log

download_lock = asyncio.Lock()

async def download_proxies():
    urls = [
        "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt",
        "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/xResults/RAW.txt",
        "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/main/All_proxies.txt"
    ]
    
    proxies = []
    
    for url in urls:
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                log(f"Downloading proxies from: {url}", "info", verbose=True)
                async with session.get(url) as response:
                    if response.status == 200:
                        text = await response.text()
                        proxies.extend([line.strip() for line in text.splitlines() if line.strip()])
                    else:
                        log(f"Failed to download {url} - Status: {response.status}", "warning", verbose=True)
        except Exception as e:
            log(f"Failed to download {url} - {str(e)}", "warning", verbose=True)
    
    proxies = list({p for p in proxies if p.startswith(('http://', 'socks4://', 'socks5://'))})
    log(f"Total downloaded proxies: {len(proxies)}\n", "info")
    return proxies

def check_proxy(proxy):
    try:
        proxies = {}
        test_url = 'https://api.ipify.org'
        
        if proxy.startswith('http://'):
            proxies = {"http": proxy, "https": proxy}
        elif proxy.startswith(('socks4://', 'socks5://')):
            proxies = {"http": proxy, "https": proxy}
        else:
            return False
        
        start_time = time.time()
        response = requests.get(test_url, proxies=proxies, timeout=5)
        end_time = time.time()
        
        if response.status_code == 200:
            speed = end_time - start_time
            return True, speed
        return False
    except Exception as e:
        return False

async def get_fresh_proxies(threads=100):
    try:
        log("Starting proxy update process...", "info")
        start_time = time.time()
        
        proxies = await download_proxies()
        if not proxies:
            log("No proxies available for checking", "error")
            return []
        
        working_proxies = []
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_proxy = {
                executor.submit(check_proxy, proxy): proxy
                for proxy in proxies
            }
            
            for future in as_completed(future_to_proxy):
                proxy = future_to_proxy[future]
                try:
                    result = future.result()
                    if result:
                        is_working, speed = result
                        if is_working:
                            working_proxies.append(proxy)
                            log(f"Working proxy: {proxy} (Response: {speed:.2f}s)", "success")
                    else:
                        log(f"Failed proxy: {proxy}", "warning", verbose=True)
                except Exception as e:
                    log(f"Error checking proxy {proxy}: {str(e)}", "warning", verbose=True)
        
        elapsed = time.time() - start_time
        log(f"Proxy update completed. Working proxies: {len(working_proxies)}/{len(proxies)} (Took: {elapsed:.2f}s)", 
            "success" if working_proxies else "error")
        
        return working_proxies
    except Exception as e:
        log(f"Error in proxy update: {str(e)}", "error")
        return []