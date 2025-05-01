import time
import re
import asyncio
import aiohttp
from .utils import log, validate_proxy

download_lock = asyncio.Lock()

async def download_proxies(validate=False, timeout=5):
    urls = [
        "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt",
        "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/xResults/RAW.txt",
        "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/main/All_proxies.txt"
    ]
    
    proxies = []

    log("Downloading fresh proxies from online sources", "i")

    for url in urls:
        try:
            async with aiohttp.ClientSession() as session:
                log(f"Downloading proxies from: {url}", "i", True)
                async with session.get(url) as response:
                    if response.status == 200:
                        text = await response.text()
                        proxies.extend([line.strip() for line in text.splitlines() if line.strip()])
        except Exception:
            continue
    
    proxies = list({p for p in proxies if p.startswith(('http://', 'socks4://', 'socks5://'))})
    
    if validate:
        return await check_proxies(proxies, timeout)
    return proxies

async def check_proxy(proxy, timeout=5):
    try:
        test_url = 'https://api.ipify.org'
        
        if not proxy or not isinstance(proxy, str):
            return False
            
        if '@' in proxy:
            if not re.match(r'^[a-zA-Z]+://[^:@]+:[^:@]+@[^:@]+:[0-9]+$', proxy):
                return False
        else:
            if not re.match(r'^[a-zA-Z]+://[^:@]+:[0-9]+$', proxy):
                return False
        
        connector = aiohttp.TCPConnector(force_close=True)
        timeout = aiohttp.ClientTimeout(total=timeout)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            headers = {'User-Agent': 'Mozilla/5.0'}
            
            start_time = time.time()
            try:
                async with session.get(test_url, 
                                    proxy=proxy, 
                                    headers=headers) as response:
                    if response.status == 200:
                        end_time = time.time()
                        speed = end_time - start_time
                        return True, speed
                    return False
            except asyncio.TimeoutError:
                log(f"Proxy timeout: {proxy}", "w", True)
                return False
            except Exception as e:
                log(f"Proxy error: {proxy} - {str(e)}", "w", True)
                return False
                
    except Exception as e:
        log(f"Error checking proxy {proxy}: {str(e)}", "w", True)
        return False

async def check_proxies(proxies: list, timeout: int = 5, workers: int = 100) -> list:
    working_proxies = []
    semaphore = asyncio.Semaphore(workers)
    
    async def _check_and_add(proxy):
        async with semaphore:
            result = await check_proxy(proxy, timeout)
            if result:
                is_working, speed = result
                if is_working:
                    working_proxies.append((proxy, speed))
                    log(f"Working proxy: {proxy} (Response: {speed:.2f}s)", "s")
            else:
                log(f"Failed proxy: {proxy}", "w", True)
    
    tasks = [_check_and_add(proxy) for proxy in proxies]
    await asyncio.gather(*tasks)
    
    working_proxies.sort(key=lambda x: x[1])
    return [proxy for proxy, speed in working_proxies]

async def load_proxies(proxy_file: str = None, timeout: int = 5, workers: int = 100) -> list:
    if proxy_file:
        log(f"Loading proxies from file: {proxy_file}", "i")
        try:
            with open(proxy_file, 'r') as f:
                proxies = [line.strip() for line in f if line.strip()]
            proxies = [p for p in proxies if validate_proxy(p)]
            if not proxies:
                log("No valid proxies found in file", "e")
                return []
                
            return await check_proxies(proxies, timeout, workers)
        except Exception as e:
            log(f"Failed to load proxies from file: {str(e)}", "e")
            return []
    
    raw_proxies = await download_proxies()
    if not raw_proxies:
        log("No proxies downloaded", "e")
        return []
    
    return await check_proxies(raw_proxies, timeout, workers)
