# Proxy updater

import requests
from concurrent.futures import ThreadPoolExecutor
import time
import sys

def download_proxies():
    """Download proxies from GitHub sources"""
    urls = [
        "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/all/data.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/refs/heads/main/proxies/all.txt",
        "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/xResults/RAW.txt",
        "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/All_proxies.txt"
    ]
    
    proxies = []
    
    for url in urls:
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                proxies.extend([line.strip() for line in response.text.splitlines() if line.strip()])
        except:
            print(f"⚠️ Failed to download proxies from {url}")
    
    proxies = list(set(proxies))
    return proxies

def check_proxy(proxy):
    """Check if a proxy is working"""
    proxies = {}
    try:
        if proxy.startswith('http://'):
            proxies = {"http": proxy, "https": proxy}
            test_url = 'http://httpbin.org/ip'
        elif proxy.startswith('socks4://'):
            proxies = {"http": proxy, "https": proxy}
            test_url = "http://httpbin.org/ip"
        elif proxy.startswith('socks5://'):
            proxies = {"http": proxy, "https": proxy}
            test_url = 'http://httpbin.org/ip'
        else:
            return False
        
        start_time = time.time()
        response = requests.get(test_url, proxies=proxies, timeout=10)
        end_time = time.time()
        
        if response.status_code == 200:
            speed = end_time - start_time
            return True, speed
        return False
    except:
        return False

def process_proxies():
    """Process the proxies and save working ones"""
    print("\nUpdating proxies...\n")
    proxies = download_proxies()
    
    if not proxies:
        print("❌ No proxies downloaded. Check your internet connection or the source URLs.")
        sys.exit(1)
    
    print(f"Total proxies to check: {len(proxies)}")
    print("Checking proxies... Please wait\n")
    
    working_proxies = []
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(check_proxy, proxies)
        
        for proxy, result in zip(proxies, results):
            if result:
                is_working, speed = result
                if is_working:
                    working_proxies.append(proxy)
                    print(f"✅ Working proxy: {proxy} - Speed: {speed:.2f}s")
            else:
                print(f"❌ Failed proxy: {proxy}")
    
    output_file = 'proxy.txt'
    with open(output_file, 'w') as f:
        f.write('\n'.join(working_proxies))
    
    print(f"\nTotal working proxies: {len(working_proxies)} out of {len(proxies)}")
    print(f"Results saved to {output_file}\n")

if __name__ == "__main__":
    process_proxies()