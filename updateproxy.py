# Proxy updater

import requests
from concurrent.futures import ThreadPoolExecutor
import time
import sys

def download_proxies():
    urls = [
        "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt",
        "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/xResults/RAW.txt",
        "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/main/All_proxies.txt"
    ]
    
    proxies = []
    
    for url in urls:
        try:
            response = requests.get(url, timeout=5)
            print(f"Downloading: {url}")
            if response.status_code == 200:
                proxies.extend([line.strip() for line in response.text.splitlines() if line.strip()])
        except Exception as e:
            print(f"Failed to download {url} - {str(e)}")
    
    proxies = list({p for p in proxies if p.startswith(('http://', 'socks4://', 'socks5://'))})
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
        response = requests.get(test_url, proxies=proxies, timeout=3)
        end_time = time.time()
        
        if response.status_code == 200:
            speed = end_time - start_time
            return True, speed
        return False
    except:
        return False

def process_proxies():
    print("\nUpdating Proxies...\n")
    proxies = download_proxies()
    
    if not proxies:
        print("No proxies downloaded. Check your internet connection.")
        sys.exit(1)
    
    print(f"\nTotal proxies to check: {len(proxies)}")
    print("Checking proxies...\n")
    
    output_file = 'proxy.txt'
    working_count = 0
    
    with open(output_file, 'w') as f:
        f.write("")

    def handle_proxy(proxy):
        nonlocal working_count
        result = check_proxy(proxy)
        if result:
            is_working, speed = result
            if is_working:
                with open(output_file, 'a') as f:
                    f.write(f"{proxy}\n")
                print(f"Working: {proxy} - Speed: {speed:.2f}s")
                working_count += 1
    
    with ThreadPoolExecutor(max_workers=300) as executor:
        executor.map(handle_proxy, proxies)
    
    print(f"\nWorking proxies: {working_count}/{len(proxies)}")
    print(f"Saved to: {output_file}")

if __name__ == "__main__":
    process_proxies()
