import os
import json
import re
from netaddr import IPAddress, IPRange
from colorama import Fore, Style

VERBOSE = False

def set_verbose(verbose):
    global VERBOSE
    VERBOSE = verbose

def log(message, level="info", verbose=False):
    if verbose and not VERBOSE:
        return
        
    levels = {
        "info": f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL}",
        "success": f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL}",
        "warning": f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL}",
        "error": f"{Fore.LIGHTRED_EX}[-]{Style.RESET_ALL}",
    }
    print(f"{levels.get(level, levels['info'])} {message}")

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

def validate_cve(cve: str) -> bool:
    cve_pattern = r'^CVE-\d{4}-(0\d{3}|[1-9]\d{3,})$'
    return bool(re.match(cve_pattern, cve))

def clean_cve_list(cves: list) -> list:
    unique_cves = []
    seen = set()
    
    for cve in cves:
        if not validate_cve(cve):
            log(f"Ignoring invalid CVE format: {cve}", "warning")
            continue
        
        cve_upper = cve.upper()
        if cve_upper not in seen:
            seen.add(cve_upper)
            unique_cves.append(cve_upper)
    
    return unique_cves

def get_ip_list(target: str) -> list:
    if os.path.exists(target):
        return load_ips_from_file(target)
    
    if '-' in target:
        start, end = target.split('-')
        return get_range(start, end)
    
    return [target] if validate_ip(target) else []

def get_range(start_ip: str, end_ip: str) -> list:
    start = IPAddress(start_ip)
    end = IPAddress(end_ip)
    ip_range = IPRange(start, end)
    return [str(ip) for ip in sorted(ip_range, key=lambda x: x.value)]

def load_ips_from_file(file_path: str) -> list:
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

def load_cves_from_file(file_path: str) -> list:
    with open(file_path, 'r') as f:
        cves = [line.strip() for line in f if line.strip()]
    return clean_cve_list(cves)

def validate_proxy(proxy: str) -> bool:
    try:
        pattern = r'^(http|socks4|socks5)://([a-zA-Z0-9_.-]+(:[a-zA-Z0-9_.-]+)?@)?[a-zA-Z0-9_.-]+:[0-9]+$'
        return bool(re.match(pattern, proxy))
    except Exception:
        return False

def validate_proxy_file(file_path: str) -> bool:
    if not os.path.exists(file_path):
        return False
    try:
        with open(file_path, 'r') as f:
            for line in f:
                if line.strip() and validate_proxy(line.strip()):
                    return True
        return False
    except Exception:
        return False

def save_results(vulnerable_hosts: list, output_file: str):
    try:
        json_output = output_file.replace('.txt', '.json') if output_file.endswith('.txt') else output_file + '.json'
        
        with open(output_file, 'w') as f:
            for host in vulnerable_hosts:
                if len(host['vulns']) == 1:
                    f.write(f"{host['ip']} is vulnerable to {host['vulns'][0]}\n")
                else:
                    f.write(f"{host['ip']} is vulnerable to {', '.join(host['vulns'])}\n")
        
        with open(json_output, 'w') as f:
            json.dump(vulnerable_hosts, f, indent=2)
        
        log(f"Found {len(vulnerable_hosts)} vulnerable IPs", "success")
        log(f"Results saved to {output_file} and {json_output}", "info")
    except Exception as e:
        log(f"Failed to save final results: {str(e)}", "error")

def save_immediate_result(result: dict, txt_file: str, json_file: str, vulnerable_hosts: list):
    try:
        with open(txt_file, 'w') as f:
            for host in vulnerable_hosts:
                if len(host['vulns']) == 1:
                    f.write(f"{host['ip']} is vulnerable to {host['vulns'][0]}\n")
                else:
                    f.write(f"{host['ip']} is vulnerable to {', '.join(host['vulns'])}\n")
        
        with open(json_file, 'w') as f:
            json.dump(vulnerable_hosts, f, indent=2)
            
    except Exception as e:
        log(f"Failed to save immediate result: {str(e)}", "error")
