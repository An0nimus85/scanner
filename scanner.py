import asyncio
import sys
import logging
import os
import re
import shutil
from concurrent.futures import ThreadPoolExecutor

from asyncclick import command, option
import httpx
from nmap import nmap

client = httpx.AsyncClient()

logger = logging.getLogger('scanner')
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_handler = logging.StreamHandler()  # For console logs
log_handler.setFormatter(formatter)
logger.addHandler(log_handler)

executor = ThreadPoolExecutor(max_workers=10)

path_list = []

async def collect_subdomains(domain: str):
    """
    Function to collect subdomains from a domain
    :param domain: Domain to collect subdomains from
    :return: List of subdomains
    """
    local_subdomains = set()
    try:
        response = await client.get(
            "https://crt.sh",
            params={
                "q": domain,
                "output": "json"
            },
            timeout=10)
    except httpx.ReadTimeout:
        logger.error(f"Request to crt.sh timed out")
        sys.exit(1)
    data = response.json()
    if not data:
        logger.error(f"No data found for {domain}: {response.status_code}")
        sys.exit(1)
    for item in data:
        subdomain_list = item['name_value'].split('\n')
        _ = [local_subdomains.add(re.sub(r"^\*\.|www\.", "", subdomain)) for subdomain in subdomain_list]
    logger.info(f"Subdomains: {local_subdomains}")
    return list(local_subdomains)

async def async_scan_port(subdomain: str):
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(executor, scan_ports, subdomain)

def scan_ports(subdomain: str):
    nm = nmap.PortScanner()
    _ = nm.scan(subdomain, arguments="-sV --script vulners", sudo=True)
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                port_info = nm[host][proto][port]
                logger.info(
                    f"""
                    =======
                    Host: {host}
                    Port: {port}
                    State: {port_info['state']}
                    Connection: {port_info['name']}
                    Product: {port_info['product']}
                    Version: {port_info['version']}
                    Potential Vulnerabilities: {port_info.get("script", {}).get("vulners")}
                    =======
                    """.strip()
                )

def check_empty_folders(path: str):
    try:
        if not os.listdir(path):
            shutil.rmtree(path)
            return True
    except Exception as e:
        logger.error(f"Can't delete folder {path}: {e}")


async def run_sqlmap(subdomain: str):
    path = os.path.join(os.getcwd(), "sqlmap_results", subdomain)
    os.makedirs(path, exist_ok=True)
    command = [
        "sqlmap",
        "-u", f"{subdomain if 'https' in subdomain else f'https://{subdomain}'}",
        "--crawl=1", # Crawl the links on the page
        "--random-agent",  # Use random user agent
        "--batch", # Optimizations
        f"--output-dir", f"{path}" # Output directory
    ]
    await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE # Delete named arguments if need logs in console
    )
    check_empty_folders(path)

@command()
@option("--domain", "-d", help="Domain to scan", required=True)
async def main(domain):
    subdomains = await collect_subdomains(domain)
    scan_port_tasks = [asyncio.create_task(async_scan_port(subdomain)) for subdomain in subdomains]
    sqlmap_tasks = [asyncio.create_task(run_sqlmap(subdomain)) for subdomain in subdomains]
    tasks = sqlmap_tasks + scan_port_tasks
    for task in asyncio.as_completed(tasks):
        await task

if __name__ == '__main__':
    asyncio.run(main())
