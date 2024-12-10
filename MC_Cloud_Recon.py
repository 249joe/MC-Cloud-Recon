import os
import subprocess
import requests
import json
import argparse
import xmltodict

# Colors for CLI
BLUE = "\033[94m"
GREEN = "\033[32m"
RED = "\033[91m"
RESET = "\033[0m"

# Tool Information
TOOL_NAME = f"{BLUE}MC Cloud Recon{RESET}"
TOOL_VERSION = "v1.0"
TOOL_AUTHOR = f"MC404{RESET}"

def print_header():
    print(f"""{BLUE}
888b     d888  .d8888b.        .d8888b.  888                        888      8888888b.                                    
8888b   d8888 d88P  Y88b      d88P  Y88b 888                        888      888   Y88b                                   
88888b.d88888 888    888      888    888 888                        888      888    888                                   
888Y88888P888 888             888        888  .d88b.  888  888  .d88888      888   d88P .d88b.   .d8888b .d88b.  88888b.  
888 Y888P 888 888             888        888 d88""88b 888  888 d88" 888      8888888P" d8P  Y8b d88P"   d88""88b 888 "88b 
888  Y8P  888 888    888      888    888 888 888  888 888  888 888  888      888 T88b  88888888 888     888  888 888  888 
888   "   888 Y88b  d88P      Y88b  d88P 888 Y88..88P Y88b 888 Y88b 888      888  T88b Y8b.     Y88b.   Y88..88P 888  888 
888       888  "Y8888P"        "Y8888P"  888  "Y88P"   "Y88888  "Y88888      888   T88b "Y8888   "Y8888P "Y88P"  888  888 
    {RESET}
    
    {GREEN}
j03ibra@gmail.com
{GREEN}Version:{RESET} {TOOL_VERSION}
{GREEN}Author: {RESET} {TOOL_AUTHOR}
    """)

def download_file(url, file_name):
    print(f"[*] Downloading {file_name}...")
    try:
        response = requests.get(url)
        if response.status_code == 200:
            with open(file_name, "w") as file:
                file.write(response.text)
            print(f"[+] {file_name} downloaded successfully!")
            return True
        else:
            print(f"{RED}[-] Failed to download {file_name}. Status Code: {response.status_code}{RESET}")
            return False
    except Exception as e:
        print(f"{RED}[-] Error downloading {file_name}: {e}{RESET}")
        return False

def extract_ips(json_file, output_file, key="ip_prefix"):
    print(f"[*] Extracting IPs from {json_file}...")
    try:
        with open(json_file, "r") as file:
            data = json.load(file)
        ips = [item[key] for item in data.get('prefixes', []) if key in item]
        with open(output_file, "w") as file:
            file.write("\n".join(ips))
        print(f"[+] Extracted {len(ips)} IP ranges to {output_file}.")
        return True
    except Exception as e:
        print(f"{RED}[-] Error processing {json_file}: {e}{RESET}")
        return False

def scan_ips(ip_file, rate=1000, output_file="masscan_results.xml"):
    print(f"[*] Scanning IPs from {ip_file}...")
    try:
        command = [
            "masscan",
            "-p443",
            f"--rate={rate}",
            "-iL", ip_file,
            "-oX", output_file
        ]
        subprocess.run(command, check=True)
        print(f"[+] Scan results saved to {output_file}.")
    except Exception as e:
        print(f"{RED}[-] Error running Masscan: {e}{RESET}")

def parse_masscan_results(xml_file="masscan_results.xml"):
    print(f"[*] Parsing results from {xml_file}...")
    try:
        with open(xml_file, "r") as file:
            data = xmltodict.parse(file.read())
        hosts = []
        if "nmaprun" in data and "host" in data["nmaprun"]:
            hosts = [host["address"]["@addr"] for host in data["nmaprun"]["host"]]
        print(f"[+] Found {len(hosts)} live hosts: {hosts}")
        return hosts
    except Exception as e:
        print(f"{RED}[-] Error parsing Masscan results: {e}{RESET}")
        return []

def extract_ssl_certificates(hosts, output_file="ssl_results.txt"):
    print(f"[*] Extracting SSL certificates...")
    results = []
    for host in hosts:
        try:
            print(f"[*] Attempting to extract certificate for {host}...")
            command = f"echo | openssl s_client -connect {host}:443 2>/dev/null | openssl x509 -noout -text"
            cert_data = subprocess.getoutput(command)
            if cert_data.strip():
                results.append(f"Host: {host}\n{cert_data}\n")
                print(f"{GREEN}[+] Certificate extracted for {host}.{RESET}")
            else:
                print(f"{RED}[-] No certificate found for {host}.{RESET}")
        except Exception as e:
            print(f"{RED}[-] Error extracting certificate for {host}: {e}{RESET}")
    with open(output_file, "w") as file:
        file.writelines(results)
    print(f"[+] SSL certificate data saved to {output_file}.")

if __name__ == "__main__":
    print_header()
    
    parser = argparse.ArgumentParser(description="Cloud Recon Tool")
    parser.add_argument("target", help="Target domain to match in SSL certificates")
    parser.add_argument("-c", "--clouds", help="Specify cloud providers (aws,gcp,azure)", default="aws,gcp,azure")
    parser.add_argument("--ip-range-aws", help="Path to custom AWS IP ranges file")
    parser.add_argument("--ip-range-gcp", help="Path to custom GCP IP ranges file")
    parser.add_argument("--ip-range-azure", help="Path to custom Azure IP ranges file")
    args = parser.parse_args()

    clouds = args.clouds.split(",")
    ip_files = []

    if "aws" in clouds:
        aws_file = args.ip_range_aws or "aws_ip_ranges.json"
        if not os.path.exists(aws_file):
            download_file("https://ip-ranges.amazonaws.com/ip-ranges.json", aws_file)
        if extract_ips(aws_file, "aws_ip_ranges.txt"):
            ip_files.append("aws_ip_ranges.txt")

    if "gcp" in clouds:
        gcp_file = args.ip_range_gcp or "gcp_ip_ranges.json"
        if not os.path.exists(gcp_file):
            download_file("https://www.gstatic.com/ipranges/cloud.json", gcp_file)
        if extract_ips(gcp_file, "gcp_ip_ranges.txt"):
            ip_files.append("gcp_ip_ranges.txt")

    if "azure" in clouds:
        azure_file = args.ip_range_azure or "azure_ip_ranges.json"
        if not os.path.exists(azure_file):
            download_file("https://download.microsoft.com/download/7/5/9/759b6ee9-b6d7-4ed5-881f-251b239e8c57/PublicIPs_20211004.xml", azure_file)
        if extract_ips(azure_file, "azure_ip_ranges.txt"):
            ip_files.append("azure_ip_ranges.txt")

    if not ip_files:
        print(f"{RED}[-] No valid IP ranges to scan.{RESET}")
        exit(1)

    merged_file = "all_ip_ranges.txt"
    with open(merged_file, "w") as outfile:
        for ip_file in ip_files:
            with open(ip_file, "r") as infile:
                outfile.writelines(infile.readlines())

    scan_ips(merged_file)
    live_hosts = parse_masscan_results()
    extract_ssl_certificates(live_hosts)
