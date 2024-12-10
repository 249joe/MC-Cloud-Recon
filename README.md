MC Cloud Recon 🌩
MC Cloud Recon is a powerful reconnaissance tool designed to streamline the process of extracting SSL certificates and analyzing cloud provider IP ranges, including AWS, GCP, and Azure. The tool assists penetration testers, security researchers, and bug bounty hunters in uncovering hidden assets and infrastructure.

Features
🌐 Cloud IP Range Discovery
Automatically fetches and processes IP ranges for AWS, GCP, and Azure.

⚡️ Fast Network Scanning
Integrates with Masscan to scan large IP ranges for open HTTPS ports (port 443).

🔐 SSL Certificate Extraction
Extracts SSL/TLS certificates from discovered hosts for subdomain enumeration and analysis.

🎯 Target Matching
Matches SSL certificate data against a specified target domain to uncover hidden assets.

🛠 Customizable Options

Select cloud providers using -c (e.g., -c aws,gcp).
Use pre-existing IP range files with --ip-range-aws, --ip-range-gcp, or --ip-range-azure.
Installation
Clone the repository:

bash

git clone https://github.com/249joe/MC-Cloud-Recon.git
cd MC-Cloud-Recon
Install dependencies:

bash

pip install -r requirements.txt
Ensure Masscan and OpenSSL are installed:

bash

sudo apt-get install masscan openssl
Usage
bash

python mc_cloud_recon.py <target> [options]
Examples
Scan AWS and GCP ranges for a specific target:

bash

python mc_cloud_recon.py example.com -c aws,gcp
Use a custom Azure IP range file:

bash

python mc_cloud_recon.py example.com --ip-range-azure /path/to/azure_ip_ranges.json
Scan all cloud providers:

bash

python mc_cloud_recon.py example.com
Options
Option  Description
<target>  The target domain to match against SSL certificates.
-c, --clouds  Specify cloud providers to scan (aws, gcp, azure).
--ip-range-aws  Path to a custom AWS IP ranges file.
--ip-range-gcp  Path to a custom GCP IP ranges file.
--ip-range-azure  Path to a custom Azure IP ranges file.
Workflow
Download Cloud IP Ranges
If no custom IP range files are provided, the tool fetches the latest ranges from:

AWS: ip-ranges.json
GCP: cloud.json
Azure: Public IP ranges (via Microsoft).
Scan with Masscan
Identifies hosts with open port 443 (HTTPS).

Extract SSL Certificates
Uses OpenSSL to retrieve and analyze certificates for subdomain enumeration.

Match Certificates
Filters SSL data based on the specified target domain.

Output
Masscan Results: masscan_results.xml
Contains the raw Masscan scan output.

SSL Analysis: ssl_results.txt
Extracted SSL certificate information.
