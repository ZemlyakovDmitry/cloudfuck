# CloudFuck

**CloudFuck** - is a tool for subdomain enumeration *(not fully ready)* and finding origin IPs. You can scan one or few domains per run. 
Code is not optimized so scan may take a while.

## Installation 
Run: `git clone https://github.com/ZemlyakovDmitry/cloudfuck && cd cloudfuck && pip install -r requirements.txt`
Edit cloudfuck.py and replace "APIKEY" at line 12 with your VirusTotal api key. You can get it [HERE](https://www.virustotal.com/gui/my-apikey).

## Usage
**To start scanning just run one of following commands:**

  To scan a single domain:
  `python cloudfuck.py --d DOMAIN`
  
   To scan a list of domains:
  `python cloudfuck.py --f FILE`
