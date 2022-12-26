import difflib
import ipaddress

import colorama as colorama
import requests as r
import urllib3
from colorama import Fore, Style

colorama.init(autoreset=True)
urllib3.disable_warnings()

headers = {"x-apikey": "APIKEY"}
# shodan_key = " "


def main(domain, nets):
    ips = []
    subs = []
    if "https://" in domain:
        domain = domain[8:]
    print(Fore.GREEN + "Starting scan for domain " + domain)
    vt_scan_domain(domain, ips, subs)
    #    if shodan_key.len > 10:
    #        shodan_scan(domain, ips, subs)
    no_cdn_ip = cdn_checker(ips, nets)
    subs = check_subs(subs)
    direct_ip(subs, no_cdn_ip)


def vt_scan_domain(domain, ips, subs):
    vt_api = "https://www.virustotal.com/api/v3/"
    print(Fore.YELLOW + "VirusTotal Scan: ")
    scan = r.get(vt_api + "domains/" + domain + "/subdomains?limit=1000", headers=headers)
    objects = scan.json()
    for dns_rec in objects["data"]:
        try:
            attr = dns_rec["attributes"]
            subs.append(dns_rec['id'])
            records = attr["last_dns_records"]
            print(f"Domain {dns_rec['id']} has following A record(s):", end=" ")
            for record in records:
                if record["type"] == 'A':
                    ips.append(record["value"])
                    print(record["value"], end=" ")
            print("")
        except Exception as e:
            print(e)
            pass


# TODO: Implement Shodan scan
# def shodan_scan(domain, ips, subs):
#    shodan_api = "https://api.shodan.io/"
#    query = "ssl.cert.subject.cn:" + domain


def cdn_checker(ips, nets) -> list:
    no_cdn_ips = []
    print(Fore.YELLOW + "Filtering out CDN IPs")
    for ip in ips:
        a = 0
        for net in nets:
            if ipaddress.ip_address(ip) in ipaddress.IPv4Network(net):
                a = 1
                pass
        if a == 0 and ip not in no_cdn_ips:
            no_cdn_ips.append(ip)
    return no_cdn_ips


def check_subs(subs_list):
    print(Fore.YELLOW + "Checking subdomains for availability. It could take a lot of time.")
    subs = []
    for sub in subs_list:
        try:
            get = r.get("https://" + sub, timeout=5)
            if get.ok:
                subs.append(sub)
        except:
            pass
    return subs


def string_similarity(str1, str2):
    result = difflib.SequenceMatcher(a=str1.lower(), b=str2.lower())
    return result.ratio()


def direct_ip(subs, ips):
    print("Started scan for direct IPs")
    for domain in subs:
        try:
            domain_page = r.get("https://" + domain, timeout=5)
            for ip in ips:
                url = "https://" + ip
                host_header = {"Host": domain}
                ip_page = r.get(url, headers=host_header, verify=False, timeout=5)
                if ip_page.status_code == (200 or 300):
                    similarity = string_similarity(domain_page.text, ip_page.text)
                    if similarity > 0.85:
                        print(
                            f"{Style.BRIGHT + Fore.YELLOW + domain + Fore.RESET} has an IP {Fore.GREEN + ip + Fore.RESET} with "
                            f"chance of " + Fore.YELLOW + str(similarity))
        except r.exceptions.RequestException:
            pass
        except Exception as e:
            print(Fore.RED + f"Something is wrong. There's an error: {Fore.RESET}\n {e}")
            pass


if __name__ == "__main__":
    import argparse

    print('  ____ _                 _ _____           _ \n'
          ' / ___| | ___  _   _  __| |  ___|   _  ___| | __ \n'
          '| |   | |/ _ \| | | |/ _` | |_ | | | |/ __| |/ / \n'
          '| |___| | (_) | |_| | (_| |  _|| |_| | (__|   < \n'
          ' \____|_|\___/ \__,_|\__,_|_|   \__,_|\___|_|\_\ \n')

    parser = argparse.ArgumentParser(
        description="CloudFuck is tool to scan domain for subdomains and find IPs which are hidden behind the WAF. ")
    ex = parser.add_mutually_exclusive_group()
    ex.add_argument('-d', '--domain', dest='domain', help='Scan single subdomain. ')
    ex.add_argument('-f', '--file', dest='file', help='List of domains to scan. 1 per line. ')
    args = parser.parse_args()


    def update_nets() -> list:
        ips = []
        print("Updating ip ranges")
        print("Getting CloudFlare ranges")
        cf_url = "https://www.cloudflare.com/ips-v4"
        page = r.get(cf_url).text
        for i in page.splitlines():
            ips.append(i)

        print("Getting GitHub Pages ranges")
        gh_url = "https://api.github.com/meta"
        page = r.get(gh_url).json()
        for i in page["pages"]:
            if "::" not in i:
                ips.append(i)

        print("Getting CloudFront ranges")
        cfr_url = "https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips"
        page = r.get(cfr_url).json()
        for i in page["CLOUDFRONT_GLOBAL_IP_LIST"]:
            ips.append(i)
        page = r.get(cfr_url).json()
        for i in page["CLOUDFRONT_REGIONAL_EDGE_IP_LIST"]:
            ips.append(i)

        print("Adding Akamai URL")
        ips += ['23.32.0.0/11', '23.192.0.0/11', '2.16.0.0/13', '104.64.0.0/10', '184.24.0.0/13', '23.0.0.0/12',
                '95.100.0.0/15', '92.122.0.0/15', '172.224.0.0/13', '184.50.0.0/15', '88.221.0.0/16', '23.64.0.0/14',
                '72.246.0.0/15', '96.16.0.0/15', '96.6.0.0/15', '69.192.0.0/16', '23.72.0.0/13', '173.222.0.0/15',
                '118.214.0.0/16', '184.84.0.0/14']
        with open("nets.txt", "w") as f:
            f.write(str(ips))
            f.close()
        return ips


    if args.domain is not None and args.file is None:
        nets = update_nets()
        main(args.domain, nets)
    elif args.file is not None:
        nets = update_nets()
        with open(f"{args.file}", "r") as f:
            for domain in f.readlines():
                domain = domain.strip()
                main(domain, nets)
            f.close()
        print(Fore.GREEN + "Scan is done")
    else:
        print(Fore.RED + "Enter domain(s) using --d or --f arguments")
