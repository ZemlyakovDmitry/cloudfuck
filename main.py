import ipaddress
import time
import requests as r
import difflib

r.packages.urllib3.disable_warnings(r.packages.urllib3.exceptions.InsecureRequestWarning)
# TODO: Import colorama and set it

headers = {"x-apikey": "APIKEY"}
shodan_key = " "
nets = ["192.30.252.153/32", "192.30.252.154/32", "185.199.108.153/32", "185.199.109.153/32", "185.199.110.153/32",
        "185.199.111.153/32", "97.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14",
        "172.64.0.0/13", "131.0.72.0/22", "120.52.22.96/27", "205.251.249.0/24", "180.163.57.128/26",
        "204.246.168.0/22", "18.160.0.0/15", "205.251.252.0/23", "54.192.0.0/16", "204.246.173.0/24", "54.230.200.0/21",
        "120.253.240.192/26", "116.129.226.128/26", "130.176.0.0/17", "108.156.0.0/14", "99.86.0.0/16",
        "205.251.200.0/21", "223.71.71.128/25", "13.32.0.0/15", "120.253.245.128/26", "13.224.0.0/14", "70.132.0.0/18",
        "15.158.0.0/16", "13.249.0.0/16", "18.238.0.0/15", "18.244.0.0/15", "205.251.208.0/20", "65.9.128.0/18",
        "130.176.128.0/18", "58.254.138.0/25", "54.230.208.0/20", "3.160.0.0/14", "116.129.226.0/25", "52.222.128.0/17",
        "18.164.0.0/15", "64.252.128.0/18", "205.251.254.0/24", "54.230.224.0/19", "71.152.0.0/17", "216.137.32.0/19",
        "204.246.172.0/24", "18.172.0.0/15", "120.52.39.128/27", "118.193.97.64/26", "223.71.71.96/27", "18.154.0.0/15",
        "54.240.128.0/18", "205.251.250.0/23", "180.163.57.0/25", "52.46.0.0/18", "223.71.11.0/27", "52.82.128.0/19",
        "54.230.0.0/17", "54.230.128.0/18", "54.239.128.0/18", "130.176.224.0/20", "36.103.232.128/26", "52.84.0.0/15",
        "143.204.0.0/16", "144.220.0.0/16", "120.52.153.192/26", "119.147.182.0/25", "120.232.236.0/25",
        "54.182.0.0/16", "58.254.138.128/26", "120.253.245.192/27", "54.239.192.0/19", "18.68.0.0/16", "18.64.0.0/14",
        "120.52.12.64/26", "99.84.0.0/16", "130.176.192.0/19", "52.124.128.0/17", "204.246.164.0/22", "13.35.0.0/16",
        "204.246.174.0/23", "36.103.232.0/25", "119.147.182.128/26", "118.193.97.128/25", "120.232.236.128/26",
        "204.246.176.0/20", "65.8.0.0/16", "65.9.0.0/17", "108.138.0.0/15", "120.253.241.160/27", "64.252.64.0/18",
        "13.113.196.64/26", "13.113.203.0/24", "52.199.127.192/26", "13.124.199.0/24", "3.35.130.128/25",
        "52.78.247.128/26", "13.233.177.192/26", "15.207.13.128/25", "15.207.213.128/25", "52.66.194.128/26",
        "13.228.69.0/24", "52.220.191.0/26", "13.210.67.128/26", "13.54.63.128/26", "99.79.169.0/24", "18.192.142.0/23",
        "35.158.136.0/24", "52.57.254.0/24", "13.48.32.0/24", "18.200.212.0/23", "52.212.248.0/26", "3.10.17.128/25",
        "3.11.53.0/24", "52.56.127.0/25", "15.188.184.0/24", "52.47.139.0/24", "18.229.220.192/26", "54.233.255.128/26",
        "3.231.2.0/25", "3.234.232.224/27", "3.236.169.192/26", "3.236.48.0/23", "34.195.252.0/24", "34.226.14.0/24",
        "13.59.250.0/26", "18.216.170.128/25", "3.128.93.0/24", "3.134.215.0/24", "52.15.127.128/26", "3.101.158.0/23",
        "52.52.191.128/26", "34.216.51.0/25", "34.223.12.224/27", "34.223.80.192/26", "35.162.63.192/26",
        "35.167.191.128/26", "44.227.178.0/24", "44.234.108.128/25", "44.234.90.252/30"]


def main():
    ips = []
    subs = []
    domain = input("Enter domain: ")
    st = time.time()
    vt_scan_domain(domain, ips, subs)
    no_cdn_ip = cdn_checker(ips)
    print(no_cdn_ip)
    direct_ip(subs, no_cdn_ip)
    et = time.time()
    elapsed_time = et - st
    print('Execution time:', elapsed_time, 'seconds')


#    if shodan_key.len > 10:
#        shodan_scan(domain, ips, subs)



def vt_scan_domain(domain, ips, subs):
    vt_api = "https://www.virustotal.com/api/v3/"
    print("VirusTotal Scan: ")
    scan = r.get(vt_api + "domains/" + domain + "/subdomains", headers=headers)
    objects = scan.json()
    for dns_rec in objects["data"]:
        attr = dns_rec["attributes"]
        subs.append(dns_rec['id'])
        print(f"Domain {dns_rec['id']} has following A records:", end=" ")
        records = attr["last_dns_records"]
        for record in records:
            if record["type"] == 'A':
                ips.append(record["value"])
                print(record["value"], end=" ")
        print("")


def cdn_checker(ips) -> list:
    no_cdn_ips = []
    for ip in ips:
        a = 0
        for net in nets:
            if ipaddress.ip_address(ip) in ipaddress.IPv4Network(net):
                a = 1
                pass
        if a == 0:
            no_cdn_ips.append(ip)
    return no_cdn_ips


def string_similarity(str1, str2):
    result = difflib.SequenceMatcher(a=str1.lower(), b=str2.lower())
    return result.ratio()


def direct_ip(subs, ips):
    print(subs)
    for domain in subs:
        try:
            domain_page = r.get("https://" + domain, timeout=5)
            for ip in ips:
                url = "https://" + ip
                host_header = {"Host": "domain"}
                ip_page = r.get(url, headers=host_header, verify=False, timeout=5)
                if ip_page.status_code == (200 or 300):
                    similarity = string_similarity(domain_page.text, ip_page.text)
                    if similarity > 0.85:
                        print(f"{domain} has an IP {ip} with chance of {similarity}")
        except:
            pass


# TODO: Implement Shodan scan
# def shodan_scan(domain, ips, subs):
#    shodan_api = "https://api.shodan.io/"
#    query = "ssl.cert.subject.cn:" + domain


main()
# TODO: Input file with the list of domains
# TODO: Output file with the list of ips
# TODO: Output file with the list of vulnerable subs
