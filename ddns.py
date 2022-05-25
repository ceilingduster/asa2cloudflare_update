#!/usr/bin/python3
import json
from pprint import pprint
import urllib3
import requests
import re
import json
import CloudFlare

user = 'admin'
pw = 'cisco'
host = '192.168.1.1'  # asa ip
port = '443'
url = f"https://{host}:{port}/api/cli"


cf = CloudFlare.CloudFlare("<CLOUDFLAREEMAIL>",
                "<CLOUDFLAREAPIKEY>", "<CLOUDFLAREDOMAINNAME>")

def update_cloudflare(domain, hostname, new_ip):
    zones = cf.zones.get(params={"name": domain})
    zone_id = zones[0]['id']
    a_record = cf.zones.dns_records.get(
        zone_id, params={"name": hostname, "type": "A"})[0]
    a_record['content'] = new_ip
    cf.zones.dns_records.put(zone_id, a_record['id'], data=a_record)


def getAddresses():
    regex = r"(GigabitEthernet[0-9]\/[0-9])\s+([a-zA-Z0-9\-]*)\s+((?:[0-9]{1,3}\.){3}[0-9]{1,3})\s+((?:[0-9]{1,3}\.){3}[0-9]{1,3})\s+([a-zA-Z0-9\-]*)\s*\n"
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    command = {"commands": ["show ip"]}
    headers = {'Content-Type': 'application/json',
               'User-Agent': 'REST API Agent'}

    int_response = requests.post(url, auth=(user, pw), data=json.dumps(
        command), headers=headers, verify=False)

    response_json = json.loads(int_response.text)

    if 'response' in json.loads(int_response.text):
        json_response = json.loads(int_response.text)['response'][0]
        matches = re.finditer(regex, json_response, re.MULTILINE)

        address_row = {}
        for matchNum, match in enumerate(matches, start=1):
            interfaces = match.groups()
            intf = interfaces[0]
            nameif = interfaces[1]
            ipaddr = interfaces[2]
            netmask = interfaces[3]
            method = interfaces[4]

            address_row[intf] = {
                'nameif': nameif,
                'ipaddr': ipaddr,
                'netmask': netmask,
                'method': method
            }

    return address_row


addresses = getAddresses()
ge0_ip = addresses["GigabitEthernet0/0"]["ipaddr"]

update_cloudflare("<domain>", "<fqdn_hostname>", ge0_ip)
