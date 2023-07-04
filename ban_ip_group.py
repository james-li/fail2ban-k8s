#!/usr/bin/env python3
from pprint import pprint

import kubernetes_client
from ipwhois import IPWhois
import threading
from concurrent.futures import ThreadPoolExecutor

counter_lock = threading.Lock()
ban_ip_subnets = {}


def add_subnet(subnet, ip):
    with counter_lock:
        ip_list = ban_ip_subnets.get(subnet, [])
        ip_list.append(ip)
        ban_ip_subnets[subnet] = ip_list


def get_subnet(ip: str):
    res = IPWhois(ip.split('/')[0])
    try:
        asn_whois = res.net.get_asn_whois()
        subnet = asn_whois.split('|')[2].strip()
        if subnet:
            return subnet, ip
    except:
        pass
    return ip, ip


def get_subnet_done(res):
    subnet, ip = res.result()
    add_subnet(subnet, ip)


if __name__ == "__main__":
    handler = kubernetes_client.pod_fail2ban_handler(False)
    ban_ip_list = handler.get_ban_ip()
    with ThreadPoolExecutor(max_workers=10) as pool:
        for ip in ban_ip_list:
            task = pool.submit(get_subnet, ip)
            task.add_done_callback(get_subnet_done)
    pprint(ban_ip_subnets)
