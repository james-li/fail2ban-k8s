#!/usr/bin/env python
import ipaddress
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from ipwhois import IPWhois

from kubernetes_client import pod_fail2ban_handler, return_on_exception

BYTES_RECV_LIMIT = 2000
BYTES_SEND_LIMIT = 2000
SESSION_TIME_LIMIT = 0.2
SUSPICIOUS_LIST = {}
WHITELIST = {}

fail2ban_handler = pod_fail2ban_handler(os.environ.get("KUBERNETES_SERVICE_PORT") is not None)

TIME_FORMAT = [
    "%d/%b/%Y:%H:%M:%S %z",
    "I%m%d %H:%M:%S.%f",
    "W%m%d %H:%M:%S.%f",
]


def get_log_time(line):
    tokens = line.split()
    if len(tokens) == 1:
        return None
    for i in range(0, len(tokens) - 1):
        time_str = (tokens[i] + " " + tokens[i + 1]).replace("[", "").replace("]", "")
        for format in TIME_FORMAT:
            try:
                return datetime.strptime(time_str, format).replace(tzinfo=timezone.utc)
            except:
                pass
    return None


@return_on_exception(False)
def match_ip_cidr(src, dst):
    src_ip = src.split('/')[0]
    return ipaddress.ip_address(src_ip) in ipaddress.ip_network(dst)


def fail2ban(from_time: datetime):
    # p.wait()
    i = 0
    ban_ip_list = fail2ban_handler.get_ban_ip()
    pod_logs = fail2ban_handler.read_log(from_time)
    for pod, pod_log in pod_logs.items():
        since_second = pod_log.get("from", 7200)
        for line in pod_log.get("log"):
            if line.strip():
                last_line = line.strip()
            else:
                continue
            try:
                ip_, time_, tzone_, tcp, tcp_200, bytes_recv_, bytes_send_, session_time_, server_ip_port = last_line.split()
                _, server_port = server_ip_port.replace('"', '').split(':')
                if tcp != "TCP" or tcp_200 != "200" or server_port not in ["2222", "18622", "18623", "18624", "18336"]:
                    continue
                ip = ip_[1:-1]
                login_time = datetime.strptime((time_ + " " + tzone_)[1:-1], "%d/%b/%Y:%H:%M:%S %z")
                from_now = int((datetime.now(timezone.utc) - login_time).total_seconds())
                if since_second > from_now:
                    since_second = from_now
                if from_time < login_time:
                    from_time = login_time
                bytes_recv = int(bytes_recv_)
                bytes_send = int(bytes_send_)
                session_time = float(session_time_)
                cidr = "%s/32" % ip
                if ip not in WHITELIST and bytes_send > BYTES_SEND_LIMIT and bytes_recv > BYTES_RECV_LIMIT:
                    logging.info("add %s to whitelist" % ip)
                    WHITELIST[ip] = 1
                    if ip in SUSPICIOUS_LIST:
                        SUSPICIOUS_LIST.pop(ip)
                    continue
                if ip in WHITELIST:
                    continue
                if bytes_send < BYTES_SEND_LIMIT and bytes_recv < BYTES_RECV_LIMIT and cidr not in ban_ip_list:
                    lst = SUSPICIOUS_LIST.get(ip, [])
                    lst.append(login_time)
                    SUSPICIOUS_LIST[ip] = lst
                    i += 1
            except:
                continue
        pod_log["from"] = since_second
    logging.info("parse log and find %d suspicious login attempts" % (i))

    if i == 0:
        return from_time
    pop = []
    updated = False
    for ip, login_time_list in SUSPICIOUS_LIST.items():
        logging.info("handle suspicious ip %s, last attempt at %s, attempt retires %d",
                     ip, login_time_list[-1].astimezone(), len(login_time_list))
        if len(login_time_list) < 5:
            # 间隔大于5分钟忽略
            if login_time_list[-1] + timedelta(minutes=10) < datetime.now(timezone.utc):
                pop.append(ip)
            continue
        cidr = "%s/32" % ip
        if cidr not in ban_ip_list:
            updated = True
            logging.info("Ban ip %s" % cidr)
            ban_ip_list[cidr] = True
        pop.append(ip)
    if updated:
        ret = fail2ban_handler.set_ban_ip(list(ban_ip_list.keys()))
    for k in pop:
        del SUSPICIOUS_LIST[k]
    return from_time


def start_fail2ban():
    from_time = datetime.now(timezone.utc) + timedelta(hours=-2)
    logging.info("Start fail2ban for gitlab ssh")
    while True:
        from_time = fail2ban(from_time)
        time.sleep(int(os.environ.get("FAIL2BAN_INTERVAL", "10")))


'''
def k8s_api_test():
    config.load_config()
    v = client.CoreV1Api()
    ret = v.list_namespaced_pod("ingress-nginx", label_selector="app=ingress-nginx")
    for x in ret.items:
        print(v.read_namespaced_pod_log(x.metadata.name, x.metadata.namespace, since_seconds=120))
    base_fail2ban_network_policy_dict = yaml.load(BASE_YML_TEMPLATE, yaml.FullLoader)
    print(base_fail2ban_network_policy_dict)
    api_client = client.NetworkingV1Api()
    print(api_client.list_namespaced_network_policy("test"))
    # body = client.V1NetworkPolicy()
    resp = api_client.patch_namespaced_network_policy("fail2ban", "test", body=base_fail2ban_network_policy_dict)
    print(resp)
'''

if __name__ == "__main__":
    EXECDIR = os.path.abspath(os.path.dirname(sys.argv[0]))
    LOGDIR = os.path.join(EXECDIR, "logs")
    logging.basicConfig(
        handlers=[logging.FileHandler(encoding='utf-8', mode='a', filename=os.path.join(LOGDIR, "log.txt"))],
        format="%(asctime)s %(levelname)s:%(message)s",
        level=logging.INFO)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s:%(message)s"))
    logging.getLogger().addHandler(stream_handler)
    start_fail2ban()
