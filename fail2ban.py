#!/usr/bin/env python3
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone

import yaml
from kubernetes import client, config, utils

cmd = "kubectl -n ingress-nginx logs ds/nginx-ingress-controller --since-time={from_time}"
BYTES_RECV_LIMIT = 2000
BYTES_SEND_LIMIT = 2000
SESSION_TIME_LIMIT = 0.2
BAN_LIST = []
SUSPICIOUS_LIST = {}

TIME_FORMAT = [
    "%d/%b/%Y:%H:%M:%S %z",
    "I%m%d %H:%M:%S.%f",
    "W%m%d %H:%M:%S.%f",
]

BASE_YML_TEMPLATE = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: fail2ban
  namespace: test
spec:
  ingress:
  - from:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 10.0.0.0/16
  podSelector:
    matchExpressions:
    - key: app
      operator: In
      values:
      - ingress-nginx
    matchLabels:
      app: ingress-nginx
  policyTypes:
  - Ingress
"""


def init_fail2ban():
    pass


def ban_ip(ip):
    pass


def get_log_time(line):
    tokens = line.split()
    if len(tokens) == 1:
        return None
    for i in range(0, len(tokens) - 1):
        time_str = (tokens[i] + " " + tokens[i + 1]).replace("[", "").replace("]", "")
        for format in TIME_FORMAT:
            try:
                return datetime.strptime(time_str, format)
            except:
                pass
    return None


def fail2ban(from_time: datetime):
    logging.info("get ingress nginx log from " + from_time.isoformat())
    # p.wait()
    last_line = None
    i = 0
    for line in read_ingress_log(from_time):
        last_line = line.decode("utf-8")
        try:
            ip_, time_, tzone_, tcp, tcp_200, bytes_recv_, bytes_send_, session_time_ = last_line.split()
            if tcp != "TCP" or tcp_200 != "200":
                continue
            ip = ip_[1:-1]
            login_time = datetime.strptime((time_ + " " + tzone_)[1:-1], "%d/%b/%Y:%H:%M:%S %z")
            bytes_recv = int(bytes_recv_)
            bytes_send = int(bytes_send_)
            session_time = float(session_time_)
            if bytes_send < BYTES_SEND_LIMIT and bytes_recv < BYTES_RECV_LIMIT:
                lst = SUSPICIOUS_LIST.get(ip, [])
                lst.append(login_time)
                SUSPICIOUS_LIST[ip] = lst
                i += 1
        except:
            continue
    logging.info("parse log and find %d suspicious login attempts" % (i))
    p.wait()
    if last_line:
        login_time = get_log_time(last_line)
        if login_time:
            from_time = login_time
    pop = []
    for ip, login_time_list in SUSPICIOUS_LIST.items():
        logging.info("handle suspicious ip %s, last attempt at %s, attempt retires %d",
                     ip, login_time_list[-1], len(login_time_list))
        if len(login_time_list) < 3:
            # 间隔大于5分钟忽略
            if login_time_list[-1] + timedelta(minutes=5) < datetime.now(timezone.utc):
                pop.append(ip)
            continue
        if ip not in BAN_LIST:
            ban_ip(ip)
        pop.append(ip)
    for k in pop:
        del SUSPICIOUS_LIST[k]
    return from_time


def start_fail2ban():
    init_fail2ban()
    from_time = datetime.now(timezone.utc) + timedelta(hours=-8)
    logging.info("Start fail2ban for gitlab ssh")
    while True:
        from_time = fail2ban(from_time)
        time.sleep(60)


def read_ingress_log(from_time: datetime):
    pass


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


if __name__ == "__main__":
    EXECDIR = os.path.abspath(os.path.dirname(sys.argv[0]))
    LOGDIR = os.path.join(EXECDIR, "logs")
    logging.basicConfig(
        handlers=[logging.FileHandler(encoding='utf-8', mode='a', filename=os.path.join(LOGDIR, "log.txt"))],
        format="%(asctime)s %(levelname)s:%(message)s",
        level=logging.INFO)
