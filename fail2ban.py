#!/usr/bin/env python3
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

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


def run_iptables_cmd(cmd: str):
    return subprocess.call(cmd.split(), stdout=None, stderr=None)


def create_fail2ban_chain():
    iptables_cmd = "iptables -N fail2ban"
    return run_iptables_cmd(iptables_cmd)


def delete_fail2ban_chain():
    run_iptables_cmd("iptables -F fail2ban")
    run_iptables_cmd("iptables -X fail2ban")


def init_fail2ban():
    iptables_cmd = "iptables -nL fail2ban"
    p = subprocess.Popen(iptables_cmd.split(), stdout=subprocess.PIPE)
    if p.wait() != 0:
        run_iptables_cmd("iptables -N fail2ban")
        run_iptables_cmd("iptables -I INPUT 1  -j fail2ban")
    for line in p.stdout:
        try:
            target, prot, _, source, destination = line.decode("UTF-8").split()
            if target != "DROP":
                continue
            logging.info("load ban ip %s" % (source))
            BAN_LIST.append(source)
        except:
            continue


def ban_ip(ip):
    iptables_cmd = "iptables -A fail2ban -s {ip}/32 -j DROP".format(ip=ip)
    if subprocess.call(iptables_cmd.split(), stdout=None, stderr=None) == 0:
        logging.info("Ban ip %s successed" % (ip))
        BAN_LIST.append(ip)


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
    log_cmd = cmd.format(from_time=from_time.strftime('%Y-%m-%dT%H:%M:%SZ')).split()
    p = subprocess.Popen(log_cmd, stdout=subprocess.PIPE)
    # p.wait()
    last_line = None
    i = 0
    for line in p.stdout:
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


if __name__ == "__main__":
    EXECDIR = os.path.abspath(os.path.dirname(sys.argv[0]))
    LOGDIR = os.path.join(EXECDIR, "logs")
    logging.basicConfig(
        handlers=[logging.FileHandler(encoding='utf-8', mode='a', filename=os.path.join(LOGDIR, "log.txt"))],
        format="%(asctime)s %(levelname)s:%(message)s",
        level=logging.INFO)
    init_fail2ban()
    from_time = datetime.now(timezone.utc) + timedelta(hours=-8)
    logging.info("Start fail2ban for gitlab ssh")
    while True:
        from_time = fail2ban(from_time)
        time.sleep(60)
