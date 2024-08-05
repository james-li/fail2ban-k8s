import logging
from datetime import datetime, timezone, timedelta

import yaml
from kubernetes import client, config

logger = logging.getLogger(__name__)


def return_on_exception(value):
    def decorate(f):
        def applicator(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except BaseException as e:
                logging.info(str(e))
                return value

        return applicator

    return decorate


class pod_fail2ban_handler(object):
    _BASE_NETWORK_POLICY = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: fail2ban
spec:
  ingress:
  - from:
    - ipBlock:
        cidr: 0.0.0.0/0
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

    def __init__(self, in_cluster=False):
        if in_cluster:
            config.load_incluster_config()
        else:
            config.load_config()
        self._core_api = client.CoreV1Api()
        self._net_api = client.NetworkingV1Api()
        self._name_space = "ingress-nginx"
        # self._name_space = "test"
        self._base_network_policy = yaml.load(self._BASE_NETWORK_POLICY, yaml.FullLoader)
        self._network_policy_name = "fail2ban"
        self._pod_selector = {"label_selector": "app=ingress-nginx"}
        self._pod_log = {}

    def set_name_space(self, namespace: str):
        self._name_space = namespace

    def set_pod_selector(self, **kwargs):
        self._pod_selector = kwargs

    @property
    def core_api(self):
        return self._core_api

    @property
    def net_api(self):
        return self._net_api

    def get_ingress_controller_pod(self):
        ret = self.core_api.list_namespaced_pod(self._name_space, **self._pod_selector)
        return [x.metadata.name for x in ret.items]

    @return_on_exception({})
    def read_log(self, from_time: datetime) -> dict:
        for pod in self.get_ingress_controller_pod():
            try:
                since_seconds = self._pod_log.get(pod).get("from")
            except:
                self._pod_log[pod] = {}
                since_seconds = None
            if not since_seconds:
                since_seconds = int((datetime.now(timezone.utc) - from_time).total_seconds())
            else:
                from_time = datetime.now(timezone.utc) + timedelta(seconds=-since_seconds)
            logger.info("get pod %s's log from %s" % (pod, from_time.astimezone()))
            pod_logs = self.core_api.read_namespaced_pod_log(pod, "ingress-nginx", since_seconds=since_seconds).split(
                '\n')
            self._pod_log[pod]["log"] = pod_logs
        return self._pod_log

    @return_on_exception(None)
    def get_network_policy(self):
        network_policy = self.net_api.list_namespaced_network_policy(self._name_space)
        return network_policy

    def create_or_update_network_poicy(self, name: str, policy):
        try:
            return self.net_api.patch_namespaced_network_policy(name, self._name_space, policy)
        except client.exceptions.ApiException as e:
            if e.status == 404:
                return self.net_api.create_namespaced_network_policy(self._name_space, policy)
            else:
                raise e

    @return_on_exception([])
    def get_ban_ip(self) -> dict:
        network_policy = self.get_network_policy()
        try:
            return {ip: True for ip in network_policy.items[0].spec.ingress[0]._from[0].ip_block._except}
        except:
            return {}

    def set_ban_ip(self, cidr_list: list):
        self._base_network_policy["spec"]["ingress"][0]["from"][0]["ipBlock"]["except"] = cidr_list
        return self.create_or_update_network_poicy(self._network_policy_name, self._base_network_policy)


if __name__ == "__main__":
    ingress = pod_fail2ban_handler()
    #    print(ingress.read_log(datetime.now(timezone.utc) - timedelta(minutes=30)))
    # print(ingress.get_network_policy())
    ban_ip_list = ingress.get_ban_ip()
    print(ban_ip_list)
    print(ingress.ban_ip("185.193.66.205/32"))
    ban_ip_list.append("185.212.201.110/32")
    print(ingress.set_ban_ip(ban_ip_list))
