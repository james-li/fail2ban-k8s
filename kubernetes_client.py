from datetime import datetime, timezone

from kubernetes import client, config


class kubernetes_client(object):
    def __init__(self):
        config.load_config()
        self._core_api = client.CoreV1Api()
        self._net_api = client.NetworkingV1Api()

    @property
    def core_api(self):
        return self._core_api

    @property
    def net_api(self):
        return self._net_api

    def get_ingress_controller_pod(self):
        ret = self.core_api.list_namespaced_pod("ingress-nginx", label_selector="app=ingress-nginx")
        return [x.metadata.name for x in ret.items]

    def read_ingress_log(self, from_time: datetime):
        since_seconds = (datetime.now(timezone.utc) - from_time).total_seconds()
        pod = self.get_ingress_controller_pod()[0]
        return self.core_api.read_namespaced_pod_log(pod, "ingress-nginx", since_seconds=since_seconds)
