import os
import time

from kubernetes import client, config


def cluster_init():
    # 判断当前环境是在 Pod 内部还是外部
    if os.getenv('KUBERNETES_SERVICE_HOST') and os.getenv('KUBERNETES_SERVICE_PORT'):
        # 在 Pod 内部运行，加载集群配置
        config.load_incluster_config()
    else:
        # 在外部运行，加载本地配置
        config.load_config()


def pod_garbage_clean():
    # 创建 Kubernetes API 客户端
    v1 = client.CoreV1Api()

    # 获取所有 Pod 列表
    pods = v1.list_pod_for_all_namespaces().items

    # 定义异常状态列表
    abnormal_statuses = ['Error', 'Evicted']

    # 从环境变量中获取异常状态并添加到异常状态列表
    extra_abnormal_statuses = os.getenv('POD_ABNORMAL_STATUS')
    if extra_abnormal_statuses:
        abnormal_statuses.extend(extra_abnormal_statuses.split(','))

    for pod in pods:
        # 过滤异常状态的 Pod
        if pod.status.phase not in ['Running', 'Succeeded'] and pod.status.container_statuses and any(
                c.state.waiting and c.state.waiting.reason in abnormal_statuses for c in pod.status.container_statuses):
            # 删除异常状态的 Pod
            v1.delete_namespaced_pod(name=pod.metadata.name, namespace=pod.metadata.namespace)
            print(f"Deleted Pod - Namespace: {pod.metadata.namespace}, Name: {pod.metadata.name}")


if __name__ == "__main__":
    internal = int(os.getenv("POD_CLEAN_INTERVAL", "10"))
    cluster_init()
    while True:
        pod_garbage_clean()
        time.sleep(internal)
