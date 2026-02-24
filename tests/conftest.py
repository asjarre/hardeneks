import os

from kubernetes import client
import pytest

from hardeneks.resources import Resources, NamespacedResources


class Response:
    def __init__(self, filename):
        with open(filename) as file:
            self.data = file.read()


def get_response(api, _file, _class):
    return api().api_client.deserialize(
        Response(_file),
        _class,
    )


@pytest.fixture(scope="function")
def resources(request):
    # Support both old format (string) and new format (tuple)
    if isinstance(request.param, tuple):
        test_name, required_resources = request.param
    else:
        # Backward compatibility: load all resources
        test_name = request.param
        required_resources = None
    
    current_directory = os.path.dirname(__file__)
    data_directory = os.path.join(
        current_directory, "data", test_name, "cluster"
    )
    resources = Resources(
        "some_region",
        "some_context",
        "some_cluster",
        ["good", "good2", "bad", "default"],
    )
    
    # Resource loaders mapping
    resource_loaders = {
        "resource_quotas": lambda: get_response(client.CoreV1Api, os.path.join(data_directory, "resource_quotas_api_response.json"), "V1ResourceQuotaList").items,
        "network_policies": lambda: get_response(client.NetworkingV1Api, os.path.join(data_directory, "network_policies_api_response.json"), "V1NetworkPolicyList").items,
        "storage_classes": lambda: get_response(client.StorageV1Api, os.path.join(data_directory, "storage_classes_api_response.json"), "V1StorageClassList").items,
        "persistent_volumes": lambda: get_response(client.CoreV1Api, os.path.join(data_directory, "persistent_volumes_api_response.json"), "V1PersistentVolumeList").items,
    }
    
    # If required_resources is None, load all (backward compatibility)
    if required_resources is None:
        for resource_name, loader in resource_loaders.items():
            setattr(resources, resource_name, loader())
    else:
        # Load only requested resources
        for resource_name, loader in resource_loaders.items():
            if resource_name in required_resources:
                setattr(resources, resource_name, loader())
            else:
                setattr(resources, resource_name, [])
    
    return resources


@pytest.fixture(scope="function")
def namespaced_resources(request):
    # Support both old format (string) and new format (tuple)
    if isinstance(request.param, tuple):
        test_name, required_resources = request.param
    else:
        # Backward compatibility: load all resources
        test_name = request.param
        required_resources = None
    
    current_directory = os.path.dirname(__file__)
    data_directory = os.path.join(
        current_directory, "data", test_name, "cluster"
    )
    resources = NamespacedResources(
        "some_region", "some_context", "some_cluster", "some_namespace"
    )
    
    # Resource loaders mapping
    resource_loaders = {
        "namespaces": lambda: get_response(client.CoreV1Api, os.path.join(data_directory, "namespaces_api_response.json"), "V1NamespaceList").items,
        "pods": lambda: get_response(client.CoreV1Api, os.path.join(data_directory, "pods_api_response.json"), "V1PodList").items,
        "services": lambda: get_response(client.CoreV1Api, os.path.join(data_directory, "services_api_response.json"), "V1ServiceList").items,
        "roles": lambda: get_response(client.RbacAuthorizationV1Api, os.path.join(data_directory, "roles_api_response.json"), "V1RoleList").items,
        "cluster_roles": lambda: get_response(client.RbacAuthorizationV1Api, os.path.join(data_directory, "cluster_roles_api_response.json"), "V1ClusterRoleList").items,
        "role_bindings": lambda: get_response(client.RbacAuthorizationV1Api, os.path.join(data_directory, "role_bindings_api_response.json"), "V1RoleBindingList").items,
        "cluster_role_bindings": lambda: get_response(client.RbacAuthorizationV1Api, os.path.join(data_directory, "cluster_role_bindings_api_response.json"), "V1ClusterRoleBindingList").items,
        "daemon_sets": lambda: get_response(client.AppsV1Api, os.path.join(data_directory, "daemon_sets_api_response.json"), "V1DaemonSetList").items,
        "stateful_sets": lambda: get_response(client.AppsV1Api, os.path.join(data_directory, "stateful_sets_api_response.json"), "V1StatefulSetList").items,
        "deployments": lambda: get_response(client.AppsV1Api, os.path.join(data_directory, "deployments_api_response.json"), "V1DeploymentList").items,
        "hpas": lambda: get_response(client.AutoscalingV1Api, os.path.join(data_directory, "horizontal_pod_autoscaler_api_response.json"), "V1HorizontalPodAutoscalerList").items,
        "service_accounts": lambda: get_response(client.CoreV1Api, os.path.join(data_directory, "service_accounts_api_response.json"), "V1ServiceAccountList").items,
    }
    
    # If required_resources is None, load all (backward compatibility)
    if required_resources is None:
        for resource_name, loader in resource_loaders.items():
            setattr(resources, resource_name, loader())
    else:
        # Load only requested resources
        for resource_name, loader in resource_loaders.items():
            if resource_name in required_resources:
                setattr(resources, resource_name, loader())
            else:
                setattr(resources, resource_name, [])

    return resources
