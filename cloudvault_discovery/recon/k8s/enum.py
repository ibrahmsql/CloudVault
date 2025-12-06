"""
Kubernetes Enumerator
Kubernetes cluster discovery and security analysis
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class K8sRisk(Enum):
    """Kubernetes security risk levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class K8sNamespace:
    """Kubernetes namespace details"""
    name: str
    status: str = "Active"
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)


@dataclass
class K8sPod:
    """Kubernetes pod details"""
    name: str
    namespace: str
    status: str = ""
    host_ip: str = ""
    pod_ip: str = ""
    node_name: str = ""
    service_account: str = "default"
    containers: List[Dict] = field(default_factory=list)
    volumes: List[Dict] = field(default_factory=list)
    labels: Dict[str, str] = field(default_factory=dict)
    
    @property
    def is_privileged(self) -> bool:
        for container in self.containers:
            sec_context = container.get('security_context', {})
            if sec_context.get('privileged'):
                return True
        return False
    
    @property
    def has_host_network(self) -> bool:
        return any(c.get('host_network') for c in self.containers)
    
    @property
    def has_host_pid(self) -> bool:
        return any(c.get('host_pid') for c in self.containers)
    
    @property
    def has_sensitive_mounts(self) -> bool:
        sensitive_paths = ['/etc/kubernetes', '/etc/shadow', '/etc/passwd', 
                         '/var/run/docker.sock', '/var/run/containerd']
        for vol in self.volumes:
            host_path = vol.get('host_path', '')
            if any(s in host_path for s in sensitive_paths):
                return True
        return False


@dataclass
class K8sSecret:
    """Kubernetes secret details"""
    name: str
    namespace: str
    secret_type: str = "Opaque"
    keys: List[str] = field(default_factory=list)


@dataclass
class K8sService:
    """Kubernetes service details"""
    name: str
    namespace: str
    service_type: str = "ClusterIP"
    cluster_ip: str = ""
    external_ip: str = ""
    ports: List[Dict] = field(default_factory=list)
    selector: Dict[str, str] = field(default_factory=dict)
    
    @property
    def is_external(self) -> bool:
        return self.service_type in ['LoadBalancer', 'NodePort']


@dataclass
class K8sRBACRole:
    """Kubernetes RBAC role details"""
    name: str
    namespace: str
    rules: List[Dict] = field(default_factory=list)
    is_cluster_role: bool = False
    
    @property
    def has_wildcard_access(self) -> bool:
        for rule in self.rules:
            if '*' in rule.get('verbs', []):
                if '*' in rule.get('resources', []):
                    return True
        return False
    
    @property
    def can_access_secrets(self) -> bool:
        for rule in self.rules:
            resources = rule.get('resources', [])
            verbs = rule.get('verbs', [])
            if 'secrets' in resources or '*' in resources:
                if any(v in verbs for v in ['get', 'list', 'watch', '*']):
                    return True
        return False


@dataclass
class K8sFinding:
    """Security finding for Kubernetes"""
    finding_type: str
    severity: K8sRisk
    resource_id: str
    resource_type: str
    namespace: str
    title: str
    description: str
    recommendation: str = ""
    mitre_techniques: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


MITRE_K8S_TECHNIQUES = {
    'container_escape': 'T1611',
    'container_admin': 'T1609',
    'deploy_container': 'T1610',
    'kubernetes_api': 'T1552.007',
    'valid_accounts': 'T1078.004',
    'credentials_in_files': 'T1552.001',
}


class KubernetesEnumerator:
    """
    Kubernetes Enumerator
    
    Discovers Kubernetes resources and analyzes security.
    Uses kubernetes python client.
    """
    
    def __init__(self,
                 kubeconfig: Optional[str] = None,
                 context: Optional[str] = None,
                 in_cluster: bool = False):
        self.kubeconfig = kubeconfig
        self.context = context
        self.in_cluster = in_cluster
        self._api_client = None
        self._core_v1 = None
        self._rbac_v1 = None
    
    def _load_config(self):
        """Load Kubernetes configuration"""
        try:
            from kubernetes import client, config
            
            if self.in_cluster:
                config.load_incluster_config()
            elif self.kubeconfig:
                config.load_kube_config(config_file=self.kubeconfig, context=self.context)
            else:
                config.load_kube_config(context=self.context)
                
        except ImportError:
            raise ImportError("kubernetes required: pip install kubernetes")
    
    def _get_core_v1(self):
        """Get CoreV1 API client"""
        if not self._core_v1:
            from kubernetes import client
            self._load_config()
            self._core_v1 = client.CoreV1Api()
        return self._core_v1
    
    def _get_rbac_v1(self):
        """Get RBACV1 API client"""
        if not self._rbac_v1:
            from kubernetes import client
            self._load_config()
            self._rbac_v1 = client.RbacAuthorizationV1Api()
        return self._rbac_v1
    
    def enumerate_namespaces(self) -> List[K8sNamespace]:
        """Enumerate namespaces"""
        namespaces = []
        
        try:
            v1 = self._get_core_v1()
            ns_list = v1.list_namespace()
            
            for ns in ns_list.items:
                namespaces.append(K8sNamespace(
                    name=ns.metadata.name,
                    status=ns.status.phase if ns.status else "Active",
                    labels=dict(ns.metadata.labels) if ns.metadata.labels else {},
                    annotations=dict(ns.metadata.annotations) if ns.metadata.annotations else {}
                ))
        except Exception as e:
            logger.error(f"Error enumerating namespaces: {e}")
        
        return namespaces
    
    def enumerate_pods(self, namespace: Optional[str] = None) -> List[K8sPod]:
        """Enumerate pods"""
        pods = []
        
        try:
            v1 = self._get_core_v1()
            
            if namespace:
                pod_list = v1.list_namespaced_pod(namespace)
            else:
                pod_list = v1.list_pod_for_all_namespaces()
            
            for pod in pod_list.items:
                containers = []
                for container in pod.spec.containers:
                    sec_ctx = container.security_context
                    containers.append({
                        'name': container.name,
                        'image': container.image,
                        'security_context': {
                            'privileged': sec_ctx.privileged if sec_ctx else False,
                            'run_as_root': sec_ctx.run_as_user == 0 if sec_ctx and sec_ctx.run_as_user else False,
                            'allow_privilege_escalation': sec_ctx.allow_privilege_escalation if sec_ctx else True,
                        } if sec_ctx else {},
                        'host_network': pod.spec.host_network,
                        'host_pid': pod.spec.host_pid,
                    })
                
                volumes = []
                for vol in (pod.spec.volumes or []):
                    if vol.host_path:
                        volumes.append({
                            'name': vol.name,
                            'host_path': vol.host_path.path,
                            'type': vol.host_path.type or ''
                        })
                
                pods.append(K8sPod(
                    name=pod.metadata.name,
                    namespace=pod.metadata.namespace,
                    status=pod.status.phase if pod.status else "",
                    host_ip=pod.status.host_ip if pod.status else "",
                    pod_ip=pod.status.pod_ip if pod.status else "",
                    node_name=pod.spec.node_name or "",
                    service_account=pod.spec.service_account_name or "default",
                    containers=containers,
                    volumes=volumes,
                    labels=dict(pod.metadata.labels) if pod.metadata.labels else {}
                ))
        except Exception as e:
            logger.error(f"Error enumerating pods: {e}")
        
        return pods
    
    def enumerate_secrets(self, namespace: Optional[str] = None) -> List[K8sSecret]:
        """Enumerate secrets (metadata only)"""
        secrets = []
        
        try:
            v1 = self._get_core_v1()
            
            if namespace:
                secret_list = v1.list_namespaced_secret(namespace)
            else:
                secret_list = v1.list_secret_for_all_namespaces()
            
            for secret in secret_list.items:
                secrets.append(K8sSecret(
                    name=secret.metadata.name,
                    namespace=secret.metadata.namespace,
                    secret_type=secret.type or "Opaque",
                    keys=list(secret.data.keys()) if secret.data else []
                ))
        except Exception as e:
            logger.error(f"Error enumerating secrets: {e}")
        
        return secrets
    
    def enumerate_services(self, namespace: Optional[str] = None) -> List[K8sService]:
        """Enumerate services"""
        services = []
        
        try:
            v1 = self._get_core_v1()
            
            if namespace:
                svc_list = v1.list_namespaced_service(namespace)
            else:
                svc_list = v1.list_service_for_all_namespaces()
            
            for svc in svc_list.items:
                ports = []
                for port in (svc.spec.ports or []):
                    ports.append({
                        'name': port.name,
                        'port': port.port,
                        'target_port': port.target_port,
                        'node_port': port.node_port,
                        'protocol': port.protocol
                    })
                
                external_ip = ""
                if svc.status.load_balancer and svc.status.load_balancer.ingress:
                    ing = svc.status.load_balancer.ingress[0]
                    external_ip = ing.ip or ing.hostname or ""
                
                services.append(K8sService(
                    name=svc.metadata.name,
                    namespace=svc.metadata.namespace,
                    service_type=svc.spec.type or "ClusterIP",
                    cluster_ip=svc.spec.cluster_ip or "",
                    external_ip=external_ip,
                    ports=ports,
                    selector=dict(svc.spec.selector) if svc.spec.selector else {}
                ))
        except Exception as e:
            logger.error(f"Error enumerating services: {e}")
        
        return services
    
    def enumerate_rbac_roles(self) -> List[K8sRBACRole]:
        """Enumerate RBAC roles and cluster roles"""
        roles = []
        
        try:
            rbac = self._get_rbac_v1()
            
            # Cluster roles
            cluster_roles = rbac.list_cluster_role()
            for role in cluster_roles.items:
                rules = []
                for rule in (role.rules or []):
                    rules.append({
                        'verbs': list(rule.verbs) if rule.verbs else [],
                        'resources': list(rule.resources) if rule.resources else [],
                        'api_groups': list(rule.api_groups) if rule.api_groups else []
                    })
                roles.append(K8sRBACRole(
                    name=role.metadata.name,
                    namespace="",
                    rules=rules,
                    is_cluster_role=True
                ))
            
            # Namespaced roles
            ns_roles = rbac.list_role_for_all_namespaces()
            for role in ns_roles.items:
                rules = []
                for rule in (role.rules or []):
                    rules.append({
                        'verbs': list(rule.verbs) if rule.verbs else [],
                        'resources': list(rule.resources) if rule.resources else [],
                        'api_groups': list(rule.api_groups) if rule.api_groups else []
                    })
                roles.append(K8sRBACRole(
                    name=role.metadata.name,
                    namespace=role.metadata.namespace,
                    rules=rules,
                    is_cluster_role=False
                ))
                
        except Exception as e:
            logger.error(f"Error enumerating RBAC: {e}")
        
        return roles
    
    def analyze_security(self,
                        pods: List[K8sPod],
                        services: List[K8sService],
                        roles: List[K8sRBACRole],
                        secrets: List[K8sSecret]) -> List[K8sFinding]:
        """Analyze Kubernetes resources for security issues"""
        findings = []
        
        for pod in pods:
            # Privileged container
            if pod.is_privileged:
                findings.append(K8sFinding(
                    finding_type='PRIVILEGED_CONTAINER',
                    severity=K8sRisk.CRITICAL,
                    resource_id=f"{pod.namespace}/{pod.name}",
                    resource_type='Pod',
                    namespace=pod.namespace,
                    title='Privileged Container Detected',
                    description=f"Pod {pod.name} runs with privileged containers",
                    recommendation='Remove privileged flag unless absolutely necessary',
                    mitre_techniques=[MITRE_K8S_TECHNIQUES['container_escape']]
                ))
            
            # Host network/PID
            if pod.has_host_network:
                findings.append(K8sFinding(
                    finding_type='HOST_NETWORK',
                    severity=K8sRisk.HIGH,
                    resource_id=f"{pod.namespace}/{pod.name}",
                    resource_type='Pod',
                    namespace=pod.namespace,
                    title='Pod Uses Host Network',
                    description=f"Pod {pod.name} shares host network namespace",
                    recommendation='Use pod network isolation',
                    mitre_techniques=[MITRE_K8S_TECHNIQUES['container_escape']]
                ))
            
            # Sensitive mounts
            if pod.has_sensitive_mounts:
                findings.append(K8sFinding(
                    finding_type='SENSITIVE_MOUNT',
                    severity=K8sRisk.CRITICAL,
                    resource_id=f"{pod.namespace}/{pod.name}",
                    resource_type='Pod',
                    namespace=pod.namespace,
                    title='Sensitive Host Path Mounted',
                    description=f"Pod {pod.name} mounts sensitive host paths",
                    recommendation='Avoid mounting sensitive host paths',
                    mitre_techniques=[MITRE_K8S_TECHNIQUES['container_escape']],
                    metadata={'volumes': pod.volumes}
                ))
            
            # Default service account
            if pod.service_account == 'default':
                findings.append(K8sFinding(
                    finding_type='DEFAULT_SA',
                    severity=K8sRisk.LOW,
                    resource_id=f"{pod.namespace}/{pod.name}",
                    resource_type='Pod',
                    namespace=pod.namespace,
                    title='Using Default Service Account',
                    description=f"Pod {pod.name} uses default service account",
                    recommendation='Create dedicated service accounts with minimal permissions'
                ))
        
        for svc in services:
            # External services
            if svc.is_external:
                findings.append(K8sFinding(
                    finding_type='EXTERNAL_SERVICE',
                    severity=K8sRisk.MEDIUM,
                    resource_id=f"{svc.namespace}/{svc.name}",
                    resource_type='Service',
                    namespace=svc.namespace,
                    title=f'External {svc.service_type} Service',
                    description=f"Service {svc.name} is exposed externally ({svc.service_type})",
                    recommendation='Ensure proper network policies and authentication',
                    metadata={'external_ip': svc.external_ip}
                ))
        
        for role in roles:
            # Wildcard access
            if role.has_wildcard_access:
                findings.append(K8sFinding(
                    finding_type='WILDCARD_RBAC',
                    severity=K8sRisk.CRITICAL,
                    resource_id=f"{role.namespace or 'cluster'}/{role.name}",
                    resource_type='ClusterRole' if role.is_cluster_role else 'Role',
                    namespace=role.namespace or "",
                    title='RBAC Role with Wildcard Access',
                    description=f"Role {role.name} has wildcard (*) access to all resources",
                    recommendation='Follow least privilege principle',
                    mitre_techniques=[MITRE_K8S_TECHNIQUES['container_admin']]
                ))
            
            # Secrets access
            if role.can_access_secrets:
                findings.append(K8sFinding(
                    finding_type='SECRETS_ACCESS',
                    severity=K8sRisk.HIGH,
                    resource_id=f"{role.namespace or 'cluster'}/{role.name}",
                    resource_type='ClusterRole' if role.is_cluster_role else 'Role',
                    namespace=role.namespace or "",
                    title='RBAC Role with Secrets Access',
                    description=f"Role {role.name} can read secrets",
                    recommendation='Limit secrets access to necessary roles only',
                    mitre_techniques=[MITRE_K8S_TECHNIQUES['credentials_in_files']]
                ))
        
        return findings
    
    def enumerate_all(self) -> Dict[str, Any]:
        """Enumerate all Kubernetes resources"""
        results = {
            'namespaces': [],
            'pods': [],
            'services': [],
            'secrets': [],
            'rbac_roles': [],
            'findings': [],
            'summary': {
                'total_namespaces': 0,
                'total_pods': 0,
                'privileged_pods': 0,
                'total_services': 0,
                'external_services': 0,
                'total_secrets': 0,
                'total_findings': 0
            }
        }
        
        namespaces = self.enumerate_namespaces()
        pods = self.enumerate_pods()
        services = self.enumerate_services()
        secrets = self.enumerate_secrets()
        roles = self.enumerate_rbac_roles()
        
        results['namespaces'] = namespaces
        results['pods'] = pods
        results['services'] = services
        results['secrets'] = secrets
        results['rbac_roles'] = roles
        
        # Analyze security
        findings = self.analyze_security(pods, services, roles, secrets)
        results['findings'] = findings
        
        # Update summary
        results['summary']['total_namespaces'] = len(namespaces)
        results['summary']['total_pods'] = len(pods)
        results['summary']['privileged_pods'] = len([p for p in pods if p.is_privileged])
        results['summary']['total_services'] = len(services)
        results['summary']['external_services'] = len([s for s in services if s.is_external])
        results['summary']['total_secrets'] = len(secrets)
        results['summary']['total_findings'] = len(findings)
        
        return results


__all__ = [
    'KubernetesEnumerator',
    'K8sNamespace',
    'K8sPod',
    'K8sSecret',
    'K8sService',
    'K8sRBACRole',
    'K8sFinding'
]
