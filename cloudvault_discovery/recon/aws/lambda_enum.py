"""
AWS Lambda Enumerator
Serverless function discovery and security analysis
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class LambdaRisk(Enum):
    """Lambda security risk levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class LambdaFunction:
    """Lambda function details"""
    function_name: str
    function_arn: str
    runtime: str
    handler: str
    role: str
    code_size: int
    description: str = ""
    timeout: int = 3
    memory_size: int = 128
    last_modified: str = ""
    vpc_config: Dict[str, Any] = field(default_factory=dict)
    environment: Dict[str, str] = field(default_factory=dict)
    layers: List[str] = field(default_factory=list)
    state: str = "Active"
    architectures: List[str] = field(default_factory=list)
    
    @property
    def has_env_vars(self) -> bool:
        return len(self.environment) > 0
    
    @property
    def is_in_vpc(self) -> bool:
        return bool(self.vpc_config.get('VpcId'))
    
    @property
    def potential_secrets(self) -> List[str]:
        """Find potential secrets in environment variables"""
        secret_patterns = [
            'password', 'secret', 'key', 'token', 'api_key', 'apikey',
            'credential', 'auth', 'private', 'access', 'conn', 'database'
        ]
        found = []
        for key in self.environment.keys():
            key_lower = key.lower()
            if any(p in key_lower for p in secret_patterns):
                found.append(key)
        return found


@dataclass
class APIGatewayEndpoint:
    """API Gateway endpoint details"""
    api_id: str
    api_name: str
    endpoint_type: str
    protocol: str = "REST"
    stage: str = ""
    invoke_url: str = ""
    description: str = ""
    auth_type: str = "NONE"
    api_key_required: bool = False
    cors_enabled: bool = False
    methods: List[Dict[str, Any]] = field(default_factory=list)
    
    @property
    def is_public(self) -> bool:
        return self.auth_type == "NONE" and not self.api_key_required


@dataclass
class LambdaFinding:
    """Security finding for Lambda"""
    finding_type: str
    severity: LambdaRisk
    resource_id: str
    resource_type: str
    title: str
    description: str
    recommendation: str = ""
    mitre_techniques: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


MITRE_LAMBDA_TECHNIQUES = {
    'exploit_public_app': 'T1190',
    'serverless_execution': 'T1648',
    'cloud_execution': 'T1059.009',
    'steal_credentials': 'T1528',
    'data_staged': 'T1074.002',
}


class LambdaEnumerator:
    """
    AWS Lambda Enumerator
    
    Discovers Lambda functions and API Gateway endpoints,
    analyzes for security issues and potential secrets.
    """
    
    def __init__(self,
                 access_key: Optional[str] = None,
                 secret_key: Optional[str] = None,
                 session_token: Optional[str] = None,
                 profile: Optional[str] = None,
                 regions: Optional[List[str]] = None):
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token
        self.profile = profile
        self.regions = regions or ['us-east-1']
        self._session = None
        self._clients = {}
    
    def _get_boto3_session(self):
        """Create boto3 session"""
        try:
            import boto3
            
            if self.profile:
                return boto3.Session(profile_name=self.profile)
            elif self.access_key and self.secret_key:
                return boto3.Session(
                    aws_access_key_id=self.access_key,
                    aws_secret_access_key=self.secret_key,
                    aws_session_token=self.session_token
                )
            else:
                return boto3.Session()
        except ImportError:
            raise ImportError("boto3 required: pip install boto3")
    
    def _get_client(self, service: str, region: str):
        """Get AWS client for service and region"""
        key = f"{service}:{region}"
        if key not in self._clients:
            if not self._session:
                self._session = self._get_boto3_session()
            self._clients[key] = self._session.client(service, region_name=region)
        return self._clients[key]
    
    def enumerate_functions(self, region: str) -> List[LambdaFunction]:
        """Enumerate Lambda functions in a region"""
        functions = []
        
        try:
            client = self._get_client('lambda', region)
            paginator = client.get_paginator('list_functions')
            
            for page in paginator.paginate():
                for func in page.get('Functions', []):
                    # Get environment variables
                    env_vars = func.get('Environment', {}).get('Variables', {})
                    
                    # Get VPC config
                    vpc_config = func.get('VpcConfig', {})
                    
                    # Get layers
                    layers = [l['Arn'] for l in func.get('Layers', [])]
                    
                    lambda_func = LambdaFunction(
                        function_name=func['FunctionName'],
                        function_arn=func['FunctionArn'],
                        runtime=func.get('Runtime', 'unknown'),
                        handler=func.get('Handler', ''),
                        role=func.get('Role', ''),
                        code_size=func.get('CodeSize', 0),
                        description=func.get('Description', ''),
                        timeout=func.get('Timeout', 3),
                        memory_size=func.get('MemorySize', 128),
                        last_modified=func.get('LastModified', ''),
                        vpc_config=vpc_config,
                        environment=env_vars,
                        layers=layers,
                        state=func.get('State', 'Active'),
                        architectures=func.get('Architectures', ['x86_64'])
                    )
                    functions.append(lambda_func)
        except Exception as e:
            logger.error(f"Error enumerating Lambda in {region}: {e}")
        
        return functions
    
    def enumerate_api_gateways(self, region: str) -> List[APIGatewayEndpoint]:
        """Enumerate API Gateway endpoints in a region"""
        endpoints = []
        
        try:
            # REST APIs
            client = self._get_client('apigateway', region)
            rest_apis = client.get_rest_apis().get('items', [])
            
            for api in rest_apis:
                api_id = api['id']
                
                # Get stages
                stages = []
                try:
                    stages = client.get_stages(restApiId=api_id).get('item', [])
                except Exception:
                    pass
                
                for stage in stages:
                    invoke_url = f"https://{api_id}.execute-api.{region}.amazonaws.com/{stage['stageName']}"
                    
                    endpoint = APIGatewayEndpoint(
                        api_id=api_id,
                        api_name=api.get('name', ''),
                        endpoint_type=','.join(api.get('endpointConfiguration', {}).get('types', [])),
                        protocol='REST',
                        stage=stage['stageName'],
                        invoke_url=invoke_url,
                        description=api.get('description', '')
                    )
                    endpoints.append(endpoint)
            
            # HTTP APIs (API Gateway v2)
            try:
                v2_client = self._get_client('apigatewayv2', region)
                http_apis = v2_client.get_apis().get('Items', [])
                
                for api in http_apis:
                    endpoint = APIGatewayEndpoint(
                        api_id=api['ApiId'],
                        api_name=api.get('Name', ''),
                        endpoint_type='REGIONAL',
                        protocol=api.get('ProtocolType', 'HTTP'),
                        invoke_url=api.get('ApiEndpoint', ''),
                        description=api.get('Description', ''),
                        cors_enabled=bool(api.get('CorsConfiguration'))
                    )
                    endpoints.append(endpoint)
            except Exception:
                pass
                
        except Exception as e:
            logger.error(f"Error enumerating API Gateway in {region}: {e}")
        
        return endpoints
    
    def analyze_security(self, 
                        functions: List[LambdaFunction],
                        endpoints: List[APIGatewayEndpoint]) -> List[LambdaFinding]:
        """Analyze Lambda and API Gateway for security issues"""
        findings = []
        
        for func in functions:
            # Check for secrets in environment
            secrets = func.potential_secrets
            if secrets:
                findings.append(LambdaFinding(
                    finding_type='ENV_SECRETS',
                    severity=LambdaRisk.CRITICAL,
                    resource_id=func.function_arn,
                    resource_type='Lambda',
                    title='Potential Secrets in Environment Variables',
                    description=f"Function {func.function_name} has potential secrets in env vars: {secrets}",
                    recommendation='Use AWS Secrets Manager or Parameter Store for sensitive values',
                    mitre_techniques=[MITRE_LAMBDA_TECHNIQUES['steal_credentials']],
                    metadata={'secret_vars': secrets}
                ))
            
            # Check for outdated runtimes
            old_runtimes = ['python2.7', 'nodejs8.10', 'nodejs6.10', 'dotnetcore2.0', 'ruby2.5']
            if func.runtime in old_runtimes:
                findings.append(LambdaFinding(
                    finding_type='OUTDATED_RUNTIME',
                    severity=LambdaRisk.MEDIUM,
                    resource_id=func.function_arn,
                    resource_type='Lambda',
                    title='Outdated Lambda Runtime',
                    description=f"Function {func.function_name} uses deprecated runtime: {func.runtime}",
                    recommendation='Upgrade to a supported runtime version'
                ))
            
            # Check for overly permissive timeout
            if func.timeout > 300:
                findings.append(LambdaFinding(
                    finding_type='HIGH_TIMEOUT',
                    severity=LambdaRisk.LOW,
                    resource_id=func.function_arn,
                    resource_type='Lambda',
                    title='High Lambda Timeout',
                    description=f"Function {func.function_name} has {func.timeout}s timeout (max cost exposure)",
                    recommendation='Review if high timeout is necessary'
                ))
            
            # Check for no VPC (potential data exfil risk)
            if not func.is_in_vpc and func.has_env_vars:
                findings.append(LambdaFinding(
                    finding_type='NO_VPC',
                    severity=LambdaRisk.LOW,
                    resource_id=func.function_arn,
                    resource_type='Lambda',
                    title='Lambda Not in VPC',
                    description=f"Function {func.function_name} has env vars but runs outside VPC",
                    recommendation='Consider placing Lambda in VPC for network isolation'
                ))
        
        for endpoint in endpoints:
            # Check for public APIs without auth
            if endpoint.is_public:
                findings.append(LambdaFinding(
                    finding_type='PUBLIC_API',
                    severity=LambdaRisk.HIGH,
                    resource_id=endpoint.api_id,
                    resource_type='APIGateway',
                    title='Public API Without Authentication',
                    description=f"API {endpoint.api_name} ({endpoint.invoke_url}) has no authentication",
                    recommendation='Add IAM, Cognito, or API key authentication',
                    mitre_techniques=[MITRE_LAMBDA_TECHNIQUES['exploit_public_app']],
                    metadata={'invoke_url': endpoint.invoke_url}
                ))
        
        return findings
    
    def enumerate_all(self) -> Dict[str, Any]:
        """Enumerate all Lambda and API Gateway resources"""
        results = {
            'regions': {},
            'functions': [],
            'endpoints': [],
            'findings': [],
            'summary': {
                'total_functions': 0,
                'total_endpoints': 0,
                'functions_with_secrets': 0,
                'public_endpoints': 0,
                'total_findings': 0
            }
        }
        
        all_functions = []
        all_endpoints = []
        
        for region in self.regions:
            logger.info(f"Enumerating Lambda in {region}")
            
            functions = self.enumerate_functions(region)
            endpoints = self.enumerate_api_gateways(region)
            
            results['regions'][region] = {
                'functions': functions,
                'endpoints': endpoints
            }
            
            all_functions.extend(functions)
            all_endpoints.extend(endpoints)
        
        results['functions'] = all_functions
        results['endpoints'] = all_endpoints
        
        # Analyze security
        findings = self.analyze_security(all_functions, all_endpoints)
        results['findings'] = findings
        
        # Update summary
        results['summary']['total_functions'] = len(all_functions)
        results['summary']['total_endpoints'] = len(all_endpoints)
        results['summary']['functions_with_secrets'] = len([f for f in all_functions if f.potential_secrets])
        results['summary']['public_endpoints'] = len([e for e in all_endpoints if e.is_public])
        results['summary']['total_findings'] = len(findings)
        
        return results


__all__ = [
    'LambdaEnumerator',
    'LambdaFunction',
    'APIGatewayEndpoint',
    'LambdaFinding'
]
