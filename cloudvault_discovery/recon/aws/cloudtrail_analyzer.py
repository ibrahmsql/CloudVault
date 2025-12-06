"""
AWS CloudTrail Log Analyzer
Suspicious API call detection and security event analysis
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CloudTrailEvent:
    """CloudTrail event details"""
    event_id: str
    event_name: str
    event_source: str
    event_time: str
    aws_region: str
    source_ip: str = ""
    user_agent: str = ""
    user_identity: Dict[str, Any] = field(default_factory=dict)
    request_parameters: Dict[str, Any] = field(default_factory=dict)
    response_elements: Dict[str, Any] = field(default_factory=dict)
    error_code: str = ""
    error_message: str = ""
    read_only: bool = True
    
    @property
    def is_error(self) -> bool:
        return bool(self.error_code)
    
    @property
    def principal_id(self) -> str:
        return self.user_identity.get('principalId', '')
    
    @property
    def user_type(self) -> str:
        return self.user_identity.get('type', '')


@dataclass
class SecurityAlert:
    """Security alert from CloudTrail analysis"""
    alert_type: str
    threat_level: ThreatLevel
    title: str
    description: str
    event_ids: List[str] = field(default_factory=list)
    source_ips: List[str] = field(default_factory=list)
    affected_resources: List[str] = field(default_factory=list)
    mitre_technique: str = ""
    recommendation: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


SUSPICIOUS_API_CALLS = {
    'iam.amazonaws.com': {
        'CreateUser': ThreatLevel.HIGH,
        'CreateAccessKey': ThreatLevel.HIGH,
        'CreateLoginProfile': ThreatLevel.HIGH,
        'AttachUserPolicy': ThreatLevel.HIGH,
        'AttachRolePolicy': ThreatLevel.HIGH,
        'PutUserPolicy': ThreatLevel.HIGH,
        'PutRolePolicy': ThreatLevel.HIGH,
        'CreateRole': ThreatLevel.MEDIUM,
        'UpdateAssumeRolePolicy': ThreatLevel.HIGH,
        'DeleteTrail': ThreatLevel.CRITICAL,
        'StopLogging': ThreatLevel.CRITICAL,
    },
    'sts.amazonaws.com': {
        'AssumeRole': ThreatLevel.MEDIUM,
        'GetSessionToken': ThreatLevel.LOW,
        'GetFederationToken': ThreatLevel.MEDIUM,
    },
    's3.amazonaws.com': {
        'DeleteBucket': ThreatLevel.HIGH,
        'DeleteBucketPolicy': ThreatLevel.MEDIUM,
        'PutBucketPolicy': ThreatLevel.MEDIUM,
        'PutBucketAcl': ThreatLevel.MEDIUM,
        'GetObject': ThreatLevel.INFO,
    },
    'ec2.amazonaws.com': {
        'RunInstances': ThreatLevel.MEDIUM,
        'CreateKeyPair': ThreatLevel.HIGH,
        'ImportKeyPair': ThreatLevel.HIGH,
        'AuthorizeSecurityGroupIngress': ThreatLevel.MEDIUM,
        'CreateSecurityGroup': ThreatLevel.LOW,
        'ModifyInstanceAttribute': ThreatLevel.MEDIUM,
    },
    'lambda.amazonaws.com': {
        'CreateFunction': ThreatLevel.MEDIUM,
        'UpdateFunctionCode': ThreatLevel.MEDIUM,
        'AddPermission': ThreatLevel.MEDIUM,
    },
    'kms.amazonaws.com': {
        'DisableKey': ThreatLevel.CRITICAL,
        'ScheduleKeyDeletion': ThreatLevel.CRITICAL,
        'PutKeyPolicy': ThreatLevel.HIGH,
    },
    'cloudtrail.amazonaws.com': {
        'DeleteTrail': ThreatLevel.CRITICAL,
        'StopLogging': ThreatLevel.CRITICAL,
        'UpdateTrail': ThreatLevel.HIGH,
    },
    'guardduty.amazonaws.com': {
        'DeleteDetector': ThreatLevel.CRITICAL,
        'DisableOrganizationAdminAccount': ThreatLevel.CRITICAL,
    },
    'secretsmanager.amazonaws.com': {
        'GetSecretValue': ThreatLevel.MEDIUM,
        'DeleteSecret': ThreatLevel.HIGH,
    },
    'ssm.amazonaws.com': {
        'GetParameter': ThreatLevel.LOW,
        'GetParameters': ThreatLevel.LOW,
        'DeleteParameter': ThreatLevel.MEDIUM,
    },
}

DATA_EXFIL_PATTERNS = [
    'GetObject', 'CopyObject', 'GetBucketLocation',
    'DescribeSnapshots', 'CopySnapshot', 'CreateSnapshot',
    'GetSecretValue', 'GetParameter', 'GetParameters',
    'DescribeDBSnapshots', 'CopyDBSnapshot',
]

FAILED_AUTH_EVENTS = [
    'ConsoleLogin', 'AssumeRole', 'GetSessionToken',
    'GetFederationToken', 'AssumeRoleWithSAML', 'AssumeRoleWithWebIdentity',
]


class CloudTrailAnalyzer:
    """
    AWS CloudTrail Log Analyzer
    
    Analyzes CloudTrail events for:
    - Suspicious API calls
    - Failed authentication attempts
    - Data exfiltration patterns
    - Privilege escalation indicators
    """
    
    def __init__(self,
                 access_key: Optional[str] = None,
                 secret_key: Optional[str] = None,
                 session_token: Optional[str] = None,
                 profile: Optional[str] = None,
                 region: str = 'us-east-1'):
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token
        self.profile = profile
        self.region = region
        self._session = None
        self._client = None
    
    def _get_boto3_session(self):
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
            return boto3.Session()
        except ImportError:
            raise ImportError("boto3 required: pip install boto3")
    
    def _get_client(self):
        if not self._client:
            if not self._session:
                self._session = self._get_boto3_session()
            self._client = self._session.client('cloudtrail', region_name=self.region)
        return self._client
    
    def lookup_events(self,
                     start_time: Optional[datetime] = None,
                     end_time: Optional[datetime] = None,
                     event_name: Optional[str] = None,
                     max_results: int = 1000) -> List[CloudTrailEvent]:
        """Lookup CloudTrail events"""
        events = []
        
        if not start_time:
            start_time = datetime.now() - timedelta(hours=24)
        if not end_time:
            end_time = datetime.now()
        
        try:
            client = self._get_client()
            
            lookup_attrs = []
            if event_name:
                lookup_attrs.append({'AttributeKey': 'EventName', 'AttributeValue': event_name})
            
            paginator = client.get_paginator('lookup_events')
            
            params = {
                'StartTime': start_time,
                'EndTime': end_time,
                'MaxResults': min(max_results, 50)
            }
            if lookup_attrs:
                params['LookupAttributes'] = lookup_attrs
            
            count = 0
            for page in paginator.paginate(**params):
                for event_data in page.get('Events', []):
                    if count >= max_results:
                        break
                    
                    import json
                    cloud_event = json.loads(event_data.get('CloudTrailEvent', '{}'))
                    
                    event = CloudTrailEvent(
                        event_id=event_data.get('EventId', ''),
                        event_name=event_data.get('EventName', ''),
                        event_source=event_data.get('EventSource', ''),
                        event_time=str(event_data.get('EventTime', '')),
                        aws_region=cloud_event.get('awsRegion', ''),
                        source_ip=cloud_event.get('sourceIPAddress', ''),
                        user_agent=cloud_event.get('userAgent', ''),
                        user_identity=cloud_event.get('userIdentity', {}),
                        request_parameters=cloud_event.get('requestParameters', {}),
                        response_elements=cloud_event.get('responseElements', {}),
                        error_code=cloud_event.get('errorCode', ''),
                        error_message=cloud_event.get('errorMessage', ''),
                        read_only=cloud_event.get('readOnly', True)
                    )
                    events.append(event)
                    count += 1
                    
                if count >= max_results:
                    break
                    
        except Exception as e:
            logger.error(f"Error looking up events: {e}")
        
        return events
    
    def detect_suspicious_calls(self, events: List[CloudTrailEvent]) -> List[SecurityAlert]:
        """Detect suspicious API calls"""
        alerts = []
        suspicious_by_type = {}
        
        for event in events:
            source = event.event_source
            name = event.event_name
            
            if source in SUSPICIOUS_API_CALLS:
                if name in SUSPICIOUS_API_CALLS[source]:
                    level = SUSPICIOUS_API_CALLS[source][name]
                    key = f"{source}:{name}"
                    
                    if key not in suspicious_by_type:
                        suspicious_by_type[key] = {
                            'level': level,
                            'events': [],
                            'ips': set(),
                            'users': set()
                        }
                    
                    suspicious_by_type[key]['events'].append(event.event_id)
                    suspicious_by_type[key]['ips'].add(event.source_ip)
                    suspicious_by_type[key]['users'].add(event.principal_id)
        
        for key, data in suspicious_by_type.items():
            source, name = key.split(':')
            alerts.append(SecurityAlert(
                alert_type='SUSPICIOUS_API',
                threat_level=data['level'],
                title=f'Suspicious API Call: {name}',
                description=f"{len(data['events'])} calls to {name} from {len(data['ips'])} IPs",
                event_ids=data['events'],
                source_ips=list(data['ips']),
                mitre_technique='T1078' if 'iam' in source else 'T1059.009',
                metadata={'users': list(data['users'])}
            ))
        
        return alerts
    
    def detect_failed_auth(self, events: List[CloudTrailEvent]) -> List[SecurityAlert]:
        """Detect failed authentication attempts"""
        alerts = []
        failed_by_ip = {}
        
        for event in events:
            if event.event_name in FAILED_AUTH_EVENTS and event.is_error:
                ip = event.source_ip
                if ip not in failed_by_ip:
                    failed_by_ip[ip] = {'count': 0, 'events': [], 'errors': set()}
                
                failed_by_ip[ip]['count'] += 1
                failed_by_ip[ip]['events'].append(event.event_id)
                failed_by_ip[ip]['errors'].add(event.error_code)
        
        for ip, data in failed_by_ip.items():
            if data['count'] >= 3:
                level = ThreatLevel.CRITICAL if data['count'] >= 10 else ThreatLevel.HIGH
                alerts.append(SecurityAlert(
                    alert_type='FAILED_AUTH',
                    threat_level=level,
                    title=f'Multiple Failed Auth from {ip}',
                    description=f"{data['count']} failed authentication attempts",
                    event_ids=data['events'],
                    source_ips=[ip],
                    mitre_technique='T1110',
                    recommendation='Block IP or investigate user',
                    metadata={'error_codes': list(data['errors'])}
                ))
        
        return alerts
    
    def detect_data_exfil(self, events: List[CloudTrailEvent]) -> List[SecurityAlert]:
        """Detect potential data exfiltration"""
        alerts = []
        exfil_by_user = {}
        
        for event in events:
            if event.event_name in DATA_EXFIL_PATTERNS:
                user = event.principal_id
                if user not in exfil_by_user:
                    exfil_by_user[user] = {'count': 0, 'events': [], 'ips': set(), 'resources': set()}
                
                exfil_by_user[user]['count'] += 1
                exfil_by_user[user]['events'].append(event.event_id)
                exfil_by_user[user]['ips'].add(event.source_ip)
                
                params = event.request_parameters
                if 'bucketName' in params:
                    exfil_by_user[user]['resources'].add(params['bucketName'])
                if 'key' in params:
                    exfil_by_user[user]['resources'].add(params.get('key', '')[:50])
        
        for user, data in exfil_by_user.items():
            if data['count'] >= 50:
                level = ThreatLevel.HIGH if data['count'] >= 100 else ThreatLevel.MEDIUM
                alerts.append(SecurityAlert(
                    alert_type='DATA_EXFIL',
                    threat_level=level,
                    title=f'Potential Data Exfiltration by {user[:20]}',
                    description=f"{data['count']} data access events from {len(data['ips'])} IPs",
                    event_ids=data['events'][:10],
                    source_ips=list(data['ips']),
                    affected_resources=list(data['resources'])[:10],
                    mitre_technique='T1530',
                    recommendation='Review user activity and data access patterns'
                ))
        
        return alerts
    
    def detect_privilege_escalation(self, events: List[CloudTrailEvent]) -> List[SecurityAlert]:
        """Detect privilege escalation attempts"""
        alerts = []
        privesc_events = [
            'CreateAccessKey', 'AttachUserPolicy', 'AttachRolePolicy',
            'PutUserPolicy', 'PutRolePolicy', 'UpdateAssumeRolePolicy',
            'CreateLoginProfile', 'AddUserToGroup'
        ]
        
        for event in events:
            if event.event_name in privesc_events and not event.is_error:
                alerts.append(SecurityAlert(
                    alert_type='PRIVESC',
                    threat_level=ThreatLevel.HIGH,
                    title=f'Privilege Escalation: {event.event_name}',
                    description=f'{event.event_name} by {event.principal_id[:30]}',
                    event_ids=[event.event_id],
                    source_ips=[event.source_ip],
                    mitre_technique='T1098',
                    metadata={'user_identity': event.user_identity}
                ))
        
        return alerts
    
    def analyze(self,
               hours_back: int = 24,
               max_events: int = 1000) -> Dict[str, Any]:
        """Run full analysis"""
        start_time = datetime.now() - timedelta(hours=hours_back)
        
        logger.info(f"Fetching CloudTrail events from last {hours_back} hours...")
        events = self.lookup_events(start_time=start_time, max_results=max_events)
        
        all_alerts = []
        all_alerts.extend(self.detect_suspicious_calls(events))
        all_alerts.extend(self.detect_failed_auth(events))
        all_alerts.extend(self.detect_data_exfil(events))
        all_alerts.extend(self.detect_privilege_escalation(events))
        
        return {
            'events_analyzed': len(events),
            'time_range': f'{hours_back} hours',
            'alerts': all_alerts,
            'summary': {
                'total_alerts': len(all_alerts),
                'critical': len([a for a in all_alerts if a.threat_level == ThreatLevel.CRITICAL]),
                'high': len([a for a in all_alerts if a.threat_level == ThreatLevel.HIGH]),
                'medium': len([a for a in all_alerts if a.threat_level == ThreatLevel.MEDIUM]),
            }
        }


__all__ = ['CloudTrailAnalyzer', 'CloudTrailEvent', 'SecurityAlert', 'ThreatLevel']
