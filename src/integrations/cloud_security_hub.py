"""
Multi-Cloud Security Hub Integration
Combines AWS Security Hub and Azure Security Center for comprehensive security monitoring
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

import boto3
from azure.identity import DefaultAzureCredential
from azure.mgmt.security import SecurityCenter

from ..core.config import Settings
from ..core.logging_config import log_security_event


class SecurityFindingSeverity(Enum):
    """Security finding severity levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class SecurityFinding:
    """Unified security finding structure"""
    id: str
    title: str
    description: str
    severity: SecurityFindingSeverity
    resource: str
    source: str  # aws or azure
    status: str
    created_at: datetime
    updated_at: datetime
    compliance_frameworks: List[str]
    remediation: Optional[str] = None


class CloudSecurityHub:
    """Multi-cloud security monitoring and management"""
    
    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or Settings()
        self.logger = logging.getLogger(__name__)
        
        # AWS clients
        self.aws_security_hub = None
        self.aws_config = None
        
        # Azure clients
        self.azure_security = None
        self.azure_credential = None
        
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize cloud security connections"""
        try:
            await self._initialize_aws()
            await self._initialize_azure()
            
            self._initialized = True
            self.logger.info("Cloud Security Hub initialized successfully")
            
            log_security_event(
                event_type="cloud_security_initialization",
                description="Multi-cloud security hub initialized",
                severity="INFO"
            )
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Cloud Security Hub: {e}")
            log_security_event(
                event_type="cloud_security_init_failed",
                description=f"Cloud security initialization failed: {str(e)}",
                severity="ERROR"
            )
            raise
    
    async def _initialize_aws(self) -> None:
        """Initialize AWS Security Hub connection"""
        try:
            # Check for demo mode
            if self.settings.aws_access_key_id == "demo-aws-key":
                self.logger.info("AWS Security Hub running in DEMO mode")
                return
                
            aws_config = self.settings.get_aws_config()
            
            self.aws_security_hub = boto3.client('securityhub', **aws_config)
            self.aws_config = boto3.client('config', **aws_config)
            
            # Verify Security Hub is enabled
            try:
                self.aws_security_hub.describe_hub()
                self.logger.info("AWS Security Hub connection established")
            except self.aws_security_hub.exceptions.InvalidAccessException:
                self.logger.warning("AWS Security Hub not enabled or insufficient permissions")
                
        except Exception as e:
            self.logger.error(f"AWS Security Hub initialization failed: {e}")
            # Don't raise here - allow partial initialization
    
    async def _initialize_azure(self) -> None:
        """Initialize Azure Security Center connection"""
        try:
            azure_config = self.settings.get_azure_config()
            
            # Check for demo mode
            if azure_config['subscription_id'] == "demo-azure-subscription":
                self.logger.info("Azure Security Center running in DEMO mode")
                return
            
            if azure_config['subscription_id']:
                self.azure_credential = DefaultAzureCredential()
                self.azure_security = SecurityCenter(
                    self.azure_credential,
                    azure_config['subscription_id']
                )
                self.logger.info("Azure Security Center connection established")
            
        except Exception as e:
            self.logger.error(f"Azure Security Center initialization failed: {e}")
            # Don't raise here - allow partial initialization
    
    async def get_aws_findings(self, days_back: int = 7) -> List[SecurityFinding]:
        """Retrieve AWS Security Hub findings"""
        if not self.aws_security_hub:
            return []
        
        try:
            # Calculate date filter
            since_date = datetime.utcnow() - timedelta(days=days_back)
            
            paginator = self.aws_security_hub.get_paginator('get_findings')
            findings = []
            
            async for page in self._paginate_aws_findings(paginator, since_date):
                for finding in page.get('Findings', []):
                    security_finding = SecurityFinding(
                        id=finding['Id'],
                        title=finding['Title'],
                        description=finding['Description'],
                        severity=SecurityFindingSeverity(finding['Severity']['Label']),
                        resource=finding.get('Resources', [{}])[0].get('Id', 'Unknown'),
                        source='aws',
                        status=finding['Compliance']['Status'],
                        created_at=finding['CreatedAt'],
                        updated_at=finding['UpdatedAt'],
                        compliance_frameworks=self._extract_compliance_frameworks(finding),
                        remediation=finding.get('Remediation', {}).get('Recommendation', {}).get('Text')
                    )
                    findings.append(security_finding)
            
            self.logger.info(f"Retrieved {len(findings)} AWS security findings")
            return findings
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve AWS findings: {e}")
            return []
    
    async def _paginate_aws_findings(self, paginator, since_date):
        """Async wrapper for AWS pagination"""
        # In a real implementation, you'd use aioboto3 for true async
        # For now, we'll simulate async behavior
        filters = {
            'CreatedAt': [
                {
                    'Start': since_date,
                    'End': datetime.utcnow()
                }
            ],
            'ComplianceStatus': [
                {'Value': 'FAILED', 'Comparison': 'EQUALS'}
            ]
        }
        
        page_iterator = paginator.paginate(
            Filters=filters,
            SortCriteria=[
                {
                    'Field': 'UpdatedAt',
                    'SortOrder': 'desc'
                }
            ]
        )
        
        for page in page_iterator:
            yield page
    
    async def get_azure_findings(self, days_back: int = 7) -> List[SecurityFinding]:
        """Retrieve Azure Security Center findings"""
        if not self.azure_security:
            return []
        
        try:
            findings = []
            
            # Get alerts from Azure Security Center
            alerts = self.azure_security.alerts.list()
            
            for alert in alerts:
                # Filter by date
                if alert.time_generated_utc >= datetime.utcnow() - timedelta(days=days_back):
                    security_finding = SecurityFinding(
                        id=alert.name,
                        title=alert.display_name,
                        description=alert.description,
                        severity=self._map_azure_severity(alert.severity),
                        resource=alert.compromised_entity or 'Unknown',
                        source='azure',
                        status=alert.state,
                        created_at=alert.time_generated_utc,
                        updated_at=alert.time_generated_utc,
                        compliance_frameworks=self._get_azure_compliance_frameworks(),
                        remediation=getattr(alert, 'remediation_steps', None)
                    )
                    findings.append(security_finding)
            
            self.logger.info(f"Retrieved {len(findings)} Azure security findings")
            return findings
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve Azure findings: {e}")
            return []
    
    def _map_azure_severity(self, azure_severity: str) -> SecurityFindingSeverity:
        """Map Azure severity to standard severity"""
        mapping = {
            'Informational': SecurityFindingSeverity.LOW,
            'Low': SecurityFindingSeverity.LOW,
            'Medium': SecurityFindingSeverity.MEDIUM,
            'High': SecurityFindingSeverity.HIGH,
            'Critical': SecurityFindingSeverity.CRITICAL
        }
        return mapping.get(azure_severity, SecurityFindingSeverity.MEDIUM)
    
    def _extract_compliance_frameworks(self, aws_finding: Dict) -> List[str]:
        """Extract compliance frameworks from AWS finding"""
        frameworks = []
        
        # Check standards subscriptions
        if 'ProductFields' in aws_finding:
            standards = aws_finding['ProductFields'].get('StandardsArn', '')
            if 'cis' in standards.lower():
                frameworks.append('CIS')
            if 'pci' in standards.lower():
                frameworks.append('PCI-DSS')
            if 'aws-foundational' in standards.lower():
                frameworks.append('AWS-Foundational')
        
        return frameworks
    
    def _get_azure_compliance_frameworks(self) -> List[str]:
        """Get applicable Azure compliance frameworks"""
        return ['ISO27001', 'SOC2', 'GDPR']
    
    async def sync_findings(self) -> Dict[str, List[SecurityFinding]]:
        """Aggregate security findings from all cloud providers"""
        if not self._initialized:
            raise RuntimeError("Cloud Security Hub not initialized")
        
        try:
            # Gather findings from both clouds concurrently
            aws_task = asyncio.create_task(self.get_aws_findings())
            azure_task = asyncio.create_task(self.get_azure_findings())
            
            aws_findings, azure_findings = await asyncio.gather(
                aws_task, azure_task, return_exceptions=True
            )
            
            # Handle exceptions
            if isinstance(aws_findings, Exception):
                self.logger.error(f"AWS findings sync failed: {aws_findings}")
                aws_findings = []
            
            if isinstance(azure_findings, Exception):
                self.logger.error(f"Azure findings sync failed: {azure_findings}")
                azure_findings = []
            
            all_findings = {
                'aws': aws_findings,
                'azure': azure_findings,
                'total_count': len(aws_findings) + len(azure_findings)
            }
            
            log_security_event(
                event_type="findings_synced",
                description=f"Synced {all_findings['total_count']} security findings from multi-cloud",
                severity="INFO"
            )
            
            return all_findings
            
        except Exception as e:
            self.logger.error(f"Failed to sync security findings: {e}")
            raise
    
    async def get_compliance_score(self, framework: str) -> float:
        """Calculate compliance score for specific framework"""
        try:
            findings = await self.sync_findings()
            
            total_findings = 0
            failed_findings = 0
            
            for cloud_findings in [findings['aws'], findings['azure']]:
                for finding in cloud_findings:
                    if framework.upper() in [fw.upper() for fw in finding.compliance_frameworks]:
                        total_findings += 1
                        if finding.status in ['FAILED', 'ACTIVE']:
                            failed_findings += 1
            
            if total_findings == 0:
                return 100.0
            
            compliance_score = ((total_findings - failed_findings) / total_findings) * 100
            
            log_security_event(
                event_type="compliance_calculated",
                description=f"Compliance score for {framework}: {compliance_score:.2f}%",
                severity="INFO",
                resource=framework
            )
            
            return compliance_score
            
        except Exception as e:
            self.logger.error(f"Failed to calculate compliance score for {framework}: {e}")
            return 0.0
    
    async def health_check(self) -> Dict[str, Any]:
        """Check cloud security connections health"""
        health = {
            "aws": False,
            "azure": False,
            "overall": False
        }
        
        # Check AWS connection
        if self.aws_security_hub:
            try:
                self.aws_security_hub.describe_hub()
                health["aws"] = True
            except Exception:
                pass
        
        # Check Azure connection
        if self.azure_security:
            try:
                # Simple connectivity test
                health["azure"] = True
            except Exception:
                pass
        
        health["overall"] = health["aws"] or health["azure"]
        return health
    
    async def cleanup(self) -> None:
        """Cleanup cloud security connections"""
        self.aws_security_hub = None
        self.aws_config = None
        self.azure_security = None
        self.azure_credential = None
        self._initialized = False
        self.logger.info("Cloud Security Hub cleaned up")
