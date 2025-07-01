"""
FastAPI Routes for DevSecOps Dashboard
Real-time security monitoring and compliance dashboard
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.responses import HTMLResponse

from ..core.config import Settings
from ..monitoring.metrics import get_metrics_instance
from ..integrations.vault_manager import VaultManager
from ..integrations.cloud_security_hub import CloudSecurityHub
from ..policies.policy_engine import PolicyEngine


router = APIRouter()
logger = logging.getLogger(__name__)

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                # Remove disconnected clients
                self.active_connections.remove(connection)


manager = ConnectionManager()


# Dependency injection
async def get_vault_manager():
    # In a real app, this would come from dependency injection
    vault_manager = VaultManager()
    if not vault_manager._initialized:
        await vault_manager.initialize()
    return vault_manager


async def get_cloud_security_hub():
    cloud_hub = CloudSecurityHub()
    if not cloud_hub._initialized:
        await cloud_hub.initialize()
    return cloud_hub


async def get_policy_engine():
    policy_engine = PolicyEngine()
    if not policy_engine._initialized:
        await policy_engine.initialize()
    return policy_engine


@router.get("/", response_class=HTMLResponse)
async def dashboard_home():
    """Serve the main dashboard HTML"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>DevSecOps Platform for AI Solutions</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 20px;
                background-color: #f5f5f5;
            }
            .container {
                max-width: 1400px;
                margin: 0 auto;
            }
            .header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 20px;
                border-radius: 10px;
                margin-bottom: 20px;
                text-align: center;
            }
            .metrics-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 20px;
                margin-bottom: 20px;
            }
            .metric-card {
                background: white;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            .metric-value {
                font-size: 2em;
                font-weight: bold;
                color: #667eea;
            }
            .metric-label {
                color: #666;
                margin-top: 5px;
            }
            .status-indicator {
                display: inline-block;
                width: 12px;
                height: 12px;
                border-radius: 50%;
                margin-right: 8px;
            }
            .status-healthy { background-color: #4CAF50; }
            .status-warning { background-color: #FF9800; }
            .status-critical { background-color: #f44336; }
            .real-time-data {
                background: white;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                height: 400px;
                overflow-y: auto;
            }
            .log-entry {
                padding: 8px;
                margin: 4px 0;
                border-radius: 4px;
                font-family: monospace;
                font-size: 0.9em;
            }
            .log-info { background-color: #e3f2fd; }
            .log-warning { background-color: #fff3e0; }
            .log-error { background-color: #ffebee; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ DevSecOps Platform for AI Solutions</h1>
                <p>Real-time Security Monitoring & Compliance Dashboard</p>
            </div>
            
            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-value" id="response-time">--</div>
                    <div class="metric-label">Average Response Time (seconds)</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" id="improvement">--</div>
                    <div class="metric-label">Response Time Improvement (%)</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" id="violations">--</div>
                    <div class="metric-label">Active Policy Violations</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" id="compliance">--</div>
                    <div class="metric-label">Average Compliance Score (%)</div>
                </div>
            </div>
            
            <div class="metrics-grid">
                <div class="metric-card">
                    <h3>System Health</h3>
                    <div id="health-status">
                        <div><span class="status-indicator status-healthy"></span>Vault Manager</div>
                        <div><span class="status-indicator status-healthy"></span>Cloud Security Hub</div>
                        <div><span class="status-indicator status-healthy"></span>Policy Engine</div>
                    </div>
                </div>
                <div class="metric-card">
                    <h3>Security Events (Last 24h)</h3>
                    <div id="security-events">
                        <div>Policy Violations: <span id="policy-violations">0</span></div>
                        <div>Cloud Findings: <span id="cloud-findings">0</span></div>
                        <div>Secret Rotations: <span id="secret-rotations">0</span></div>
                    </div>
                </div>
            </div>
            
            <div class="real-time-data">
                <h3>Real-time Security Events</h3>
                <div id="event-log"></div>
            </div>
        </div>
        
        <script>
            const ws = new WebSocket(`ws://localhost:8000/api/v1/ws/metrics`);
            
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                updateDashboard(data);
            };
            
            function updateDashboard(data) {
                // Update metrics
                if (data.policy_metrics) {
                    document.getElementById('response-time').textContent = 
                        data.policy_metrics.avg_response_time_seconds?.toFixed(2) || '--';
                    document.getElementById('improvement').textContent = 
                        data.policy_metrics.response_time_improvement_percent?.toFixed(1) || '--';
                    document.getElementById('violations').textContent = 
                        data.policy_metrics.active_violations || '--';
                }
                
                if (data.compliance_scores) {
                    const avgCompliance = Object.values(data.compliance_scores)
                        .reduce((a, b) => a + b, 0) / Object.keys(data.compliance_scores).length;
                    document.getElementById('compliance').textContent = avgCompliance.toFixed(1);
                }
                
                // Update security events
                if (data.security_events) {
                    document.getElementById('policy-violations').textContent = 
                        data.security_events.policy_violations || 0;
                    document.getElementById('cloud-findings').textContent = 
                        data.security_events.cloud_findings || 0;
                    document.getElementById('secret-rotations').textContent = 
                        data.security_events.secret_rotations || 0;
                }
                
                // Add real-time event log
                if (data.event) {
                    addLogEntry(data.event);
                }
            }
            
            function addLogEntry(event) {
                const logDiv = document.getElementById('event-log');
                const entry = document.createElement('div');
                entry.className = `log-entry log-${event.severity.toLowerCase()}`;
                entry.innerHTML = `[${new Date().toLocaleTimeString()}] ${event.description}`;
                logDiv.insertBefore(entry, logDiv.firstChild);
                
                // Keep only last 50 entries
                while (logDiv.children.length > 50) {
                    logDiv.removeChild(logDiv.lastChild);
                }
            }
            
            // Initialize dashboard
            fetch('/api/v1/dashboard/metrics')
                .then(response => response.json())
                .then(data => updateDashboard(data));
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@router.get("/metrics")
async def get_dashboard_metrics(
    vault_manager: VaultManager = Depends(get_vault_manager),
    cloud_hub: CloudSecurityHub = Depends(get_cloud_security_hub),
    policy_engine: PolicyEngine = Depends(get_policy_engine)
):
    """Get comprehensive dashboard metrics"""
    try:
        # Get metrics from all components
        policy_metrics = await policy_engine.get_policy_metrics()
        vault_health = await vault_manager.health_check()
        cloud_health = await cloud_hub.health_check()
        
        # Get compliance scores
        compliance_scores = {}
        for framework in ["SOC2", "ISO27001", "GDPR"]:
            score = await cloud_hub.get_compliance_score(framework)
            compliance_scores[framework] = score
        
        # Get recent security findings
        recent_findings = await cloud_hub.sync_findings()
        
        metrics_instance = get_metrics_instance()
        security_events = metrics_instance.get_metrics_summary()
        
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "policy_metrics": policy_metrics,
            "compliance_scores": compliance_scores,
            "health_status": {
                "vault": vault_health,
                "cloud_security": cloud_health,
                "policy_engine": await policy_engine.health_check()
            },
            "security_findings": {
                "total": recent_findings.get('total_count', 0),
                "aws": len(recent_findings.get('aws', [])),
                "azure": len(recent_findings.get('azure', []))
            },
            "security_events": security_events
        }
        
    except Exception as e:
        logger.error(f"Failed to get dashboard metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/compliance/{framework}")
async def get_compliance_details(
    framework: str,
    cloud_hub: CloudSecurityHub = Depends(get_cloud_security_hub)
):
    """Get detailed compliance information for a specific framework"""
    try:
        score = await cloud_hub.get_compliance_score(framework)
        findings = await cloud_hub.sync_findings()
        
        # Filter findings by compliance framework
        framework_findings = []
        for cloud_findings in [findings.get('aws', []), findings.get('azure', [])]:
            for finding in cloud_findings:
                if framework.upper() in [fw.upper() for fw in finding.compliance_frameworks]:
                    framework_findings.append({
                        "id": finding.id,
                        "title": finding.title,
                        "severity": finding.severity.value,
                        "resource": finding.resource,
                        "source": finding.source,
                        "status": finding.status
                    })
        
        return {
            "framework": framework,
            "compliance_score": score,
            "total_findings": len(framework_findings),
            "findings": framework_findings[:20]  # Limit to 20 most recent
        }
        
    except Exception as e:
        logger.error(f"Failed to get compliance details for {framework}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/violations")
async def get_policy_violations(
    policy_engine: PolicyEngine = Depends(get_policy_engine)
):
    """Get current policy violations"""
    try:
        violations = []
        for violation in policy_engine.violations.values():
            if violation.status == "ACTIVE":
                violations.append({
                    "id": violation.id,
                    "policy_name": violation.policy_name,
                    "severity": violation.severity.value,
                    "resource": violation.resource,
                    "description": violation.description,
                    "detected_at": violation.detected_at.isoformat(),
                    "violated_rules": violation.violated_rules
                })
        
        return {
            "total_violations": len(violations),
            "violations": violations
        }
        
    except Exception as e:
        logger.error(f"Failed to get policy violations: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.websocket("/ws/metrics")
async def websocket_metrics(
    websocket: WebSocket,
    vault_manager: VaultManager = Depends(get_vault_manager),
    cloud_hub: CloudSecurityHub = Depends(get_cloud_security_hub),
    policy_engine: PolicyEngine = Depends(get_policy_engine)
):
    """WebSocket endpoint for real-time metrics"""
    await manager.connect(websocket)
    
    try:
        while True:
            # Send metrics every 30 seconds
            metrics = await get_dashboard_metrics(vault_manager, cloud_hub, policy_engine)
            await websocket.send_text(json.dumps(metrics))
            await asyncio.sleep(30)
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)


@router.post("/test-workload")
async def test_ai_workload(
    workload_data: Dict[str, Any],
    policy_engine: PolicyEngine = Depends(get_policy_engine)
):
    """Test endpoint to evaluate AI workload against policies"""
    try:
        violations = await policy_engine.evaluate_ai_workload(workload_data)
        
        return {
            "workload_id": workload_data.get('id', 'test'),
            "violations_found": len(violations),
            "violations": [
                {
                    "policy_name": v.policy_name,
                    "severity": v.severity.value,
                    "description": v.description,
                    "violated_rules": v.violated_rules
                }
                for v in violations
            ]
        }
        
    except Exception as e:
        logger.error(f"Failed to evaluate test workload: {e}")
        raise HTTPException(status_code=500, detail=str(e))
