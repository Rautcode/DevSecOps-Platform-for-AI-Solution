"""
Role-Based Access Control (RBAC) System
Advanced permission management for DevSecOps Platform
"""

from typing import Dict, List, Set, Optional, Any
from enum import Enum
from dataclasses import dataclass, field

from .models import UserRole, Permission


@dataclass
class Role:
    """Role definition with permissions"""
    name: str
    description: str
    permissions: Set[Permission] = field(default_factory=set)
    inherits_from: Optional[str] = None
    is_system_role: bool = False
    
    def add_permission(self, permission: Permission) -> None:
        """Add permission to role"""
        self.permissions.add(permission)
    
    def remove_permission(self, permission: Permission) -> None:
        """Remove permission from role"""
        self.permissions.discard(permission)
    
    def has_permission(self, permission: Permission) -> bool:
        """Check if role has specific permission"""
        return permission in self.permissions


class RBACManager:
    """
    Role-Based Access Control Manager
    Manages roles, permissions, and access control policies
    """
    
    def __init__(self):
        self.roles: Dict[str, Role] = {}
        self.user_roles: Dict[int, UserRole] = {}
        self.permission_cache: Dict[str, Set[Permission]] = {}
        self._initialize_default_roles()
    
    def _initialize_default_roles(self) -> None:
        """Initialize default system roles with permissions"""
        
        # Viewer Role - Read-only access
        viewer_role = Role(
            name=UserRole.VIEWER.value,
            description="Read-only access to dashboards and reports",
            is_system_role=True
        )
        viewer_role.permissions.update([
            Permission.READ_POLICY,
            Permission.READ_SECURITY_EVENTS,
            Permission.READ_CLOUD_SECURITY,
            Permission.READ_COMPLIANCE,
        ])
        self.roles[UserRole.VIEWER.value] = viewer_role
        
        # AI Engineer Role - AI/ML specific permissions
        ai_engineer_role = Role(
            name=UserRole.AI_ENGINEER.value,
            description="AI/ML model scanning and policy management",
            inherits_from=UserRole.VIEWER.value,
            is_system_role=True
        )
        ai_engineer_role.permissions.update([
            Permission.SCAN_AI_MODELS,
            Permission.MANAGE_AI_POLICIES,
            Permission.READ_SECRETS,
            Permission.CREATE_POLICY,
            Permission.UPDATE_POLICY,
        ])
        self.roles[UserRole.AI_ENGINEER.value] = ai_engineer_role
        
        # Security Analyst Role - Security monitoring and analysis
        security_analyst_role = Role(
            name=UserRole.SECURITY_ANALYST.value,
            description="Security event monitoring and incident response",
            inherits_from=UserRole.VIEWER.value,
            is_system_role=True
        )
        security_analyst_role.permissions.update([
            Permission.CREATE_SECURITY_EVENTS,
            Permission.MANAGE_ALERTS,
            Permission.READ_CLOUD_SECURITY,
            Permission.MANAGE_CLOUD_SECURITY,
            Permission.EXECUTE_POLICY,
            Permission.SCAN_AI_MODELS,
        ])
        self.roles[UserRole.SECURITY_ANALYST.value] = security_analyst_role
        
        # Policy Manager Role - Policy creation and management
        policy_manager_role = Role(
            name=UserRole.POLICY_MANAGER.value,
            description="Policy creation, modification, and enforcement",
            inherits_from=UserRole.SECURITY_ANALYST.value,
            is_system_role=True
        )
        policy_manager_role.permissions.update([
            Permission.CREATE_POLICY,
            Permission.UPDATE_POLICY,
            Permission.DELETE_POLICY,
            Permission.EXECUTE_POLICY,
            Permission.MANAGE_AI_POLICIES,
            Permission.WRITE_SECRETS,
        ])
        self.roles[UserRole.POLICY_MANAGER.value] = policy_manager_role
        
        # Compliance Officer Role - Compliance and audit management
        compliance_officer_role = Role(
            name=UserRole.COMPLIANCE_OFFICER.value,
            description="Compliance monitoring and audit management",
            inherits_from=UserRole.VIEWER.value,
            is_system_role=True
        )
        compliance_officer_role.permissions.update([
            Permission.READ_COMPLIANCE,
            Permission.MANAGE_COMPLIANCE,
            Permission.GENERATE_REPORTS,
            Permission.VIEW_AUDIT_LOGS,
            Permission.READ_SECURITY_EVENTS,
        ])
        self.roles[UserRole.COMPLIANCE_OFFICER.value] = compliance_officer_role
        
        # Auditor Role - Audit and monitoring access
        auditor_role = Role(
            name=UserRole.AUDITOR.value,
            description="Audit access with read-only permissions",
            inherits_from=UserRole.VIEWER.value,
            is_system_role=True
        )
        auditor_role.permissions.update([
            Permission.VIEW_AUDIT_LOGS,
            Permission.READ_COMPLIANCE,
            Permission.GENERATE_REPORTS,
            Permission.READ_CLOUD_SECURITY,
        ])
        self.roles[UserRole.AUDITOR.value] = auditor_role
        
        # Admin Role - Full system access
        admin_role = Role(
            name=UserRole.ADMIN.value,
            description="Full administrative access to all system features",
            is_system_role=True
        )
        # Admin gets all permissions
        admin_role.permissions.update(list(Permission))
        self.roles[UserRole.ADMIN.value] = admin_role
        
        # Build permission cache
        self._build_permission_cache()
    
    def _build_permission_cache(self) -> None:
        """Build permission cache with inheritance"""
        self.permission_cache.clear()
        
        for role_name, role in self.roles.items():
            all_permissions = set(role.permissions)
            
            # Add inherited permissions
            if role.inherits_from and role.inherits_from in self.roles:
                parent_permissions = self.get_role_permissions(role.inherits_from)
                all_permissions.update(parent_permissions)
            
            self.permission_cache[role_name] = all_permissions
    
    def get_role(self, role_name: str) -> Optional[Role]:
        """Get role by name"""
        return self.roles.get(role_name)
    
    def get_role_permissions(self, role_name: str) -> Set[Permission]:
        """Get all permissions for a role (including inherited)"""
        if role_name in self.permission_cache:
            return self.permission_cache[role_name].copy()
        
        role = self.get_role(role_name)
        if not role:
            return set()
        
        permissions = set(role.permissions)
        
        # Add inherited permissions
        if role.inherits_from and role.inherits_from in self.roles:
            parent_permissions = self.get_role_permissions(role.inherits_from)
            permissions.update(parent_permissions)
        
        return permissions
    
    def user_has_permission(self, user_role: UserRole, permission: Permission) -> bool:
        """Check if user role has specific permission"""
        role_permissions = self.get_role_permissions(user_role.value)
        return permission in role_permissions
    
    def user_has_any_permission(self, user_role: UserRole, permissions: List[Permission]) -> bool:
        """Check if user role has any of the specified permissions"""
        role_permissions = self.get_role_permissions(user_role.value)
        return any(perm in role_permissions for perm in permissions)
    
    def user_has_all_permissions(self, user_role: UserRole, permissions: List[Permission]) -> bool:
        """Check if user role has all specified permissions"""
        role_permissions = self.get_role_permissions(user_role.value)
        return all(perm in role_permissions for perm in permissions)
    
    def create_custom_role(
        self, 
        name: str, 
        description: str, 
        permissions: List[Permission],
        inherits_from: Optional[str] = None
    ) -> Role:
        """Create a custom role"""
        if name in self.roles:
            raise ValueError(f"Role '{name}' already exists")
        
        role = Role(
            name=name,
            description=description,
            permissions=set(permissions),
            inherits_from=inherits_from,
            is_system_role=False
        )
        
        self.roles[name] = role
        self._build_permission_cache()
        return role
    
    def update_role_permissions(self, role_name: str, permissions: List[Permission]) -> bool:
        """Update role permissions"""
        role = self.get_role(role_name)
        if not role or role.is_system_role:
            return False
        
        role.permissions = set(permissions)
        self._build_permission_cache()
        return True
    
    def delete_custom_role(self, role_name: str) -> bool:
        """Delete a custom role"""
        role = self.get_role(role_name)
        if not role or role.is_system_role:
            return False
        
        del self.roles[role_name]
        self._build_permission_cache()
        return True
    
    def get_user_permissions(self, user_role: UserRole) -> Set[Permission]:
        """Get all permissions for a user"""
        return self.get_role_permissions(user_role.value)
    
    def can_access_resource(
        self, 
        user_role: UserRole, 
        resource_type: str, 
        action: str
    ) -> bool:
        """
        Check if user can access a specific resource with an action
        
        Args:
            user_role: User's role
            resource_type: Type of resource (e.g., 'policy', 'user', 'vault')
            action: Action to perform (e.g., 'read', 'write', 'delete')
            
        Returns:
            True if access is allowed
        """
        # Map resource types and actions to permissions
        permission_map = {
            ('user', 'read'): Permission.READ_USER,
            ('user', 'create'): Permission.CREATE_USER,
            ('user', 'update'): Permission.UPDATE_USER,
            ('user', 'delete'): Permission.DELETE_USER,
            
            ('policy', 'read'): Permission.READ_POLICY,
            ('policy', 'create'): Permission.CREATE_POLICY,
            ('policy', 'update'): Permission.UPDATE_POLICY,
            ('policy', 'delete'): Permission.DELETE_POLICY,
            ('policy', 'execute'): Permission.EXECUTE_POLICY,
            
            ('vault', 'read'): Permission.READ_SECRETS,
            ('vault', 'write'): Permission.WRITE_SECRETS,
            ('vault', 'manage'): Permission.MANAGE_VAULT,
            
            ('security', 'read'): Permission.READ_SECURITY_EVENTS,
            ('security', 'create'): Permission.CREATE_SECURITY_EVENTS,
            ('security', 'manage'): Permission.MANAGE_ALERTS,
            
            ('cloud', 'read'): Permission.READ_CLOUD_SECURITY,
            ('cloud', 'manage'): Permission.MANAGE_CLOUD_SECURITY,
            
            ('compliance', 'read'): Permission.READ_COMPLIANCE,
            ('compliance', 'manage'): Permission.MANAGE_COMPLIANCE,
            ('compliance', 'report'): Permission.GENERATE_REPORTS,
            
            ('ai', 'scan'): Permission.SCAN_AI_MODELS,
            ('ai', 'manage'): Permission.MANAGE_AI_POLICIES,
            
            ('system', 'manage'): Permission.MANAGE_SYSTEM,
            ('audit', 'read'): Permission.VIEW_AUDIT_LOGS,
        }
        
        required_permission = permission_map.get((resource_type, action))
        if not required_permission:
            return False
        
        return self.user_has_permission(user_role, required_permission)
    
    def get_accessible_resources(self, user_role: UserRole) -> Dict[str, List[str]]:
        """
        Get all resources and actions accessible to a user role
        
        Returns:
            Dictionary mapping resource types to allowed actions
        """
        user_permissions = self.get_user_permissions(user_role)
        accessible = {}
        
        # Resource action mapping
        resource_actions = {
            'user': {
                Permission.READ_USER: 'read',
                Permission.CREATE_USER: 'create',
                Permission.UPDATE_USER: 'update',
                Permission.DELETE_USER: 'delete',
            },
            'policy': {
                Permission.READ_POLICY: 'read',
                Permission.CREATE_POLICY: 'create',
                Permission.UPDATE_POLICY: 'update',
                Permission.DELETE_POLICY: 'delete',
                Permission.EXECUTE_POLICY: 'execute',
            },
            'vault': {
                Permission.READ_SECRETS: 'read',
                Permission.WRITE_SECRETS: 'write',
                Permission.MANAGE_VAULT: 'manage',
            },
            'security': {
                Permission.READ_SECURITY_EVENTS: 'read',
                Permission.CREATE_SECURITY_EVENTS: 'create',
                Permission.MANAGE_ALERTS: 'manage',
            },
            'cloud': {
                Permission.READ_CLOUD_SECURITY: 'read',
                Permission.MANAGE_CLOUD_SECURITY: 'manage',
            },
            'compliance': {
                Permission.READ_COMPLIANCE: 'read',
                Permission.MANAGE_COMPLIANCE: 'manage',
                Permission.GENERATE_REPORTS: 'report',
            },
            'ai': {
                Permission.SCAN_AI_MODELS: 'scan',
                Permission.MANAGE_AI_POLICIES: 'manage',
            },
            'system': {
                Permission.MANAGE_SYSTEM: 'manage',
            },
            'audit': {
                Permission.VIEW_AUDIT_LOGS: 'read',
            },
        }
        
        for resource_type, perm_action_map in resource_actions.items():
            actions = []
            for permission, action in perm_action_map.items():
                if permission in user_permissions:
                    actions.append(action)
            
            if actions:
                accessible[resource_type] = actions
        
        return accessible
    
    def validate_role_hierarchy(self) -> bool:
        """Validate role inheritance hierarchy for cycles"""
        visited = set()
        rec_stack = set()
        
        def has_cycle(role_name: str) -> bool:
            if role_name in rec_stack:
                return True
            if role_name in visited:
                return False
            
            visited.add(role_name)
            rec_stack.add(role_name)
            
            role = self.get_role(role_name)
            if role and role.inherits_from:
                if has_cycle(role.inherits_from):
                    return True
            
            rec_stack.remove(role_name)
            return False
        
        for role_name in self.roles:
            if role_name not in visited:
                if has_cycle(role_name):
                    return False
        
        return True
    
    def get_role_hierarchy(self) -> Dict[str, Any]:
        """Get role hierarchy as nested dictionary"""
        hierarchy = {}
        
        # Find root roles (no inheritance)
        root_roles = [
            role_name for role_name, role in self.roles.items()
            if not role.inherits_from
        ]
        
        def build_hierarchy(role_name: str) -> Dict[str, Any]:
            role = self.get_role(role_name)
            if not role:
                return {}
            
            children = [
                name for name, r in self.roles.items()
                if r.inherits_from == role_name
            ]
            
            return {
                "name": role_name,
                "description": role.description,
                "permissions": list(role.permissions),
                "is_system_role": role.is_system_role,
                "children": [build_hierarchy(child) for child in children]
            }
        
        for root_role in root_roles:
            hierarchy[root_role] = build_hierarchy(root_role)
        
        return hierarchy
