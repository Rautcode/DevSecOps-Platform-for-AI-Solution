<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

# DevSecOps Platform for AI Solutions - Copilot Instructions

## Project Overview
This is a comprehensive DevSecOps platform specifically designed for AI solutions, integrating:
- HashiCorp Vault for secrets management
- AWS Security Hub for cloud security monitoring
- Azure Security Center for multi-cloud security
- Python-based automation and policy enforcement

## Code Style Guidelines
- Use async/await patterns for all I/O operations
- Implement comprehensive error handling with structured logging
- Follow security best practices (input validation, encryption, least privilege)
- Use type hints and dataclasses for better code clarity
- Implement dependency injection for testability

## Security Considerations 
- Always validate and sanitize inputs
- Use secrets management (Vault) for all sensitive data
- Implement proper authentication and authorization
- Log security events with correlation IDs
- Follow zero-trust architecture principles

## Performance Guidelines
- Target 40% improvement in incident response time
- Use async operations for concurrent processing
- Implement caching where appropriate
- Optimize database queries and API calls
- Use connection pooling for external services

## Architecture Patterns
- Use factory patterns for cloud provider integrations
- Implement observer pattern for real-time monitoring
- Use command pattern for policy enforcement actions
- Apply strategy pattern for different compliance frameworks

## Testing Standards
- Write unit tests for all business logic
- Include integration tests for external services
- Mock external dependencies in tests
- Achieve minimum 80% code coverage
- Include security-focused test cases

## Documentation Requirements
- Document all public APIs with docstrings
- Include usage examples for complex functions
- Maintain up-to-date configuration documentation
- Document security policies and procedures
