# Production Deployment Guide

## DevSecOps Platform for AI Solutions - Production Ready

This guide covers deploying the DevSecOps Platform for AI Solutions in a production environment with enterprise-grade security, scalability, and monitoring.

## 🚀 Quick Production Start

### Prerequisites

- Docker & Docker Compose
- PostgreSQL database
- HashiCorp Vault (external)
- Redis (optional, for caching)
- SSL certificates
- Production environment variables

### 1. Environment Configuration

```bash
# Copy and customize environment file
cp .env.example .env.production

# Set production values
export APP_ENVIRONMENT=production
export APP_DEBUG=false
export SECURITY_TLS_ENABLED=true
export DB_HOST=your-postgres-host
export VAULT_ADDR=https://your-vault-server
```

### 2. Security Setup

```bash
# Generate secure keys (minimum 32 characters)
export SECURITY_SECRET_KEY=$(openssl rand -hex 32)
export SECURITY_JWT_SECRET=$(openssl rand -hex 32)
export SECURITY_ENCRYPTION_KEY=$(openssl rand -hex 32)

# Set database credentials
export DB_PASSWORD=$(openssl rand -base64 32)
```

### 3. Database Setup

```bash
# Initialize PostgreSQL database
createdb devsecops
psql devsecops < scripts/init-db.sql

# Run migrations
python -m alembic upgrade head
```

### 4. Vault Configuration

```bash
# Initialize Vault policies and secrets
python scripts/vault_setup.py --production
```

### 5. Deploy with Docker

```bash
# Production deployment
docker-compose -f docker-compose.yml up -d

# Or with custom configuration
docker-compose -f docker-compose.prod.yml up -d
```

## 🔒 Security Hardening

### Authentication & Authorization

- **Multi-factor Authentication**: Configure MFA for all admin accounts
- **Role-Based Access Control**: 7 built-in roles with granular permissions
- **Session Management**: Secure JWT tokens with refresh mechanism
- **Account Lockout**: Protection against brute force attacks

### API Security

- **Rate Limiting**: Configurable request limits per user/IP
- **CORS Protection**: Strict origin validation
- **Security Headers**: HSTS, CSP, X-Frame-Options, etc.
- **Input Validation**: Comprehensive request validation

### Data Protection

- **Encryption at Rest**: Database and file encryption
- **Encryption in Transit**: TLS 1.3 for all connections
- **Secret Management**: HashiCorp Vault integration
- **Audit Logging**: Complete audit trail with correlation IDs

## 📊 Monitoring & Observability

### Health Monitoring

```bash
# Health check endpoint
curl https://your-domain/health

# Detailed status (authenticated)
curl -H "Authorization: Bearer $TOKEN" https://your-domain/api/v1/status
```

### Metrics Collection

- **Prometheus**: Application and infrastructure metrics
- **Grafana**: Pre-configured dashboards
- **Custom Metrics**: Policy execution, security events, performance

### Logging

- **Structured Logging**: JSON format with correlation IDs
- **Log Aggregation**: Configurable log shipping
- **Security Events**: Dedicated security event logging

## 🏗️ High Availability Deployment

### Load Balancer Configuration

```nginx
upstream devsecops_backend {
    server app1:8000 max_fails=3 fail_timeout=30s;
    server app2:8000 max_fails=3 fail_timeout=30s;
    server app3:8000 max_fails=3 fail_timeout=30s;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    
    location / {
        proxy_pass http://devsecops_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Database High Availability

```yaml
# PostgreSQL with replication
services:
  postgres-primary:
    image: postgres:15
    environment:
      POSTGRES_REPLICATION_MODE: master
      POSTGRES_REPLICATION_USER: replicator
      POSTGRES_REPLICATION_PASSWORD: repl_password
  
  postgres-replica:
    image: postgres:15
    environment:
      POSTGRES_REPLICATION_MODE: slave
      POSTGRES_MASTER_HOST: postgres-primary
      POSTGRES_REPLICATION_USER: replicator
      POSTGRES_REPLICATION_PASSWORD: repl_password
```

## 🔧 Performance Optimization

### Application Tuning

```bash
# Gunicorn workers (CPU cores * 2 + 1)
GUNICORN_WORKERS=9

# Database connection pooling
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=30

# Redis caching
REDIS_URL=redis://redis-cluster:6379/0
```

### Database Optimization

```sql
-- Create indexes for better performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_auth_sessions_user_id ON auth_sessions(user_id);
```

### Caching Strategy

- **Application Cache**: Redis for session storage
- **Query Cache**: Database query result caching
- **Static Assets**: CDN for static content
- **API Response Cache**: Configurable TTL for API responses

## 🚨 Incident Response

### Automated Alerts

```yaml
# Prometheus alerting rules
groups:
  - name: devsecops.rules
    rules:
      - alert: HighFailedLoginRate
        expr: rate(failed_login_attempts_total[5m]) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: High failed login rate detected
      
      - alert: DatabaseConnectionFailure
        expr: database_connections_failed_total > 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: Database connection failures detected
```

### Emergency Procedures

1. **Security Incident**: Automatic account lockout and alerting
2. **Performance Issues**: Auto-scaling triggers
3. **Data Breach**: Immediate notification and audit log export
4. **Service Outage**: Failover to backup systems

## 📋 Maintenance Tasks

### Regular Maintenance

```bash
# Daily tasks
./scripts/daily_maintenance.sh

# Weekly tasks
./scripts/weekly_maintenance.sh

# Database maintenance
python scripts/db_maintenance.py --vacuum --analyze
```

### Backup Strategy

```bash
# Database backup
pg_dump devsecops | gzip > backups/devsecops_$(date +%Y%m%d_%H%M%S).sql.gz

# Vault backup
vault operator raft snapshot save backup_$(date +%Y%m%d_%H%M%S).snap

# Application data backup
tar -czf app_data_backup_$(date +%Y%m%d_%H%M%S).tar.gz data/ logs/
```

### Security Updates

```bash
# Check for security vulnerabilities
python -m safety check
bandit -r src/

# Update dependencies
pip-audit
docker scout scan
```

## 🔍 Troubleshooting

### Common Issues

#### Authentication Problems
```bash
# Check JWT token validity
python scripts/verify_token.py $TOKEN

# Reset user password
python scripts/reset_password.py --user admin

# Check RBAC permissions
python scripts/check_permissions.py --user $USER --resource $RESOURCE
```

#### Database Issues
```bash
# Check database connectivity
python scripts/db_health_check.py

# Check slow queries
python scripts/analyze_slow_queries.py

# Database migration issues
python -m alembic current
python -m alembic history
```

#### Performance Issues
```bash
# Check application metrics
curl http://localhost:9090/metrics

# Database performance
python scripts/db_performance_check.py

# Memory usage analysis
python scripts/memory_analysis.py
```

### Log Analysis

```bash
# Application logs
tail -f logs/application.log | jq '.'

# Security events
grep "LOGIN_FAILED\|POLICY_VIOLATION" logs/security.log

# Performance metrics
grep "response_time" logs/application.log | jq '.response_time'
```

## 📚 Additional Resources

- [Security Architecture Guide](docs/security-architecture.md)
- [API Documentation](docs/api-reference.md)
- [Monitoring Setup](docs/monitoring-setup.md)
- [Backup & Recovery](docs/backup-recovery.md)
- [Compliance Guide](docs/compliance.md)

## 🆘 Support

For production support:
- Security Issues: security@yourcompany.com
- Technical Support: support@yourcompany.com
- Documentation: docs.yourplatform.com

---

**⚠️ Security Notice**: Always review and customize security configurations for your specific environment. This platform handles sensitive data and requires proper security measures.
