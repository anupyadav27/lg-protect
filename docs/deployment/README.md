# Deployment Guide

Complete guide for deploying LG-Protect in various environments.

## 🚀 Quick Deployment Options

### 1. Local Development (5 minutes)
```bash
git clone https://github.com/anupyadav27/lg-protect.git
cd lg-protect
docker-compose up -d
```

### 2. Production Docker (15 minutes)
```bash
./infrastructure/docker-compose/deploy-microservices.sh --production
```

### 3. Kubernetes (30 minutes)
```bash
kubectl apply -f infrastructure/kubernetes/
```

## 🏢 Deployment Environments

### Local Development
**Purpose**: Development and testing
**Requirements**: Docker Desktop, 8GB RAM
**Services**: All services with development tools

### Staging
**Purpose**: Pre-production testing
**Requirements**: Cloud infrastructure, load balancing
**Services**: Production-like with relaxed security

### Production
**Purpose**: Live enterprise deployment
**Requirements**: High availability, monitoring, backup
**Services**: Full security, scaling, and observability

## 🐳 Docker Deployment

### Prerequisites
- Docker Engine 20.10+
- Docker Compose 2.0+
- 8GB RAM minimum
- 50GB disk space

### Quick Start
```bash
# Clone repository
git clone https://github.com/anupyadav27/lg-protect.git
cd lg-protect

# Start all services
docker-compose -f infrastructure/docker-compose/docker-compose.yml up -d

# Verify deployment
curl http://localhost:8000/health
```

### Service URLs
- **API Gateway**: http://localhost:8000
- **Inventory Service**: http://localhost:3000
- **Compliance Service**: http://localhost:3001
- **Data Security**: http://localhost:3002
- **Redis Commander**: http://localhost:8081
- **Grafana**: http://localhost:3000

### Docker Compose Configuration
```yaml
# infrastructure/docker-compose/docker-compose.yml
version: '3.8'
services:
  api-gateway:
    build: ../../backend/api-gateway
    ports: ["8000:8000"]
    environment:
      - REDIS_URL=redis://redis:6379
      - DATABASE_URL=dynamodb://dynamodb-local:8000
    depends_on: [redis, dynamodb-local]

  inventory-service:
    build: ../../backend/services/inventory-service
    ports: ["3000:3000"]
    environment:
      - REDIS_URL=redis://redis:6379
      - AWS_DEFAULT_REGION=us-east-1
    volumes:
      - aws-credentials:/root/.aws
```

### Environment Variables
```bash
# AWS Configuration
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_DEFAULT_REGION=us-east-1

# Service Configuration
REDIS_URL=redis://redis:6379
DATABASE_URL=dynamodb://dynamodb-local:8000
LOG_LEVEL=INFO

# Security
JWT_SECRET=your_jwt_secret
API_KEY_SECRET=your_api_key_secret
```

## ☸️ Kubernetes Deployment

### Prerequisites
- Kubernetes 1.21+
- kubectl configured
- Helm 3.0+ (optional)
- Ingress controller
- Persistent storage

### Deployment Steps
```bash
# Apply namespace
kubectl create namespace lg-protect

# Apply ConfigMaps and Secrets
kubectl apply -f infrastructure/kubernetes/config/

# Deploy services
kubectl apply -f infrastructure/kubernetes/services/

# Deploy ingress
kubectl apply -f infrastructure/kubernetes/ingress/

# Verify deployment
kubectl get pods -n lg-protect
```

### Service Deployment
```yaml
# infrastructure/kubernetes/services/inventory-service.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: inventory-service
  namespace: lg-protect
spec:
  replicas: 3
  selector:
    matchLabels:
      app: inventory-service
  template:
    metadata:
      labels:
        app: inventory-service
    spec:
      containers:
      - name: inventory-service
        image: lg-protect/inventory-service:latest
        ports:
        - containerPort: 3000
        env:
        - name: REDIS_URL
          value: "redis://redis:6379"
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
```

### Ingress Configuration
```yaml
# infrastructure/kubernetes/ingress/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: lg-protect-ingress
  namespace: lg-protect
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - api.lg-protect.com
    secretName: lg-protect-tls
  rules:
  - host: api.lg-protect.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: api-gateway
            port:
              number: 8000
```

### Autoscaling
```yaml
# infrastructure/kubernetes/autoscaling/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: inventory-service-hpa
  namespace: lg-protect
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: inventory-service
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

## ☁️ Cloud Provider Deployment

### AWS EKS
```bash
# Create EKS cluster
eksctl create cluster --name lg-protect --region us-east-1 --nodes 3

# Deploy LG-Protect
kubectl apply -f infrastructure/kubernetes/aws/

# Configure AWS Load Balancer Controller
kubectl apply -f infrastructure/kubernetes/aws/alb-controller.yaml
```

### Google GKE
```bash
# Create GKE cluster
gcloud container clusters create lg-protect --num-nodes=3 --zone=us-central1-a

# Deploy LG-Protect
kubectl apply -f infrastructure/kubernetes/gcp/

# Configure GCP Load Balancer
kubectl apply -f infrastructure/kubernetes/gcp/glb-config.yaml
```

### Azure AKS
```bash
# Create AKS cluster
az aks create --resource-group lg-protect --name lg-protect --node-count 3

# Deploy LG-Protect
kubectl apply -f infrastructure/kubernetes/azure/

# Configure Azure Application Gateway
kubectl apply -f infrastructure/kubernetes/azure/agw-config.yaml
```

## 🔧 Configuration Management

### Environment-Specific Configs
```bash
# Development
cp config/development.env .env

# Staging
cp config/staging.env .env

# Production
cp config/production.env .env
```

### Secret Management
```bash
# Kubernetes Secrets
kubectl create secret generic lg-protect-secrets \
  --from-literal=aws-access-key-id=$AWS_ACCESS_KEY_ID \
  --from-literal=aws-secret-access-key=$AWS_SECRET_ACCESS_KEY \
  --from-literal=jwt-secret=$JWT_SECRET

# AWS Secrets Manager
aws secretsmanager create-secret \
  --name lg-protect/production \
  --secret-string file://secrets.json
```

### Database Migration
```bash
# DynamoDB table creation
python scripts/create_dynamodb_tables.py --environment production

# Data migration
python scripts/migrate_data.py --from development --to production
```

## 📊 Monitoring & Observability

### Prometheus Configuration
```yaml
# infrastructure/monitoring/prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'lg-protect-services'
    static_configs:
      - targets: 
        - 'api-gateway:8000'
        - 'inventory-service:3000'
        - 'compliance-service:3001'
```

### Grafana Dashboards
```bash
# Import dashboards
curl -X POST http://admin:admin@localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @infrastructure/monitoring/grafana/lg-protect-dashboard.json
```

### Log Aggregation
```yaml
# infrastructure/logging/fluentd.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluentd-config
data:
  fluent.conf: |
    <source>
      @type tail
      path /var/log/containers/lg-protect*.log
      pos_file /var/log/fluentd-containers.log.pos
      tag kubernetes.*
      format json
    </source>
```

## 🔒 Security Configuration

### TLS/SSL Setup
```bash
# Generate certificates with cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.8.0/cert-manager.yaml

# Create ClusterIssuer
kubectl apply -f infrastructure/security/cluster-issuer.yaml
```

### Network Security
```yaml
# infrastructure/security/network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: lg-protect-network-policy
spec:
  podSelector:
    matchLabels:
      app: lg-protect
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          role: api-gateway
```

### RBAC Configuration
```yaml
# infrastructure/security/rbac.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: lg-protect-role
rules:
- apiGroups: [""]
  resources: ["pods", "services"]
  verbs: ["get", "list", "watch"]
```

## 🚀 Production Checklist

### Pre-Deployment
- [ ] AWS credentials configured
- [ ] Domain name and SSL certificates ready
- [ ] Database backup strategy implemented
- [ ] Monitoring and alerting configured
- [ ] Load testing completed
- [ ] Security scanning passed

### Post-Deployment
- [ ] Health checks passing
- [ ] Monitoring dashboards operational
- [ ] Log aggregation working
- [ ] Backup and restore tested
- [ ] Incident response procedures documented
- [ ] Team training completed

### Performance Tuning
- [ ] Resource limits optimized
- [ ] Database indexes created
- [ ] Cache configuration tuned
- [ ] CDN configured (if applicable)
- [ ] Auto-scaling policies set

## 🔄 Maintenance & Updates

### Rolling Updates
```bash
# Kubernetes rolling update
kubectl set image deployment/inventory-service \
  inventory-service=lg-protect/inventory-service:v2.0.0

# Docker Compose update
docker-compose pull
docker-compose up -d
```

### Backup Procedures
```bash
# Database backup
aws dynamodb scan --table-name lg-protect-scans > backup-scans.json

# Configuration backup
kubectl get configmaps -o yaml > configmaps-backup.yaml
```

### Health Monitoring
```bash
# Automated health checks
curl -f http://localhost:8000/health || exit 1

# Service-specific health
curl -f http://localhost:3000/api/health/inventory || exit 1
```

## 🆘 Troubleshooting

### Common Issues

#### Services Not Starting
```bash
# Check service logs
docker-compose logs inventory-service

# Check Kubernetes events
kubectl describe pod inventory-service-xxx
```

#### Database Connection Issues
```bash
# Test DynamoDB connectivity
aws dynamodb list-tables --endpoint-url http://localhost:8000

# Check Redis connectivity
redis-cli -h localhost ping
```

#### Performance Issues
```bash
# Monitor resource usage
docker stats

# Check Kubernetes metrics
kubectl top pods
```

### Recovery Procedures
```bash
# Restart all services
docker-compose restart

# Kubernetes pod restart
kubectl delete pod -l app=inventory-service
```

---

*For specific deployment scenarios, see the infrastructure directory and consult the [Architecture Guide](../architecture/README.md)*