# Frequently Asked Questions (FAQ)

Common questions and answers about LG-Protect platform.

## 🚀 Getting Started

### Q: What is LG-Protect?
**A:** LG-Protect is an enterprise-grade Cloud Security Posture Management (CSPM) platform that provides comprehensive security and compliance monitoring for AWS environments. It discovers resources across 60+ AWS services, validates compliance frameworks, and provides real-time security insights.

### Q: What are the system requirements?
**A:** 
- **Python**: 3.7 or higher
- **Memory**: 4GB RAM minimum (8GB recommended for enterprise)
- **Disk**: 2GB free space
- **AWS**: Valid AWS account with read permissions
- **Docker**: For containerized deployment

### Q: How long does the first scan take?
**A:** Typical scan times:
- **Small environment** (1 account, 2 regions): 2-3 minutes
- **Medium environment** (3 accounts, 5 regions): 5-10 minutes
- **Large enterprise** (10+ accounts, all regions): 15-30 minutes

### Q: What AWS permissions do I need?
**A:** Read-only permissions for the services you want to scan. See the [Getting Started Guide](../getting-started/README.md#required-aws-permissions) for the complete permission list.

## 🔧 Technical Questions

### Q: How does multi-account scanning work?
**A:** LG-Protect supports 4 authentication methods:
1. **AWS CLI Profiles**: Use existing configured profiles
2. **Access Key Pairs**: Direct credentials for each account
3. **Cross-Account IAM Roles**: Secure role assumption with external IDs
4. **Mixed Authentication**: Combination of methods

The EnterpriseAccountManager handles credential management and validates access before scanning.

### Q: Can I scan specific services or regions?
**A:** Yes! You can customize scans by:
```bash
# Scan specific services
python simplified_service_enablement_checker.py --services ec2,s3,iam

# Scan specific regions
python simplified_service_enablement_checker.py --regions us-east-1,us-west-2

# Combine both
python simplified_service_enablement_checker.py --services ec2,s3 --regions us-east-1
```

### Q: How do I handle rate limiting from AWS?
**A:** LG-Protect includes built-in rate limiting protection:
- **Automatic retries** with exponential backoff
- **Configurable worker limits** (default: 15 concurrent workers)
- **Adaptive throttling** based on AWS responses
- **Regional distribution** to spread API calls

### Q: What's the difference between service enablement and resource discovery?
**A:** 
- **Service Enablement**: Whether an AWS service is available/activated in your account
- **Resource Discovery**: Actual resources (EC2 instances, S3 buckets, etc.) found within enabled services

LG-Protect does both - it checks service availability AND discovers actual resources with their identifiers.

## 🏢 Enterprise & Multi-Account

### Q: How do I set up enterprise multi-account scanning?
**A:** Use the interactive enterprise setup:
```bash
python simplified_service_enablement_checker.py --enterprise
```

This guides you through:
- Adding multiple AWS accounts
- Configuring authentication methods
- Setting up cross-account roles
- Customizing scan parameters

### Q: Can I use cross-account IAM roles?
**A:** Yes! Cross-account roles are the recommended approach for enterprise environments:

```python
account_manager.add_account(
    name="audit-account",
    role_arn="arn:aws:iam::123456789:role/LGProtectAuditRole",
    external_id="unique-external-id-12345"
)
```

### Q: How do I manage hundreds of AWS accounts?
**A:** For large-scale deployments:
1. **Use AWS Organizations** with cross-account roles
2. **Implement account discovery** via Organizations API
3. **Use AWS CLI profiles** for batch account setup
4. **Configure credential caching** to reduce API calls
5. **Deploy with Kubernetes** for horizontal scaling

### Q: Can I exclude certain accounts or regions?
**A:** Yes, you can filter at multiple levels:
- **Account filtering**: Skip specific accounts during setup
- **Region filtering**: Exclude regions with no resources
- **Service filtering**: Skip unnecessary services
- **Resource tagging**: Exclude resources by tags (roadmap)

## 📊 Results & Reports

### Q: What output formats are available?
**A:** LG-Protect generates multiple output formats:
- **CSV files**: Excel-compatible for analysis
- **JSON reports**: Machine-readable structured data
- **Summary dashboards**: Executive-level insights
- **Error analysis**: Detailed error categorization

### Q: How do I understand the CSV output?
**A:** The CSV follows a hierarchical structure:
```csv
Account_ID,Account_Name,Region_Type,Region_Name,Service_Name,Service_Enabled,Resource_Count,Resource_Identifiers
123456789,production,Global,global,s3,True,15,bucket1; bucket2; bucket3
```

- **Global services** appear once per account (S3, IAM, CloudFront)
- **Regional services** appear per region (EC2, RDS, Lambda)
- **Resource identifiers** show actual resource names/IDs

### Q: Where are scan results stored?
**A:** Results are organized in timestamped directories:
```
service_enablement_results/
├── scan_20250712_143022/        # Latest scan
│   ├── account_service_inventory_20250712_143022.csv
│   ├── service_enablement_summary_20250712_143022.json
│   └── error_analysis_20250712_143022.json
└── latest_scan -> scan_20250712_143022/  # Convenient symlink
```

### Q: Can I schedule automated scans?
**A:** Currently, you can schedule scans using:
- **Cron jobs** on Linux/macOS
- **Task Scheduler** on Windows
- **Kubernetes CronJobs** for containerized deployments
- **AWS EventBridge** for cloud-native scheduling

Integrated scheduling is on the roadmap for v2.0.

## 🔒 Security & Compliance

### Q: How secure is my AWS credential information?
**A:** LG-Protect follows security best practices:
- **No credential storage**: Credentials are used in-memory only
- **AWS IAM roles**: Temporary credentials with time limits
- **Least privilege**: Only read permissions required
- **Session isolation**: Each account uses isolated sessions
- **Audit logging**: All API calls are logged

### Q: What compliance frameworks are supported?
**A:** Current and planned frameworks:
- ✅ **Custom compliance** via service configuration
- 🔜 **SOC 2 Type II** (in development)
- 🔜 **PCI-DSS v3.2.1** (in development)
- 🔜 **HIPAA Security Rule** (in development)
- 🔜 **CIS Benchmarks** (in development)

### Q: Does LG-Protect modify my AWS resources?
**A:** **No**. LG-Protect is completely read-only. It only uses AWS describe/list APIs to discover resources. It never creates, modifies, or deletes AWS resources.

## 🚨 Troubleshooting

### Q: Why am I getting permission denied errors?
**A:** Common causes and solutions:
1. **Insufficient permissions**: Verify your AWS user/role has the required permissions
2. **Credential issues**: Check `aws sts get-caller-identity` works
3. **Region restrictions**: Some regions require opt-in
4. **Service limits**: Your account may have service quotas

### Q: The scan is taking too long. How do I speed it up?
**A:** Optimization strategies:
```bash
# Reduce concurrent workers
python simplified_service_enablement_checker.py --max-workers 5

# Scan fewer regions
python simplified_service_enablement_checker.py --regions us-east-1,us-west-2

# Skip large services initially
python simplified_service_enablement_checker.py --skip ec2,cloudtrail
```

### Q: Some services show "not enabled" but I know they're enabled. Why?
**A:** Possible reasons:
1. **Service not available in region**: Not all services are in all regions
2. **Different API endpoint**: Service might use different region endpoint
3. **Permission issues**: Missing specific service permissions
4. **Service configuration**: Service enabled but no resources created

### Q: How do I report bugs or request features?
**A:** Multiple ways to get support:
- **GitHub Issues**: For bugs and feature requests
- **Documentation**: Check troubleshooting guides
- **Error logs**: Include error details from the scan results
- **Community**: Join discussions and share experiences

## 🔮 Platform & Roadmap

### Q: What cloud providers are supported?
**A:** Current and planned support:
- ✅ **AWS**: Complete support for 60+ services
- 🔜 **Azure**: Planned for Q4 2025
- 🔜 **Google Cloud**: Planned for Q1 2026
- 🔜 **Multi-cloud**: Unified dashboard for all providers

### Q: Is there a SaaS version available?
**A:** Currently LG-Protect is:
- **Open source**: Available on GitHub
- **Self-hosted**: Deploy in your own environment
- **Enterprise**: Custom deployments and support available

A SaaS version is being evaluated for future release.

### Q: Can I extend LG-Protect with custom services?
**A:** Yes! LG-Protect is designed for extensibility:
- **Custom service mappings**: Add new AWS services
- **Discovery engines**: Create custom resource discovery
- **Output formats**: Extend reporting capabilities
- **API integration**: Connect with existing tools

See the [Developer Guide](../development/README.md) for extension documentation.

### Q: How does LG-Protect compare to AWS Config?
**A:** Key differences:

| Feature | LG-Protect | AWS Config |
|---------|------------|------------|
| **Scope** | Multi-account discovery | Single account compliance |
| **Cost** | Free/open source | Pay per configuration item |
| **Setup** | Run anywhere | AWS service setup required |
| **Output** | CSV, JSON, custom | AWS-specific formats |
| **Real-time** | On-demand scanning | Continuous monitoring |
| **Compliance** | Multiple frameworks | AWS-specific rules |

Both tools are complementary and can be used together.

## 💡 Best Practices

### Q: What's the best way to organize multi-account scans?
**A:** Recommended approaches:
1. **By environment**: dev, staging, production accounts
2. **By business unit**: separate account groups per division
3. **By compliance scope**: group accounts by regulatory requirements
4. **By region**: organize by primary geographic regions

### Q: How often should I run scans?
**A:** Recommended frequency:
- **Daily**: Production environments and critical accounts
- **Weekly**: Development and staging environments
- **Monthly**: Comprehensive enterprise-wide audits
- **On-demand**: Before audits, compliance reviews, or incidents

### Q: Should I run scans from inside AWS or externally?
**A:** Both approaches work:

**External (laptop/on-premises)**:
- ✅ Simple setup and testing
- ✅ No AWS infrastructure costs
- ❌ Network latency for API calls
- ❌ Limited by local compute resources

**Inside AWS (EC2/Lambda)**:
- ✅ Faster API calls (same region)
- ✅ Scalable compute resources
- ✅ Integration with AWS services
- ❌ Additional infrastructure to manage

For enterprise deployments, running inside AWS is recommended.

---

*Can't find your question? Check the [Troubleshooting Guide](../user-guide/troubleshooting.md) or [contact support](../user-guide/support.md).*