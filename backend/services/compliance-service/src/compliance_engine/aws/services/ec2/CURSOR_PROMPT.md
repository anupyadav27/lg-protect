# Service Conversion Prompt - EC2

## 🎯 Copy this entire content and paste it to Cursor.ai

---

**I'm working on implementing Tier 3 for AWS compliance services.**

**Context:**
- Tier 1 is complete (all __init__.py and *_client.py files are generated)
- I need to convert service files from prowler to BaseService pattern
- I need to convert check files from prowler to BaseCheck pattern
- I'm working on the **ec2** service

**Current Service Details:**
- **Service Name:** ec2
- **Service File:** ec2_service.py
- **Check Files:** 
  - ec2_ami_public
  - ec2_client_vpn_endpoint_connection_logging_enabled
  - ec2_ebs_default_encryption
  - ec2_ebs_public_snapshot
  - ec2_ebs_snapshot_account_block_public_access
  - ec2_ebs_snapshots_encrypted
  - ec2_ebs_volume_encryption
  - ec2_ebs_volume_protected_by_backup_plan
  - ec2_ebs_volume_snapshots_exists
  - ec2_elastic_ip_shodan
  - ec2_elastic_ip_unassigned
  - ec2_instance_account_imdsv2_enabled
  - ec2_instance_detailed_monitoring_enabled
  - ec2_instance_imdsv2_enabled
  - ec2_instance_internet_facing_with_instance_profile
  - ec2_instance_managed_by_ssm
  - ec2_instance_older_than_specific_days
  - ec2_instance_paravirtual_type
  - ec2_instance_port_cassandra_exposed_to_internet
  - ec2_instance_port_cifs_exposed_to_internet
  - ec2_instance_port_elasticsearch_kibana_exposed_to_internet
  - ec2_instance_port_ftp_exposed_to_internet
  - ec2_instance_port_kafka_exposed_to_internet
  - ec2_instance_port_kerberos_exposed_to_internet
  - ec2_instance_port_ldap_exposed_to_internet
  - ec2_instance_port_memcached_exposed_to_internet
  - ec2_instance_port_mongodb_exposed_to_internet
  - ec2_instance_port_mysql_exposed_to_internet
  - ec2_instance_port_oracle_exposed_to_internet
  - ec2_instance_port_postgresql_exposed_to_internet
  - ec2_instance_port_rdp_exposed_to_internet
  - ec2_instance_port_redis_exposed_to_internet
  - ec2_instance_port_sqlserver_exposed_to_internet
  - ec2_instance_port_ssh_exposed_to_internet
  - ec2_instance_port_telnet_exposed_to_internet
  - ec2_instance_profile_attached
  - ec2_instance_public_ip
  - ec2_instance_secrets_user_data
  - ec2_instance_uses_single_eni
  - ec2_launch_template_imdsv2_required
  - ec2_launch_template_no_public_ip
  - ec2_launch_template_no_secrets
  - ec2_networkacl_allow_ingress_any_port
  - ec2_networkacl_allow_ingress_tcp_port_22
  - ec2_networkacl_allow_ingress_tcp_port_3389
  - ec2_networkacl_unused
  - ec2_securitygroup_allow_ingress_from_internet_to_all_ports
  - ec2_securitygroup_allow_ingress_from_internet_to_any_port
  - ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports
  - ec2_securitygroup_allow_ingress_from_internet_to_port_mongodb_27017_27018
  - ec2_securitygroup_allow_ingress_from_internet_to_tcp_ftp_port_20_21
  - ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22
  - ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389
  - ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_cassandra_7199_9160_8888
  - ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_kafka_9092
  - ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_memcached_11211
  - ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mysql_3306
  - ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_oracle_1521_2483
  - ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_postgres_5432
  - ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379
  - ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_sql_server_1433_1434
  - ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_telnet_23
  - ec2_securitygroup_allow_wide_open_public_ipv4
  - ec2_securitygroup_default_restrict_traffic
  - ec2_securitygroup_from_launch_wizard
  - ec2_securitygroup_not_used
  - ec2_securitygroup_with_many_ingress_egress_rules
  - ec2_transitgateway_auto_accept_vpc_attachments

**What I need you to do:**

### Step 1: Analyze Current Files
- Read and analyze the current ec2_service.py file
- Read and analyze all check files in the ec2 directory
- Understand the current prowler structure and dependencies
- Identify the resource types and their properties
- List all AWS API calls used by the service

### Step 2: Convert Service File
- Convert ec2_service.py from prowler to BaseService pattern
- Remove ALL prowler dependencies
- Import BaseService and ComplianceResult from base
- Implement _get_service_name() method
- Implement _load_resources_for_region() method
- Define service-specific data models (Pydantic classes)
- Add proper error handling and logging
- Include type hints for all methods

### Step 3: Convert Check Files
- Convert all check files from prowler to BaseCheck pattern
- Remove ALL prowler dependencies
- Import BaseCheck and ComplianceResult from base
- Import the corresponding service: from ..ec2_service import Ec2Service
- Implement execute() method for each check with proper return type: List[ComplianceResult]
- Implement compliance logic for each check
- Add proper error handling with try/catch blocks
- Add logging with logger.error() for exceptions
- Include type hints for all methods

### Step 4: Quality Assurance
- Verify no prowler dependencies remain in any file
- Check that all imports work correctly
- Ensure error handling is implemented with try/catch
- Verify type hints are present, especially return types
- Confirm logging is configured with logger = logging.getLogger(__name__)
- Test that the service can be imported
- Test that check files can be imported

### Step 5: Testing
- Test service imports work correctly
- Test check imports work correctly
- Test service functionality
- Test check execution
- Ensure no errors occur

**Requirements:**
- Remove ALL prowler dependencies
- Use BaseService and BaseCheck patterns
- Add proper error handling and logging
- Include type hints, especially List[ComplianceResult] return type
- Follow the established patterns from completed services (bedrock, accessanalyzer, backup, etc.)

**Please start with Step 1 and proceed through each step systematically.**

---
