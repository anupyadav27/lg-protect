from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class ec2_securitygroup_default_restrict_traffic(Check):
    def execute(self):
        findings = []
        for security_group_arn, security_group in ec2_client.security_groups.items():
            # Check if ignoring flag is set and if the VPC and the default SG are in used
            if security_group.name == "default" and (
                ec2_client.provider.scan_unused_services
                or (
                    security_group.vpc_id in vpc_client.vpcs
                    and vpc_client.vpcs[security_group.vpc_id].in_use
                    and len(security_group.network_interfaces) > 0
                )
            ):
                report = Check_Report_AWS(
                    metadata=self.metadata(), resource=security_group
                )
                report.resource_details = security_group.name
                report.status = "FAIL"
                report.status_extended = (
                    f"Default Security Group ({security_group.id}) rules allow traffic."
                )
                if not security_group.ingress_rules and not security_group.egress_rules:
                    report.status = "PASS"
                    report.status_extended = f"Default Security Group ({security_group.id}) rules do not allow traffic."

                findings.append(report)

        return findings
