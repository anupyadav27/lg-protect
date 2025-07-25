from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ssm.ssm_client import ssm_client
from prowler.providers.aws.services.ssm.ssm_service import ResourceStatus


class ssm_managed_compliant_patching(Check):
    def execute(self):
        findings = []
        for resource in ssm_client.compliance_resources.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=resource)
            # Find tags of the instance in ec2_client
            for instance in ec2_client.instances:
                if instance.id == resource.id:
                    report.resource_tags = instance.tags

            if resource.status == ResourceStatus.COMPLIANT:
                report.status = "PASS"
                report.status_extended = (
                    f"EC2 managed instance {resource.id} is compliant."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"EC2 managed instance {resource.id} is non-compliant."
                )

            findings.append(report)

        return findings
