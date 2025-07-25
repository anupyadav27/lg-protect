from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class vpc_subnet_different_az(Check):
    def execute(self):
        findings = []
        for vpc in vpc_client.vpcs.values():
            if vpc_client.provider.scan_unused_services or vpc.in_use:
                report = Check_Report_AWS(metadata=self.metadata(), resource=vpc)
                report.status = "FAIL"
                report.status_extended = (
                    f"VPC {vpc.name if vpc.name else vpc.id} has no subnets."
                )
                if vpc.subnets:
                    availability_zone = None
                    for subnet in vpc.subnets:
                        if (
                            availability_zone
                            and subnet.availability_zone != availability_zone
                        ):
                            report.status = "PASS"
                            report.status_extended = f"VPC {vpc.name if vpc.name else vpc.id} has subnets in more than one availability zone."
                            break
                        availability_zone = subnet.availability_zone
                        report.status_extended = f"VPC {vpc.name if vpc.name else vpc.id} has only subnets in {availability_zone}."

                findings.append(report)

        return findings
