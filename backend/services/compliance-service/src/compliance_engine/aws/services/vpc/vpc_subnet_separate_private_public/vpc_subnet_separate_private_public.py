from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class vpc_subnet_separate_private_public(Check):
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
                    public = False
                    private = False
                    for subnet in vpc.subnets:
                        if subnet.public:
                            public = True
                            report.status_extended = f"VPC {vpc.name if vpc.name else vpc.id} has only public subnets."
                        if not subnet.public:
                            private = True
                            report.status_extended = f"VPC {vpc.name if vpc.name else vpc.id} has only private subnets."
                        if public and private:
                            report.status = "PASS"
                            report.status_extended = f"VPC {vpc.name if vpc.name else vpc.id} has private and public subnets."
                findings.append(report)

        return findings
