from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_inside_vpc(Check):
    def execute(self):
        findings = []
        for db_instance in rds_client.db_instances.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=db_instance)
            if db_instance.vpc_id:
                report.status = "PASS"
                report.status_extended = f"RDS Instance {db_instance.id} is deployed in a VPC {db_instance.vpc_id}."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"RDS Instance {db_instance.id} is not deployed in a VPC."
                )

            findings.append(report)

        return findings
