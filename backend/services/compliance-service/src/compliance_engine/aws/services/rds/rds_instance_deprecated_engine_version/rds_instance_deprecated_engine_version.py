from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_deprecated_engine_version(Check):
    def execute(self):
        findings = []
        for db_instance in rds_client.db_instances.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=db_instance)
            report.status = "FAIL"
            report.status_extended = f"RDS instance {db_instance.id} is using a deprecated engine {db_instance.engine} with version {db_instance.engine_version}."
            if (
                hasattr(
                    rds_client.db_engines.get(db_instance.region, {}).get(
                        db_instance.engine, {}
                    ),
                    "engine_versions",
                )
                and db_instance.engine_version
                in rds_client.db_engines[db_instance.region][
                    db_instance.engine
                ].engine_versions
            ):
                report.status = "PASS"
                report.status_extended = f"RDS instance {db_instance.id} is not using a deprecated engine {db_instance.engine} with version {db_instance.engine_version}."

            findings.append(report)

        return findings
