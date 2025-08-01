from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elasticache.elasticache_client import (
    elasticache_client,
)


class elasticache_redis_cluster_auto_minor_version_upgrades(Check):
    def execute(self):
        findings = []
        for repl_group in elasticache_client.replication_groups.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=repl_group)
            report.status = "PASS"
            report.status_extended = f"Elasticache Redis cache cluster {repl_group.id} does have automated minor version upgrades enabled."

            if not repl_group.auto_minor_version_upgrade:
                report.status = "FAIL"
                report.status_extended = f"Elasticache Redis cache cluster {repl_group.id} does not have automated minor version upgrades enabled."

            findings.append(report)

        return findings
