from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.storagegateway.storagegateway_client import (
    storagegateway_client,
)


class storagegateway_fileshare_encryption_enabled(Check):
    def execute(self):
        findings = []
        for fileshare in storagegateway_client.fileshares:
            report = Check_Report_AWS(metadata=self.metadata(), resource=fileshare)
            report.status = "FAIL"
            report.status_extended = (
                f"StorageGateway File Share {fileshare.id} is not using KMS CMK."
            )
            if fileshare.kms:
                report.status = "PASS"
                report.status_extended = (
                    f"StorageGateway File Share {fileshare.id} is using KMS CMK."
                )

            findings.append(report)

        return findings
