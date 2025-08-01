from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_root_mfa_enabled(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        # Check if the root credentials are managed by AWS Organizations
        if (
            iam_client.organization_features is not None
            and "RootCredentialsManagement" not in iam_client.organization_features
        ):
            if iam_client.credential_report:
                for user in iam_client.credential_report:
                    if user["user"] == "<root_account>":
                        report = Check_Report_AWS(
                            metadata=self.metadata(), resource=user
                        )
                        report.region = iam_client.region
                        report.resource_id = user["user"]
                        report.resource_arn = user["arn"]
                        if user["mfa_active"] == "false":
                            report.status = "FAIL"
                            report.status_extended = (
                                "MFA is not enabled for root account."
                            )
                        else:
                            report.status = "PASS"
                            report.status_extended = "MFA is enabled for root account."
                        findings.append(report)

        return findings
