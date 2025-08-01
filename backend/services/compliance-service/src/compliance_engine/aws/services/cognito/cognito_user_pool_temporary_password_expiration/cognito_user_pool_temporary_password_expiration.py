from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cognito.cognito_idp_client import cognito_idp_client


class cognito_user_pool_temporary_password_expiration(Check):
    def execute(self):
        findings = []
        for pool in cognito_idp_client.user_pools.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=pool)
            if pool.password_policy:
                if pool.password_policy.temporary_password_validity_days <= 7:
                    report.status = "PASS"
                    report.status_extended = f"User pool {pool.name} has temporary password expiration set to {pool.password_policy.temporary_password_validity_days} days."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"User pool {pool.name} has temporary password expiration set to {pool.password_policy.temporary_password_validity_days} days."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"User pool {pool.name} has not password policy set."
                )
            findings.append(report)

        return findings
