from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)
from prowler.providers.aws.services.s3.s3_client import s3_client


class cloudtrail_bucket_requires_mfa_delete(Check):
    def execute(self):
        findings = []
        if cloudtrail_client.trails is not None:
            for trail in cloudtrail_client.trails.values():
                if trail.is_logging:
                    trail_bucket_is_in_account = False
                    trail_bucket = trail.s3_bucket
                    report = Check_Report_AWS(metadata=self.metadata(), resource=trail)
                    report.region = trail.home_region
                    report.status = "FAIL"
                    report.status_extended = f"Trail {trail.name} bucket ({trail_bucket}) does not have MFA delete enabled."
                    for bucket in s3_client.buckets.values():
                        if trail_bucket == bucket.name:
                            trail_bucket_is_in_account = True
                            if bucket.mfa_delete:
                                report.status = "PASS"
                                report.status_extended = f"Trail {trail.name} bucket ({trail_bucket}) has MFA delete enabled."
                    # check if trail bucket is a cross account bucket
                    if not trail_bucket_is_in_account:
                        report.status = "MANUAL"
                        report.status_extended = f"Trail {trail.name} bucket ({trail_bucket}) is a cross-account bucket or out of Prowler's audit scope, please check it manually."

                    findings.append(report)

        return findings
