from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)
from prowler.providers.aws.services.s3.s3_client import s3_client


class cloudtrail_logs_s3_bucket_access_logging_enabled(Check):
    def execute(self):
        findings = []
        if cloudtrail_client.trails is not None:
            for trail in cloudtrail_client.trails.values():
                if trail.name:
                    trail_bucket_is_in_account = False
                    trail_bucket = trail.s3_bucket
                    report = Check_Report_AWS(metadata=self.metadata(), resource=trail)
                    report.region = trail.home_region
                    report.status = "FAIL"
                    if trail.is_multiregion:
                        report.status_extended = f"Multiregion Trail {trail.name} S3 bucket access logging is not enabled for bucket {trail_bucket}."
                    else:
                        report.status_extended = f"Single region Trail {trail.name} S3 bucket access logging is not enabled for bucket {trail_bucket}."
                    for bucket in s3_client.buckets.values():
                        if trail_bucket == bucket.name:
                            trail_bucket_is_in_account = True
                            if bucket.logging:
                                report.status = "PASS"
                                if trail.is_multiregion:
                                    report.status_extended = f"Multiregion Trail {trail.name} S3 bucket access logging is enabled for bucket {trail_bucket}."
                                else:
                                    report.status_extended = f"Single region Trail {trail.name} S3 bucket access logging is enabled for bucket {trail_bucket}."
                            break

                    # check if trail is delivering logs in a cross account bucket or another region out of Prowler's audit scope
                    if not trail_bucket_is_in_account:
                        report.status = "MANUAL"
                        report.status_extended = f"Trail {trail.name} is delivering logs to bucket {trail_bucket} which is a cross-account bucket or out of Prowler's audit scope, please check it manually."
                    findings.append(report)

        return findings
