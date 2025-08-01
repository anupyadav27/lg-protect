from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudfront.cloudfront_client import (
    cloudfront_client,
)
from prowler.providers.aws.services.s3.s3_client import s3_client


class cloudfront_distributions_s3_origin_non_existent_bucket(Check):
    def execute(self):
        findings = []
        for distribution in cloudfront_client.distributions.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=distribution)
            report.status = "PASS"
            report.status_extended = f"CloudFront Distribution {distribution.id} does not have non-existent S3 buckets as origins."
            non_existent_buckets = []

            for origin in distribution.origins:
                if origin.s3_origin_config:
                    bucket_name = origin.domain_name.split(".s3")[0]
                    if not s3_client._head_bucket(bucket_name):
                        non_existent_buckets.append(bucket_name)

            if non_existent_buckets:
                report.status = "FAIL"
                report.status_extended = f"CloudFront Distribution {distribution.id} has non-existent S3 buckets as origins: {','.join(non_existent_buckets)}."

            findings.append(report)

        return findings
