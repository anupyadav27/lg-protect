from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.s3.s3_client import s3_client


class s3_bucket_kms_encryption(Check):
    def execute(self):
        findings = []
        for bucket in s3_client.buckets.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=bucket)
            if bucket.encryption == "aws:kms" or bucket.encryption == "aws:kms:dsse":
                report.status = "PASS"
                report.status_extended = f"S3 Bucket {bucket.name} has Server Side Encryption with {bucket.encryption}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Server Side Encryption is not configured with kms for S3 Bucket {bucket.name}."
            findings.append(report)
        return findings
