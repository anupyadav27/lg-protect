from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)
from prowler.providers.aws.services.cloudwatch.cloudwatch_client import (
    cloudwatch_client,
)
from prowler.providers.aws.services.cloudwatch.lib.metric_filters import (
    check_cloudwatch_log_metric_filter,
)
from prowler.providers.aws.services.cloudwatch.logs_client import logs_client


class cloudwatch_changes_to_network_acls_alarm_configured(Check):
    def execute(self):
        pattern = r"\$\.eventName\s*=\s*.?CreateNetworkAcl.+\$\.eventName\s*=\s*.?CreateNetworkAclEntry.+\$\.eventName\s*=\s*.?DeleteNetworkAcl.+\$\.eventName\s*=\s*.?DeleteNetworkAclEntry.+\$\.eventName\s*=\s*.?ReplaceNetworkAclEntry.+\$\.eventName\s*=\s*.?ReplaceNetworkAclAssociation.?"
        findings = []

        report = check_cloudwatch_log_metric_filter(
            pattern,
            cloudtrail_client.trails,
            logs_client.metric_filters,
            cloudwatch_client.metric_alarms,
            self.metadata(),
        )

        if cloudtrail_client.trails is not None:
            if report is None:
                report = Check_Report_AWS(metadata=self.metadata(), resource={})
                report.status = "FAIL"
                report.status_extended = "No CloudWatch log groups found with metric filters or alarms associated."
                report.region = logs_client.region
                report.resource_id = logs_client.audited_account
                report.resource_arn = logs_client.log_group_arn_template
                report.resource_tags = []

            findings.append(report)

        return findings
