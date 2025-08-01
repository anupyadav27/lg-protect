from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.glue.glue_client import glue_client
from prowler.providers.aws.services.iam.lib.policy import is_policy_public


class glue_data_catalogs_not_publicly_accessible(Check):
    def execute(self):
        findings = []
        for data_catalog in glue_client.data_catalogs.values():
            if data_catalog.policy is None:
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=data_catalog)
            report.resource_id = glue_client.audited_account
            report.resource_arn = glue_client._get_data_catalog_arn_template(
                data_catalog.region
            )
            report.status = "PASS"
            report.status_extended = "Glue Data Catalog is not publicly accessible."
            if is_policy_public(
                data_catalog.policy,
                glue_client.audited_account,
            ):
                report.status = "FAIL"
                report.status_extended = "Glue Data Catalog is publicly accessible due to its resource policy."

            findings.append(report)

        return findings
