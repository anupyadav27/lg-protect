from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)


class cloudtrail_multi_region_enabled(Check):
    def execute(self):
        findings = []
        if cloudtrail_client.trails is not None:
            for region in cloudtrail_client.regional_clients.keys():
                trail_is_logging = False
                for trail in cloudtrail_client.trails.values():
                    if trail.region == region or trail.is_multiregion:
                        report = Check_Report_AWS(
                            metadata=self.metadata(), resource=trail
                        )
                        report.region = region
                        if trail.is_logging:
                            trail_is_logging = True
                            report.status = "PASS"
                            if trail.is_multiregion:
                                report.status_extended = f"Trail {trail.name} is multiregion and it is logging."
                            else:
                                report.status_extended = f"Trail {trail.name} is not multiregion and it is logging."
                            # Since there exists a logging trail in that region there is no point in checking the remaining trails
                            # Store the finding and exit the loop
                            findings.append(report)
                            break
                # If there are no trails logging it is needed to store the FAIL once all the trails have been checked
                if not trail_is_logging:
                    report.status = "FAIL"
                    report.status_extended = (
                        "No CloudTrail trails enabled with logging were found."
                    )
                    report.resource_arn = cloudtrail_client._get_trail_arn_template(
                        region
                    )
                    report.resource_id = cloudtrail_client.audited_account
                    findings.append(report)
        return findings
