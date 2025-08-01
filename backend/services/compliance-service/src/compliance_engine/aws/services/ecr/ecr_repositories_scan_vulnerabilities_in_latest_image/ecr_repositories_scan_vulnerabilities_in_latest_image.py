from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecr.ecr_client import ecr_client


class ecr_repositories_scan_vulnerabilities_in_latest_image(Check):
    def execute(self):
        findings = []

        # Get minimun severity to report
        minimum_severity = ecr_client.audit_config.get(
            "ecr_repository_vulnerability_minimum_severity", "MEDIUM"
        )

        for registry in ecr_client.registries.values():
            for repository in registry.repositories:
                # First check if the repository has images
                if len(repository.images_details) > 0:
                    # We only want to check the latest image pushed that is scannable
                    image = repository.images_details[-1]
                    report = Check_Report_AWS(
                        metadata=self.metadata(), resource=repository
                    )
                    report.status = "PASS"
                    status_extended_prefix = f"ECR repository '{repository.name}' has scanned the {image.type} container image with digest '{image.latest_digest}' and tag '{image.latest_tag}' "
                    report.status_extended = (
                        status_extended_prefix + "without findings."
                    )
                    if not image.scan_findings_status:
                        report.status = "FAIL"
                        report.status_extended = (
                            status_extended_prefix + "without a scan."
                        )
                    elif image.scan_findings_status == "FAILED":
                        report.status = "FAIL"
                        report.status_extended = (
                            status_extended_prefix + "with scan status FAILED."
                        )
                    elif (
                        image.scan_findings_status != "FAILED"
                        and image.scan_findings_severity_count
                    ):
                        if (
                            minimum_severity == "CRITICAL"
                            and image.scan_findings_severity_count.critical
                        ):
                            report.status = "FAIL"
                            report.status_extended = (
                                status_extended_prefix
                                + f"with findings: CRITICAL->{image.scan_findings_severity_count.critical}."
                            )
                        elif minimum_severity == "HIGH" and (
                            image.scan_findings_severity_count.critical
                            or image.scan_findings_severity_count.high
                        ):
                            report.status = "FAIL"
                            report.status_extended = (
                                status_extended_prefix
                                + f"with findings: CRITICAL->{image.scan_findings_severity_count.critical}, HIGH->{image.scan_findings_severity_count.high}."
                            )
                        elif minimum_severity == "MEDIUM" and (
                            image.scan_findings_severity_count.critical
                            or image.scan_findings_severity_count.high
                            or image.scan_findings_severity_count.medium
                        ):
                            report.status = "FAIL"
                            report.status_extended = (
                                status_extended_prefix
                                + f"with findings: CRITICAL->{image.scan_findings_severity_count.critical}, HIGH->{image.scan_findings_severity_count.high}, MEDIUM->{image.scan_findings_severity_count.medium}."
                            )

                    findings.append(report)

        return findings
