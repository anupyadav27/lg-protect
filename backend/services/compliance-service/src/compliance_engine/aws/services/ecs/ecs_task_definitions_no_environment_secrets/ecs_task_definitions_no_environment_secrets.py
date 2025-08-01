from json import dumps

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import detect_secrets_scan
from prowler.providers.aws.services.ecs.ecs_client import ecs_client


class ecs_task_definitions_no_environment_secrets(Check):
    def execute(self):
        findings = []
        secrets_ignore_patterns = ecs_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        for task_definition in ecs_client.task_definitions.values():
            report = Check_Report_AWS(
                metadata=self.metadata(), resource=task_definition
            )
            report.resource_id = f"{task_definition.name}:{task_definition.revision}"
            report.status = "PASS"
            extended_status_parts = []

            for container in task_definition.container_definitions:
                container_secrets_found = []

                if container.environment:
                    dump_env_vars = {}
                    original_env_vars = []
                    for env_var in container.environment:
                        dump_env_vars.update({env_var.name: env_var.value})
                        original_env_vars.append(env_var.name)

                    env_data = dumps(dump_env_vars, indent=2)
                    detect_secrets_output = detect_secrets_scan(
                        data=env_data,
                        excluded_secrets=secrets_ignore_patterns,
                        detect_secrets_plugins=ecs_client.audit_config.get(
                            "detect_secrets_plugins",
                        ),
                    )
                    if detect_secrets_output:
                        secrets_string = ", ".join(
                            [
                                f"{secret['type']} on the environment variable {original_env_vars[secret['line_number'] - 2]}"
                                for secret in detect_secrets_output
                            ]
                        )
                        container_secrets_found.append(
                            f"Secrets in container {container.name} -> {secrets_string}"
                        )
                if container_secrets_found:
                    report.status = "FAIL"
                    extended_status_parts.extend(container_secrets_found)
            if report.status == "FAIL":
                report.status_extended = (
                    f"Potential secrets found in ECS task definition {task_definition.name} with revision {task_definition.revision}: "
                    + "; ".join(extended_status_parts)
                    + "."
                )
            else:
                report.status_extended = f"No secrets found in variables of ECS task definition {task_definition.name} with revision {task_definition.revision}."
            findings.append(report)

        return findings
