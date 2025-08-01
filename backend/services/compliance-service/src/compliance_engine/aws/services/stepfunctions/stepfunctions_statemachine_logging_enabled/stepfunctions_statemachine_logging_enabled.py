from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.stepfunctions.stepfunctions_client import (
    stepfunctions_client,
)
from prowler.providers.aws.services.stepfunctions.stepfunctions_service import (
    LoggingLevel,
)


class stepfunctions_statemachine_logging_enabled(Check):
    """
    Check if AWS Step Functions state machines have logging enabled.

    This class verifies whether each AWS Step Functions state machine has logging enabled by checking
    for the presence of a loggingConfiguration property in the state machine's configuration.
    """

    def execute(self) -> List[Check_Report_AWS]:
        """
        Execute the Step Functions state machines logging enabled check.

        Iterates over all Step Functions state machines and generates a report indicating whether
        each state machine has logging enabled.

        Returns:
            List[Check_Report_AWS]: A list of report objects with the results of the check.
        """
        findings = []
        for state_machine in stepfunctions_client.state_machines.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=state_machine)
            report.status = "PASS"
            report.status_extended = f"Step Functions state machine {state_machine.name} has logging enabled."

            if (
                not state_machine.logging_configuration
                or state_machine.logging_configuration.level == LoggingLevel.OFF
            ):
                report.status = "FAIL"
                report.status_extended = f"Step Functions state machine {state_machine.name} does not have logging enabled."
            findings.append(report)

        return findings
