"""
Ensure that the API Server only makes use of Strong Cryptographic Ciphers

This check ensures that the Kubernetes API server is configured to only use strong cryptographic ciphers, minimizing the risk of vulnerabilities associated with weaker ciphers. Strong ciphers enhance the security of TLS connections to the API server.
"""

from typing import List
from kubernetes import client
from kubernetes_checks.base import KubernetesCheckBase
from utility.base_reporting import CheckResult, CheckStatus, CheckSeverity

# Define a set of strong ciphers (example: Kubernetes 1.23+ recommended ciphers)
DEFAULT_STRONG_CIPHERS = {
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
}

class apiserver_strong_ciphers_only(KubernetesCheckBase):
    """Ensure that the API Server only makes use of Strong Cryptographic Ciphers"""

    def execute(self) -> List[CheckResult]:
        findings = []
        try:
            v1_api = client.CoreV1Api(self.provider)
            api_server_pods = v1_api.list_namespaced_pod(
                namespace="kube-system",
                label_selector="component=kube-apiserver"
            )

            for pod in api_server_pods.items:
                check_passed = False
                for container in pod.spec.containers:
                    args = container.args or []
                    for i, arg in enumerate(args):
                        # Handle --tls-cipher-suites=... and --tls-cipher-suites ...
                        if arg.startswith("--tls-cipher-suites="):
                            ciphers = set(cipher.strip() for cipher in arg.split("=", 1)[1].split(","))
                            if ciphers and ciphers.issubset(DEFAULT_STRONG_CIPHERS):
                                check_passed = True
                                break
                        elif arg == "--tls-cipher-suites" and i + 1 < len(args):
                            ciphers = set(cipher.strip() for cipher in args[i + 1].split(","))
                            if ciphers and ciphers.issubset(DEFAULT_STRONG_CIPHERS):
                                check_passed = True
                                break
                    if check_passed:
                        break

                result = CheckResult(
                    check_id="apiserver_strong_ciphers_only",
                    check_name="Ensure that the API Server only makes use of Strong Cryptographic Ciphers",
                    status=CheckStatus.PASS if check_passed else CheckStatus.FAIL,
                    status_extended=(
                        f"API server is restricted to strong cryptographic ciphers in pod {pod.metadata.name}."
                        if check_passed else
                        f"Configuration is not properly set in pod {pod.metadata.name}."
                    ),
                    resource_id=pod.metadata.name,
                    resource_name=pod.metadata.name,
                    resource_type="Pod",
                    namespace="kube-system",
                    severity=CheckSeverity.HIGH
                )
                if not check_passed:
                    result.recommendations = [
                        "Restrict the API server to only use strong cryptographic ciphers for enhanced security."
                    ]
                findings.append(result)

        except Exception as e:
            findings.append(CheckResult(
                check_id="apiserver_strong_ciphers_only",
                check_name="Ensure that the API Server only makes use of Strong Cryptographic Ciphers",
                status=CheckStatus.ERROR,
                status_extended=f"Error checking apiserver_strong_ciphers_only: {str(e)}",
                resource_id="unknown",
                resource_name="unknown",
                resource_type="Pod",
                severity=CheckSeverity.HIGH
            ))

        return findings
