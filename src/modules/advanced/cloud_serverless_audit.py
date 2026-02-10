"""Cloud serverless function configuration auditor.

Audits serverless function configurations for security issues including timeout settings,
memory limits, environment variable secrets, IAM roles, and VPC configuration.
"""

import asyncio
import re
import json
from typing import Any

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

SECRET_PATTERNS = [
    (r"(?:AKIA|ASIA)[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"[0-9a-zA-Z/+]{40}", "Potential AWS Secret Key"),
    (r"(?:password|passwd|pwd|secret|token|api.?key)\s*[:=]\s*['\"]?[^\s'\"]{8,}", "Generic secret"),
    (r"mongodb(\+srv)?://[^\s]+", "MongoDB connection string"),
    (r"postgres(ql)?://[^\s]+", "PostgreSQL connection string"),
    (r"mysql://[^\s]+", "MySQL connection string"),
    (r"redis://[^\s]+", "Redis connection string"),
]

PROVIDER_LIMITS = {
    "aws_lambda": {"max_timeout": 900, "max_memory": 10240, "min_memory": 128},
    "azure_functions": {"max_timeout": 600, "max_memory": 14336, "min_memory": 128},
    "gcp_functions": {"max_timeout": 540, "max_memory": 8192, "min_memory": 128},
}


class CloudServerlessAuditModule(AtsModule):
    """Audit serverless function configurations for security issues."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="cloud_serverless_audit",
            category=ModuleCategory.ADVANCED,
            description="Audit serverless function configurations for security misconfigurations",
            version="1.0.0",
            parameters=[
                Parameter(name="config_data", type=ParameterType.STRING,
                          description="Serverless function configuration JSON", required=True),
                Parameter(name="provider", type=ParameterType.CHOICE,
                          description="Serverless provider",
                          choices=["aws_lambda", "azure_functions", "gcp_functions"],
                          default="aws_lambda"),
                Parameter(name="check_env_secrets", type=ParameterType.BOOLEAN,
                          description="Scan environment variables for secrets", default=True),
            ],
            outputs=[
                OutputField(name="findings", type="list", description="Audit findings"),
                OutputField(name="risk_score", type="float", description="Risk score 0-100"),
                OutputField(name="function_summary", type="dict", description="Function config summary"),
            ],
            tags=["advanced", "cloud", "serverless", "lambda", "audit"],
            author="ATS-Toolkit",
            dangerous=False,
        )

    def validate_inputs(self, config: dict[str, Any]) -> tuple[bool, str]:
        data = config.get("config_data", "").strip()
        if not data:
            return False, "Configuration data JSON is required"
        try:
            json.loads(data)
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON: {e}"
        return True, ""

    def _extract_functions(self, config: dict, provider: str) -> list[dict]:
        """Extract function definitions from various config formats."""
        functions = []
        if "Functions" in config:
            for name, func in config["Functions"].items():
                func["_name"] = name
                functions.append(func)
        elif "functions" in config:
            if isinstance(config["functions"], dict):
                for name, func in config["functions"].items():
                    func["_name"] = name
                    functions.append(func)
            elif isinstance(config["functions"], list):
                functions = config["functions"]
        else:
            config["_name"] = config.get("FunctionName", config.get("name", "unknown"))
            functions = [config]
        return functions

    def _audit_function(self, func: dict, provider: str, check_secrets: bool) -> tuple[list, dict]:
        """Audit a single function configuration."""
        findings = []
        limits = PROVIDER_LIMITS.get(provider, PROVIDER_LIMITS["aws_lambda"])
        name = func.get("_name", func.get("FunctionName", func.get("name", "unknown")))

        summary = {"name": name, "runtime": None, "timeout": None, "memory": None, "vpc": False}

        timeout = func.get("Timeout", func.get("timeout", func.get("httpTrigger", {}).get("timeout")))
        if timeout is not None:
            summary["timeout"] = timeout
            if isinstance(timeout, (int, float)):
                if timeout >= limits["max_timeout"]:
                    findings.append({"severity": "medium", "function": name,
                                     "issue": f"Maximum timeout ({timeout}s) - potential abuse for long-running tasks"})
                elif timeout > limits["max_timeout"] * 0.8:
                    findings.append({"severity": "low", "function": name,
                                     "issue": f"Near-maximum timeout ({timeout}s)"})
        else:
            findings.append({"severity": "low", "function": name,
                             "issue": "No explicit timeout configured - using provider default"})

        memory = func.get("MemorySize", func.get("memorySize", func.get("memory")))
        if memory is not None:
            summary["memory"] = memory
            if isinstance(memory, int) and memory >= limits["max_memory"] * 0.8:
                findings.append({"severity": "medium", "function": name,
                                 "issue": f"High memory allocation ({memory}MB) - cost and abuse risk"})

        runtime = func.get("Runtime", func.get("runtime", ""))
        summary["runtime"] = runtime
        deprecated_runtimes = ["python2.7", "nodejs8.10", "nodejs10.x", "dotnetcore2.1",
                               "ruby2.5", "python3.6", "nodejs12.x"]
        if runtime and any(runtime.lower().startswith(dr) for dr in deprecated_runtimes):
            findings.append({"severity": "high", "function": name,
                             "issue": f"Deprecated runtime: {runtime} - no security patches"})

        role = func.get("Role", func.get("role", func.get("serviceAccountEmail", "")))
        if role:
            if "*" in str(role) or "admin" in str(role).lower():
                findings.append({"severity": "critical", "function": name,
                                 "issue": f"Overly permissive IAM role: {str(role)[:80]}"})
            if "arn:aws:iam::" in str(role) and ":root" in str(role):
                findings.append({"severity": "critical", "function": name,
                                 "issue": "Function uses root account role"})

        vpc_config = func.get("VpcConfig", func.get("vpcConnector", func.get("vpc", None)))
        if vpc_config:
            summary["vpc"] = True
            subnet_ids = vpc_config.get("SubnetIds", []) if isinstance(vpc_config, dict) else []
            sg_ids = vpc_config.get("SecurityGroupIds", []) if isinstance(vpc_config, dict) else []
            if isinstance(vpc_config, dict) and not subnet_ids:
                findings.append({"severity": "medium", "function": name,
                                 "issue": "VPC configured but no subnets specified"})
        else:
            findings.append({"severity": "low", "function": name,
                             "issue": "Function not attached to VPC - direct internet access"})

        if check_secrets:
            env_vars = func.get("Environment", {}).get("Variables", {})
            if not env_vars:
                env_vars = func.get("environment", func.get("env", {}))
            for key, value in env_vars.items() if isinstance(env_vars, dict) else []:
                combined = f"{key}={value}"
                for pattern, desc in SECRET_PATTERNS:
                    if re.search(pattern, combined, re.IGNORECASE):
                        masked = str(value)[:4] + "****" if len(str(value)) > 4 else "****"
                        findings.append({"severity": "critical", "function": name,
                                         "issue": f"{desc} found in env var {key}: {masked}"})
                        break

        layers = func.get("Layers", func.get("layers", []))
        if isinstance(layers, list) and len(layers) > 5:
            findings.append({"severity": "low", "function": name,
                             "issue": f"Many layers attached ({len(layers)}) - review for supply chain risk"})

        reserved = func.get("ReservedConcurrentExecutions",
                           func.get("reservedConcurrency", func.get("maxInstances")))
        if reserved is None:
            findings.append({"severity": "medium", "function": name,
                             "issue": "No concurrency limit - potential for cost abuse"})

        return findings, summary

    async def execute(self, config: dict[str, Any]) -> dict[str, Any]:
        data = json.loads(config["config_data"])
        provider = config.get("provider", "aws_lambda")
        check_secrets = config.get("check_env_secrets", True)

        functions = self._extract_functions(data, provider)
        all_findings = []
        summaries = []

        for func in functions:
            findings, summary = self._audit_function(func, provider, check_secrets)
            all_findings.extend(findings)
            summaries.append(summary)

        severity_map = {"critical": 25, "high": 15, "medium": 8, "low": 3}
        risk_score = min(sum(severity_map.get(f["severity"], 0) for f in all_findings), 100.0)

        return {
            "provider": provider,
            "functions_audited": len(functions),
            "findings": all_findings,
            "finding_count": len(all_findings),
            "risk_score": round(risk_score, 1),
            "risk_level": "critical" if risk_score >= 60 else "high" if risk_score >= 35 else "medium" if risk_score >= 15 else "low",
            "function_summaries": summaries,
        }
