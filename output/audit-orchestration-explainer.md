# Vulnerability Orchestrator Audit Walkthrough

This document explains how the vulnerability-orchestrator agent coordinated the security audit of this repository in OpenCode, how each sub-agent was invoked, what artifacts were produced, and what information was available during execution.

> Note: This is an execution summary and prompt transcript. It does **not** include hidden chain-of-thought or private model reasoning. Where internal sub-agent system prompts or exact token accounting were not exposed to the orchestrator, that limitation is called out explicitly.

---

## 1. OpenCode Overview

OpenCode is an agentic coding environment that lets an AI assistant operate over a local repository using tools such as file reads, search, shell commands, patch application, GitHub CLI/API operations, and specialized sub-agents.

At a high level, OpenCode sessions are structured around:

- **Main agent / orchestrator**: The primary assistant that receives the user request, plans the workflow, invokes tools, delegates work, and summarizes results.
- **Tools**: Controlled capabilities exposed to the agent, such as reading files, applying patches, running shell commands, or launching sub-agents.
- **Sub-agents**: Specialized agents optimized for focused workflows such as threat modeling, security auditing, vulnerability fixing, reporting, or code exploration.
- **Skills**: Instruction set to define how agents should perform a common task such as writing unit tests, or requiring all documentation to use a specific pattern.
- **Repository context**: The working directory, Git state, project instructions, and any local guidance files such as `AGENTS.md`.
- **Permissions / constraints**: Tool access is constrained by the environment. For example, shell commands run in the repository, file edits are performed through patch tools, and GitHub operations use available credentials and scopes.

OpenCode agent definitions can specify operational parameters such as:

- **Model**: Which AI model powers an agent.
- **Temperature**: How deterministic or creative the model should be.
- **Tool permissions**: Which tools the agent may call, such as shell, file-read, patch, GitHub, or web-fetch tools.
- **System instructions**: Role-specific behavior, workflows, safety rules, and output requirements.
- **Working directory / repository scope**: The filesystem and repository context the agent can operate within.

---

## 2. Audit Objective

The user requested a security audit of OWASP Juice Shop while explicitly asking that the repository be treated as if it were **not intentionally vulnerable**.

The audit therefore treated findings as production application vulnerabilities rather than training challenges. The goal was to:

1. Produce a threat model.
2. Ingest GitHub security findings.
3. Run a high-confidence vulnerability audit.
4. Generate standardized reports including SARIF.
5. Upload SARIF to GitHub code scanning.
6. Create remediation branches and pull requests where safe fixes could be made.

---

## 3. Orchestrator Workflow

The orchestrator followed this workflow:

1. Created a task list for the overall audit.
2. Ran threat modeling and GitHub security finding ingestion in parallel.
3. Passed those artifacts into the security auditor.
4. Passed canonical findings into the vulnerability reporter.
5. Passed findings and reports into the vulnerability fixer.
6. Summarized the audit artifacts, SARIF upload, remediation branches, PRs, and validation results.

The high-level task plan was:

| Step | Status | Purpose |
|---|---|---|
| Generate repository threat model | Completed | Establish architecture, assets, trust boundaries, and likely attack paths |
| Ingest GitHub security findings | Completed | Normalize supplemental CodeQL, Dependabot, and secret scanning data |
| Run security audit with normalized findings | Completed | Triage candidates and identify confirmed vulnerabilities |
| Produce standardized reports and upload SARIF/results to GitHub | Completed | Generate JSON, CSV, Markdown, and SARIF outputs |
| Create remediation branches and fixes for confirmed findings | Completed | Fix safe findings and defer risky/product-sensitive changes |

---

## 4. Main Agent to Sub-Agent Prompt Transcript

This section includes the prompts that the main orchestrator passed to each sub-agent during the audit.

### 4.1 Threat Model Sub-Agent

**Sub-agent type:** `threat-model`

**Prompt passed by orchestrator:**

```text
Create a comprehensive threat model for /Users/barrydawson/Desktop/repo/juice-shop treating this as a normal production web application, not an intentionally vulnerable training app. Store the threat model artifact in the repository if your workflow supports it. Focus on architecture, assets, trust boundaries, entry points, authentication/authorization, data stores, third-party dependencies, and abuse cases. Return the artifact paths and concise summary. This threat model will feed subsequent SAST/SCA triage.
```

**Returned artifacts:**

- `output/threat-model.md`
- `output/security-config.json`

**Summary of result:**

The sub-agent modeled Juice Shop as a production e-commerce web application and highlighted high-risk areas such as JWT/key handling, SQL injection, generated CRUD authorization, file upload and parser abuse, SSRF, IDOR, mass assignment, public file exposure, payment data handling, and business logic abuse.

---

### 4.2 GitHub Security Findings Ingestion Sub-Agent

**Sub-agent type:** `vuln-github-ingest`

**Prompt passed by orchestrator:**

```text
Ingest GitHub Advanced Security/code scanning/dependabot/security findings for /Users/barrydawson/Desktop/repo/juice-shop using available GitHub tooling. Normalize candidate findings into the expected artifact format for downstream vulnerability audit. Treat these as supplemental candidates requiring validation. Return artifact paths, counts by source/severity, and any access/upload limitations.
```

**Returned artifact:**

- `artifacts/github_security_mcp_findings.json`

**Summary of result:**

The sub-agent ingested 52 GitHub security candidates:

- 30 CodeQL findings
- 22 Dependabot findings
- 0 secret scanning findings

It reported 36 open findings and 16 fixed findings. The findings came from the fork `joesnipes/juice-shop`; upstream OWASP API calls returned 404 in that context.

---

### 4.3 Security Auditor Sub-Agent

**Sub-agent type:** `security-auditor`

**Prompt passed by orchestrator:**

```text
Run a comprehensive security audit of /Users/barrydawson/Desktop/repo/juice-shop treating it as a normal production web application, not as intentionally vulnerable. Use the threat model artifacts at output/threat-model.md and output/security-config.json plus normalized GitHub findings at artifacts/github_security_mcp_findings.json. Triage every candidate with high confidence. Require evidence for every confirmed/needs-review finding: filename, line, vulnerable snippet, CWE, OWASP category, severity, exploit rationale, and recommended fix. If evidence is weak mark false-positive; if inconclusive mark needs reviewed. Zero findings is valid but do not ignore real vulnerabilities. Produce canonical normalized findings artifact for reporting and return path, counts by status/severity, and the top actionable findings.
```

**Returned artifact:**

- `output/canonical-security-findings.json`

**Summary of result:**

The auditor triaged 36 candidates:

| Status | Count |
|---|---:|
| Confirmed | 19 |
| Needs review | 1 |
| False positive | 16 |

Confirmed severity counts:

| Severity | Count |
|---|---:|
| Critical | 8 |
| High | 7 |
| Medium | 3 |
| Low | 1 |

Top actionable findings included SQL injection in login, hardcoded/vulnerable JWT signing configuration, mass assignment, MarsDB injection, and public exposure of sensitive files and operational endpoints.

---

### 4.4 Vulnerability Reporter Sub-Agent

**Sub-agent type:** `vuln-reporter`

**Prompt passed by orchestrator:**

```text
Render standardized vulnerability reports from /Users/barrydawson/Desktop/repo/juice-shop/output/canonical-security-findings.json and threat model artifacts. Output JSON, CSV, SARIF, and Markdown under /Users/barrydawson/Desktop/repo/juice-shop/output. Publish/upload SARIF to GitHub code scanning if credentials and repository permissions allow; otherwise record exact limitation. Enforce SARIF compatibility: level must be one of error|warning|note|none; encode critical/high/medium/low via properties.security-severity CVSS-style string on both rules and results; false-positive/informational as 0.0. Enforce tool identity: output/findings.sarif must use runs[0].tool.driver.name exactly 'Barrys Special AI Vuln Audit' before upload. Return all report paths, upload status, and summary counts.
```

**Returned artifacts:**

- `output/findings.json`
- `output/findings.csv`
- `output/findings.md`
- `output/findings.sarif`

**GitHub upload:**

- Upload ID: `9057fd8a-4d95-11f1-9f61-54424a7bc1a9`
- Upload URL: `https://api.github.com/repos/joesnipes/juice-shop/code-scanning/sarifs/9057fd8a-4d95-11f1-9f61-54424a7bc1a9`
- Processing status: `complete`

**Additional publication:**

- Threat model PR: `https://github.com/joesnipes/juice-shop/pull/18`

---

### 4.5 Vulnerability Fixer Sub-Agent

**Sub-agent type:** `vuln-fixer`

**Prompt passed by orchestrator:**

```text
Create separate SCA and SAST remediation branches for /Users/barrydawson/Desktop/repo/juice-shop based on confirmed findings in output/canonical-security-findings.json and generated reports in output/. Fix confirmed vulnerabilities where a safe behavior-preserving remediation can be made; validate functionality. Treat this as a normal production app, but preserve application functionality as much as possible. For each fix/remediation manifest entry require: vulnerable code snippet, changed code snippet, vulnerability ID, CWE/OWASP, GitHub security finding link (or uploaded SARIF/API URL if no direct alert link), validation status, and functionality-preservation notes. If a safe fix cannot be made without product/developer input, mark developer_decision_required rather than making risky changes. Return branch names, PR URLs if created, remediation manifest paths, validation commands/results, and any findings deferred.
```

**Returned artifacts:**

- `output/remediation-plan.json`
- `output/remediation-plan.md`

**Created remediation branches and PRs:**

| Remediation area | Branch | PR |
|---|---|---|
| SCA | `security-fixes/sca-20260511-200206` | `https://github.com/joesnipes/juice-shop/pull/19` |
| SAST | `security-fixes/sast-20260511-200206` | `https://github.com/joesnipes/juice-shop/pull/20` |

**Fix summary:**

- SCA fixed: `JS-PROD-015`
- SAST fixed: `JS-PROD-001`, `JS-PROD-002`, `JS-PROD-006`, `JS-PROD-007`, `JS-PROD-008`, `JS-PROD-009`, `JS-PROD-012`, `JS-PROD-013`, `JS-PROD-014`
- Deferred: `JS-PROD-003`, `JS-PROD-004`, `JS-PROD-005`, `JS-PROD-010`, `JS-PROD-011`

---

## 5. Sub-Agent Internal Prompts and Reasoning

The orchestrator could see:

- The sub-agent type selected.
- The prompt passed from the orchestrator to the sub-agent.
- The final result returned by the sub-agent.
- Artifact paths created by the sub-agent.

The orchestrator could **not** see:

- Hidden system prompts embedded inside each sub-agent definition.
- Private chain-of-thought or detailed internal reasoning traces.
- Full intermediate tool transcripts from inside each sub-agent, unless included in the sub-agent final result.

For presentation purposes, the best representation of “behind the scenes” is therefore:

1. The orchestrator workflow and task sequencing.
2. The exact delegation prompts shown above.
3. The artifacts each sub-agent produced.
4. The final decisions, counts, branches, reports, and validation outputs returned by each sub-agent.

This preserves auditability without exposing private model reasoning.

---

## 6. Model and Token Usage

### AI Models Used

- vuln-orchestrator: `openai/gpt-5.5`
- threat-model: `openai/gpt-5.5`
- vuln-github-ingest: `opencode/minimax-m2.5-free`
- security-auditor: `openai/gpt-5.5`
- vuln-reporter: `openai/gpt-5.3-codex`
- vuln-fixer: `openai/gpt-5.5`

### Token Consumption

Exact token usage was **not exposed** to the orchestrator during this run. No tool output included authoritative prompt-token, completion-token, or total-token accounting for the main model or sub-agent model calls.

Because exact usage was unavailable, this report does not fabricate token numbers.

| Component | Exact token count available? | Notes |
|---|---:|---|
| Main orchestrator | No | No token telemetry was returned in the session transcript |
| `threat-model` sub-agent | No | Final result was returned, but token accounting was not included |
| `vuln-github-ingest` sub-agent | No | Final result was returned, but token accounting was not included |
| `security-auditor` sub-agent | No | Final result was returned, but token accounting was not included |
| `vuln-reporter` sub-agent | No | Final result was returned, but token accounting was not included |
| `vuln-fixer` sub-agent | No | Final result was returned, but token accounting was not included |

Recommended ways to capture token usage in a future demo:

1. Enable provider/API usage logging if available.
2. Capture OpenCode session telemetry if the runtime exposes it.
3. Add a wrapper around model calls to record prompt, completion, and total tokens.
4. Export per-agent run metadata after completion, if supported by the OpenCode installation.

---

## 7. Final Audit Outputs

The audit produced the following outputs:

| Artifact | Purpose |
|---|---|
| `output/threat-model.md` | Human-readable threat model |
| `output/security-config.json` | Security audit configuration/context |
| `artifacts/github_security_mcp_findings.json` | Normalized GitHub security findings |
| `output/canonical-security-findings.json` | Canonical triaged findings |
| `output/findings.json` | JSON report |
| `output/findings.csv` | CSV report |
| `output/findings.md` | Markdown report |
| `output/findings.sarif` | SARIF report uploaded to GitHub Code Scanning |
| `output/remediation-plan.json` | Machine-readable remediation manifest |
| `output/remediation-plan.md` | Human-readable remediation manifest |

---

## 8. Final GitHub Outputs

| Output | URL |
|---|---|
| Threat model PR | `https://github.com/joesnipes/juice-shop/pull/18` |
| SCA remediation PR | `https://github.com/joesnipes/juice-shop/pull/19` |
| SAST remediation PR | `https://github.com/joesnipes/juice-shop/pull/20` |
| SARIF upload API URL | `https://api.github.com/repos/joesnipes/juice-shop/code-scanning/sarifs/9057fd8a-4d95-11f1-9f61-54424a7bc1a9` |

---

## 9. Key Presentation Takeaways

- The main orchestrator did not perform every task itself. It coordinated specialized sub-agents.
- Threat modeling and GitHub finding ingestion were parallelized because they were independent.
- The auditor used both source analysis and normalized GitHub findings to reduce false positives.
- The reporter enforced GitHub-compatible SARIF requirements before upload.
- The fixer separated dependency remediation from source-code remediation into different branches and PRs.
- Risky fixes were deferred instead of forcing unsafe changes.
- Exact token telemetry was not available in this run, so token counts should be presented as unavailable rather than estimated.
