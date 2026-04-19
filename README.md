# eu-ai-act-policies

**Shift-left EU AI Act compliance using OPA/Rego.**

Enforce EU AI Act obligations at PR time, not audit time. Rego policy bundle + JSON schema + GitHub Actions workflow. Drop into any repo that ships AI systems.

> Full enforcement deadline: **August 2, 2026**. This is 3.5 months away.

---

## What this is

A policy-as-code library that translates EU AI Act articles into machine-executable Rego rules evaluated by [Conftest](https://www.conftest.dev/) and [OPA](https://www.openpolicyagent.org/).

Every AI system deployer is required to maintain an AI inventory, classify systems by risk, enforce human oversight, enable logging, and implement transparency disclosures. This library makes those obligations testable in CI/CD — **blocking non-compliant deployments before they reach production**.

---

## Coverage

| Article | Obligation | Enforcement point |
|---------|-----------|-------------------|
| Art. 5  | Prohibited practices (unacceptable risk) | PR gate |
| Art. 6 / Annex III | Auto-classification of high-risk domains | PR gate |
| Art. 9  | Risk management system | PR gate |
| Art. 10 | Data governance + GDPR stacking | PR gate |
| Art. 12 | Logging + 180-day retention | PR gate + k8s admission |
| Art. 13 | Transparency (instructions, limitations) | PR gate |
| Art. 14 | Human oversight — critical for agentic AI | PR gate |
| Art. 50 | AI disclosure + synthetic content labelling | PR gate |
| Art. 72/73 | Post-market monitoring + incident reporting | PR gate |

---

## Quick start

### 1. Add your AI system manifest

Create `ai-system.json` in your repo root (or alongside your service's deployment manifests). See `schemas/ai-system.example.json` for a complete example.

```json
{
  "system": {
    "id": "my-ai-system",
    "name": "My AI System",
    "version": "1.0.0",
    "risk_tier": "high",
    "use_case_domain": "employment",
    "agent_type": "semi_autonomous",
    "deployer": "Your Organisation"
  },
  "oversight": {
    "human_in_loop_threshold": "All decisions affecting individuals require human review",
    "override_mechanism": "Reviewer can exclude any AI recommendation",
    "responsible_person": "Head of AI Governance"
  },
  "logging": {
    "enabled": true,
    "retention_days": 365,
    "storage_location": "s3://your-audit-logs/"
  }
  ...
}
```

### 2. Run Conftest locally

```bash
# Install Conftest
brew install conftest  # or download from github.com/open-policy-agent/conftest

# Test your manifest
conftest test ai-system.json --policy policies/ --all-namespaces

# Example passing output:
# PASS - ai-system.json - eu_ai_act.article14 - data.eu_ai_act.article14.deny is empty

# Example failing output:
# FAIL - ai-system.json - eu_ai_act.article14
# Article 14(1): High-risk AI system must define human_in_loop_threshold
```

### 3. Add the GitHub Actions workflow

Copy `github/eu-ai-act.yml` to `.github/workflows/eu-ai-act.yml` in your repo.

The workflow:
- Triggers on any PR that modifies `ai-system.json`
- Runs all Rego policies via Conftest
- Runs OPA unit tests
- Posts a compliance report as a PR comment
- **Blocks merge if any DENY rules fire**
- Warns (but does not block) on WARN rules

### 4. Run OPA unit tests

```bash
# Install OPA
brew install opa  # or download from openpolicyagent.org

# Run all tests
opa test policies/ tests/ -v
```

---

## Policy structure

```
policies/
  eu_ai_act/
    classification.rego         # Annex III auto-classification
    article9_risk_management.rego
    article10_data_governance.rego
    article12_logging.rego
    article13_50_transparency.rego
    article14_human_oversight.rego  ← most critical for agentic AI

tests/
  eu_ai_act_test.rego           # OPA unit tests for all policies

schemas/
  ai-system.schema.json         # JSON Schema for the manifest
  ai-system.example.json        # Fully populated example

github/
  eu-ai-act.yml                 # GitHub Actions workflow
```

---

## Agentic AI — Article 14 in focus

The strictest policies apply to autonomous agents. Any `agent_type` of `autonomous` or `semi_autonomous` in a high-risk domain will be denied unless it declares:

- `oversight.human_in_loop_threshold` — explicit condition triggering human review
- `oversight.override_mechanism` — how a human can intervene or halt
- `oversight.autonomy_scope` — exactly what the agent may do without per-action approval
- `oversight.human_in_loop_threshold != "none"` — hard block on fully unsupervised agents

This directly maps to Article 14(1), 14(4)(b), and 14(5)(a).

---

## Annex III auto-classification

Declaring `risk_tier: "minimal"` does not protect you from Annex III. If your `use_case_domain` is in the list below, the classification policy **automatically elevates** the effective risk tier to `high` and all high-risk policies apply:

- `employment`
- `credit_scoring`
- `insurance`
- `biometrics`
- `education`
- `law_enforcement`
- `healthcare_critical`
- `critical_infrastructure`
- `migration_asylum`
- `administration_of_justice`
- `essential_public_services`

---

## Kubernetes admission (Article 12)

For runtime enforcement at deploy time, the Article 12 policy includes a commented-out OPA Gatekeeper `ConstraintTemplate` variant. Pods with label `eu-ai-act/risk-tier: high` that lack the annotation `eu-ai-act/log-retention-days >= 180` will be denied admission.

See `policies/eu_ai_act/article12_logging.rego` for the commented k8s variant.

---

## GDPR stacking

GDPR and the EU AI Act apply simultaneously. The Article 10 policy enforces:

- `gdpr_lawful_basis` is required when `personal_data_processed: true`
- `legitimate_interests` is blocked as a basis when `special_category_data: true` (GDPR Art. 9)

Fines are additive: EU AI Act (€15M / 3% turnover) + GDPR (€20M / 4% turnover).

---

## Extending for your organisation

Fork this repo and add an `extensions/` directory for organisation-specific policies:

```rego
package my_org.ai_extensions

import data.eu_ai_act.classification

# Example: Require ARB approval reference for all high-risk systems
deny contains msg if {
  classification.effective_risk_tier == "high"
  not input.system.arb_approval_id
  msg := "Internal: High-risk AI systems require ARB approval ID before deployment."
}
```

---

## Contributing

PRs welcome for:
- Additional article coverage (Art. 11 technical documentation, Art. 15 accuracy)
- Gatekeeper ConstraintTemplate manifests
- GitLab CI / Jenkins / Azure DevOps workflow variants
- Policy bundles for sector-specific extensions (financial services, healthcare)

---

## Disclaimer

This policy library is a practitioner tool to help teams implement shift-left EU AI Act compliance controls. It is not legal advice. Policy interpretations are based on the official EU AI Act text (Regulation (EU) 2024/1689). Consult qualified legal counsel for compliance decisions affecting your organisation.

Enforcement deadline: **August 2, 2026** (high-risk systems and transparency obligations).
