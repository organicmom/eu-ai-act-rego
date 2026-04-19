package eu_ai_act.classification

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# ─────────────────────────────────────────────────────────────────────────────
# EU AI Act — Annex III Auto-Classification
# Article 6: Classification rules for high-risk AI systems
#
# Use case domains that ALWAYS trigger high-risk classification
# regardless of what the manifest declares.
# ─────────────────────────────────────────────────────────────────────────────

annex_iii_domains := {
  "employment",
  "credit_scoring",
  "insurance",
  "biometrics",
  "education",
  "law_enforcement",
  "healthcare_critical",
  "critical_infrastructure",
  "migration_asylum",
  "administration_of_justice",
  "essential_public_services"
}

# ─────────────────────────────────────────────────────────────────────────────
# Effective risk tier resolution
# Auto-elevates to "high" when use_case_domain is in Annex III
# ─────────────────────────────────────────────────────────────────────────────

effective_risk_tier := "high" if {
  input.system.use_case_domain in annex_iii_domains
}

effective_risk_tier := input.system.risk_tier if {
  not input.system.use_case_domain in annex_iii_domains
}

# ─────────────────────────────────────────────────────────────────────────────
# DENY: Unacceptable risk — Article 5 prohibited practices
# ─────────────────────────────────────────────────────────────────────────────

deny contains msg if {
  input.system.risk_tier == "unacceptable"
  msg := "Article 5: System is declared 'unacceptable' risk. Deployment prohibited under EU AI Act."
}

# ─────────────────────────────────────────────────────────────────────────────
# WARN: Manifest under-declares risk tier
# ─────────────────────────────────────────────────────────────────────────────

warn contains msg if {
  input.system.risk_tier != "high"
  input.system.use_case_domain in annex_iii_domains
  msg := sprintf(
    "Annex III: use_case_domain '%v' triggers mandatory high-risk classification. Manifest declares '%v'. Update risk_tier to 'high'.",
    [input.system.use_case_domain, input.system.risk_tier]
  )
}

# ─────────────────────────────────────────────────────────────────────────────
# INFO: Autonomous agents in high-risk domains require extra scrutiny
# ─────────────────────────────────────────────────────────────────────────────

warn contains msg if {
  effective_risk_tier == "high"
  input.system.agent_type in {"semi_autonomous", "autonomous"}
  msg := sprintf(
    "High-risk domain '%v' + agent_type '%v': ensure Article 14 human oversight controls are strictly enforced.",
    [input.system.use_case_domain, input.system.agent_type]
  )
}
