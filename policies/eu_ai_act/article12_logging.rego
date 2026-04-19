package eu_ai_act.article12

import future.keywords.if
import future.keywords.contains
import data.eu_ai_act.classification

# ─────────────────────────────────────────────────────────────────────────────
# EU AI Act — Article 12: Record-Keeping and Logging
#
# High-risk AI systems must:
# - Automatically log events throughout operation
# - Retain logs for minimum 6 months (180 days) — deployers
# - Capture inputs, outputs, and human override events
# - Logs must be retrievable for regulatory review
#
# This policy runs at:
# 1. PR time (via Conftest against ai-system.json manifest)
# 2. Kubernetes admission time (via OPA Gatekeeper against pod spec)
# ─────────────────────────────────────────────────────────────────────────────

minimum_retention_days := 180

# ─────────────────────────────────────────────────────────────────────────────
# DENY — logging not enabled for high-risk systems
# ─────────────────────────────────────────────────────────────────────────────

deny contains msg if {
  classification.effective_risk_tier == "high"
  not input.logging.enabled
  msg := "Article 12(1): High-risk AI system must have automatic logging enabled. Set logging.enabled = true."
}

# ─────────────────────────────────────────────────────────────────────────────
# DENY — retention below 180 days for high-risk
# ─────────────────────────────────────────────────────────────────────────────

deny contains msg if {
  classification.effective_risk_tier == "high"
  input.logging.enabled == true
  retention := input.logging.retention_days
  retention < minimum_retention_days
  msg := sprintf(
    "Article 12(1): Log retention %v days is below the 180-day minimum required for high-risk AI systems. Update logging.retention_days >= 180.",
    [retention]
  )
}

# ─────────────────────────────────────────────────────────────────────────────
# DENY — no storage location declared
# ─────────────────────────────────────────────────────────────────────────────

deny contains msg if {
  classification.effective_risk_tier == "high"
  input.logging.enabled == true
  not input.logging.storage_location
  msg := "Article 12: High-risk system logging must declare storage_location. Logs must be retrievable for regulatory review."
}

# ─────────────────────────────────────────────────────────────────────────────
# WARN — outputs not captured in logs
# ─────────────────────────────────────────────────────────────────────────────

warn contains msg if {
  classification.effective_risk_tier == "high"
  input.logging.enabled == true
  not input.logging.covers_outputs
  msg := "Article 12: Logs should capture AI system outputs and decisions (logging.covers_outputs). Required for audit traceability."
}

# ─────────────────────────────────────────────────────────────────────────────
# WARN — human override events not logged
# ─────────────────────────────────────────────────────────────────────────────

warn contains msg if {
  classification.effective_risk_tier == "high"
  not input.logging.covers_human_overrides
  msg := "Article 12 + Article 14: Human override events should be logged (logging.covers_human_overrides). Essential for proving human oversight in audits."
}

# ─────────────────────────────────────────────────────────────────────────────
# WARN — logs not integrity-protected
# ─────────────────────────────────────────────────────────────────────────────

warn contains msg if {
  classification.effective_risk_tier == "high"
  not input.logging.integrity_protected
  msg := "Article 12: Logs for high-risk AI systems should be tamper-evident / write-once (logging.integrity_protected). Unprotected logs may not be accepted as regulatory evidence."
}

# ─────────────────────────────────────────────────────────────────────────────
# Kubernetes admission control variant
# Evaluates pod spec annotations instead of manifest
# Use with OPA Gatekeeper ConstraintTemplate
# ─────────────────────────────────────────────────────────────────────────────

# deny_k8s contains msg if {
#   input.request.object.metadata.labels["eu-ai-act/risk-tier"] == "high"
#   not input.request.object.metadata.annotations["eu-ai-act/logging-enabled"]
#   msg := "Article 12: AI workload pod missing annotation 'eu-ai-act/logging-enabled'. High-risk AI systems require logging."
# }
#
# deny_k8s contains msg if {
#   input.request.object.metadata.labels["eu-ai-act/risk-tier"] == "high"
#   retention := input.request.object.metadata.annotations["eu-ai-act/log-retention-days"]
#   to_number(retention) < 180
#   msg := sprintf("Article 12: Log retention annotation %v days < 180 day minimum for high-risk AI.", [retention])
# }
