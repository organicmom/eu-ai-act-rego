package eu_ai_act.article9

import future.keywords.if
import future.keywords.contains
import data.eu_ai_act.classification

# ─────────────────────────────────────────────────────────────────────────────
# EU AI Act — Article 9: Risk Management System
#
# High-risk AI systems must have a risk management system that is:
# - Established, implemented, documented, and maintained
# - Continuous and iterative throughout the system lifecycle
# - Covering identification, evaluation, and mitigation of risks
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# DENY rules — high-risk systems only
# ─────────────────────────────────────────────────────────────────────────────

deny contains msg if {
  classification.effective_risk_tier == "high"
  not input.risk_management.risk_management_documented
  msg := "Article 9(1): High-risk AI system must have a documented risk management system. Set risk_management.risk_management_documented = true and provide risk_assessment_url."
}

deny contains msg if {
  classification.effective_risk_tier == "high"
  not input.risk_management.residual_risks_identified
  msg := "Article 9(2)(d): Residual risks must be identified and communicated to deployers. Set risk_management.residual_risks_identified = true."
}

deny contains msg if {
  classification.effective_risk_tier == "high"
  not input.risk_management.risk_assessment_url
  msg := "Article 9: High-risk system requires a risk assessment URL. Provide a link to the risk assessment document in risk_management.risk_assessment_url."
}

# ─────────────────────────────────────────────────────────────────────────────
# DENY — post-market monitoring (Article 72) required for high-risk
# ─────────────────────────────────────────────────────────────────────────────

deny contains msg if {
  classification.effective_risk_tier == "high"
  not input.risk_management.post_market_monitoring_plan
  msg := "Article 72: High-risk AI systems require a post-market monitoring plan. Set risk_management.post_market_monitoring_plan = true."
}

# ─────────────────────────────────────────────────────────────────────────────
# DENY — incident reporting (Article 73) required for high-risk
# ─────────────────────────────────────────────────────────────────────────────

deny contains msg if {
  classification.effective_risk_tier == "high"
  not input.risk_management.incident_reporting_process
  msg := "Article 73: High-risk AI systems require a serious incident reporting process. Set risk_management.incident_reporting_process = true."
}

# ─────────────────────────────────────────────────────────────────────────────
# WARN — conformity assessment for high-risk (Article 43/48/49)
# Not a hard deny — may be in progress — but flag it
# ─────────────────────────────────────────────────────────────────────────────

warn contains msg if {
  classification.effective_risk_tier == "high"
  not input.conformity.conformity_assessment_completed
  msg := "Article 43: High-risk AI system conformity assessment not yet completed. Required before go-live."
}

warn contains msg if {
  classification.effective_risk_tier == "high"
  not input.conformity.eu_database_registered
  msg := "Article 49: High-risk AI systems must be registered in the EU AI database before deployment."
}
