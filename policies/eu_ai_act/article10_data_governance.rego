package eu_ai_act.article10

import future.keywords.if
import future.keywords.in
import future.keywords.contains
import data.eu_ai_act.classification

# ─────────────────────────────────────────────────────────────────────────────
# EU AI Act — Article 10: Data and Data Governance
#
# Training, validation, and testing datasets for high-risk AI systems must:
# - Have documented provenance, collection methods, and characteristics
# - Be examined for possible biases
# - Have appropriate data governance and management practices
#
# GDPR obligations stack on top when personal data is processed.
# ─────────────────────────────────────────────────────────────────────────────

gdpr_valid_bases := {
  "consent",
  "contract",
  "legal_obligation",
  "vital_interests",
  "public_task",
  "legitimate_interests",
  "not_applicable"
}

# ─────────────────────────────────────────────────────────────────────────────
# DENY — high-risk systems
# ─────────────────────────────────────────────────────────────────────────────

deny contains msg if {
  classification.effective_risk_tier == "high"
  not input.data_governance.training_data_documented
  msg := "Article 10(2): High-risk AI system training data must be documented (provenance, collection methods, characteristics). Set data_governance.training_data_documented = true and provide data_provenance_url."
}

deny contains msg if {
  classification.effective_risk_tier == "high"
  not input.data_governance.bias_assessment_completed
  msg := "Article 10(2)(f): High-risk AI system datasets must be examined for possible biases. Set data_governance.bias_assessment_completed = true."
}

deny contains msg if {
  classification.effective_risk_tier == "high"
  not input.data_governance.data_provenance_url
  msg := "Article 10: High-risk system requires data provenance documentation. Provide data_governance.data_provenance_url."
}

# ─────────────────────────────────────────────────────────────────────────────
# DENY — GDPR stacking: personal data requires lawful basis declaration
# Article 10 + GDPR Article 6 apply simultaneously
# ─────────────────────────────────────────────────────────────────────────────

deny contains msg if {
  input.data_governance.personal_data_processed == true
  not input.data_governance.gdpr_lawful_basis
  msg := "GDPR Article 6 + EU AI Act Article 10: System processes personal data but no GDPR lawful basis declared. Set data_governance.gdpr_lawful_basis."
}

deny contains msg if {
  input.data_governance.personal_data_processed == true
  basis := input.data_governance.gdpr_lawful_basis
  not basis in gdpr_valid_bases
  msg := sprintf(
    "GDPR Article 6: '%v' is not a valid lawful basis. Must be one of: %v",
    [basis, concat(", ", gdpr_valid_bases)]
  )
}

# ─────────────────────────────────────────────────────────────────────────────
# DENY — special category data (GDPR Art.9) triggers extra obligations
# ─────────────────────────────────────────────────────────────────────────────

deny contains msg if {
  input.data_governance.special_category_data == true
  input.data_governance.gdpr_lawful_basis == "legitimate_interests"
  msg := "GDPR Article 9: Legitimate interests is NOT a valid basis for special category data. Use explicit consent, substantial public interest, or another Art.9(2) basis."
}

# ─────────────────────────────────────────────────────────────────────────────
# WARN — limited-risk systems: data documentation recommended
# ─────────────────────────────────────────────────────────────────────────────

warn contains msg if {
  classification.effective_risk_tier == "limited"
  not input.data_governance.training_data_documented
  msg := "Article 10 (advisory): Limited-risk systems are encouraged to document training data. Good practice ahead of potential reclassification."
}
