package eu_ai_act.article13_50

import future.keywords.if
import future.keywords.in
import future.keywords.contains
import data.eu_ai_act.classification

# ─────────────────────────────────────────────────────────────────────────────
# EU AI Act — Article 13: Transparency and Provision of Information
#                Article 50: Transparency Obligations for Certain AI Systems
#
# Article 13: Providers of high-risk AI must supply deployers with:
# - Instructions for use
# - Description of capabilities, limitations, performance
# - Human oversight requirements
#
# Article 50: Applies to ALL AI systems interacting with humans:
# - Chatbots must disclose they are AI
# - AI-generated content must be labelled
# - Deep fakes must be clearly marked
# Effective: August 2026
# ─────────────────────────────────────────────────────────────────────────────

# Systems that interact directly with users — Article 50 applies regardless of risk tier
user_facing_domains := {
  "customer_support",
  "content_generation",
  "code_generation",
  "analytics"
}

user_facing := true if {
  input.system.use_case_domain in user_facing_domains
}

user_facing := true if {
  input.system.agent_type in {"semi_autonomous", "autonomous"}
}

# ─────────────────────────────────────────────────────────────────────────────
# DENY — Article 50(1): Any system interacting with humans must disclose AI
# ─────────────────────────────────────────────────────────────────────────────

deny contains msg if {
  user_facing
  not input.transparency.ai_disclosure_implemented
  msg := "Article 50(1): Systems interacting with natural persons must inform users they are interacting with an AI system. Set transparency.ai_disclosure_implemented = true."
}

# ─────────────────────────────────────────────────────────────────────────────
# DENY — Article 50(2): Content generation systems must label synthetic content
# ─────────────────────────────────────────────────────────────────────────────

deny contains msg if {
  input.system.use_case_domain == "content_generation"
  not input.transparency.synthetic_content_labelled
  msg := "Article 50(2): Content generation systems must label AI-generated content as artificially generated. Set transparency.synthetic_content_labelled = true."
}

deny contains msg if {
  input.system.use_case_domain == "content_generation"
  not input.transparency.machine_readable_marking
  msg := "Article 50(2): AI-generated content must include machine-readable marking for downstream detection. Set transparency.machine_readable_marking = true."
}

# ─────────────────────────────────────────────────────────────────────────────
# DENY — Article 13(1): High-risk system provider must supply instructions
# ─────────────────────────────────────────────────────────────────────────────

deny contains msg if {
  classification.effective_risk_tier == "high"
  not input.transparency.instructions_for_use_documented
  msg := "Article 13(1): High-risk AI provider must supply deployer with instructions for use. Set transparency.instructions_for_use_documented = true."
}

deny contains msg if {
  classification.effective_risk_tier == "high"
  not input.transparency.limitations_documented
  msg := "Article 13(3)(b): High-risk AI provider must document limitations and foreseeable circumstances of degraded performance. Set transparency.limitations_documented = true."
}

# ─────────────────────────────────────────────────────────────────────────────
# WARN — autonomous agents interacting with users should disclose AI nature
# ─────────────────────────────────────────────────────────────────────────────

warn contains msg if {
  input.system.agent_type in {"semi_autonomous", "autonomous"}
  not input.transparency.ai_disclosure_implemented
  msg := "Article 50: Autonomous agents interacting with users must disclose AI nature. Recommended even where not strictly user-facing."
}
