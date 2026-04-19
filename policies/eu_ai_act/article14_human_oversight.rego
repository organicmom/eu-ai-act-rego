package eu_ai_act.article14

import future.keywords.if
import future.keywords.in
import future.keywords.contains
import data.eu_ai_act.classification

# ─────────────────────────────────────────────────────────────────────────────
# EU AI Act — Article 14: Human Oversight
#
# High-risk AI systems must be designed to allow effective human oversight.
# Persons assigned to human oversight must be able to:
# - Understand the system's capabilities and limitations
# - Monitor system performance and detect anomalies
# - Interpret results and maintain awareness of automation bias
# - Override automated decisions and halt the system
#
# THIS IS THE MOST CRITICAL POLICY FOR AGENTIC AI.
# Any autonomous agent operating in a high-risk domain needs hard gates here.
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# DENY — high-risk systems must define human oversight threshold
# ─────────────────────────────────────────────────────────────────────────────

deny contains msg if {
  classification.effective_risk_tier == "high"
  not input.oversight.human_in_loop_threshold
  msg := "Article 14(1): High-risk AI system must define the conditions under which a human must review before action is taken. Set oversight.human_in_loop_threshold."
}

# ─────────────────────────────────────────────────────────────────────────────
# DENY — override mechanism must be declared
# ─────────────────────────────────────────────────────────────────────────────

deny contains msg if {
  classification.effective_risk_tier == "high"
  not input.oversight.override_mechanism
  msg := "Article 14(4)(b): High-risk AI system must define how a human can intervene, override, or halt the system. Set oversight.override_mechanism."
}

# ─────────────────────────────────────────────────────────────────────────────
# DENY — responsible person must be named
# ─────────────────────────────────────────────────────────────────────────────

deny contains msg if {
  classification.effective_risk_tier == "high"
  not input.oversight.responsible_person
  msg := "Article 14(4): High-risk AI system must name the role or team responsible for human oversight. Set oversight.responsible_person."
}

# ─────────────────────────────────────────────────────────────────────────────
# DENY — employment domain: human review is mandatory for individual decisions
# Article 14(5)(a) + Annex III: employment AI must allow review of decisions
# ─────────────────────────────────────────────────────────────────────────────

deny contains msg if {
  input.system.use_case_domain == "employment"
  not input.oversight.review_required_for_high_impact
  msg := "Article 14(5)(a) + Annex III: Employment AI must allow persons to review, question, and override automated decisions affecting individuals. Set oversight.review_required_for_high_impact = true."
}

# ─────────────────────────────────────────────────────────────────────────────
# DENY — autonomous agents in high-risk domains need explicit autonomy scope
# ─────────────────────────────────────────────────────────────────────────────

deny contains msg if {
  classification.effective_risk_tier == "high"
  input.system.agent_type == "autonomous"
  not input.oversight.autonomy_scope
  msg := "Article 14: Autonomous agents in high-risk domains must explicitly declare the scope of autonomous action (what the agent may do without per-action human approval). Set oversight.autonomy_scope."
}

# ─────────────────────────────────────────────────────────────────────────────
# DENY — fully autonomous agents with NO oversight in high-risk domains
# This is a hard block. An autonomous agent with no human-in-loop threshold
# operating in credit, employment, healthcare etc. is non-compliant.
# ─────────────────────────────────────────────────────────────────────────────

deny contains msg if {
  classification.effective_risk_tier == "high"
  input.system.agent_type == "autonomous"
  input.oversight.human_in_loop_threshold == "none"
  msg := "Article 14: Autonomous agents in high-risk domains CANNOT declare human_in_loop_threshold = 'none'. Human oversight is mandatory."
}

# ─────────────────────────────────────────────────────────────────────────────
# WARN — semi-autonomous agents should also define oversight threshold
# ─────────────────────────────────────────────────────────────────────────────

warn contains msg if {
  input.system.agent_type == "semi_autonomous"
  not input.oversight.human_in_loop_threshold
  msg := "Article 14 (advisory): Semi-autonomous agents should define human_in_loop_threshold even if not strictly high-risk. Best practice for all agentic systems."
}

# ─────────────────────────────────────────────────────────────────────────────
# WARN — credit scoring and healthcare: individual decision review mandatory
# ─────────────────────────────────────────────────────────────────────────────

warn contains msg if {
  input.system.use_case_domain in {"credit_scoring", "healthcare_critical"}
  not input.oversight.review_required_for_high_impact
  msg := sprintf(
    "Article 14(5): '%v' domain AI should allow individual decision review. Set oversight.review_required_for_high_impact = true.",
    [input.system.use_case_domain]
  )
}
