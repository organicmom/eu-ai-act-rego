package eu_ai_act.article14_test

import future.keywords.if

# ─────────────────────────────────────────────────────────────────────────────
# Tests for Article 14 — Human Oversight
# Run with: opa test policies/ -v
# ─────────────────────────────────────────────────────────────────────────────

# Helper: fully compliant high-risk employment manifest
compliant_high_risk := {
  "system": {
    "id": "test-hr-tool",
    "name": "Test HR Tool",
    "version": "1.0.0",
    "risk_tier": "high",
    "use_case_domain": "employment",
    "agent_type": "semi_autonomous",
    "deployer": "Test Corp"
  },
  "data_governance": {
    "training_data_documented": true,
    "bias_assessment_completed": true,
    "gdpr_lawful_basis": "legitimate_interests",
    "personal_data_processed": true,
    "special_category_data": false
  },
  "logging": {
    "enabled": true,
    "retention_days": 365,
    "storage_location": "s3://test-logs/",
    "covers_inputs": true,
    "covers_outputs": true,
    "covers_human_overrides": true,
    "integrity_protected": true
  },
  "oversight": {
    "human_in_loop_threshold": "All candidate decisions require recruiter review",
    "override_mechanism": "Recruiter can exclude any ranked candidate",
    "responsible_person": "Head of HR Technology",
    "review_required_for_high_impact": true,
    "autonomy_scope": "System may only rank CVs. Cannot contact candidates."
  },
  "transparency": {
    "ai_disclosure_implemented": true,
    "synthetic_content_labelled": false,
    "machine_readable_marking": false,
    "instructions_for_use_documented": true,
    "limitations_documented": true
  },
  "risk_management": {
    "risk_management_documented": true,
    "residual_risks_identified": true,
    "risk_assessment_url": "https://docs.internal/risk",
    "post_market_monitoring_plan": true,
    "incident_reporting_process": true
  },
  "conformity": {
    "conformity_assessment_completed": true,
    "ce_marking_affixed": false,
    "eu_database_registered": false
  }
}

# ─── Passing tests ────────────────────────────────────────────────────────────

test_compliant_system_no_denies if {
  count(data.eu_ai_act.article14.deny) == 0 with input as compliant_high_risk
}

# ─── Article 14 denial tests ──────────────────────────────────────────────────

test_deny_missing_oversight_threshold if {
  manifest := json.patch(compliant_high_risk, [
    {"op": "remove", "path": "/oversight/human_in_loop_threshold"}
  ])
  denies := data.eu_ai_act.article14.deny with input as manifest
  count(denies) > 0
}

test_deny_missing_override_mechanism if {
  manifest := json.patch(compliant_high_risk, [
    {"op": "remove", "path": "/oversight/override_mechanism"}
  ])
  denies := data.eu_ai_act.article14.deny with input as manifest
  count(denies) > 0
}

test_deny_missing_responsible_person if {
  manifest := json.patch(compliant_high_risk, [
    {"op": "remove", "path": "/oversight/responsible_person"}
  ])
  denies := data.eu_ai_act.article14.deny with input as manifest
  count(denies) > 0
}

test_deny_employment_without_review_flag if {
  manifest := json.patch(compliant_high_risk, [
    {"op": "replace", "path": "/oversight/review_required_for_high_impact", "value": false}
  ])
  denies := data.eu_ai_act.article14.deny with input as manifest
  count(denies) > 0
}

test_deny_autonomous_agent_no_autonomy_scope if {
  manifest := json.patch(compliant_high_risk, [
    {"op": "replace", "path": "/system/agent_type", "value": "autonomous"},
    {"op": "remove", "path": "/oversight/autonomy_scope"}
  ])
  denies := data.eu_ai_act.article14.deny with input as manifest
  count(denies) > 0
}

test_deny_autonomous_agent_threshold_none if {
  manifest := json.patch(compliant_high_risk, [
    {"op": "replace", "path": "/system/agent_type", "value": "autonomous"},
    {"op": "replace", "path": "/oversight/human_in_loop_threshold", "value": "none"}
  ])
  denies := data.eu_ai_act.article14.deny with input as manifest
  count(denies) > 0
}

# ─── Article 12 tests ─────────────────────────────────────────────────────────

test_deny_logging_disabled if {
  manifest := json.patch(compliant_high_risk, [
    {"op": "replace", "path": "/logging/enabled", "value": false}
  ])
  denies := data.eu_ai_act.article12.deny with input as manifest
  count(denies) > 0
}

test_deny_logging_retention_below_180 if {
  manifest := json.patch(compliant_high_risk, [
    {"op": "replace", "path": "/logging/retention_days", "value": 90}
  ])
  denies := data.eu_ai_act.article12.deny with input as manifest
  count(denies) > 0
}

test_pass_logging_retention_exactly_180 if {
  manifest := json.patch(compliant_high_risk, [
    {"op": "replace", "path": "/logging/retention_days", "value": 180}
  ])
  denies := data.eu_ai_act.article12.deny with input as manifest
  count(denies) == 0
}

# ─── Annex III classification tests ──────────────────────────────────────────

test_annex_iii_elevates_credit_to_high if {
  manifest := json.patch(compliant_high_risk, [
    {"op": "replace", "path": "/system/use_case_domain", "value": "credit_scoring"},
    {"op": "replace", "path": "/system/risk_tier", "value": "minimal"}
  ])
  data.eu_ai_act.classification.effective_risk_tier == "high" with input as manifest
}

test_non_annex_iii_keeps_declared_tier if {
  manifest := json.patch(compliant_high_risk, [
    {"op": "replace", "path": "/system/use_case_domain", "value": "internal_tooling"},
    {"op": "replace", "path": "/system/risk_tier", "value": "minimal"}
  ])
  data.eu_ai_act.classification.effective_risk_tier == "minimal" with input as manifest
}

# ─── Article 10 GDPR stacking tests ──────────────────────────────────────────

test_deny_personal_data_no_lawful_basis if {
  manifest := json.patch(compliant_high_risk, [
    {"op": "replace", "path": "/data_governance/personal_data_processed", "value": true},
    {"op": "remove", "path": "/data_governance/gdpr_lawful_basis"}
  ])
  denies := data.eu_ai_act.article10.deny with input as manifest
  count(denies) > 0
}

test_deny_special_category_with_legitimate_interests if {
  manifest := json.patch(compliant_high_risk, [
    {"op": "replace", "path": "/data_governance/special_category_data", "value": true},
    {"op": "replace", "path": "/data_governance/gdpr_lawful_basis", "value": "legitimate_interests"}
  ])
  denies := data.eu_ai_act.article10.deny with input as manifest
  count(denies) > 0
}

# ─── Article 5 prohibited practice test ──────────────────────────────────────

test_deny_unacceptable_risk_system if {
  manifest := json.patch(compliant_high_risk, [
    {"op": "replace", "path": "/system/risk_tier", "value": "unacceptable"}
  ])
  denies := data.eu_ai_act.classification.deny with input as manifest
  count(denies) > 0
}
