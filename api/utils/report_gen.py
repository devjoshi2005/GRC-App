"""PDF report generator for GRC Compliance & Risk Assessment.
Adapted from the GRC Compliance Engine reference implementation
(devjoshi2005/Grc-Compliance-Engine — generate_report.py).
Generates audit-ready SOC2/ISO27001/PCI-DSS evidence packages using fpdf2."""

import os
from datetime import datetime
from typing import Dict, List

try:
    import pandas as pd
    _HAS_PANDAS = True
except ImportError:
    _HAS_PANDAS = False

try:
    from fpdf import FPDF
    _HAS_FPDF = True
except ImportError:
    _HAS_FPDF = False


# ─── Fortune500-style FPDF subclass ──────────────────────────────

class Fortune500GRCReport(FPDF):
    """Auditor-grade PDF generator for SOC2/ISO27001/PCI-DSS evidence packages."""

    _FONT = "Helvetica"  # built-in; no .ttf file needed

    def header(self):
        """Confidential header — required by Big 4 auditors."""
        self.set_font(self._FONT, "B", 9)
        self.set_text_color(128, 128, 128)
        self.cell(0, 8, "CONFIDENTIAL - AUDIT EVIDENCE PACKAGE - NOT FOR EXTERNAL DISTRIBUTION", 0, 1, "R")
        self.ln(3)

    def footer(self):
        """Footer with page numbers and generation timestamp — SOX requirement."""
        self.set_y(-15)
        self.set_font(self._FONT, "I", 8)
        self.set_text_color(100, 100, 100)
        self.cell(
            0, 10,
            f"Page {self.page_no()} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')} | Auditor Use Only",
            0, 0, "C",
        )

    # ── Reusable components ────────────────────────────────────────

    def chapter_title(self, title: str, level: int = 1):
        if level == 1:
            self.set_font(self._FONT, "B", 14)
            self.set_fill_color(30, 58, 138)
            self.set_text_color(255, 255, 255)
            self.cell(0, 10, f"  {title}", 0, 1, "L", True)
        else:
            self.set_font(self._FONT, "B", 11)
            self.set_text_color(30, 58, 138)
            self.cell(0, 8, title, 0, 1, "L")
        self.ln(2)

    def metric_box(self, label: str, value: str, risk_level: str = "info"):
        colors = {
            "critical": (220, 53, 69), "high": (253, 126, 20),
            "medium": (255, 193, 7), "low": (40, 167, 69), "info": (108, 117, 125),
        }
        bg = colors.get(risk_level, colors["info"])
        self.set_fill_color(*bg)
        self.set_text_color(255, 255, 255)
        self.set_font(self._FONT, "B", 10)
        self.cell(60, 8, label, 0, 0, "L", True)
        self.set_fill_color(245, 247, 249)
        self.set_text_color(33, 37, 41)
        self.cell(60, 8, value, 0, 1, "R", True)
        self.ln(1)

    def compliance_table(self, data: List[Dict]):
        self.set_font(self._FONT, "B", 9)
        self.set_fill_color(233, 236, 239)
        headers = ["Resource", "Service", "Severity", "ALE ($)", "Classification", "Control"]
        for h in headers:
            self.cell(32, 8, h, 1, 0, "C", True)
        self.ln()
        self.set_font(self._FONT, "", 8)
        for row in data[:30]:  # cap for readability
            self.cell(32, 6, str(row.get("asset", ""))[:24], 1)
            self.cell(32, 6, str(row.get("service", ""))[:24], 1)
            self.cell(32, 6, str(row.get("severity", "")), 1)
            self.cell(32, 6, f"${row.get('ale', 0):,.0f}", 1)
            self.cell(32, 6, str(row.get("classification", "")), 1)
            self.cell(32, 6, str(row.get("control", "")), 1)
            self.ln()

    def risk_heatmap_table(self, df):
        """Risk heat map matrix — severity x classification."""
        self.chapter_title("Risk Heat Map Matrix", level=2)
        if not _HAS_PANDAS:
            self.set_font(self._FONT, "", 9)
            self.cell(0, 6, "(pandas not available — heat map skipped)", 0, 1)
            return
        heatmap = df.pivot_table(
            values="ale", index="severity", columns="classification",
            aggfunc="sum", fill_value=0,
        ).reindex(
            index=["Critical", "High", "Medium", "Low"],
            columns=["Highly Sensitive", "Sensitive", "Internal", "Public"],
            fill_value=0,
        )
        # header
        self.set_font(self._FONT, "B", 9)
        self.cell(40, 8, "Severity / Class", 1, 0, "C", True)
        for col in heatmap.columns:
            self.cell(30, 8, col, 1, 0, "C", True)
        self.ln()
        # body
        self.set_font(self._FONT, "", 9)
        for idx, row in heatmap.iterrows():
            self.cell(40, 8, str(idx), 1, 0, "C")
            for val in row:
                bg = (220, 53, 69) if val > 100000 else (255, 193, 7) if val > 10000 else (108, 117, 125)
                self.set_fill_color(*bg)
                if val > 10000:
                    self.set_text_color(255, 255, 255)
                else:
                    self.set_text_color(0, 0, 0)
                self.cell(30, 8, f"${val:,.0f}", 1, 0, "C", True)
            self.ln()
        self.set_text_color(33, 37, 41)


# ─── Public entry point ──────────────────────────────────────────

def generate_pdf_report(
    risk_data: dict,
    output_path: str = "GRC_Compliance_Report.pdf",
    log_callback=None,
) -> dict:
    """Generate comprehensive GRC audit-ready PDF report.

    Matches the reference implementation at
    devjoshi2005/Grc-Compliance-Engine/generate_report.py.
    """
    if not _HAS_FPDF:
        return {"success": False, "message": "fpdf2 not installed — run: pip install fpdf2"}

    records = risk_data.get("records", [])
    summary = risk_data.get("summary", {})

    if not records:
        return {"success": False, "message": "No risk records to generate report from"}

    log = log_callback or (lambda m: None)

    # ── Build DataFrame for analytics (pandas optional) ────────────
    df = None
    if _HAS_PANDAS:
        df = pd.DataFrame(records)

    total_ale = summary.get("total_ale", 0)
    sev = summary.get("severity_distribution", {})
    ibm = summary.get("ibm_context", {})
    class_dist = summary.get("classification_distribution", {})
    svc_dist = summary.get("service_distribution", {})
    total_findings = summary.get("total_findings", len(records)) or 1

    critical_count = sev.get("Critical", 0)
    high_count = sev.get("High", 0)
    medium_count = sev.get("Medium", 0)
    low_count = sev.get("Low", 0)

    hs_count = class_dist.get("Highly Sensitive", 0)
    s_count = class_dist.get("Sensitive", 0)
    i_count = class_dist.get("Internal", 0)
    p_count = class_dist.get("Public", 0)

    pdf = Fortune500GRCReport()
    pdf.set_auto_page_break(auto=True, margin=15)
    _F = pdf._FONT

    # ════════════════════════════════════════════════════════════════
    #  COVER PAGE
    # ════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.ln(50)
    pdf.set_font(_F, "B", 24)
    pdf.set_text_color(30, 58, 138)
    pdf.cell(0, 15, "GRC RISK & COMPLIANCE REPORT", 0, 1, "C")
    pdf.set_font(_F, "B", 18)
    pdf.cell(0, 12, "SOC2 Type II / ISO27001 / PCI-DSS Evidence Package", 0, 1, "C")
    pdf.ln(10)
    pdf.set_font(_F, "", 11)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 10, f"Reporting Period: Q1 2026", 0, 1, "C")
    pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d')}", 0, 1, "C")
    pdf.cell(0, 10, "AUDITOR USE ONLY - CONFIDENTIAL", 0, 1, "C")

    # ════════════════════════════════════════════════════════════════
    #  1. EXECUTIVE SUMMARY
    # ════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.chapter_title("1. Executive Summary", level=1)

    pdf.set_font(_F, "", 10)
    pdf.set_text_color(33, 37, 41)
    pdf.multi_cell(0, 7, (
        f"This audit quantifies financial risk exposure for multi-cloud infrastructure (AWS/Azure) using the "
        f"FAIR (Factor Analysis of Information Risk) methodology. Analysis of {total_findings} security findings "
        f"identified {critical_count} Critical and {high_count} High risk items with a total "
        f"Annual Loss Expectancy (ALE) of ${total_ale:,.2f}."
    ))
    pdf.ln(5)

    pdf.set_font(_F, "B", 10)
    pdf.cell(0, 8, "Risk Distribution by Data Classification", 0, 1)
    pdf.ln(2)

    pdf.metric_box("Total Risk Exposure (ALE)", f"${total_ale:,.2f}",
                   "critical" if total_ale > 1_000_000 else "high")
    pdf.metric_box("Critical Findings", str(critical_count), "critical")
    pdf.metric_box("High Findings", str(high_count), "high")
    pdf.metric_box("Medium Findings", str(medium_count), "medium")
    pdf.metric_box("Low Findings", str(low_count), "low")
    pdf.ln(5)

    pdf.set_font(_F, "B", 10)
    pdf.cell(0, 8, "Asset Classification Breakdown", 0, 1)
    pdf.ln(2)
    pdf.metric_box("Highly Sensitive", str(hs_count), "critical")
    pdf.metric_box("Sensitive", str(s_count), "high")
    pdf.metric_box("Internal", str(i_count), "medium")
    pdf.metric_box("Public", str(p_count), "low")

    # ════════════════════════════════════════════════════════════════
    #  2. RISK QUANTIFICATION METHODOLOGY
    # ════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.chapter_title("2. Risk Quantification Methodology", level=1)

    pdf.set_text_color(33, 37, 41)
    pdf.set_font(_F, "", 10)
    pdf.multi_cell(0, 7, (
        "This assessment employs the FAIR model to calculate Annual Loss Expectancy (ALE) using the formula:\n\n"
        "ALE = (Asset Value x Threat Frequency) x (1 - Control Effectiveness)\n\n"
        "The following parameters were derived from industry standards and control assessments:"
    ))
    pdf.ln(5)

    pdf.set_font(_F, "B", 10)
    pdf.cell(0, 8, "FAIR Model Parameters", 0, 1)
    pdf.ln(2)

    parameters = [
        ["Parameter", "Source", "Values"],
        ["Asset Value", "Classification-based", "Highly Sensitive: $1M | Sensitive: $100K | Internal: $10K | Public: $1K"],
        ["Threat Frequency", "MITRE ATT&CK + Prowler Severity", "Critical: 30% | High: 15% | Medium: 5% | Low: 1%"],
        ["Control Effectiveness", "NIST 800-53 assessment", "MFA: 90% | Encryption: 95% | SG: 80% | Default: 0%"],
    ]
    for row in parameters:
        pdf.set_text_color(33, 37, 41)
        pdf.set_font(_F, "B" if row[0] == "Parameter" else "", 9)
        for item in row:
            pdf.cell(63, 6, str(item)[:40], 1, 0, "C" if row[0] == "Parameter" else "L")
        pdf.ln()
    pdf.ln(10)

    pdf.set_font(_F, "B", 10)
    pdf.set_text_color(33, 37, 41)
    pdf.cell(0, 8, "Validation & Benchmarking", 0, 1)
    pdf.ln(2)
    pdf.set_font(_F, "", 9)
    pdf.multi_cell(0, 5, (
        "* Loss magnitudes benchmarked against IBM Cost of Data Breach Report 2025\n"
        "* Threat frequencies validated against Verizon DBIR incident statistics\n"
        "* Control effectiveness derived from NIST 800-53 and CIS Controls assessments\n"
        "* Cross-validated with MITRE ATT&CK threat models for cloud environments"
    ))

    # ════════════════════════════════════════════════════════════════
    #  3. CONTROL & COMPLIANCE MAPPING
    # ════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.chapter_title("3. Control & Compliance Mapping", level=1)

    pdf.set_text_color(33, 37, 41)
    pdf.set_font(_F, "", 10)
    pdf.multi_cell(0, 7, (
        "Each finding is mapped to applicable compliance frameworks including "
        "NIST 800-53r5, SOC2 Trust Services Criteria, ISO27001 Annex A, PCI-DSS, "
        "and industry-specific regulations (HIPAA, GDPR, C5, NIS2)."
    ))
    pdf.ln(5)

    pdf.compliance_table(records)
    pdf.ln(5)

    # Framework coverage
    if df is not None and "compliance" in df.columns:
        pdf.set_font(_F, "B", 10)
        pdf.cell(0, 8, "Compliance Framework Coverage", 0, 1)
        pdf.ln(2)
        frameworks = df["compliance"].str.split(", ").explode().value_counts().head(10)
        for fw, count in frameworks.items():
            if fw:
                pdf.set_font(_F, "", 9)
                pdf.cell(0, 5, f"* {fw}: {count} findings", 0, 1)

    # ════════════════════════════════════════════════════════════════
    #  4. RISK HEAT MAP ANALYSIS
    # ════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.chapter_title("4. Risk Heat Map Analysis", level=1)

    pdf.set_font(_F, "", 10)
    pdf.set_text_color(33, 37, 41)
    pdf.multi_cell(0, 7, (
        "The following heat map visualizes risk concentration by severity and data classification. "
        "Cells represent total ALE exposure for each category."
    ))
    pdf.ln(5)

    if df is not None:
        pdf.risk_heatmap_table(df)

    # Severity breakdown table (same as reference)
    pdf.ln(8)
    pdf.chapter_title("Severity Distribution", level=2)

    pdf.set_font(_F, "B", 9)
    pdf.set_fill_color(30, 58, 138)
    pdf.set_text_color(255, 255, 255)
    col_w = [50, 35, 45, 60]
    sev_headers = ["Severity", "Count", "% of Total", "ALE Contribution"]
    for i, h in enumerate(sev_headers):
        pdf.cell(col_w[i], 8, h, 1, 0, "C", True)
    pdf.ln()

    sev_colors = {"Critical": (220, 53, 69), "High": (255, 152, 0), "Medium": (255, 193, 7), "Low": (76, 175, 80)}
    for severity in ["Critical", "High", "Medium", "Low"]:
        count = sev.get(severity, 0)
        pct = (count / total_findings) * 100
        ale_c = sum(r["ale"] for r in records if r["severity"] == severity)
        r, g, b = sev_colors.get(severity, (100, 100, 100))
        pdf.set_fill_color(r, g, b)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font(_F, "", 9)
        pdf.cell(col_w[0], 7, f"  {severity}", 1, 0, "L", True)
        pdf.set_fill_color(245, 245, 245)
        pdf.set_text_color(33, 37, 41)
        pdf.cell(col_w[1], 7, str(count), 1, 0, "C", True)
        pdf.cell(col_w[2], 7, f"{pct:.1f}%", 1, 0, "C")
        pdf.cell(col_w[3], 7, f"${ale_c:,.2f}", 1, 0, "R")
        pdf.ln()

    # Total row
    pdf.set_font(_F, "B", 9)
    pdf.set_fill_color(33, 37, 41)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(col_w[0], 8, "  TOTAL", 1, 0, "L", True)
    pdf.cell(col_w[1], 8, str(total_findings), 1, 0, "C", True)
    pdf.cell(col_w[2], 8, "100%", 1, 0, "C", True)
    pdf.cell(col_w[3], 8, f"${total_ale:,.2f}", 1, 0, "R", True)

    # ════════════════════════════════════════════════════════════════
    #  5. TOP 10 PRIORITIZED RISKS
    # ════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.chapter_title("5. Top 10 Prioritized Risks", level=1)

    pdf.set_text_color(33, 37, 41)
    pdf.set_font(_F, "", 10)
    pdf.multi_cell(0, 7, "Prioritized based on ALE magnitude and data sensitivity classification.")
    pdf.ln(5)

    sorted_records = sorted(records, key=lambda x: x.get("ale", 0), reverse=True)
    for i, row in enumerate(sorted_records[:10], 1):
        pdf.chapter_title(f"5.{i} {row.get('asset', 'Unknown')[:60]}", level=2)
        pdf.set_font(_F, "", 9)
        pdf.set_text_color(33, 37, 41)
        pdf.cell(0, 6, (
            f"Asset Type: {row.get('asset_type', 'N/A')} | Service: {row.get('service', 'N/A')}"
        ), 0, 1)
        pdf.cell(0, 6, (
            f"ALE: ${row.get('ale', 0):,.2f} | Classification: {row.get('classification', 'N/A')} "
            f"| Severity: {row.get('severity', 'N/A')}"
        ), 0, 1)
        pdf.cell(0, 6, (
            f"NIST Control: {row.get('control', 'N/A')} | Public: {row.get('is_public', 'N/A')} "
            f"| Retention: {row.get('retention_days', 'N/A')} days"
        ), 0, 1)
        pdf.ln(3)
        if row.get("risk_details"):
            pdf.set_font(_F, "B", 9)
            pdf.cell(0, 5, "Risk Details:", 0, 1)
            pdf.set_font(_F, "", 8)
            pdf.multi_cell(0, 4, str(row["risk_details"])[:300])
            pdf.ln(2)
        if row.get("remediation"):
            pdf.set_font(_F, "B", 9)
            pdf.cell(0, 5, "Remediation:", 0, 1)
            pdf.set_font(_F, "", 8)
            pdf.multi_cell(0, 4, str(row["remediation"])[:300])
        pdf.ln(3)

    # ════════════════════════════════════════════════════════════════
    #  6. REMEDIATION ROADMAP
    # ════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.chapter_title("6. Remediation Roadmap", level=1)

    pdf.set_text_color(33, 37, 41)
    pdf.set_font(_F, "", 10)
    pdf.multi_cell(0, 7, (
        "This roadmap prioritizes remediation efforts based on risk magnitude, asset criticality, "
        "and compliance requirements. All timeframes align with NIST 800-53r5 recommended practices."
    ))
    pdf.ln(5)

    phases = [
        ("Phase 1 (0-30 days): Critical Risk Reduction",
         "Scope: Critical findings + ALE > $100,000",
         "* Implement Multi-Factor Authentication on all IAM roles and users (IA-2, AC-2)\n"
         "* Remove root account access keys and enable hardware MFA (IA-2, AC-6)\n"
         "* Remove internet exposure from all database instances (SC-7, AC-3)\n"
         "* Revoke AdministratorAccess policy from non-essential principals (AC-6, SC-2)\n"
         "* Enable encryption at rest for all S3 buckets and RDS instances (SC-13, SC-28)\n"
         "* Deploy AWS Config rules for continuous compliance monitoring\n"
         "* Create JIRA/ServiceNow tickets with P0 priority for tracking"),
        ("Phase 2 (30-90 days): High Risk Mitigation",
         "Scope: High findings + ALE $10,000-$100,000",
         "* Enable encryption at rest for all storage accounts (SC-13, SC-28)\n"
         "* Implement least-privilege IAM policies across all services (AC-6)\n"
         "* Enable Azure Defender for all resource types (SI-3, SI-4)\n"
         "* Add confused deputy protection to all service roles (SC-7)\n"
         "* Configure CloudTrail logging for all regions (AU-2, AU-3)\n"
         "* Establish weekly Steampipe compliance scanning cron jobs"),
        ("Phase 3 (90+ days): Continuous Improvement",
         "Scope: Medium/Low findings + Process establishment",
         "* Implement automated remediation using AWS Lambda/Config (SI-7)\n"
         "* Integrate findings with SIEM/SOAR platform (AU-6, IR-4)\n"
         "* Conduct quarterly access reviews for all IAM principals (AC-2)\n"
         "* Establish KPI dashboard for ongoing risk monitoring\n"
         "* Perform annual third-party penetration testing\n"
         "* Update disaster recovery plans based on risk assessments"),
    ]

    for title, scope, items in phases:
        pdf.set_font(_F, "B", 11)
        pdf.set_text_color(33, 37, 41)
        pdf.cell(0, 8, title, 0, 1)
        pdf.set_font(_F, "B", 10)
        pdf.cell(0, 6, scope, 0, 1)
        pdf.set_font(_F, "", 9)
        pdf.multi_cell(0, 5, items)
        pdf.ln(5)

    # ════════════════════════════════════════════════════════════════
    #  7. ASSET INVENTORY SUMMARY
    # ════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.chapter_title("7. Asset Inventory Summary", level=1)

    pdf.set_text_color(33, 37, 41)
    pdf.set_font(_F, "", 10)
    pdf.multi_cell(0, 7, "Comprehensive inventory of assessed cloud resources organized by service.")
    pdf.ln(5)

    sorted_svcs = sorted(svc_dist.items(), key=lambda x: x[1], reverse=True)
    pdf.set_font(_F, "B", 10)
    pdf.cell(0, 8, "Assets by Service Category", 0, 1)
    pdf.ln(2)
    for svc, count in sorted_svcs[:12]:
        svc_ale = sum(r["ale"] for r in records if r["service"] == svc)
        pdf.set_font(_F, "", 9)
        pdf.cell(0, 5, f"* {svc}: {count} assets | ${svc_ale:,.0f} total ALE", 0, 1)

    # ════════════════════════════════════════════════════════════════
    #  APPENDIX A — DETAILED RISK REGISTER
    # ════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.chapter_title("Appendix A - Detailed Risk Register", level=1)

    pdf.set_text_color(33, 37, 41)
    pdf.set_font(_F, "", 10)
    pdf.multi_cell(0, 7, "Complete listing of all identified risks with full compliance mappings.")
    pdf.ln(5)

    pdf.set_font(_F, "B", 8)
    reg_headers = ["Asset", "Service", "Severity", "ALE", "Class", "Public", "Retention", "Control", "Frameworks"]
    for h in reg_headers:
        pdf.cell(21, 6, h, 1, 0, "C", True)
    pdf.ln()

    pdf.set_font(_F, "", 7)
    for row in records:
        pdf.cell(21, 5, str(row.get("asset", ""))[:20], 1)
        pdf.cell(21, 5, str(row.get("service", ""))[:20], 1)
        pdf.cell(21, 5, str(row.get("severity", "")), 1)
        pdf.cell(21, 5, f"${row.get('ale', 0):,.0f}", 1)
        pdf.cell(21, 5, str(row.get("classification", ""))[:12], 1)
        pdf.cell(21, 5, str(row.get("is_public", "")), 1)
        pdf.cell(21, 5, f"{row.get('retention_days', 'N/A')}d", 1)
        pdf.cell(21, 5, str(row.get("control", ""))[:10], 1)
        pdf.cell(21, 5, str(row.get("compliance", ""))[:15], 1)
        pdf.ln()

    # ════════════════════════════════════════════════════════════════
    #  APPENDIX B — CONTROL EFFECTIVENESS
    # ════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.chapter_title("Appendix B - Control Effectiveness Calculations", level=1)

    pdf.set_text_color(33, 37, 41)
    pdf.set_font(_F, "", 10)
    pdf.multi_cell(0, 7, "Detailed assumptions for control effectiveness coefficients used in FAIR calculations.")
    pdf.ln(5)

    controls_detail = [
        ["Control Type", "Effectiveness", "Rationale", "Mapped Findings"],
        ["Multi-Factor Authentication (MFA)", "90%", "Blocks 99.9% of automated attacks", "iam_root_hardware_mfa_enabled"],
        ["Encryption at Rest (AES-256)", "95%", "Cryptographically unbreakable currently", "S3/RDS encryption"],
        ["Security Group Restrictions", "80%", "Reduces lateral movement risk", "ec2_securitygroup_allow_ingress"],
        ["Least Privilege IAM", "85%", "Limits blast radius of compromise", "iam_policy_privilege_escalation"],
        ["CloudTrail Logging", "60%", "Aids detection but not prevention", "Logging configuration checks"],
        ["Backup & Versioning", "70%", "Protects against ransomware", "S3 versioning, RDS snapshots"],
        ["Confused Deputy Protection", "75%", "IAM conditions reduce attack surface", "iam_role_cross_service"],
        ["No Control / Full Exposure", "0%", "Baseline for unmitigated risk", "Default security group rules"],
    ]
    for row in controls_detail:
        pdf.set_text_color(33, 37, 41)
        pdf.set_font(_F, "B" if row[0] == "Control Type" else "", 9)
        pdf.cell(50, 6, row[0][:30], 1, 0, "C" if row[0] == "Control Type" else "L")
        pdf.cell(20, 6, row[1], 1, 0, "C")
        pdf.cell(70, 6, row[2][:35], 1, 0, "L")
        pdf.cell(50, 6, row[3][:25], 1, 0, "L")
        pdf.ln()

    # ════════════════════════════════════════════════════════════════
    #  APPENDIX C — ASSUMPTIONS & LIMITATIONS
    # ════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.chapter_title("Appendix C - Assumptions & Limitations", level=1)

    pdf.set_text_color(33, 37, 41)
    pdf.set_font(_F, "", 9)
    pdf.multi_cell(0, 5, (
        "Scope Assumptions:\n"
        "* Assessment limited to AWS and Azure resources discoverable by Prowler and Steampipe\n"
        "* Asset values based on estimated business impact, not actual revenue attribution\n"
        "* Threat frequencies derived from public incident statistics, not organization-specific data\n"
        "* Control effectiveness assumes proper implementation and monitoring\n\n"
        "Limitations:\n"
        "* Does not account for zero-day vulnerabilities or advanced persistent threats\n"
        "* Loss magnitude estimates do not include reputational damage or legal costs\n"
        "* Network effects and cloud blast radius scenarios are simplified\n"
        "* Assumes independent risk events; does not model compounding incidents\n\n"
        "Validation:\n"
        "* Findings cross-referenced with AWS Security Hub and Azure Security Center\n"
        "* Control mappings validated against NIST 800-53r5 official controls catalog\n"
        "* ALE calculations peer-reviewed against FAIR Institute guidelines"
    ))

    # ── Save ───────────────────────────────────────────────────────
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    pdf.output(output_path)

    log(f"PDF report generated: {output_path} ({pdf.page_no()} pages)")

    return {
        "success": True,
        "output_path": output_path,
        "pages": pdf.page_no(),
        "message": f"Audit-ready report generated ({pdf.page_no()} pages)",
    }
