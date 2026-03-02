"""
GRC Compliance Engine — Flask Application
Full-stack multi-cloud GRC scanning, remediation, and risk quantification.
"""

import json
import os
import sys
import uuid
import threading
import time
import re
from pathlib import Path
from datetime import datetime

# Ensure api/ is on the import path
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, render_template, request, jsonify, send_file, session

from config import (
    COMPLIANCE_FRAMEWORKS, OPENAI_MODELS, OUTPUT_DIR, UPLOAD_DIR, POLICY_DIR,
    DEFAULT_STEAMPIPE_COLUMNS, AWS_SERVICES, AZURE_SERVICES, SEVERITY_LEVELS,
)
from utils.crypto import CredentialEncryptor
from utils.validators import validate_aws, validate_azure, validate_openai
from utils.scanner import run_prowler_scan
from utils.ai_engine import create_embeddings, generate_remediation, export_chromadb
from utils.policy_engine import validate_rego_file, batch_validate_remediations
from utils.steampipe import extract_columns, export_to_csv
from utils.risk_engine import generate_risk_report
from utils.report_gen import generate_pdf_report

# ─── Flask App Setup ─────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", uuid.uuid4().hex)

# In-memory stores (session-scoped in production, global for demo)
encryptor = CredentialEncryptor()
pipeline_tasks = {}  # task_id → task state


# ═══════════════════════════════════════════════════════════════════
#  ROUTES — Pages
# ═══════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template(
        "index.html",
        frameworks=COMPLIANCE_FRAMEWORKS,
        models=OPENAI_MODELS,
        default_columns=DEFAULT_STEAMPIPE_COLUMNS,
        aws_services=AWS_SERVICES,
        azure_services=AZURE_SERVICES,
        severity_levels=SEVERITY_LEVELS,
    )


# ═══════════════════════════════════════════════════════════════════
#  ROUTES — Credential Validation
# ═══════════════════════════════════════════════════════════════════

@app.route("/api/validate/aws", methods=["POST"])
def api_validate_aws():
    data = request.json
    access_key = data.get("access_key_id", "").strip()
    secret_key = data.get("secret_access_key", "").strip()

    if not access_key or not secret_key:
        return jsonify({"valid": False, "message": "Both AWS Access Key ID and Secret Access Key are required"}), 400

    result = validate_aws(access_key, secret_key)

    # Encrypt and store if valid
    if result["valid"]:
        session["aws_access_key"] = encryptor.encrypt(access_key)
        session["aws_secret_key"] = encryptor.encrypt(secret_key)
        session["aws_validated"] = True

    return jsonify(result)


@app.route("/api/validate/azure", methods=["POST"])
def api_validate_azure():
    data = request.json
    client_id = data.get("client_id", "").strip()
    tenant_id = data.get("tenant_id", "").strip()
    client_secret = data.get("client_secret", "").strip()

    if not all([client_id, tenant_id, client_secret]):
        return jsonify({"valid": False, "message": "Client ID, Tenant ID, and Client Secret are all required"}), 400

    result = validate_azure(client_id, tenant_id, client_secret)

    if result["valid"]:
        session["azure_client_id"] = encryptor.encrypt(client_id)
        session["azure_tenant_id"] = encryptor.encrypt(tenant_id)
        session["azure_client_secret"] = encryptor.encrypt(client_secret)
        session["azure_validated"] = True

    return jsonify(result)


@app.route("/api/validate/openai", methods=["POST"])
def api_validate_openai():
    data = request.json
    api_key = data.get("api_key", "").strip()
    model = data.get("model", "gpt-4o")

    if not api_key:
        return jsonify({"valid": False, "message": "OpenAI API key is required"}), 400

    result = validate_openai(api_key, model)

    if result["valid"]:
        session["openai_key"] = encryptor.encrypt(api_key)
        session["openai_model"] = model
        session["openai_validated"] = True

    return jsonify(result)


# ═══════════════════════════════════════════════════════════════════
#  ROUTES — File Upload (Rego Policy)
# ═══════════════════════════════════════════════════════════════════

@app.route("/api/upload/rego", methods=["POST"])
def api_upload_rego():
    if "file" not in request.files:
        return jsonify({"valid": False, "message": "No file uploaded"}), 400

    file = request.files["file"]
    if not file.filename.endswith(".rego"):
        return jsonify({"valid": False, "message": "File must be a .rego file"}), 400

    content = file.read().decode("utf-8", errors="replace")

    # Sanitize
    validation = validate_rego_file(content)

    if validation["valid"]:
        rego_path = os.path.join(str(UPLOAD_DIR), "custom_policy.rego")
        with open(rego_path, "w") as f:
            f.write(content)
        session["custom_rego"] = True

    return jsonify(validation)


# ═══════════════════════════════════════════════════════════════════
#  ROUTES — Pipeline Execution
# ═══════════════════════════════════════════════════════════════════

@app.route("/api/run-pipeline", methods=["POST"])
def api_run_pipeline():
    """Start the full GRC pipeline in a background thread."""
    data = request.json

    # Validate inputs
    frameworks = data.get("frameworks", [])
    if not frameworks:
        return jsonify({"error": "Select at least one compliance framework"}), 400

    columns = data.get("steampipe_columns", DEFAULT_STEAMPIPE_COLUMNS)
    use_default_rego = data.get("use_default_rego", True)

    # ── Scan-scope filters (optional) ──
    services          = data.get("services", [])           # e.g. ["s3", "iam", "ec2"]
    resource_tags     = data.get("resource_tags", [])      # e.g. ["Environment=prod"]
    resource_arns     = data.get("resource_arns", [])      # e.g. ["arn:aws:s3:::my-bucket"]
    severity          = data.get("severity", [])           # e.g. ["critical", "high"]
    regions           = data.get("regions", [])            # e.g. ["us-east-1"]
    excluded_services = data.get("excluded_services", [])  # e.g. ["rds", "lambda"]

    # Get credentials from request (encrypt immediately)
    aws_creds = None
    if data.get("aws_access_key_id") and data.get("aws_secret_access_key"):
        aws_creds = {
            "access_key_id": data["aws_access_key_id"],
            "secret_access_key": data["aws_secret_access_key"],
        }

    azure_creds = None
    if data.get("azure_client_id") and data.get("azure_tenant_id") and data.get("azure_client_secret"):
        azure_creds = {
            "client_id": data["azure_client_id"],
            "tenant_id": data["azure_tenant_id"],
            "client_secret": data["azure_client_secret"],
        }

    openai_key = data.get("openai_api_key", "")
    openai_model = data.get("openai_model", "gpt-4o")

    if not aws_creds and not azure_creds:
        return jsonify({"error": "At least one cloud provider (AWS or Azure) credentials required"}), 400

    if not openai_key:
        return jsonify({"error": "OpenAI API key is required"}), 400

    # Create task
    task_id = uuid.uuid4().hex[:12]
    task = {
        "id": task_id,
        "status": "running",
        "current_step": 0,
        "total_steps": 8,
        "steps": {
            "prowler": {"status": "pending", "message": ""},
            "embeddings": {"status": "pending", "message": ""},
            "remediation": {"status": "pending", "message": ""},
            "opa_validation": {"status": "pending", "message": ""},
            "steampipe": {"status": "pending", "message": ""},
            "risk_quantification": {"status": "pending", "message": ""},
            "report": {"status": "pending", "message": ""},
            "dashboard": {"status": "pending", "message": ""},
        },
        "logs": [],
        "outputs": {},
        "started_at": datetime.now().isoformat(),
    }
    pipeline_tasks[task_id] = task

    # Load rego policy
    rego_policy = ""
    if use_default_rego:
        default_rego_path = os.path.join(str(POLICY_DIR), "security_policy.rego")
        if os.path.exists(default_rego_path):
            with open(default_rego_path) as f:
                rego_policy = f.read()
    else:
        custom_rego_path = os.path.join(str(UPLOAD_DIR), "custom_policy.rego")
        if os.path.exists(custom_rego_path):
            with open(custom_rego_path) as f:
                rego_policy = f.read()

    # Start pipeline in background thread
    scan_opts = {
        "services": services,
        "resource_tags": resource_tags,
        "resource_arns": resource_arns,
        "severity": severity,
        "regions": regions,
        "excluded_services": excluded_services,
    }

    thread = threading.Thread(
        target=_execute_pipeline,
        args=(task_id, aws_creds, azure_creds, openai_key, openai_model,
              frameworks, columns, rego_policy, scan_opts),
        daemon=True,
    )
    thread.start()

    return jsonify({"task_id": task_id, "message": "Pipeline started"})


@app.route("/api/pipeline-status/<task_id>")
def api_pipeline_status(task_id):
    """Get current pipeline status."""
    task = pipeline_tasks.get(task_id)
    if not task:
        return jsonify({"error": "Task not found"}), 404
    return jsonify(task)


@app.route("/api/download/<task_id>/<step>")
def api_download(task_id, step):
    """Download output from a specific pipeline step."""
    task = pipeline_tasks.get(task_id)
    if not task:
        return jsonify({"error": "Task not found"}), 404

    output_dir = os.path.join(str(OUTPUT_DIR), task_id)

    file_map = {
        "prowler": ("prowler_findings.json", "application/json"),
        "embeddings": ("chromadb_export.json", "application/json"),
        "remediation": ("remediation_plan.json", "application/json"),
        "opa_validation": ("opa_validation_results.json", "application/json"),
        "steampipe": ("steampipe_extraction.csv", "text/csv"),
        "risk_quantification": ("risk_quantification_report.json", "application/json"),
        "report": ("GRC_Compliance_Report.pdf", "application/pdf"),
        "dashboard": ("risk_quantification_report.json", "application/json"),
    }

    if step not in file_map:
        return jsonify({"error": f"Unknown step: {step}"}), 400

    filename, mimetype = file_map[step]
    filepath = os.path.join(output_dir, filename)

    if not os.path.exists(filepath):
        return jsonify({"error": f"Output not yet available for step: {step}"}), 404

    return send_file(filepath, mimetype=mimetype, as_attachment=True, download_name=filename)


@app.route("/api/launch-dashboard", methods=["POST"])
def api_launch_dashboard():
    """Launch Streamlit dashboard for the given task."""
    data = request.json
    task_id = data.get("task_id", "")
    task = pipeline_tasks.get(task_id)

    if not task:
        return jsonify({"error": "Task not found"}), 404

    risk_file = os.path.join(str(OUTPUT_DIR), task_id, "risk_quantification_report.json")
    if not os.path.exists(risk_file):
        return jsonify({"error": "Risk report not yet generated"}), 404

    # Try to launch Streamlit
    try:
        import subprocess
        dashboard_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "streamlit_dashboard.py")

        if os.path.exists(dashboard_path):
            env = os.environ.copy()
            env["GRC_RISK_FILE"] = risk_file
            subprocess.Popen(
                ["streamlit", "run", dashboard_path, "--server.port", "8501", "--server.headless", "true"],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return jsonify({
                "success": True,
                "url": "http://localhost:8501",
                "message": "Streamlit dashboard launched on port 8501",
            })
        else:
            return jsonify({"success": False, "message": "Streamlit dashboard file not found"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Could not launch Streamlit: {str(e)[:200]}"})


@app.route("/api/config")
def api_config():
    """Return configuration data for frontend."""
    return jsonify({
        "frameworks": COMPLIANCE_FRAMEWORKS,
        "models": OPENAI_MODELS,
        "default_columns": DEFAULT_STEAMPIPE_COLUMNS,
        "aws_services": AWS_SERVICES,
        "azure_services": AZURE_SERVICES,
        "severity_levels": SEVERITY_LEVELS,
    })


# ═══════════════════════════════════════════════════════════════════
#  Pipeline Execution (Background Thread)
# ═══════════════════════════════════════════════════════════════════

def _execute_pipeline(task_id, aws_creds, azure_creds, openai_key, openai_model,
                      frameworks, columns, rego_policy, scan_opts=None):
    """Execute the full GRC pipeline sequentially."""  # noqa: E501
    task = pipeline_tasks[task_id]
    output_dir = os.path.join(str(OUTPUT_DIR), task_id)
    os.makedirs(output_dir, exist_ok=True)
    db_path = os.path.join(output_dir, "compliance_db")

    def log(msg):
        task["logs"].append({"time": datetime.now().strftime("%H:%M:%S"), "message": msg})

    def update_step(step, status, message=""):
        task["steps"][step]["status"] = status
        task["steps"][step]["message"] = message
        if status == "running":
            task["current_step"] += 1

    try:
        # ── Step 1: Prowler Scan ──────────────────────────────────
        update_step("prowler", "running", "Scanning cloud environments...")
        log("Starting Prowler scan...")

        opts = scan_opts or {}
        scan_result = run_prowler_scan(
            aws_creds=aws_creds,
            azure_creds=azure_creds,
            output_dir=output_dir,
            compliance_frameworks=frameworks,
            services=opts.get("services", []),
            resource_tags=opts.get("resource_tags", []),
            resource_arns=opts.get("resource_arns", []),
            severity=opts.get("severity", []),
            regions=opts.get("regions", []),
            excluded_services=opts.get("excluded_services", []),
            log_callback=log,
        )

        findings = []
        if scan_result.get("combined_file") and os.path.exists(scan_result["combined_file"]):
            with open(scan_result["combined_file"]) as f:
                findings = json.load(f)

        # Save findings copy
        prowler_out = os.path.join(output_dir, "prowler_findings.json")
        with open(prowler_out, "w") as f:
            json.dump(findings, f, indent=2, default=str)

        task["outputs"]["prowler"] = {
            "total_findings": len(findings),
            "aws_findings": scan_result.get("aws", {}).get("finding_count", 0) if scan_result.get("aws") else 0,
            "azure_findings": scan_result.get("azure", {}).get("finding_count", 0) if scan_result.get("azure") else 0,
        }
        update_step("prowler", "completed", f"{len(findings)} findings discovered")
        log(f"Prowler scan complete: {len(findings)} findings")

        # ── Step 2: ChromaDB Embeddings ───────────────────────────
        update_step("embeddings", "running", "Ingesting compliance PDFs into ChromaDB via LlamaIndex...")
        log("Loading compliance PDF documents and creating vector embeddings...")

        embed_result = create_embeddings(
            frameworks=frameworks,
            api_key=openai_key,
            db_path=db_path,
            log_callback=log,
        )

        # Export ChromaDB for download
        chroma_export = export_chromadb(db_path)
        chroma_export_path = os.path.join(output_dir, "chromadb_export.json")
        with open(chroma_export_path, "w") as f:
            json.dump(chroma_export, f, indent=2, default=str)

        task["outputs"]["embeddings"] = {
            "chunks": embed_result.get("chunks", 0),
            "frameworks": embed_result.get("frameworks", 0),
            "loaded_files": embed_result.get("loaded_files", []),
        }
        update_step("embeddings", "completed", embed_result.get("message", ""))

        # ── Step 3: AI Remediation ────────────────────────────────
        update_step("remediation", "running", "Generating one-shot AI remediation via LlamaIndex RAG...")
        log("Querying LlamaIndex engine — filtered findings (FAIL + Critical/High + New)...")

        remediation_result = generate_remediation(
            findings=findings,
            api_key=openai_key,
            model=openai_model,
            rego_policy=rego_policy,
            db_path=db_path,
            log_callback=log,
        )

        rem_path = os.path.join(output_dir, "remediation_plan.json")
        with open(rem_path, "w") as f:
            json.dump(remediation_result.get("remediations", []), f, indent=2, default=str)

        task["outputs"]["remediation"] = {
            "analyzed": remediation_result.get("analyzed", 0),
            "generated": len(remediation_result.get("remediations", [])),
        }
        update_step("remediation", "completed", remediation_result.get("message", ""))

        # ── Step 4: OPA Policy Validation ─────────────────────────
        update_step("opa_validation", "running", "Validating remediation against OPA policies...")
        log("Running OPA Rego policy validation...")

        opa_results = batch_validate_remediations(
            remediations=remediation_result.get("remediations", []),
            rego_policy=rego_policy,
            log_callback=log,
        )

        opa_path = os.path.join(output_dir, "opa_validation_results.json")
        with open(opa_path, "w") as f:
            json.dump(opa_results, f, indent=2, default=str)

        compliant_count = len([r for r in opa_results if r.get("compliant")])
        task["outputs"]["opa_validation"] = {
            "total_checked": len(opa_results),
            "compliant": compliant_count,
            "violations": len(opa_results) - compliant_count,
        }
        update_step("opa_validation", "completed",
                     f"{compliant_count}/{len(opa_results)} remediations passed policy check")

        # ── Step 5: Steampipe Extraction ──────────────────────────
        update_step("steampipe", "running", "Extracting columns from findings...")
        log(f"Extracting Steampipe columns: {columns}")

        extraction = extract_columns(
            findings=findings,
            columns=columns,
            log_callback=log,
        )

        csv_data = export_to_csv(extraction)
        csv_path = os.path.join(output_dir, "steampipe_extraction.csv")
        with open(csv_path, "w") as f:
            f.write(csv_data)

        # Also save as JSON
        steampipe_json_path = os.path.join(output_dir, "steampipe_extraction.json")
        with open(steampipe_json_path, "w") as f:
            json.dump(extraction, f, indent=2, default=str)

        task["outputs"]["steampipe"] = {
            "rows": extraction.get("row_count", 0),
            "columns": len(columns),
            "sql_query": extraction.get("sql_query", ""),
        }
        update_step("steampipe", "completed", extraction.get("message", ""))

        # ── Step 6: Risk Quantification ───────────────────────────
        update_step("risk_quantification", "running", "Calculating FAIR risk quantification...")
        log("Running FAIR model risk quantification (IBM DBR 2025 metrics)...")

        risk_result = generate_risk_report(
            findings=findings,
            log_callback=log,
        )

        risk_path = os.path.join(output_dir, "risk_quantification_report.json")
        with open(risk_path, "w") as f:
            json.dump({
                "records": risk_result.get("records", []),
                "summary": risk_result.get("summary", {}),
            }, f, indent=2, default=str)

        task["outputs"]["risk_quantification"] = risk_result.get("summary", {})
        update_step("risk_quantification", "completed", risk_result.get("message", ""))

        # ── Step 7: PDF Report ────────────────────────────────────
        update_step("report", "running", "Generating audit-ready PDF report...")
        log("Generating GRC compliance PDF report...")

        pdf_path = os.path.join(output_dir, "GRC_Compliance_Report.pdf")
        report_result = generate_pdf_report(
            risk_data=risk_result,
            output_path=pdf_path,
            log_callback=log,
        )

        task["outputs"]["report"] = {
            "pages": report_result.get("pages", 0),
            "path": pdf_path if report_result.get("success") else None,
        }
        update_step("report", "completed" if report_result.get("success") else "failed",
                     report_result.get("message", ""))

        # ── Step 8: Dashboard Ready ───────────────────────────────
        update_step("dashboard", "running", "Preparing dashboard data...")
        log("Dashboard data prepared — ready to launch Streamlit")
        update_step("dashboard", "completed", "Dashboard data ready — click 'Open Dashboard'")

        task["status"] = "completed"
        task["completed_at"] = datetime.now().isoformat()
        log("Pipeline completed successfully!")

    except Exception as e:
        task["status"] = "failed"
        task["error"] = str(e)[:500]
        log(f"Pipeline failed: {str(e)[:300]}")

        # Mark remaining steps as failed
        for step_name, step_data in task["steps"].items():
            if step_data["status"] in ("pending", "running"):
                step_data["status"] = "failed"
                step_data["message"] = "Pipeline aborted"


# ═══════════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
