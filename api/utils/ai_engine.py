"""OpenAI remediation engine with ChromaDB compliance embeddings.

Uses LlamaIndex RAG pipeline:
 • PyMuPDFReader  → load 4 compliance PDFs from docs/
 • ChromaVectorStore + VectorStoreIndex → embed & persist
 • query_engine (similarity_top_k=3, response_mode="compact") → one-shot remediation
 • Outputs EXACT Terraform (HCL) remediation code per finding
 • Extracts HCL blocks into .tf files (mirrors generate_terraform_code.py)

Matching patterns from reference repo: RAG.py + extract_learn.py + generate_terraform_code.py
"""

import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

# ─── Lazy singletons ──────────────────────────────────────────────
_index = None
_qa_engine = None
_qa_engine_model = None

# Default paths
DOCS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "docs")
COMPLIANCE_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "compliance_db1")
LLM_MODEL = "gpt-4o-mini"

# PDF files expected in docs/
PDF_FILES = [
    "NIST.SP.800-53r5.pdf",
    "PCI-DSS-v4_0_1.pdf",
    "NIST_ISO_MAPPING.pdf",
    "CIS_AWS_Foundations.pdf",
]

# Severity & status filters (matching extract_learn.py)
SEVERITY_FILTER = ["Critical", "High"]


# ─── PDF Ingestion → ChromaDB (mirrors RAG.py) ───────────────────

def create_embeddings(
    frameworks: list[str] | None = None,
    api_key: str = "",
    db_path: str = "",
    docs_dir: str = "",
    log_callback=None,
) -> dict:
    """Ingest compliance PDFs via LlamaIndex PyMuPDFReader into ChromaDB.

    Parameters
    ----------
    frameworks : list[str] | None
        Ignored (kept for API compat). We always embed the full PDF corpus.
    api_key : str
        OpenAI API key for the embedding model.
    db_path : str
        Directory for ChromaDB persistent storage.
    docs_dir : str
        Directory containing compliance PDFs.
    log_callback : callable | None
        Logging function.
    """
    from llama_index.core import VectorStoreIndex, StorageContext, Settings
    from llama_index.readers.file import PyMuPDFReader
    from llama_index.vector_stores.chroma import ChromaVectorStore
    from llama_index.embeddings.openai import OpenAIEmbedding
    import chromadb

    if not api_key:
        api_key = os.getenv("OPENAI_API_KEY", "")
    if not db_path:
        db_path = COMPLIANCE_DB_PATH
    if not docs_dir:
        docs_dir = DOCS_DIR

    try:
        # Configure embedding model
        Settings.embed_model = OpenAIEmbedding(api_key=api_key)

        # Load all PDFs
        loader = PyMuPDFReader()
        all_docs = []
        loaded_files = []
        for fname in PDF_FILES:
            fpath = os.path.join(docs_dir, fname)
            if os.path.exists(fpath):
                if log_callback:
                    log_callback(f"Loading PDF: {fname}")
                all_docs.extend(loader.load(file_path=fpath))
                loaded_files.append(fname)
            else:
                if log_callback:
                    log_callback(f"WARNING: PDF not found — {fpath}")

        if not all_docs:
            return {
                "success": False,
                "message": f"No compliance PDFs found in {docs_dir}. Run: bash setup_docs.sh",
            }

        # Create / recreate ChromaDB collection
        chroma_client = chromadb.PersistentClient(path=db_path)
        # Drop existing collection if present
        try:
            chroma_client.delete_collection("compliance")
        except Exception:
            pass

        chroma_collection = chroma_client.create_collection("compliance")
        vector_store = ChromaVectorStore(chroma_collection=chroma_collection)
        storage_context = StorageContext.from_defaults(vector_store=vector_store)

        # Build index (chunk_size=1000, chunk_overlap=100 per RAG.py)
        index = VectorStoreIndex.from_documents(
            all_docs,
            storage_context=storage_context,
            chunk_size=1000,
            chunk_overlap=100,
        )

        # Cache for later use
        global _index
        _index = index

        msg = f"Embedded {len(all_docs)} document sections from {len(loaded_files)} PDFs into ChromaDB"
        if log_callback:
            log_callback(msg)

        return {
            "success": True,
            "chunks": len(all_docs),
            "frameworks": len(loaded_files),
            "db_path": db_path,
            "loaded_files": loaded_files,
            "message": msg,
        }

    except Exception as e:
        return {"success": False, "message": f"Embedding error: {str(e)[:300]}"}


# ─── Load existing ChromaDB index ────────────────────────────────

def _load_index(api_key: str, db_path: str = ""):
    """Load an existing ChromaDB collection into a VectorStoreIndex."""
    global _index
    if _index is not None:
        return _index

    from llama_index.core import VectorStoreIndex, StorageContext, Settings
    from llama_index.vector_stores.chroma import ChromaVectorStore
    from llama_index.embeddings.openai import OpenAIEmbedding
    import chromadb

    if not db_path:
        db_path = COMPLIANCE_DB_PATH

    Settings.embed_model = OpenAIEmbedding(api_key=api_key)

    chroma_client = chromadb.PersistentClient(path=db_path)
    chroma_collection = chroma_client.get_or_create_collection("compliance")
    vector_store = ChromaVectorStore(chroma_collection=chroma_collection)
    storage_context = StorageContext.from_defaults(vector_store=vector_store)
    _index = VectorStoreIndex.from_vector_store(
        vector_store,
        storage_context=storage_context,
        embed_model=Settings.embed_model,
    )
    return _index


def _get_qa_engine(api_key: str, model: str = LLM_MODEL, db_path: str = ""):
    """Return a LlamaIndex query engine (cached per model)."""
    global _qa_engine, _qa_engine_model
    if _qa_engine is not None and _qa_engine_model == model:
        return _qa_engine

    from llama_index.llms.openai import OpenAI as LlamaOpenAI

    index = _load_index(api_key, db_path)
    llm = LlamaOpenAI(model=model, temperature=0, api_key=api_key, max_tokens=1500)
    _qa_engine = index.as_query_engine(
        llm=llm,
        similarity_top_k=3,
        response_mode="compact",
    )
    _qa_engine_model = model
    return _qa_engine


# ─── One-shot prompt (mirrors extract_learn.py build_grc_prompt) ──

def _build_grc_prompt(finding_summary: dict) -> str:
    """Build the one-shot GRC remediation prompt.

    Matches the reference repo's extract_learn.py build_grc_prompt exactly.
    The ``{context_str}`` placeholder is replaced by LlamaIndex's query engine
    with the retrieved compliance context automatically.
    """
    return f"""
You are a Senior GRC Cloud Architect. 
Below is a Prowler security finding and relevant compliance context (NIST, ISO, CIS).

INSTRUCTIONS:
1. Map this finding to the specific NIST/PCI control in the context.
2. Explain the "Business Risk" for a CISO.
3. Provide the EXACT Terraform (HCL) code to fix this. Use current best practices.

COMPLIANCE CONTEXT:
{{context_str}}

PROWLER FINDING:
{json.dumps(finding_summary, indent=2)}
RESPONSE:
"""


# ─── Terraform HCL extraction (mirrors generate_terraform_code.py) ──

HCL_REGEX = r"```(?:hcl|terraform)?\s*(.*?)\s*```"


def _extract_terraform_blocks(analysis: str) -> list[str]:
    """Extract all Terraform/HCL code blocks from analysis text."""
    matches = re.findall(HCL_REGEX, analysis, re.DOTALL)
    return [m.strip() for m in matches if m.strip()]


def extract_terraform_files(
    remediations: list[dict],
    output_dir: str = "",
    log_callback=None,
) -> dict:
    """Extract HCL blocks from remediation analyses into .tf files.

    Mirrors reference repo's generate_terraform_code.py:
    reads grc_remediation_plan.json → extracts ```hcl blocks → saves .tf files.
    """
    if not output_dir:
        output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "extracted_remediations")
    os.makedirs(output_dir, exist_ok=True)

    extracted = []
    for i, item in enumerate(remediations):
        analysis_text = item.get("analysis", "")
        resource_id = item.get("resource", "unknown").split("/")[-1]

        blocks = _extract_terraform_blocks(analysis_text)
        if not blocks:
            continue

        for j, code_content in enumerate(blocks):
            filename = f"item_{i}_block_{j}_{resource_id}.tf"
            filepath = os.path.join(output_dir, filename)
            with open(filepath, "w") as tf_file:
                tf_file.write(code_content)
            extracted.append({"file": filename, "finding": item.get("finding_title", ""), "resource": resource_id})

        if log_callback:
            log_callback(f"  [{i}] Extracted {len(blocks)} Terraform blocks for {resource_id}")

    return {
        "success": True,
        "total_files": len(extracted),
        "output_dir": output_dir,
        "files": extracted,
        "message": f"Extracted {len(extracted)} Terraform files to {output_dir}",
    }


# ─── Remediation generation (one-shot, batched) ──────────────────

def generate_remediation(
    findings: list[dict],
    api_key: str,
    model: str = LLM_MODEL,
    rego_policy: str = "",
    db_path: str = "",
    severity_filter: list[str] | None = None,
    log_callback=None,
) -> dict:
    """Generate AI remediation using LlamaIndex query engine + ChromaDB context.

    Filters findings by severity (Critical/High by default),
    then queries the LlamaIndex engine in one shot per finding.
    """
    if severity_filter is None:
        severity_filter = SEVERITY_FILTER
    if not db_path:
        db_path = COMPLIANCE_DB_PATH

    # Filter findings by severity only — no status_code filter so all
    # findings (PASS, FAIL, etc.) with matching severity get remediation.
    filtered = [
        f for f in findings
        if f.get("severity") in severity_filter
    ]

    # Deduplicate by finding title — same check on different resources
    # produces identical remediation code, so process once and reuse.
    seen_titles: set[str] = set()
    deduped = []
    for f in filtered:
        title = f.get("finding_info", {}).get("title", "")
        if title and title not in seen_titles:
            seen_titles.add(title)
            deduped.append(f)
    skipped = len(filtered) - len(deduped)
    filtered = deduped

    if log_callback:
        log_callback(f"Filtered {len(filtered)}/{len(findings)} findings "
                     f"(severity: {severity_filter}"
                     f"{f', {skipped} duplicates removed' if skipped else ''})")

    if not filtered:
        return {
            "success": True,
            "total_findings": len(findings),
            "analyzed": 0,
            "remediations": [],
            "message": "No findings matched filter criteria (Critical/High severity)",
        }

    # Get the query engine
    try:
        qa_engine = _get_qa_engine(api_key, model, db_path)
    except Exception as e:
        return {
            "success": False,
            "total_findings": len(findings),
            "analyzed": 0,
            "remediations": [],
            "message": f"Failed to initialise LlamaIndex query engine: {str(e)[:300]}",
        }

    remediations = []
    total = len(filtered)

    def _process_finding(idx_finding):
        """Process a single finding — runs in a thread."""
        i, finding = idx_finding
        try:
            # Match reference repo's concise 6-field summary (fewer tokens = faster)
            finding_summary = {
                "Title": finding.get("finding_info", {}).get("title", "Unknown"),
                "Resource": (finding.get("resources") or [{}])[0].get("uid", "unknown"),
                "Severity": finding.get("severity", ""),
                "Description": finding.get("finding_info", {}).get("desc", ""),
                "Risk": finding.get("risk_details", ""),
                "Remediation": finding.get("remediation", {}).get("desc", ""),
            }

            prompt = _build_grc_prompt(finding_summary)
            response = qa_engine.query(prompt)
            analysis = str(response)
            tf_blocks = _extract_terraform_blocks(analysis)

            if log_callback:
                log_callback(f"  [{i+1}/{total}] {finding_summary['Title'][:60]}...")

            return {
                "finding_title": finding_summary["Title"],
                "resource": finding_summary["Resource"],
                "severity": finding_summary["Severity"],
                "analysis": analysis,
                "terraform_blocks": tf_blocks,
                "has_terraform": len(tf_blocks) > 0,
                "compliance_context_used": True,
                "model_used": model,
            }
        except Exception as e:
            return {
                "finding_title": finding.get("finding_info", {}).get("title", "Unknown"),
                "resource": (finding.get("resources") or [{}])[0].get("uid", "unknown"),
                "severity": finding.get("severity", ""),
                "analysis": f"Error: {str(e)[:300]}",
                "error": True,
            }

    # Parallel LLM calls — 6 workers for faster throughput
    max_workers = min(6, total) if total > 1 else 1
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_process_finding, (i, f)): i
            for i, f in enumerate(filtered)
        }
        indexed_results = {}
        for future in as_completed(futures):
            idx = futures[future]
            indexed_results[idx] = future.result()
        # Preserve original order
        remediations = [indexed_results[i] for i in range(total)]

    tf_count = sum(1 for r in remediations if r.get("has_terraform"))

    return {
        "success": True,
        "total_findings": len(findings),
        "analyzed": len(filtered),
        "remediations": remediations,
        "terraform_count": tf_count,
        "message": f"Generated {len(remediations)} remediation plans ({tf_count} with Terraform code)",
    }


# ─── Export helper (kept for download endpoint) ──────────────────

def export_chromadb(db_path: str = "") -> dict:
    """Export ChromaDB collection data for download."""
    import chromadb

    if not db_path:
        db_path = COMPLIANCE_DB_PATH

    try:
        client = chromadb.PersistentClient(path=db_path)
        collection = client.get_collection("compliance")
        data = collection.get(include=["documents", "metadatas"])
        return {
            "collection": "compliance",
            "count": len(data["ids"]),
            "ids": data["ids"],
            "documents": data["documents"],
            "metadatas": data["metadatas"],
        }
    except Exception as e:
        return {"error": str(e)}
