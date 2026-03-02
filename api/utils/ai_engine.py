"""OpenAI remediation engine with ChromaDB compliance embeddings.

Uses LlamaIndex RAG pipeline:
 • PyMuPDFReader  → load 4 compliance PDFs from docs/
 • ChromaVectorStore + VectorStoreIndex → embed & persist
 • query_engine (similarity_top_k=3, response_mode="compact") → one-shot remediation

Matching patterns from reference repo: RAG.py + extract_learn.py
"""

import json
import os
from pathlib import Path
from typing import Any

# ─── Lazy singletons ──────────────────────────────────────────────
_index = None
_qa_engine = None

# Default paths
DOCS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "docs")
COMPLIANCE_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "compliance_db1")
LLM_MODEL = "gpt-4o"

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
    """Return a LlamaIndex query engine (cached)."""
    global _qa_engine
    if _qa_engine is not None:
        return _qa_engine

    from llama_index.llms.openai import OpenAI as LlamaOpenAI

    index = _load_index(api_key, db_path)
    llm = LlamaOpenAI(model=model, temperature=0, api_key=api_key)
    _qa_engine = index.as_query_engine(
        llm=llm,
        similarity_top_k=3,
        response_mode="compact",
    )
    return _qa_engine


# ─── One-shot prompt (mirrors extract_learn.py build_grc_prompt) ──

def _build_grc_prompt(finding_summary: dict) -> str:
    """Build the one-shot GRC remediation prompt.

    The ``{context_str}`` placeholder is replaced by LlamaIndex's query engine
    with the retrieved compliance context automatically.
    """
    return f"""You are a Senior GRC Cloud Architect.
Below is a Prowler security finding and relevant compliance context (NIST, ISO, CIS).

INSTRUCTIONS:
1. Map this finding to the specific NIST/PCI control in the context.
2. Explain the "Business Risk" for a CISO.
3. Provide the EXACT Terraform (HCL) code to fix this. Use current best practices.

COMPLIANCE CONTEXT:
{{context_str}}

PROWLER FINDING:
{json.dumps(finding_summary, indent=2)}

RESPONSE:"""


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

    Filters findings (status_code==FAIL, severity in Critical/High, status==New)
    then queries the LlamaIndex engine in one shot per finding (batched, fast).
    """
    if severity_filter is None:
        severity_filter = SEVERITY_FILTER
    if not db_path:
        db_path = COMPLIANCE_DB_PATH

    # Filter findings exactly like extract_learn.py
    filtered = [
        f for f in findings
        if f.get("status_code") == "FAIL"
        and f.get("severity") in severity_filter
        and f.get("status") == "New"
    ]

    if log_callback:
        log_callback(f"Filtered {len(filtered)}/{len(findings)} findings "
                     f"(severity: {severity_filter}, status_code: FAIL, status: New)")

    if not filtered:
        return {
            "success": True,
            "total_findings": len(findings),
            "analyzed": 0,
            "remediations": [],
            "message": "No findings matched filter criteria (FAIL + Critical/High + New)",
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
    for i, finding in enumerate(filtered):
        try:
            # Build concise finding summary for the prompt
            finding_summary = {
                "title": finding.get("finding_info", {}).get("title", "Unknown"),
                "description": finding.get("finding_info", {}).get("desc", ""),
                "severity": finding.get("severity", ""),
                "status_code": finding.get("status_code", ""),
                "resource": (finding.get("resources") or [{}])[0].get("uid", "unknown"),
                "resource_type": (finding.get("resources") or [{}])[0].get("type", ""),
                "region": (finding.get("resources") or [{}])[0].get("region", ""),
                "provider": finding.get("cloud", {}).get("provider", ""),
                "risk_details": finding.get("risk_details", ""),
                "remediation_hint": finding.get("remediation", {}).get("desc", ""),
                "compliance": finding.get("unmapped", {}).get("compliance", {}),
            }

            prompt = _build_grc_prompt(finding_summary)

            # One-shot query — LlamaIndex retrieves context_str and sends to LLM
            response = qa_engine.query(prompt)
            analysis = str(response)

            remediations.append({
                "finding_title": finding_summary["title"],
                "resource": finding_summary["resource"],
                "severity": finding_summary["severity"],
                "analysis": analysis,
                "compliance_context_used": True,
                "model_used": model,
            })

            if log_callback:
                log_callback(f"  [{i+1}/{len(filtered)}] {finding_summary['title'][:60]}...")

        except Exception as e:
            remediations.append({
                "finding_title": finding.get("finding_info", {}).get("title", "Unknown"),
                "resource": (finding.get("resources") or [{}])[0].get("uid", "unknown"),
                "severity": finding.get("severity", ""),
                "analysis": f"Error: {str(e)[:300]}",
                "error": True,
            })

    return {
        "success": True,
        "total_findings": len(findings),
        "analyzed": len(filtered),
        "remediations": remediations,
        "message": f"Generated {len(remediations)} remediation plans",
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
