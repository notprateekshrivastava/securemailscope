from __future__ import annotations

import logging

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response

from .dashboard import render_dashboard

from .config import settings
from .ml.model import model_available
from .reports import render_html, render_json, render_pdf
from .schemas import AnalysisResult, HealthResponse
from .service import service
from .storage import list_results, load_result
from .analysis.tshark import TSharkAnalysisError, TSharkUnavailable, tshark_available

logger = logging.getLogger("securemailscope.api")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description=(
        "AI-assisted cryptographic security posture assessment for passive SMTP, IMAP and POP3 PCAP analysis."
    ),
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def report_model_status() -> None:
    """Print the ML status once at startup so a stale model is never a silent surprise."""
    bundle = service.model_bundle
    if bundle.available:
        logger.info("ML model loaded (version %s)", bundle.version)
    else:
        logger.warning("ML model NOT in use (status: %s). %s", bundle.version, bundle.note or "")
        logger.warning("Rule-based classification is applied. Train the model with: python -m app.ml.train")


@app.get("/", tags=["system"])
def root() -> dict[str, str]:
    return {
        "service": settings.app_name,
        "version": settings.version,
        "dashboard": "/dashboard",
        "docs": "/docs",
        "openapi": "/openapi.json",
    }


@app.get("/dashboard", response_class=HTMLResponse, tags=["system"])
def dashboard() -> HTMLResponse:
    """Interactive dashboard: upload, history, per-session evidence and ML output."""
    return HTMLResponse(content=render_dashboard())


@app.get("/api/v1/health", response_model=HealthResponse, tags=["system"])
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        tshark_available=tshark_available(),
        ml_model_available=service.model_bundle.available,
        ml_model_status=service.model_bundle.version,
        ml_model_note=service.model_bundle.note,
        version=settings.version,
    )


@app.post("/api/v1/analyses/upload", response_model=AnalysisResult, tags=["analysis"])
def upload_analysis(
    file: UploadFile = File(...),
    uploaded_by: str = Form("user"),
) -> AnalysisResult:
    filename = file.filename or "capture.pcap"
    allowed = {".pcap", ".pcapng", ".cap", ".pcap.gz", ".json"}
    if not any(filename.lower().endswith(extension) for extension in allowed):
        raise HTTPException(status_code=400, detail="Upload a PCAP/PCAPNG/CAP file")
    try:
        allowed_sources = {"user", "ntro", "team", "demo"}
        source = uploaded_by.strip().lower() or "user"
        if source not in allowed_sources:
            raise HTTPException(
                status_code=400,
                detail=f"uploaded_by must be one of: {', '.join(sorted(allowed_sources))}",
            )
        return service.analyze_upload(file.file, filename, uploaded_by=source)
    except TSharkUnavailable as exc:
        raise HTTPException(
            status_code=503,
            detail="TShark is not installed. Run the Docker image or install Wireshark/TShark.",
        ) from exc
    except (TSharkAnalysisError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {type(exc).__name__}") from exc


@app.post("/api/v1/demo/analysis", response_model=AnalysisResult, tags=["analysis"])
def demo_analysis() -> AnalysisResult:
    """Generate a deterministic secure/weak/plaintext fixture for frontend development."""
    return service.create_demo()


@app.get("/api/v1/analyses", response_model=list[AnalysisResult], tags=["analysis"])
def analyses(summary_only: bool = False) -> list[AnalysisResult]:
    """List stored analyses.

    ``summary_only=true`` drops the sessions, findings and recommendations from each item.
    Use it to render a list: a capture with 3,000 sessions makes the full list response
    about 16 MB, which a list does not need, and the per-capture endpoint returns the full
    record when a row is opened. The default is unchanged for existing clients.
    """
    items = list_results()
    if not summary_only:
        return items
    trimmed: list[AnalysisResult] = []
    for item in items:
        copy = item.model_copy(
            update={
                "sessions": [],
                "findings": [],
                "recommendations": [],
                "metadata": {**item.metadata, "summary_only": True},
            }
        )
        trimmed.append(copy)
    return trimmed


@app.get("/api/v1/analyses/{analysis_id}", response_model=AnalysisResult, tags=["analysis"])
def get_analysis(analysis_id: str) -> AnalysisResult:
    try:
        return load_result(analysis_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Analysis not found") from exc


@app.get("/api/v1/analyses/{analysis_id}/sessions/{session_id}", tags=["analysis"])
def get_session(analysis_id: str, session_id: str) -> dict:
    result = get_analysis(analysis_id)
    for session in result.sessions:
        if session.session_id == session_id or session.tcp_stream_id == session_id:
            return session.model_dump(mode="json")
    raise HTTPException(status_code=404, detail="Session not found")


@app.get("/api/v1/analyses/{analysis_id}/reports/{report_format}", tags=["reports"])
def report(analysis_id: str, report_format: str) -> Response:
    result = get_analysis(analysis_id)
    report_format = report_format.lower()
    if report_format == "json":
        return Response(
            content=render_json(result),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{analysis_id}.json"'},
        )
    if report_format == "html":
        return HTMLResponse(content=render_html(result).decode("utf-8"), headers={
            "Content-Disposition": f'attachment; filename="{analysis_id}.html"'
        })
    if report_format == "pdf":
        try:
            content = render_pdf(result)
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        return Response(
            content=content,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{analysis_id}.pdf"'},
        )
    raise HTTPException(status_code=400, detail="report_format must be json, html or pdf")


@app.post("/api/v1/models/reload", tags=["system"])
def reload_models() -> dict[str, object]:
    service.reload_models()
    return {"loaded": model_available(settings.model_dir)}
