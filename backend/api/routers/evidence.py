from __future__ import annotations
import time
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from core.database import get_db
from api.deps import get_current_active_user, get_project_or_404
from models.user import User
from models.finding import Finding
from models.evidence import Evidence
from schemas.evidence import EvidenceSchema, ReplayRequestSchema, ReplayResponseSchema

router = APIRouter()


@router.get("/findings/{finding_id}/evidence", response_model=list[EvidenceSchema])
async def list_evidence(
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND"})
    await get_project_or_404(finding.project_id, db, user)

    ev_result = await db.execute(select(Evidence).where(Evidence.finding_id == finding_id))
    return ev_result.scalars().all()


@router.get("/evidence/{evidence_id}", response_model=EvidenceSchema)
async def get_evidence(
    evidence_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    result = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
    evidence = result.scalar_one_or_none()
    if not evidence:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND"})

    # Verify project access via finding
    finding_result = await db.execute(select(Finding).where(Finding.id == evidence.finding_id))
    finding = finding_result.scalar_one_or_none()
    if finding:
        await get_project_or_404(finding.project_id, db, user)
    return evidence


@router.post("/evidence/{evidence_id}/replay", response_model=ReplayResponseSchema)
async def replay_evidence(
    evidence_id: uuid.UUID,
    body: ReplayRequestSchema,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    result = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
    evidence = result.scalar_one_or_none()
    if not evidence:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND"})

    if not evidence.http_request:
        raise HTTPException(status_code=400, detail={"code": "NO_REQUEST", "message": "No HTTP request stored for this evidence"})

    # Parse original request
    import httpx, re
    request_lines = evidence.http_request.split("\n")
    if not request_lines:
        raise HTTPException(status_code=400, detail={"code": "INVALID_REQUEST"})

    first_line = request_lines[0].strip().split()
    if len(first_line) < 2:
        raise HTTPException(status_code=400, detail={"code": "INVALID_REQUEST"})

    method = first_line[0]
    path = first_line[1]

    # Extract headers
    headers = {}
    body_start = 0
    for i, line in enumerate(request_lines[1:], 1):
        if line.strip() == "":
            body_start = i + 1
            break
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()

    # Get host from headers
    host = headers.get("Host", headers.get("host", ""))
    if not host:
        raise HTTPException(status_code=400, detail={"code": "NO_HOST"})

    scheme = "https" if "443" in host else "http"
    url = f"{scheme}://{host}{path}"

    # Scope check
    finding_result = await db.execute(select(Finding).where(Finding.id == evidence.finding_id))
    finding = finding_result.scalar_one_or_none()
    if finding:
        project = await get_project_or_404(finding.project_id, db, user)
        scope_urls = project.scope_urls or [project.target_url]
        if not any(url.startswith(s) for s in scope_urls):
            raise HTTPException(status_code=422, detail={"code": "SCOPE_VIOLATION", "message": "URL is outside project scope"})

    # Apply modifications
    if body.modified_headers:
        headers.update(body.modified_headers)

    request_body = "\n".join(request_lines[body_start:]).strip()
    if body.modified_body:
        request_body = body.modified_body

    params = None
    if body.modified_params:
        params = body.modified_params

    try:
        t0 = time.monotonic()
        async with httpx.AsyncClient(timeout=30, follow_redirects=False) as client:
            resp = await client.request(
                method=method,
                url=url,
                headers={k: v for k, v in headers.items() if k.lower() not in ("host", "content-length")},
                content=request_body.encode() if request_body else None,
                params=params,
            )
        elapsed_ms = int((time.monotonic() - t0) * 1000)

        max_kb = 64 * 1024
        response_body = resp.text[:max_kb]

        return ReplayResponseSchema(
            status_code=resp.status_code,
            response_headers=dict(resp.headers),
            response_body=response_body,
            elapsed_ms=elapsed_ms,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail={"code": "REPLAY_ERROR", "message": str(e)})
