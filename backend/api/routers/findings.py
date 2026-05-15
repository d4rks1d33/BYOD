from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from core.database import get_db
from api.deps import get_current_active_user, get_project_or_404
from models.user import User
from models.finding import Finding
from models.evidence import Evidence
from schemas.finding import FindingDetailSchema, FindingUpdateSchema, FindingSummarySchema
from schemas.common import PaginatedResponse

router = APIRouter()


@router.get("/projects/{project_id}/findings", response_model=PaginatedResponse[FindingSummarySchema])
async def list_findings(
    project_id: uuid.UUID,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    scan_id: Optional[uuid.UUID] = None,
    cwe: Optional[str] = None,
    cvss_min: Optional[float] = None,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    sort: str = "severity_desc",
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    await get_project_or_404(project_id, db, user)

    # Valid enum values
    VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
    VALID_STATUSES = {"new", "verified", "false_positive", "accepted_risk", "fixed"}

    filters = [Finding.project_id == project_id]
    if severity:
        severities = [s.strip() for s in severity.split(",") if s.strip() in VALID_SEVERITIES]
        if severities:
            filters.append(Finding.severity.in_(severities))
    if status:
        # Map legacy "open" → "new" for backwards compatibility
        statuses = [
            ("new" if s.strip() == "open" else s.strip())
            for s in status.split(",")
            if s.strip()
        ]
        statuses = [s for s in statuses if s in VALID_STATUSES]
        if statuses:
            filters.append(Finding.status.in_(statuses))
    if scan_id:
        filters.append(Finding.scan_id == scan_id)
    if cwe:
        filters.append(Finding.cwe_id == cwe)
    if cvss_min is not None:
        filters.append(Finding.cvss_score >= cvss_min)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    order_clause = Finding.created_at.desc() if "created" in sort else Finding.cvss_score.desc() if "cvss" in sort else Finding.created_at.desc()

    result = await db.execute(
        select(Finding).where(*filters).offset((page - 1) * limit).limit(limit).order_by(order_clause)
    )
    findings = result.scalars().all()

    count_result = await db.execute(select(func.count(Finding.id)).where(*filters))
    total = count_result.scalar_one()

    return PaginatedResponse(items=list(findings), total=total, page=page, limit=limit)


@router.get("/findings/{finding_id}", response_model=FindingDetailSchema)
async def get_finding(
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND"})
    await get_project_or_404(finding.project_id, db, user)
    return finding


@router.patch("/findings/{finding_id}", response_model=FindingSummarySchema)
async def update_finding(
    finding_id: uuid.UUID,
    body: FindingUpdateSchema,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND"})
    await get_project_or_404(finding.project_id, db, user)

    if body.status:
        finding.status = body.status
    if body.notes is not None:
        finding.notes = body.notes

    await db.commit()
    await db.refresh(finding)
    return finding


@router.post("/findings/{finding_id}/verify", response_model=FindingSummarySchema)
async def verify_finding(
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND"})
    await get_project_or_404(finding.project_id, db, user)

    finding.status = "verified"
    finding.verified_at = datetime.now(timezone.utc)
    finding.verified_by_id = user.id
    await db.commit()
    await db.refresh(finding)
    return finding


@router.post("/findings/{finding_id}/false-positive", response_model=FindingSummarySchema)
async def mark_false_positive(
    finding_id: uuid.UUID,
    body: dict = {},
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND"})
    await get_project_or_404(finding.project_id, db, user)

    finding.status = "false_positive"
    if isinstance(body, dict) and body.get("reason"):
        finding.notes = body["reason"]
    await db.commit()
    await db.refresh(finding)
    return finding


@router.get("/projects/{project_id}/findings/export")
async def export_findings(
    project_id: uuid.UUID,
    format: str = "json",
    severity: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    import json as json_mod
    await get_project_or_404(project_id, db, user)

    filters = [Finding.project_id == project_id]
    if severity:
        filters.append(Finding.severity.in_(severity.split(",")))

    result = await db.execute(select(Finding).where(*filters))
    findings = result.scalars().all()

    if format == "json":
        data = [
            {"id": str(f.id), "title": f.title, "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
             "status": f.status.value if hasattr(f.status, "value") else str(f.status), "endpoint": str(f.endpoint) if f.endpoint else None,
             "cwe_id": f.cwe_id, "tool": f.tool, "created_at": f.created_at.isoformat()}
            for f in findings
        ]
        return JSONResponse(content=data, headers={"Content-Disposition": f'attachment; filename="findings-{project_id}.json"'})

    elif format == "csv":
        import csv, io
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["id", "title", "severity", "status", "endpoint", "cwe_id", "tool", "created_at"])
        writer.writeheader()
        for f in findings:
            writer.writerow({
                "id": str(f.id), "title": f.title,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "status": f.status.value if hasattr(f.status, "value") else str(f.status),
                "endpoint": str(f.endpoint) if f.endpoint else "", "cwe_id": f.cwe_id or "",
                "tool": f.tool or "", "created_at": f.created_at.isoformat(),
            })
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(
            output.getvalue(),
            headers={"Content-Disposition": f'attachment; filename="findings-{project_id}.csv"'}
        )

    raise HTTPException(status_code=400, detail={"code": "INVALID_FORMAT"})
