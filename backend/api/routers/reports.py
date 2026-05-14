from __future__ import annotations
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from core.database import get_db
from api.deps import get_current_active_user, get_project_or_404
from models.user import User
from models.report_job import ReportJob
from schemas.report import ReportJobSchema, ReportCreateSchema

router = APIRouter()


@router.get("/projects/{project_id}/reports", response_model=list[ReportJobSchema])
async def list_reports(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    await get_project_or_404(project_id, db, user)
    result = await db.execute(select(ReportJob).where(ReportJob.project_id == project_id))
    return result.scalars().all()


@router.post("/projects/{project_id}/reports", response_model=ReportJobSchema)
async def create_report(
    project_id: uuid.UUID,
    body: ReportCreateSchema,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    await get_project_or_404(project_id, db, user)

    job = ReportJob(
        project_id=project_id,
        scan_id=body.scan_id,
        format=body.format,
        requested_by_id=user.id,
        status="pending",
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    from workers.tasks.report_tasks import generate_report
    generate_report.apply_async(args=[str(job.id)], queue="report")

    return job


@router.get("/reports/{report_id}", response_model=ReportJobSchema)
async def get_report(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    result = await db.execute(select(ReportJob).where(ReportJob.id == report_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND"})
    await get_project_or_404(job.project_id, db, user)
    return job


@router.get("/reports/{report_id}/download")
async def download_report(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    result = await db.execute(select(ReportJob).where(ReportJob.id == report_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND"})
    await get_project_or_404(job.project_id, db, user)

    if job.status != "complete":
        raise HTTPException(status_code=400, detail={"code": "NOT_READY", "message": "Report is not ready yet"})

    if not job.file_path:
        raise HTTPException(status_code=404, detail={"code": "FILE_MISSING"})

    import os
    if not os.path.exists(job.file_path):
        raise HTTPException(status_code=404, detail={"code": "FILE_MISSING"})

    media_type = "application/pdf" if job.format == "pdf" else "text/html" if job.format == "html" else "application/json"
    filename = f"report-{job.project_id}.{job.format}"
    return FileResponse(job.file_path, media_type=media_type, filename=filename)


@router.delete("/reports/{report_id}", status_code=204)
async def delete_report(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    result = await db.execute(select(ReportJob).where(ReportJob.id == report_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND"})
    await get_project_or_404(job.project_id, db, user)

    if job.file_path:
        import os
        try:
            os.remove(job.file_path)
        except OSError:
            pass

    await db.delete(job)
    await db.commit()
