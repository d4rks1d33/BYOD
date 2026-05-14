from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_

from core.database import get_db
from api.deps import get_current_active_user, get_project_or_404
from models.user import User
from models.project import Project, ProjectMember
from models.scan import Scan
from models.finding import Finding
from schemas.project import (
    ProjectCreateSchema, ProjectUpdateSchema, ProjectSchema,
    ProjectMemberSchema, ProjectStatsSchema
)
from schemas.common import PaginatedResponse

router = APIRouter()


@router.get("/", response_model=PaginatedResponse[ProjectSchema])
async def list_projects(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    archived: bool = False,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    offset = (page - 1) * limit
    query = (
        select(Project)
        .where(
            or_(Project.owner_id == user.id,
                Project.id.in_(select(ProjectMember.project_id).where(ProjectMember.user_id == user.id))),
            Project.archived_at.is_(None) if not archived else Project.archived_at.isnot(None),
        )
        .offset(offset)
        .limit(limit)
        .order_by(Project.created_at.desc())
    )
    result = await db.execute(query)
    projects = result.scalars().all()

    count_result = await db.execute(
        select(func.count(Project.id)).where(
            or_(Project.owner_id == user.id,
                Project.id.in_(select(ProjectMember.project_id).where(ProjectMember.user_id == user.id))),
            Project.archived_at.is_(None) if not archived else Project.archived_at.isnot(None),
        )
    )
    total = count_result.scalar_one()
    return PaginatedResponse(items=list(projects), total=total, page=page, limit=limit)


@router.post("/", response_model=ProjectSchema, status_code=201)
async def create_project(
    body: ProjectCreateSchema,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    project = Project(
        id=uuid.uuid4(),
        name=body.name,
        description=body.description,
        target_url=body.target_url,
        target_type=body.target_type,
        scope_urls=body.scope_urls or [body.target_url],
        exclude_patterns=body.exclude_patterns or [],
        config=body.config.model_dump() if body.config else {},
        owner_id=user.id,
    )
    db.add(project)
    await db.commit()
    await db.refresh(project)
    return project


@router.get("/{project_id}", response_model=ProjectSchema)
async def get_project(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    return await get_project_or_404(project_id, db, user)


@router.put("/{project_id}", response_model=ProjectSchema)
async def update_project(
    project_id: uuid.UUID,
    body: ProjectUpdateSchema,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    project = await get_project_or_404(project_id, db, user)
    if project.owner_id != user.id:
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "Only project owner can update"})

    update_data = body.model_dump(exclude_unset=True)
    if "config" in update_data and update_data["config"]:
        update_data["config"] = update_data["config"].model_dump() if hasattr(update_data["config"], "model_dump") else update_data["config"]

    for field, value in update_data.items():
        setattr(project, field, value)

    await db.commit()
    await db.refresh(project)
    return project


@router.delete("/{project_id}", status_code=204)
async def delete_project(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    project = await get_project_or_404(project_id, db, user)
    if project.owner_id != user.id:
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN"})
    project.archived_at = datetime.now(timezone.utc)
    await db.commit()


@router.get("/{project_id}/stats", response_model=ProjectStatsSchema)
async def get_project_stats(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    await get_project_or_404(project_id, db, user)

    severity_counts = {}
    for severity in ["critical", "high", "medium", "low", "info"]:
        count_result = await db.execute(
            select(func.count(Finding.id)).where(
                Finding.project_id == project_id,
                Finding.severity == severity,
            )
        )
        severity_counts[severity] = count_result.scalar_one()

    total_result = await db.execute(select(func.count(Finding.id)).where(Finding.project_id == project_id))
    verified_result = await db.execute(select(func.count(Finding.id)).where(Finding.project_id == project_id, Finding.status == "verified"))
    fp_result = await db.execute(select(func.count(Finding.id)).where(Finding.project_id == project_id, Finding.status == "false_positive"))
    scans_result = await db.execute(select(func.count(Scan.id)).where(Scan.project_id == project_id))

    return ProjectStatsSchema(
        total_findings=total_result.scalar_one(),
        findings_by_severity=severity_counts,
        verified_findings=verified_result.scalar_one(),
        false_positives=fp_result.scalar_one(),
        total_scans=scans_result.scalar_one(),
        last_scan_duration_ms=None,
        attack_surface_endpoints=0,
        coverage_pct=0.0,
    )


@router.post("/{project_id}/members", response_model=ProjectMemberSchema, status_code=201)
async def add_member(
    project_id: uuid.UUID,
    body: dict,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    project = await get_project_or_404(project_id, db, user)
    if project.owner_id != user.id:
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN"})

    member = ProjectMember(
        id=uuid.uuid4(),
        project_id=project_id,
        user_id=body["user_id"],
        role=body.get("role", "project_analyst"),
    )
    db.add(member)
    await db.commit()
    await db.refresh(member)
    return member


@router.delete("/{project_id}/members/{user_id}", status_code=204)
async def remove_member(
    project_id: uuid.UUID,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    project = await get_project_or_404(project_id, db, user)
    if project.owner_id != user.id:
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN"})

    result = await db.execute(
        select(ProjectMember).where(ProjectMember.project_id == project_id, ProjectMember.user_id == user_id)
    )
    member = result.scalar_one_or_none()
    if member:
        await db.delete(member)
        await db.commit()
