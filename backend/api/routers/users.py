from __future__ import annotations
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from core.database import get_db
from api.deps import get_current_active_user, require_role
from models.user import User
from schemas.user import UserSchema, UserUpdateSchema, UserListSchema

router = APIRouter()


@router.get("/users/me", response_model=UserSchema)
async def get_me(user: User = Depends(get_current_active_user)):
    return user


@router.patch("/users/me", response_model=UserSchema)
async def update_me(
    body: UserUpdateSchema,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    if body.full_name is not None:
        user.full_name = body.full_name
    if body.email is not None:
        # Check uniqueness
        existing = await db.execute(select(User).where(User.email == body.email, User.id != user.id))
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail={"code": "EMAIL_TAKEN"})
        user.email = body.email
    if body.password:
        from core.security import hash_password
        user.hashed_password = hash_password(body.password)
    await db.commit()
    await db.refresh(user)
    return user


@router.get("/users", response_model=list[UserListSchema])
async def list_users(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    result = await db.execute(select(User))
    return result.scalars().all()


@router.get("/users/{user_id}", response_model=UserSchema)
async def get_user(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
):
    result = await db.execute(select(User).where(User.id == user_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND"})
    return target


@router.patch("/users/{user_id}", response_model=UserSchema)
async def admin_update_user(
    user_id: uuid.UUID,
    body: UserUpdateSchema,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role("admin")),
):
    result = await db.execute(select(User).where(User.id == user_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND"})

    if body.full_name is not None:
        target.full_name = body.full_name
    if body.role is not None:
        target.role = body.role
    if body.is_active is not None:
        target.is_active = body.is_active
    await db.commit()
    await db.refresh(target)
    return target


@router.delete("/users/{user_id}", status_code=204)
async def delete_user(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    if current_user.id == user_id:
        raise HTTPException(status_code=400, detail={"code": "CANNOT_DELETE_SELF"})
    result = await db.execute(select(User).where(User.id == user_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND"})
    await db.delete(target)
    await db.commit()
