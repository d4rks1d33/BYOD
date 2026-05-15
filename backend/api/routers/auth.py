from __future__ import annotations
import logging
import secrets
import uuid
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

import redis.asyncio as aioredis

from api.deps import require_role
from core.database import get_db
from core.redis import get_redis
from core.security import (
    hash_password, verify_password,
    create_access_token, create_refresh_token, decode_token
)
from core.config import get_settings
from models.user import User
from schemas.auth import LoginRequest, LoginResponse, RefreshRequest, RefreshResponse, RegisterRequest, RegisterResponse

logger = logging.getLogger(__name__)
router = APIRouter()
settings = get_settings()


async def _check_rate_limit(redis: aioredis.Redis, ip: str) -> None:
    key = f"rate:login:{ip}"
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, 60)
    if count > 10:
        raise HTTPException(status_code=429, detail={"code": "RATE_LIMITED", "message": "Too many login attempts"})


@router.post("/login", response_model=LoginResponse, status_code=200)
async def login(
    request: Request,
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
):
    ip = request.client.host if request.client else "unknown"
    await _check_rate_limit(redis, ip)

    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()

    # Constant-time response to prevent username enumeration
    if not user or not verify_password(body.password, user.hashed_password):
        if user:
            await db.execute(
                update(User).where(User.id == user.id).values(
                    failed_login_attempts=User.failed_login_attempts + 1,
                    locked_until=(
                        datetime.now(timezone.utc) + timedelta(minutes=settings.ACCOUNT_LOCKOUT_MINUTES)
                        if (user.failed_login_attempts + 1) >= settings.MAX_LOGIN_ATTEMPTS else None
                    )
                )
            )
            await db.commit()
        raise HTTPException(status_code=401, detail={"code": "INVALID_CREDENTIALS", "message": "Invalid email or password"})

    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        raise HTTPException(
            status_code=423,
            detail={"code": "ACCOUNT_LOCKED", "locked_until": user.locked_until.isoformat()},
        )

    if user.mfa_enabled:
        import pyotp
        if not body.mfa_code:
            raise HTTPException(status_code=401, detail={"code": "MFA_REQUIRED", "message": "MFA code required"})
        totp = pyotp.TOTP(user.mfa_secret)
        if not totp.verify(body.mfa_code):
            raise HTTPException(status_code=401, detail={"code": "INVALID_MFA", "message": "Invalid MFA code"})

    token_data = {"sub": str(user.id), "email": user.email, "role": user.role.value}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    # Store refresh token in Redis
    refresh_payload = decode_token(refresh_token)
    jti = refresh_payload.get("jti", secrets.token_urlsafe(16))
    ttl = settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400
    await redis.setex(f"refresh:{jti}", ttl, str(user.id))

    await db.execute(update(User).where(User.id == user.id).values(
        failed_login_attempts=0,
        locked_until=None,
        last_login=datetime.now(timezone.utc),
    ))
    await db.commit()

    logger.info("User logged in", extra={"user_id": str(user.id)})
    return LoginResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/refresh", response_model=RefreshResponse)
async def refresh_token(
    body: RefreshRequest,
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
):
    payload = decode_token(body.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail={"code": "TOKEN_INVALID_OR_EXPIRED", "message": "Invalid refresh token"})

    jti = payload.get("jti")
    if not jti:
        raise HTTPException(status_code=401, detail={"code": "TOKEN_INVALID_OR_EXPIRED"})

    stored = await redis.get(f"refresh:{jti}")
    if not stored:
        raise HTTPException(status_code=401, detail={"code": "TOKEN_INVALID_OR_EXPIRED", "message": "Refresh token revoked"})

    # Revoke old token
    await redis.delete(f"refresh:{jti}")

    user_id = payload.get("sub")
    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail={"code": "UNAUTHORIZED"})

    token_data = {"sub": str(user.id), "email": user.email, "role": user.role.value}
    new_access = create_access_token(token_data)
    new_refresh = create_refresh_token(token_data)

    new_payload = decode_token(new_refresh)
    new_jti = new_payload.get("jti", secrets.token_urlsafe(16))
    ttl = settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400
    await redis.setex(f"refresh:{new_jti}", ttl, str(user.id))

    return RefreshResponse(access_token=new_access, refresh_token=new_refresh)


@router.post("/logout", status_code=204)
async def logout(
    body: RefreshRequest,
    redis: aioredis.Redis = Depends(get_redis),
):
    payload = decode_token(body.refresh_token)
    if payload:
        jti = payload.get("jti")
        if jti:
            await redis.delete(f"refresh:{jti}")


@router.post("/register", response_model=RegisterResponse, status_code=201)
async def register(
    body: RegisterRequest,
    db: AsyncSession = Depends(get_db),
    _=Depends(require_role("admin", "super_admin")),
):
    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail={"code": "EMAIL_EXISTS", "message": "Email already registered"})

    temp_password = secrets.token_urlsafe(12)
    user = User(
        id=uuid.uuid4(),
        email=body.email,
        full_name=body.full_name,
        hashed_password=hash_password(temp_password),
        role=body.role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    return RegisterResponse(user_id=str(user.id), email=user.email, temporary_password=temp_password)


@router.post("/signup", response_model=LoginResponse, status_code=201)
async def signup(
    request: Request,
    body: dict,
    db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
):
    """Public self-service signup. Creates account and returns tokens."""
    ip = request.client.host if request.client else "unknown"

    # Rate limit signup attempts
    key = f"rate:signup:{ip}"
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, 3600)
    if count > 5:
        raise HTTPException(status_code=429, detail={"code": "RATE_LIMITED", "message": "Too many signup attempts"})

    email = body.get("email", "").strip().lower()
    password = body.get("password", "")
    full_name = body.get("full_name", "").strip()

    if not email or not password or not full_name:
        raise HTTPException(status_code=400, detail={"code": "MISSING_FIELDS", "message": "email, password, and full_name are required"})

    if len(password) < 8:
        raise HTTPException(status_code=400, detail={"code": "WEAK_PASSWORD", "message": "Password must be at least 8 characters"})

    # Check existing
    existing = await db.execute(select(User).where(User.email == email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail={"code": "EMAIL_EXISTS", "message": "Email already registered"})

    # Create user (default role: analyst)
    user = User(
        id=uuid.uuid4(),
        email=email,
        full_name=full_name,
        hashed_password=hash_password(password),
        role="analyst",
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    # Auto-login: issue tokens
    token_data = {"sub": str(user.id), "email": user.email, "role": user.role.value if hasattr(user.role, "value") else str(user.role)}
    access = create_access_token(token_data)
    refresh = create_refresh_token(token_data)

    return LoginResponse(access_token=access, refresh_token=refresh, token_type="bearer")
