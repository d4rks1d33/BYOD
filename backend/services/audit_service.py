from __future__ import annotations
import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

_CHAIN_GENESIS = "0" * 64


class AuditService:

    @staticmethod
    def log(
        db,
        *,
        actor_id: Optional[str],
        actor_email: Optional[str],
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        project_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[dict] = None,
    ):
        from models.audit_log import AuditLog
        from sqlalchemy import select, desc

        now = datetime.now(timezone.utc)

        prev_result = db.execute(
            select(AuditLog.hash)
            .where(AuditLog.resource_type == resource_type, AuditLog.resource_id == resource_id)
            .order_by(desc(AuditLog.created_at))
            .limit(1)
        )
        prev_hash = prev_result.scalar_one_or_none() or _CHAIN_GENESIS

        chain_input = f"{prev_hash}{action}{resource_id or ''}{now.isoformat()}"
        new_hash = hashlib.sha256(chain_input.encode()).hexdigest()

        record = AuditLog(
            actor_id=actor_id,
            actor_email=actor_email,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            project_id=project_id,
            ip_address=ip_address,
            details=details or {},
            prev_hash=prev_hash,
            hash=new_hash,
            created_at=now,
        )
        db.add(record)
        db.flush()
        return record
