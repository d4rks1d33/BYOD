#!/usr/bin/env python3
"""Seed the database with initial admin user, AI config, and sample project."""
from __future__ import annotations
import asyncio
import secrets
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


async def main() -> None:
    from core.database import init_db
    from core.config import get_settings
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy import select

    settings = get_settings()
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    await init_db()

    from models.user import User
    from models.project import Project
    from models.ai_model_config import AIModelConfig
    from core.security import hash_password

    async with async_session() as db:
        # Admin user
        result = await db.execute(select(User).where(User.email == "admin@autopentest.local"))
        admin = result.scalar_one_or_none()
        if not admin:
            temp_password = secrets.token_urlsafe(16)
            admin = User(
                email="admin@autopentest.local",
                hashed_password=hash_password(temp_password),
                full_name="Admin",
                role="admin",
                is_active=True,
            )
            db.add(admin)
            await db.flush()
            print(f"\n✅ Admin user created")
            print(f"   Email:    admin@autopentest.local")
            print(f"   Password: {temp_password}")
            print(f"   ⚠️  Save this password — it won't be shown again.\n")
        else:
            print("   Admin user already exists, skipping.")

        # Default AI model config
        result = await db.execute(select(AIModelConfig).where(AIModelConfig.is_default == True))
        existing_ai = result.scalar_one_or_none()
        if not existing_ai:
            ai_config = AIModelConfig(
                name="Local GGUF Model",
                provider="llamacpp",
                model_ref=f"{settings.MODEL_PATH}/{settings.DEFAULT_MODEL_FILE}",
                config={"n_ctx": 4096, "temperature": 0.1},
                is_default=True,
                is_active=True,
            )
            db.add(ai_config)
            print("✅ Default AI model config created (llama.cpp)")

        # Sample project
        result = await db.execute(select(Project).where(Project.name == "Demo Project"))
        existing_proj = result.scalar_one_or_none()
        if not existing_proj and admin.id:
            project = Project(
                name="Demo Project",
                description="Sample project for testing DAST/SAST",
                target_url="http://testphp.vulnweb.com",
                target_type="web",
                status="active",
                owner_id=admin.id,
                scope_urls=["http://testphp.vulnweb.com"],
            )
            db.add(project)
            print("✅ Sample project created (target: testphp.vulnweb.com)")

        await db.commit()

    await engine.dispose()
    print("\n🚀 Database seeded successfully.")


if __name__ == "__main__":
    asyncio.run(main())
