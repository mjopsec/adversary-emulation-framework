"""API endpoints untuk manajemen APT Profile."""

from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_session
from core.models.apt_profile import APTProfile
from core.schemas.apt_profile import APTProfileCreate, APTProfileRead, APTProfileUpdate

router = APIRouter(prefix="/apt-profiles", tags=["apt_profiles"])

DBSession = Annotated[AsyncSession, Depends(get_session)]


@router.get("/", response_model=list[APTProfileRead], summary="Daftar APT profiles")
async def list_apt_profiles(
    db: DBSession,
    targets_ot: bool | None = None,
) -> list[APTProfileRead]:
    """Ambil semua APT profiles. Filter berdasarkan kemampuan OT jika diperlukan."""
    query = select(APTProfile).order_by(APTProfile.name)
    if targets_ot is not None:
        query = query.where(APTProfile.targets_ot == targets_ot)
    result = await db.execute(query)
    return [APTProfileRead.model_validate(p) for p in result.scalars().all()]


@router.post(
    "/",
    response_model=APTProfileRead,
    status_code=status.HTTP_201_CREATED,
    summary="Buat APT profile custom",
)
async def create_apt_profile(data: APTProfileCreate, db: DBSession) -> APTProfileRead:
    profile = APTProfile(
        id=str(uuid4()),
        name=data.name,
        description=data.description,
        mitre_group_id=data.mitre_group_id,
        motivation=data.motivation,
        sophistication=data.sophistication,
        targets_ot=data.targets_ot,
        is_custom=data.is_custom,
        attributed_country=data.attributed_country,
    )
    profile.technique_preferences = data.technique_preferences
    profile.preferred_tools = data.preferred_tools
    profile.known_aliases = data.known_aliases

    db.add(profile)
    await db.commit()
    await db.refresh(profile)
    return APTProfileRead.model_validate(profile)


@router.get("/{profile_id}", response_model=APTProfileRead, summary="Detail APT profile")
async def get_apt_profile(profile_id: str, db: DBSession) -> APTProfileRead:
    result = await db.execute(select(APTProfile).where(APTProfile.id == profile_id))
    profile = result.scalar_one_or_none()
    if not profile:
        raise HTTPException(status_code=404, detail="APT profile tidak ditemukan.")
    return APTProfileRead.model_validate(profile)


@router.delete("/{profile_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Hapus APT profile")
async def delete_apt_profile(profile_id: str, db: DBSession) -> None:
    result = await db.execute(select(APTProfile).where(APTProfile.id == profile_id))
    profile = result.scalar_one_or_none()
    if not profile:
        raise HTTPException(status_code=404, detail="APT profile tidak ditemukan.")
    if not profile.is_custom:
        raise HTTPException(
            status_code=400,
            detail="Profil bawaan tidak bisa dihapus.",
        )
    await db.delete(profile)
    await db.commit()


@router.patch("/{profile_id}", response_model=APTProfileRead, summary="Update APT profile")
async def update_apt_profile(
    profile_id: str,
    data: APTProfileUpdate,
    db: DBSession,
) -> APTProfileRead:
    result = await db.execute(select(APTProfile).where(APTProfile.id == profile_id))
    profile = result.scalar_one_or_none()
    if not profile:
        raise HTTPException(status_code=404, detail="APT profile tidak ditemukan.")
    if not profile.is_custom:
        raise HTTPException(
            status_code=400,
            detail="Profil bawaan tidak bisa diubah. Buat profil custom baru.",
        )

    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        if hasattr(profile, key):
            setattr(profile, key, value)

    await db.commit()
    await db.refresh(profile)
    return APTProfileRead.model_validate(profile)
