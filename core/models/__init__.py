"""
Models package — ekspor semua ORM model agar terdaftar di SQLAlchemy metadata.
Import dari sini memastikan Alembic dan create_all() menemukan semua tabel.
"""

from core.models.agent import Agent, AgentTask
from core.models.apt_profile import APTProfile
from core.models.campaign import Campaign, CampaignStep
from core.models.execution import Execution
from core.models.finding import Finding
from core.models.purple_session import PurpleEvent, PurpleSession
from core.models.technique import Technique

__all__ = [
    "Agent",
    "AgentTask",
    "APTProfile",
    "Campaign",
    "CampaignStep",
    "Execution",
    "Finding",
    "PurpleEvent",
    "PurpleSession",
    "Technique",
]
