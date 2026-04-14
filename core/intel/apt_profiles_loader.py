"""
APT Profile Loader.

Memuat profil APT bawaan dari data MITRE ATT&CK Groups
dan juga dari file YAML custom di direktori data/apt_profiles/.
"""

import json
from pathlib import Path

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from core.config import Settings


# Profil APT bawaan yang relevan untuk ICS/OT dan Enterprise IT
BUILTIN_APT_PROFILES = [
    {
        "name": "APT28 (Fancy Bear)",
        "mitre_group_id": "G0007",
        "description": (
            "Kelompok ancaman yang disponsori negara Rusia, dikaitkan dengan GRU. "
            "Menarget pemerintah, militer, dan sektor energi. "
            "Dikenal dengan kampanye spear-phishing dan penggunaan custom malware."
        ),
        "motivation": "espionage",
        "sophistication": "nation_state",
        "targets_ot": False,
        "is_custom": False,
        "attributed_country": "Russia",
        "technique_preferences": [
            "T1566", "T1078", "T1027", "T1055", "T1021",
            "T1003", "T1071", "T1105", "T1059",
        ],
        "preferred_tools": ["X-Agent", "Sofacy", "Zebrocy", "CHOPSTICK"],
        "known_aliases": ["Fancy Bear", "STRONTIUM", "Sofacy", "Sednit"],
    },
    {
        "name": "APT29 (Cozy Bear)",
        "mitre_group_id": "G0016",
        "description": (
            "Kelompok APT Rusia yang dikaitkan dengan SVR. "
            "Dikenal dengan teknik yang sangat stealth, persistence jangka panjang, "
            "dan penggunaan supply chain attack. Menarget pemerintah dan sektor kritis."
        ),
        "motivation": "espionage",
        "sophistication": "nation_state",
        "targets_ot": False,
        "is_custom": False,
        "attributed_country": "Russia",
        "technique_preferences": [
            "T1195", "T1078", "T1027", "T1036", "T1562",
            "T1070", "T1071", "T1090", "T1550",
        ],
        "preferred_tools": ["SUNBURST", "TEARDROP", "WellMess", "MiniDuke"],
        "known_aliases": ["Cozy Bear", "The Dukes", "Office Monkeys", "YTTRIUM"],
    },
    {
        "name": "Sandworm",
        "mitre_group_id": "G0034",
        "description": (
            "Kelompok ancaman Rusia (GRU Unit 74455) yang berfokus pada sabotase "
            "infrastruktur kritis, termasuk jaringan listrik Ukraina (2015, 2016) "
            "dan serangan NotPetya. Salah satu aktor ICS/OT paling berbahaya."
        ),
        "motivation": "sabotage",
        "sophistication": "nation_state",
        "targets_ot": True,
        "is_custom": False,
        "attributed_country": "Russia",
        "technique_preferences": [
            "T0800", "T0816", "T0828", "T0831", "T0840",
            "T1078", "T1190", "T1059", "T1486",
        ],
        "preferred_tools": ["Industroyer", "BlackEnergy", "Exaramel", "NotPetya"],
        "known_aliases": ["Voodoo Bear", "ELECTRUM", "BlackEnergy Group", "TeleBots"],
    },
    {
        "name": "Lazarus Group",
        "mitre_group_id": "G0032",
        "description": (
            "Kelompok ancaman Korea Utara yang disponsori negara. "
            "Termotivasi secara finansial (pencurian kripto, bank) dan espionage. "
            "Dikenal dengan serangan SWIFT, ransomware, dan supply chain attacks."
        ),
        "motivation": "financial",
        "sophistication": "nation_state",
        "targets_ot": False,
        "is_custom": False,
        "attributed_country": "North Korea",
        "technique_preferences": [
            "T1566", "T1059", "T1105", "T1027", "T1055",
            "T1486", "T1041", "T1071", "T1036",
        ],
        "preferred_tools": ["BLINDINGCAN", "HOPLIGHT", "ELECTRICFISH", "AppleJeus"],
        "known_aliases": ["HIDDEN COBRA", "Guardians of Peace", "ZINC", "Diamond Sleet"],
    },
    {
        "name": "TRITON/TRISIS Actor",
        "mitre_group_id": "G0088",
        "description": (
            "Kelompok ancaman yang mengembangkan malware TRITON, satu-satunya malware "
            "yang didesain khusus untuk menyerang Safety Instrumented System (SIS). "
            "Menarget fasilitas petrokimia di Timur Tengah."
        ),
        "motivation": "sabotage",
        "sophistication": "nation_state",
        "targets_ot": True,
        "is_custom": False,
        "attributed_country": "Russia",
        "technique_preferences": [
            "T0857", "T0821", "T0843", "T0845", "T0862",
            "T1078", "T1190", "T1021",
        ],
        "preferred_tools": ["TRITON", "TRISIS", "HatMan"],
        "known_aliases": ["XENOTIME", "TEMP.Veles"],
    },
    {
        "name": "Custom ICS Red Team",
        "mitre_group_id": None,
        "description": (
            "Profil custom untuk red team engagement pada lingkungan ICS/OT. "
            "Menggunakan TTP gabungan dari berbagai kelompok APT yang menarget OT. "
            "Sesuaikan profil ini dengan tujuan spesifik engagement."
        ),
        "motivation": "espionage",
        "sophistication": "high",
        "targets_ot": True,
        "is_custom": True,
        "attributed_country": None,
        "technique_preferences": [
            "T0801", "T0802", "T0843", "T0845", "T0856",
            "T0869", "T0871", "T0882",
        ],
        "preferred_tools": [],
        "known_aliases": [],
    },
    {
        "name": "Custom Enterprise Red Team",
        "mitre_group_id": None,
        "description": (
            "Profil custom untuk red team engagement pada lingkungan Enterprise IT. "
            "Menggunakan TTP yang umum digunakan oleh APT dan cybercriminal groups. "
            "Sesuaikan profil ini dengan tujuan spesifik engagement."
        ),
        "motivation": "espionage",
        "sophistication": "high",
        "targets_ot": False,
        "is_custom": True,
        "attributed_country": None,
        "technique_preferences": [
            "T1566", "T1078", "T1059", "T1055", "T1021",
            "T1003", "T1486", "T1041",
        ],
        "preferred_tools": [],
        "known_aliases": [],
    },
]


async def load_builtin_profiles(session: AsyncSession) -> dict[str, int]:
    """
    Muat profil APT bawaan ke database.
    Skip profil yang sudah ada (berdasarkan nama).

    Returns: dict dengan jumlah profil yang diinsert dan diskip.
    """
    from core.models.apt_profile import APTProfile

    existing_names_result = await session.execute(
        select(APTProfile.name)
    )
    existing_names = set(existing_names_result.scalars().all())

    inserted = 0
    skipped = 0

    for profile_data in BUILTIN_APT_PROFILES:
        if profile_data["name"] in existing_names:
            skipped += 1
            continue

        profile = APTProfile(
            name=profile_data["name"],
            description=profile_data.get("description"),
            mitre_group_id=profile_data.get("mitre_group_id"),
            motivation=profile_data["motivation"],
            sophistication=profile_data["sophistication"],
            _technique_preferences=json.dumps(profile_data.get("technique_preferences", [])),
            _preferred_tools=json.dumps(profile_data.get("preferred_tools", [])),
            _known_aliases=json.dumps(profile_data.get("known_aliases", [])),
            targets_ot=profile_data.get("targets_ot", False),
            is_custom=profile_data.get("is_custom", True),
            attributed_country=profile_data.get("attributed_country"),
        )
        session.add(profile)
        inserted += 1

    await session.commit()
    logger.info(
        "APT profiles loaded: {} diinsert, {} sudah ada (diskip)",
        inserted, skipped,
    )
    return {"inserted": inserted, "skipped": skipped}
