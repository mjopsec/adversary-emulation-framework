"""
Attack Path Graph — Graf jalur serangan berbasis NetworkX.

Membangun directed graph dari teknik-teknik yang telah dieksekusi dalam kampanye.
Setiap node adalah teknik ATT&CK; edge merepresentasikan urutan eksekusi.

Kemampuan utama:
1. Bangun graph dari riwayat eksekusi kampanye
2. Identifikasi critical path (jalur terpanjang menuju impact)
3. Temukan chokepoints (node dengan banyak ketergantungan)
4. Visualisasi dalam format ATT&CK Navigator layer (JSON)
5. Export ke berbagai format (dict, Graphviz DOT)

Graph attributes:
- Node: technique_id, name, status, tactic, detected, risk_level
- Edge: sequence_number, duration_seconds, pivot (bool)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from loguru import logger


# ─── Node dan Edge Data ───────────────────────────────────────────────────────

@dataclass
class PathNode:
    """Node dalam attack path graph."""
    technique_id: str
    name: str
    tactic: str
    status: str                        # success | failed | partial | aborted | skipped
    risk_level: str = "medium"
    detected: bool = False
    execution_order: int = 0
    duration_seconds: float | None = None
    target: str | None = None
    artifacts: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def is_success(self) -> bool:
        return self.status == "success"

    @property
    def color_for_navigator(self) -> str:
        """Warna untuk ATT&CK Navigator berdasarkan status deteksi."""
        if not self.is_success:
            return "#999999"   # Abu-abu: gagal/dibatalkan
        if self.detected:
            return "#4CAF50"   # Hijau: terdeteksi (baik untuk defender)
        return "#f44336"       # Merah: tidak terdeteksi (gap!)

    @property
    def score_for_navigator(self) -> float:
        """Skor untuk ATT&CK Navigator heat (0-100)."""
        if not self.is_success:
            return 0
        return 50 if self.detected else 100


@dataclass
class PathEdge:
    """Edge dalam attack path graph."""
    source_id: str
    target_id: str
    sequence: int
    is_pivot: bool = False             # Apakah ini hasil pivot (teknik asli gagal)
    duration_gap_seconds: float = 0.0  # Jeda antara dua eksekusi


# ─── Attack Path Graph ────────────────────────────────────────────────────────

class AttackPathGraph:
    """
    Directed graph jalur serangan dari satu kampanye.

    Menggunakan NetworkX di bawahnya; jika NetworkX tidak tersedia,
    fallback ke implementasi adjacency list sederhana.
    """

    def __init__(self, campaign_id: str, campaign_name: str = "") -> None:
        self.campaign_id = campaign_id
        self.campaign_name = campaign_name
        self._nodes: dict[str, PathNode] = {}
        self._edges: list[PathEdge] = []
        self._adjacency: dict[str, list[str]] = {}  # source → list of targets
        self._nx_graph = None

        # Coba import NetworkX
        try:
            import networkx as nx
            self._nx_graph = nx.DiGraph()
            self._nx_available = True
        except ImportError:
            logger.debug("NetworkX tidak tersedia — menggunakan adjacency list sederhana.")
            self._nx_available = False

    # ─── Build Graph ──────────────────────────────────────────────────────────

    def add_node(self, node: PathNode) -> None:
        """Tambahkan node teknik ke graph."""
        self._nodes[node.technique_id] = node
        if self._nx_available and self._nx_graph is not None:
            self._nx_graph.add_node(
                node.technique_id,
                name=node.name,
                tactic=node.tactic,
                status=node.status,
                detected=node.detected,
                risk_level=node.risk_level,
                execution_order=node.execution_order,
                duration=node.duration_seconds,
            )
        logger.debug(
            "Graph node ditambahkan: {} ({}) status={}",
            node.technique_id, node.name, node.status,
        )

    def add_edge(self, edge: PathEdge) -> None:
        """Tambahkan edge antar dua node."""
        self._edges.append(edge)

        # Update adjacency list
        if edge.source_id not in self._adjacency:
            self._adjacency[edge.source_id] = []
        self._adjacency[edge.source_id].append(edge.target_id)

        if self._nx_available and self._nx_graph is not None:
            self._nx_graph.add_edge(
                edge.source_id,
                edge.target_id,
                sequence=edge.sequence,
                is_pivot=edge.is_pivot,
                duration_gap=edge.duration_gap_seconds,
            )

    def build_from_executions(self, executions: list[dict]) -> None:
        """
        Build graph dari list execution records.

        Format execution dict yang diharapkan:
        {
            "technique_id": "T1566",
            "technique_name": "Phishing",
            "tactic": "initial-access",
            "status": "success",
            "detected": false,
            "risk_level": "medium",
            "order_index": 0,
            "duration_seconds": 3.2,
            "target": "192.168.1.100",
            "artifacts_created": [],
            "is_pivot": false,
        }
        """
        # Urutkan berdasarkan order_index
        sorted_execs = sorted(executions, key=lambda e: e.get("order_index", 0))

        prev_technique_id: str | None = None
        for i, exec_data in enumerate(sorted_execs):
            technique_id = exec_data.get("technique_id", "UNKNOWN")
            if not technique_id or technique_id == "UNKNOWN":
                continue

            node = PathNode(
                technique_id=technique_id,
                name=exec_data.get("technique_name", technique_id),
                tactic=exec_data.get("tactic", "unknown"),
                status=exec_data.get("status", "failed"),
                risk_level=exec_data.get("risk_level", "medium"),
                detected=exec_data.get("detected", False),
                execution_order=i,
                duration_seconds=exec_data.get("duration_seconds"),
                target=exec_data.get("target"),
                artifacts=exec_data.get("artifacts_created", []),
            )
            self.add_node(node)

            # Tambah edge dari node sebelumnya
            if prev_technique_id and prev_technique_id != technique_id:
                edge = PathEdge(
                    source_id=prev_technique_id,
                    target_id=technique_id,
                    sequence=i,
                    is_pivot=exec_data.get("is_pivot", False),
                )
                self.add_edge(edge)

            prev_technique_id = technique_id

        logger.info(
            "Attack path graph built: {} nodes, {} edges",
            len(self._nodes), len(self._edges),
        )

    # ─── Analysis ─────────────────────────────────────────────────────────────

    def get_critical_path(self) -> list[str]:
        """
        Temukan jalur terpanjang dari entry point ke impact.
        Returns: list technique_ids dalam urutan critical path.
        """
        if not self._nodes:
            return []

        if self._nx_available and self._nx_graph is not None:
            try:
                import networkx as nx
                # Gunakan DAG longest path jika graph adalah DAG
                if nx.is_directed_acyclic_graph(self._nx_graph):
                    return nx.dag_longest_path(self._nx_graph)
                # Jika ada siklus, fallback ke execution order
            except Exception as e:
                logger.debug("NetworkX critical path error: {}", e)

        # Fallback: urutan eksekusi linear
        return [
            node.technique_id
            for node in sorted(self._nodes.values(), key=lambda n: n.execution_order)
            if node.is_success
        ]

    def get_chokepoints(self) -> list[str]:
        """
        Identifikasi node dengan banyak ketergantungan (chokepoints).
        Chokepoint = node yang banyak dikunjungi / banyak teknik bergantung padanya.
        Returns: list technique_ids yang merupakan chokepoint.
        """
        if not self._nodes:
            return []

        if self._nx_available and self._nx_graph is not None:
            try:
                import networkx as nx
                # Node dengan betweenness centrality tinggi
                centrality = nx.betweenness_centrality(self._nx_graph)
                threshold = sum(centrality.values()) / len(centrality) if centrality else 0
                chokepoints = [
                    node for node, score in centrality.items()
                    if score > threshold and node in self._nodes
                ]
                return sorted(chokepoints, key=lambda n: centrality[n], reverse=True)
            except Exception as e:
                logger.debug("NetworkX chokepoint error: {}", e)

        # Fallback: node dengan paling banyak successors
        in_degree: dict[str, int] = {}
        for edge in self._edges:
            in_degree[edge.target_id] = in_degree.get(edge.target_id, 0) + 1

        avg = sum(in_degree.values()) / len(in_degree) if in_degree else 0
        return [nid for nid, deg in in_degree.items() if deg > avg]

    def get_detection_gaps(self) -> list[str]:
        """
        Teknik yang BERHASIL tapi TIDAK TERDETEKSI = detection gap kritis.
        Returns: list technique_ids yang merupakan gap.
        """
        return [
            node.technique_id
            for node in self._nodes.values()
            if node.is_success and not node.detected
        ]

    def get_pivot_sequences(self) -> list[tuple[str, str]]:
        """
        Temukan semua sequence pivot (edge yang merupakan hasil pivot).
        Returns: list of (from_technique, to_technique) tuples.
        """
        return [
            (e.source_id, e.target_id)
            for e in self._edges
            if e.is_pivot
        ]

    def compute_statistics(self) -> dict:
        """Hitung statistik dari graph."""
        total = len(self._nodes)
        if total == 0:
            return {"total_nodes": 0}

        success_nodes = [n for n in self._nodes.values() if n.is_success]
        failed_nodes = [n for n in self._nodes.values() if n.status == "failed"]
        aborted_nodes = [n for n in self._nodes.values() if n.status == "aborted"]
        detected_success = [n for n in success_nodes if n.detected]
        undetected_success = [n for n in success_nodes if not n.detected]

        durations = [n.duration_seconds for n in self._nodes.values() if n.duration_seconds]

        return {
            "total_nodes": total,
            "total_edges": len(self._edges),
            "success_count": len(success_nodes),
            "failed_count": len(failed_nodes),
            "aborted_count": len(aborted_nodes),
            "detected_count": len(detected_success),
            "undetected_count": len(undetected_success),
            "detection_rate": round(len(detected_success) / len(success_nodes), 2) if success_nodes else 0,
            "success_rate": round(len(success_nodes) / total, 2),
            "pivot_count": sum(1 for e in self._edges if e.is_pivot),
            "avg_duration_seconds": (
                round(sum(durations) / len(durations), 2) if durations else None
            ),
            "critical_path": self.get_critical_path(),
            "detection_gaps": self.get_detection_gaps(),
            "chokepoints": self.get_chokepoints(),
        }

    # ─── Export ───────────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Export graph ke dict Python."""
        return {
            "campaign_id": self.campaign_id,
            "campaign_name": self.campaign_name,
            "nodes": [
                {
                    "id": node.technique_id,
                    "name": node.name,
                    "tactic": node.tactic,
                    "status": node.status,
                    "detected": node.detected,
                    "risk_level": node.risk_level,
                    "order": node.execution_order,
                    "duration": node.duration_seconds,
                    "target": node.target,
                }
                for node in sorted(self._nodes.values(), key=lambda n: n.execution_order)
            ],
            "edges": [
                {
                    "source": edge.source_id,
                    "target": edge.target_id,
                    "sequence": edge.sequence,
                    "is_pivot": edge.is_pivot,
                }
                for edge in self._edges
            ],
            "statistics": self.compute_statistics(),
        }

    def to_navigator_layer(self) -> dict:
        """
        Export ke format ATT&CK Navigator layer JSON.
        Dapat di-import langsung ke https://mitre-attack.github.io/attack-navigator/
        """
        techniques_layer = []
        for node in self._nodes.values():
            techniques_layer.append({
                "techniqueID": node.technique_id,
                "tactic": node.tactic,
                "color": node.color_for_navigator,
                "comment": (
                    f"Status: {node.status} | "
                    f"Detected: {'Ya' if node.detected else 'TIDAK'} | "
                    f"Risk: {node.risk_level}"
                ),
                "enabled": True,
                "score": node.score_for_navigator,
                "metadata": [
                    {"name": "status", "value": node.status},
                    {"name": "detected", "value": str(node.detected)},
                    {"name": "risk", "value": node.risk_level},
                ],
            })

        return {
            "name": f"AEP Campaign: {self.campaign_name}",
            "versions": {
                "attack": "14",
                "navigator": "4.9.1",
                "layer": "4.5",
            },
            "domain": "enterprise-attack",
            "description": (
                f"Attack path dari kampanye '{self.campaign_name}'. "
                f"Merah = tidak terdeteksi (gap). Hijau = terdeteksi. Abu = gagal."
            ),
            "filters": {
                "platforms": [
                    "Windows", "Linux", "macOS",
                    "Network", "ICS",
                ],
            },
            "sorting": 0,
            "layout": {
                "layout": "side",
                "aggregateFunction": "max",
                "showID": True,
                "showName": True,
            },
            "hideDisabled": False,
            "techniques": techniques_layer,
            "gradient": {
                "colors": ["#ff6666", "#ff0000"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [
                {"label": "Tidak terdeteksi (GAP)", "color": "#f44336"},
                {"label": "Terdeteksi", "color": "#4CAF50"},
                {"label": "Gagal/Dibatalkan", "color": "#999999"},
            ],
            "metadata": [
                {"name": "campaign_id", "value": self.campaign_id},
                {"name": "generated_by", "value": "AEP Platform"},
            ],
        }

    def to_graphviz_dot(self) -> str:
        """Export ke format Graphviz DOT untuk visualisasi."""
        lines = [f'digraph "{self.campaign_name or self.campaign_id}" {{']
        lines.append("  rankdir=LR;")
        lines.append("  node [shape=box, style=filled];")

        for node in self._nodes.values():
            if node.is_success and not node.detected:
                color = "red"
            elif node.is_success:
                color = "lightgreen"
            else:
                color = "lightgray"

            label = f"{node.technique_id}\\n{node.name[:20]}\\n[{node.tactic}]"
            lines.append(
                f'  "{node.technique_id}" [label="{label}" fillcolor="{color}"];'
            )

        for edge in self._edges:
            style = "dashed" if edge.is_pivot else "solid"
            lines.append(
                f'  "{edge.source_id}" -> "{edge.target_id}" [style={style}];'
            )

        lines.append("}")
        return "\n".join(lines)

    def __repr__(self) -> str:
        return (
            f"<AttackPathGraph campaign={self.campaign_id!r} "
            f"nodes={len(self._nodes)} edges={len(self._edges)}>"
        )


# ─── Factory Function ─────────────────────────────────────────────────────────

def build_attack_path(
    campaign_id: str,
    campaign_name: str,
    executions: list[dict],
) -> AttackPathGraph:
    """
    Convenience function: bangun attack path graph dari executions.

    Args:
        campaign_id:   ID kampanye
        campaign_name: Nama kampanye
        executions:    List execution records (dari DB atau API)

    Returns:
        AttackPathGraph yang sudah di-populate
    """
    graph = AttackPathGraph(campaign_id=campaign_id, campaign_name=campaign_name)
    graph.build_from_executions(executions)
    return graph
