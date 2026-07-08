"""
Knowledge Forge — ChromaDB-backed cross-build persistent adversarial memory.

Stores attacks tagged by CWE category and codebase fingerprint.
Recalled attacks are injected into the Breaker's opening prompt on new runs,
elevating day-1 attack quality for similar codebases.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

_COLLECTION_NAME = "gauntlex_attacks"
_DEFAULT_FORGE_DIR = Path(".gauntlex/forge")


class KnowledgeForge:
    """
    Wraps ChromaDB for persistent adversarial memory.

    Lazy-initializes: ChromaDB is only imported/started when first used.
    This keeps `import gauntlex` fast even if ChromaDB is slow to start.
    """

    def __init__(self, forge_dir: Path | str = _DEFAULT_FORGE_DIR):
        self._forge_dir = Path(forge_dir)
        self._client = None
        self._collection = None

    def _ensure_init(self) -> None:
        if self._client is not None:
            return
        try:
            import chromadb

            self._forge_dir.mkdir(parents=True, exist_ok=True)
            self._client = chromadb.PersistentClient(path=str(self._forge_dir))
            self._collection = self._client.get_or_create_collection(
                name=_COLLECTION_NAME,
                metadata={"hnsw:space": "cosine"},
            )
        except ImportError:
            raise RuntimeError(
                "chromadb is not installed. Run: pip install chromadb>=0.5"
            )

    def store_attack(
        self,
        attack_id: str,
        description: str,
        cwe: str,
        severity: str,
        run_id: str,
        effectiveness: float = 0.0,
        codebase_fingerprint: str = "",
    ) -> None:
        self._ensure_init()
        doc_id = f"{run_id}::{attack_id}"
        self._collection.upsert(
            ids=[doc_id],
            documents=[description],
            metadatas=[
                {
                    "cwe": cwe,
                    "severity": severity,
                    "run_id": run_id,
                    "effectiveness": str(effectiveness),
                    "fingerprint": codebase_fingerprint,
                }
            ],
        )

    def recall_attacks(
        self,
        spec_or_code: str,
        n_results: int = 10,
        min_effectiveness: float = 0.3,
    ) -> list[dict]:
        """Return the most relevant historical attacks for the given spec/code."""
        self._ensure_init()
        try:
            results = self._collection.query(
                query_texts=[spec_or_code],
                n_results=n_results,
                where={"effectiveness": {"$gte": str(min_effectiveness)}},
            )
        except Exception:
            # Graceful degradation: if query fails (e.g., empty collection), return nothing
            return []

        attacks = []
        for doc, meta in zip(
            results.get("documents", [[]])[0],
            results.get("metadatas", [[]])[0],
        ):
            attacks.append({"description": doc, **meta})
        return attacks

    def format_recalled_for_prompt(self, attacks: list[dict]) -> str:
        if not attacks:
            return ""
        lines = []
        for a in attacks:
            eff = float(a.get("effectiveness", 0))
            lines.append(f"- [{a.get('cwe', '?')}] {a['description']} (effectiveness: {eff:.2f})")
        return "\n".join(lines)

    def count(self) -> int:
        self._ensure_init()
        return self._collection.count()

    def is_available(self) -> bool:
        """Check if ChromaDB is available without raising."""
        try:
            self._ensure_init()
            return True
        except Exception:
            return False
