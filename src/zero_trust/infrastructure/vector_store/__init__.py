"""Vector store infrastructure - Weaviate integration."""

from zero_trust.infrastructure.vector_store.client import (
    VectorStoreClient,
    get_vector_store,
)
from zero_trust.infrastructure.vector_store.schemas import (
    ThreatIntelCollection,
    SecurityAdvisoryCollection,
)

__all__ = [
    "VectorStoreClient",
    "get_vector_store",
    "ThreatIntelCollection",
    "SecurityAdvisoryCollection",
]
