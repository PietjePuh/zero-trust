"""
Weaviate vector store client.

Provides semantic search capabilities for threat intelligence
and security advisories using hybrid search (vector + keyword).
"""

from functools import lru_cache
from typing import Any

import structlog
import weaviate
from weaviate.classes.config import Configure, DataType, Property
from weaviate.classes.query import Filter, MetadataQuery
from weaviate.exceptions import WeaviateConnectionError

from zero_trust.config import Settings, get_settings
from zero_trust.core.exceptions import VectorStoreError

logger = structlog.get_logger(__name__)


class VectorStoreClient:
    """
    Weaviate vector store client.

    Provides methods for:
    - Storing and retrieving threat intelligence
    - Semantic search across security data
    - Hybrid search combining vector and keyword matching
    """

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._client: weaviate.WeaviateClient | None = None

    async def connect(self) -> None:
        """Establish connection to Weaviate."""
        try:
            if self.settings.weaviate.api_key:
                self._client = weaviate.connect_to_custom(
                    http_host=self._parse_host(self.settings.weaviate.url),
                    http_port=self._parse_port(self.settings.weaviate.url),
                    http_secure=self.settings.weaviate.url.startswith("https"),
                    auth_credentials=weaviate.auth.AuthApiKey(
                        self.settings.weaviate.api_key.get_secret_value()
                    ),
                )
            else:
                self._client = weaviate.connect_to_local(
                    host=self._parse_host(self.settings.weaviate.url),
                    port=self._parse_port(self.settings.weaviate.url),
                )

            await logger.ainfo("vector_store_connected", url=self.settings.weaviate.url)

        except WeaviateConnectionError as e:
            await logger.aerror("vector_store_connection_failed", error=str(e))
            raise VectorStoreError(
                "Failed to connect to vector store",
                operation="connect",
                context={"url": self.settings.weaviate.url, "error": str(e)},
            ) from e

    async def close(self) -> None:
        """Close connection to Weaviate."""
        if self._client:
            self._client.close()
            self._client = None
            await logger.ainfo("vector_store_disconnected")

    @property
    def client(self) -> weaviate.WeaviateClient:
        """Get the Weaviate client, raising if not connected."""
        if self._client is None:
            raise VectorStoreError(
                "Vector store not connected",
                operation="get_client",
            )
        return self._client

    async def ensure_collections(self) -> None:
        """Ensure required collections exist."""
        await self._create_threat_intel_collection()
        await self._create_security_advisory_collection()

    async def _create_threat_intel_collection(self) -> None:
        """Create the threat intelligence collection if it doesn't exist."""
        collection_name = "ThreatIntel"

        if self.client.collections.exists(collection_name):
            return

        self.client.collections.create(
            name=collection_name,
            description="Threat indicators and IOCs for semantic search",
            vectorizer_config=Configure.Vectorizer.text2vec_transformers(),
            properties=[
                Property(name="indicator_id", data_type=DataType.TEXT),
                Property(name="type", data_type=DataType.TEXT),
                Property(name="value", data_type=DataType.TEXT),
                Property(name="description", data_type=DataType.TEXT),
                Property(name="severity", data_type=DataType.TEXT),
                Property(name="category", data_type=DataType.TEXT),
                Property(name="confidence", data_type=DataType.NUMBER),
                Property(name="source", data_type=DataType.TEXT),
                Property(name="tags", data_type=DataType.TEXT_ARRAY),
                Property(name="mitre_tactics", data_type=DataType.TEXT_ARRAY),
                Property(name="mitre_techniques", data_type=DataType.TEXT_ARRAY),
            ],
        )

        await logger.ainfo("collection_created", name=collection_name)

    async def _create_security_advisory_collection(self) -> None:
        """Create the security advisory collection if it doesn't exist."""
        collection_name = "SecurityAdvisory"

        if self.client.collections.exists(collection_name):
            return

        self.client.collections.create(
            name=collection_name,
            description="Security advisories, CVEs, and vulnerability information",
            vectorizer_config=Configure.Vectorizer.text2vec_transformers(),
            properties=[
                Property(name="advisory_id", data_type=DataType.TEXT),
                Property(name="title", data_type=DataType.TEXT),
                Property(name="description", data_type=DataType.TEXT),
                Property(name="severity", data_type=DataType.TEXT),
                Property(name="cvss_score", data_type=DataType.NUMBER),
                Property(name="affected_products", data_type=DataType.TEXT_ARRAY),
                Property(name="cve_ids", data_type=DataType.TEXT_ARRAY),
                Property(name="references", data_type=DataType.TEXT_ARRAY),
                Property(name="published_date", data_type=DataType.DATE),
                Property(name="remediation", data_type=DataType.TEXT),
            ],
        )

        await logger.ainfo("collection_created", name=collection_name)

    async def add_threat_indicator(
        self,
        indicator_id: str,
        indicator_type: str,
        value: str,
        description: str,
        severity: str,
        category: str,
        confidence: float,
        source: str,
        tags: list[str] | None = None,
        mitre_tactics: list[str] | None = None,
        mitre_techniques: list[str] | None = None,
    ) -> str:
        """
        Add a threat indicator to the vector store.

        Returns the UUID of the created object.
        """
        collection = self.client.collections.get("ThreatIntel")

        result = collection.data.insert(
            properties={
                "indicator_id": indicator_id,
                "type": indicator_type,
                "value": value,
                "description": description,
                "severity": severity,
                "category": category,
                "confidence": confidence,
                "source": source,
                "tags": tags or [],
                "mitre_tactics": mitre_tactics or [],
                "mitre_techniques": mitre_techniques or [],
            }
        )

        await logger.ainfo(
            "threat_indicator_added",
            indicator_id=indicator_id,
            vector_id=str(result),
        )

        return str(result)

    async def search_threats(
        self,
        query: str,
        limit: int = 10,
        filters: dict[str, Any] | None = None,
        alpha: float = 0.5,
    ) -> list[dict[str, Any]]:
        """
        Search for threat indicators using hybrid search.

        Args:
            query: Natural language query or IOC value
            limit: Maximum number of results
            filters: Optional filters (severity, category, etc.)
            alpha: Balance between vector (1.0) and keyword (0.0) search

        Returns:
            List of matching threat indicators
        """
        collection = self.client.collections.get("ThreatIntel")

        # Build filter if provided
        weaviate_filter = None
        if filters:
            filter_conditions = []
            if "severity" in filters:
                filter_conditions.append(
                    Filter.by_property("severity").equal(filters["severity"])
                )
            if "category" in filters:
                filter_conditions.append(
                    Filter.by_property("category").equal(filters["category"])
                )
            if filter_conditions:
                weaviate_filter = filter_conditions[0]
                for cond in filter_conditions[1:]:
                    weaviate_filter = weaviate_filter & cond

        # Perform hybrid search
        results = collection.query.hybrid(
            query=query,
            alpha=alpha,
            limit=limit,
            filters=weaviate_filter,
            return_metadata=MetadataQuery(score=True),
        )

        return [
            {
                "id": str(obj.uuid),
                **obj.properties,
                "score": obj.metadata.score if obj.metadata else None,
            }
            for obj in results.objects
        ]

    async def search_advisories(
        self,
        query: str,
        limit: int = 10,
        min_cvss: float | None = None,
    ) -> list[dict[str, Any]]:
        """
        Search for security advisories using semantic search.

        Args:
            query: Natural language query
            limit: Maximum number of results
            min_cvss: Minimum CVSS score filter

        Returns:
            List of matching security advisories
        """
        collection = self.client.collections.get("SecurityAdvisory")

        weaviate_filter = None
        if min_cvss is not None:
            weaviate_filter = Filter.by_property("cvss_score").greater_or_equal(min_cvss)

        results = collection.query.hybrid(
            query=query,
            alpha=0.7,  # Favor semantic search for advisories
            limit=limit,
            filters=weaviate_filter,
            return_metadata=MetadataQuery(score=True),
        )

        return [
            {
                "id": str(obj.uuid),
                **obj.properties,
                "score": obj.metadata.score if obj.metadata else None,
            }
            for obj in results.objects
        ]

    def _parse_host(self, url: str) -> str:
        """Extract host from URL."""
        url = url.replace("http://", "").replace("https://", "")
        return url.split(":")[0].split("/")[0]

    def _parse_port(self, url: str) -> int:
        """Extract port from URL."""
        url = url.replace("http://", "").replace("https://", "")
        if ":" in url:
            port_str = url.split(":")[1].split("/")[0]
            return int(port_str)
        return 443 if url.startswith("https") else 80


@lru_cache
def get_vector_store(settings: Settings | None = None) -> VectorStoreClient:
    """Get or create the vector store client singleton."""
    return VectorStoreClient(settings)
