# RAG tools for the AI SOC engineer: retrieval + local rule snapshots.
from tools.rag.ingest import IngestWazuhRules
from tools.rag.retrieve import RetrieveWazuhDocs

TOOLS = [RetrieveWazuhDocs, IngestWazuhRules]

__all__ = ["TOOLS", "RetrieveWazuhDocs", "IngestWazuhRules"]
