# Search + schema tools over the Wazuh indexer (alerts/events live here).
from tools.indexer.search import (
    GetIndexSchema,
    GetWazuhAlert,
    SearchWazuhAlerts,
    SearchWazuhEvents,
    SearchWazuhIndex,
    VerifyOpenSearchQuery,
)

TOOLS = [
    SearchWazuhAlerts,
    SearchWazuhEvents,
    GetWazuhAlert,
    SearchWazuhIndex,
    GetIndexSchema,
    VerifyOpenSearchQuery,
]
