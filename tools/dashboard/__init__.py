# Wazuh dashboard (OpenSearch Dashboards saved-objects) tools.
from tools.dashboard.dashboards import (
    CreateWazuhDashboard,
    DeleteWazuhDashboard,
    GetWazuhDashboards,
    UpdateWazuhDashboard,
    VerifyWazuhDashboard,
)
from tools.dashboard.engine import DesignDetectionDashboard, DesignThreatIntelDashboard
from tools.dashboard.visualizations import CreateWazuhVisualization, GetWazuhVisualizations

TOOLS = [
    GetWazuhVisualizations,
    CreateWazuhVisualization,
    GetWazuhDashboards,
    CreateWazuhDashboard,
    UpdateWazuhDashboard,
    VerifyWazuhDashboard,
    DeleteWazuhDashboard,
    DesignDetectionDashboard,
    DesignThreatIntelDashboard,
]

__all__ = ["TOOLS"]
