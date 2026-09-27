# Wazuh manager tools for the AI SOC engineer.
from tools.wazuh.agents import (
    DisableWazuhAgent,
    GetWazuhAgent,
    GetWazuhAgents,
    GetWazuhClusterStatus,
    GetWazuhManagerStatus,
    RestartWazuhManager,
)
from tools.wazuh.configuration import GetWazuhConfiguration
from tools.wazuh.decoders import (
    CreateWazuhDecoder,
    DeleteWazuhDecoder,
    GetWazuhDecoders,
    ModifyWazuhDecoder,
)
from tools.wazuh.logtest import EndWazuhLogtestSession, RunWazuhLogtest
from tools.wazuh.rules import (
    CreateWazuhRule,
    DeleteWazuhRule,
    GetWazuhRule,
    GetWazuhRules,
    UpdateWazuhRule,
)

TOOLS = [
    GetWazuhRules,
    GetWazuhRule,
    CreateWazuhRule,
    UpdateWazuhRule,
    DeleteWazuhRule,
    GetWazuhDecoders,
    CreateWazuhDecoder,
    ModifyWazuhDecoder,
    DeleteWazuhDecoder,
    GetWazuhAgents,
    GetWazuhAgent,
    GetWazuhManagerStatus,
    GetWazuhClusterStatus,
    RestartWazuhManager,
    DisableWazuhAgent,
    GetWazuhConfiguration,
    RunWazuhLogtest,
    EndWazuhLogtestSession,
]

__all__ = ["TOOLS"]
