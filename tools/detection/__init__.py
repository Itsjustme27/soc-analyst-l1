# Detection-engineering workflows for the AI SOC engineer.
from tools.detection.detection_engine import (
    TOOLS,
    DevelopWazuhRule,
    VerifyRuleDeployment,
)
from tools.detection.drafter import DraftWazuhRule

# Drafting is READ (it generates text, writes nothing); the propose/verify
# workflows keep their own permissions.
TOOLS = [*TOOLS, DraftWazuhRule]

__all__ = ["TOOLS", "DevelopWazuhRule", "VerifyRuleDeployment", "DraftWazuhRule"]
