# OSINT enrichment: shared web search for the agents.
#
# Deliberately does NOT re-export `web_search` here. Doing so makes
# `tools.osint.web_search` ambiguous - Python resolves the package attribute to
# the FUNCTION, shadowing the submodule of the same name, so
# `import tools.osint.web_search as ws` silently yields a function and
# `ws.cfg` raises AttributeError. Import from the module path instead:
#
#     from tools.osint.web_search import web_search
from tools.osint import web_search as _module

__all__ = ["_module"]
