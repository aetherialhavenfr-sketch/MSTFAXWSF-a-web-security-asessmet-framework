"""Pipeline modules. To add a new one, subclass ExternalToolModule (or BaseModule),
give it a unique ``key`` and register it in REGISTRY and config.MODULE_ORDER."""
from .ffuf import FfufModule
from .katana import KatanaModule
from .nikto import NiktoModule
from .nuclei import NucleiModule
from .recon import ReconModule
from .whatweb import WhatWebModule

REGISTRY = {
    m.key: m
    for m in (ReconModule, WhatWebModule, KatanaModule, FfufModule, NiktoModule, NucleiModule)
}
