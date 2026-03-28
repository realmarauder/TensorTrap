# GitHub Issue: Supply Chain Risk — Runtime pip installs and dynamic imports

**Repository:** https://github.com/kijai/ComfyUI-KJNodes
**Files:** `nodes/mask_nodes.py:452`, `nodes/image_nodes.py:118`, `nodes/nodes.py:2116`

---

**Title:** Security: Runtime pip install and dynamic imports create supply chain risk

**Body:**

## Summary

KJNodes performs runtime `pip install` commands in multiple node files and uses `importlib.import_module()` for dynamic module loading. These patterns create supply chain attack surfaces.

## Affected Code

**Runtime pip install** (`mask_nodes.py:452`, `image_nodes.py:118`):
Pip install commands run at import time or during node execution without user confirmation.

**Dynamic module import** (`nodes.py:2116`):
`importlib.import_module()` loads modules dynamically, which can execute arbitrary code if the module path is compromised.

## Why This Matters

- Runtime pip installs can be hijacked via typosquatting or package compromise (see Ultralytics Dec 2024 attack)
- Dynamic imports can load arbitrary Python modules
- No integrity verification on installed packages

## Recommended Fix

1. Move all dependency installation to a dedicated `install.py` or `requirements.txt` with pinned versions and hashes
2. Replace dynamic imports with explicit static imports where possible
3. Add user confirmation before any pip install operations

## Discovery

Found by [TensorTrap](https://github.com/realmarauder/TensorTrap) automated node auditor.
