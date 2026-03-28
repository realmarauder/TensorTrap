# GitHub Issue: Dynamic imports for cross-node integration

**Repository:** https://github.com/kijai/ComfyUI-KJNodes
**Files:**
- [`nodes/image_nodes.py:4119-4122`](https://github.com/kijai/ComfyUI-KJNodes/blob/main/nodes/image_nodes.py#L4119-L4122) — `importlib.import_module()` for VideoHelperSuite
- [`nodes/nodes.py:2116`](https://github.com/kijai/ComfyUI-KJNodes/blob/main/nodes/nodes.py#L2116) — `importlib.import_module()` for Advanced-ControlNet

---

**Title:** Security note: Dynamic imports via importlib for cross-node integration

**Body:**

## Summary

KJNodes uses `importlib.import_module()` in multiple locations to load other ComfyUI custom node packages for cross-node integration. While the current usage targets specific known packages, `importlib` is a mechanism that can load arbitrary Python modules.

## Affected Code

[`nodes/image_nodes.py:4119-4122`](https://github.com/kijai/ComfyUI-KJNodes/blob/main/nodes/image_nodes.py#L4119-L4122):
```python
cls.vhs_nodes = importlib.import_module("ComfyUI-VideoHelperSuite.videohelpersuite")
```

[`nodes/nodes.py:2116`](https://github.com/kijai/ComfyUI-KJNodes/blob/main/nodes/nodes.py#L2116):
```python
adv_control = importlib.import_module("ComfyUI-Advanced-ControlNet.adv_control")
```

## Risk Assessment

**Current risk: LOW** — The module names are hardcoded strings targeting specific known ComfyUI packages. This is a common pattern for optional cross-node dependencies.

**Potential risk:** If module names were ever derived from user input or workflow values, this would become a code execution vector. Flagging for awareness rather than as an active vulnerability.

## Recommendation

No immediate action needed. The current implementation is acceptable for cross-node integration. This is an informational finding from an automated security audit.

## Discovery

Found by [TensorTrap](https://github.com/realmarauder/TensorTrap) automated node auditor. After manual review, this was downgraded from HIGH to LOW/informational — the automated scanner flagged `importlib` usage, but the actual implementation is safe in its current form.
