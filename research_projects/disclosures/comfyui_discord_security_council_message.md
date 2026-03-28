# ComfyUI Discord Security Review Council Message

**Post to:** #security-review-council channel

---

Hi team,

I'm Sean Michael from M2 Dynamics, the developer of TensorTrap (AI model file security scanner, https://github.com/realmarauder/TensorTrap).

We've been building a ComfyUI integration (https://github.com/realmarauder/ComfyUI-TensorTrap) that includes an automated custom node auditor. During testing, we ran the auditor against installed node packages and found a critical vulnerability that I wanted to flag:

**RES4LYF — Arbitrary Code Execution via Pickle Deserialization**

The `Base64ToConditioning` node in RES4LYF (https://github.com/ClownsharkBatwing/RES4LYF) accepts a STRING input, base64-decodes it, and passes it directly to `pickle.loads()` with no validation.

**Exact location:** [`conditioning.py:502`](https://github.com/ClownsharkBatwing/RES4LYF/blob/0dc91c00c4c3fb38e7874fcd7a2a327765e8882c/conditioning.py#L502)

This means any workflow that uses this node can embed a malicious pickle payload in the workflow JSON that achieves full RCE when the workflow is executed.

This is particularly concerning because:
- The payload is embedded in the workflow itself, not in a package update
- A shared workflow on CivitAI/Discord could exploit this silently
- No supply chain compromise needed — just a crafted workflow JSON

The developer's intention is legitimate (serializing conditioning data between machines for T5 offloading), but the implementation is a textbook CWE-502 deserialization vulnerability.

We've also identified supply chain risks (runtime `os.system()` pip installs) in:
- ComfyUI-Frame-Interpolation ([`install.py:46-56`](https://github.com/Fannovel16/ComfyUI-Frame-Interpolation/blob/main/install.py#L46-L56))
- WAS Node Suite ([`WAS_Node_Suite.py:342-355`](https://github.com/WASasquatch/was-node-suite-comfyui/blob/main/WAS_Node_Suite.py#L342-L355))

These use patterns nearly identical to the Ultralytics attack vector from December 2024.

I've submitted a security advisory to the RES4LYF repo and will be filing issues on the other repos. Wanted to flag this here as well so the security council is aware.

We've published our full research on ComfyUI security at: https://github.com/realmarauder/TensorTrap/tree/main/research_projects

Happy to discuss further. The goal is to make the ecosystem safer for everyone.

— Sean Michael
M2 Dynamics
smichael.us@gmail.com
