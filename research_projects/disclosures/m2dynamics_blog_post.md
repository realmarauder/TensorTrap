# Blog Post: TensorTrap Discovers Critical Vulnerability in ComfyUI Custom Node Ecosystem

**For publication on:** https://m2dynamics.us
**Date:** 2026-03-28
**Author:** Sean Michael, M2 Dynamics

---

## TensorTrap Uncovers Dangerous Code Patterns in Popular ComfyUI Nodes

During the development of [ComfyUI-TensorTrap](https://github.com/realmarauder/ComfyUI-TensorTrap), our new security integration for ComfyUI, we ran our automated node auditor against a standard installation of ComfyUI with commonly-used custom node packages. What we found was concerning: **13 out of 16 installed packages contained code patterns that pose security risks**, including one critical arbitrary code execution vulnerability.

### The Critical Finding: Pickle Deserialization in a Live Node

The most serious discovery was in **RES4LYF**, a popular utility node package. Its `Base64ToConditioning` node ([`conditioning.py:502`](https://github.com/ClownsharkBatwing/RES4LYF/blob/0dc91c00c4c3fb38e7874fcd7a2a327765e8882c/conditioning.py#L502)) accepts a text string input, base64-decodes it, and passes it directly to Python's `pickle.loads()` — with no validation, no sanitization, and no restrictions on what pickle can deserialize.

This matters because `pickle.loads()` can execute arbitrary Python code. A malicious workflow shared on CivitAI, Discord, or Reddit could embed a crafted payload in the node's input value. When a user downloads and runs that workflow, the payload executes with full system access — file theft, reverse shells, credential harvesting, cryptomining — anything the attacker wants.

The developer's intent was legitimate: serializing conditioning data between machines to offload T5 text encoding. But the implementation creates a textbook [CWE-502](https://cwe.mitre.org/data/definitions/502.html) deserialization vulnerability that any shared workflow can exploit.

### Supply Chain Risks: Runtime pip Installs

We also found multiple popular packages running `os.system()` and `subprocess` calls to install pip packages at runtime:

- **ComfyUI-Frame-Interpolation** runs `os.system(pip install ...)` for CuPy and other dependencies ([`install.py:46-56`](https://github.com/Fannovel16/ComfyUI-Frame-Interpolation/blob/main/install.py#L46-L56)), reading package names from a requirements file
- **WAS Node Suite** uses `subprocess.check_call` for automatic package installation ([`WAS_Node_Suite.py:342-355`](https://github.com/WASasquatch/was-node-suite-comfyui/blob/main/WAS_Node_Suite.py#L342-L355))

These patterns are nearly identical to the attack vector used in the **December 2024 Ultralytics supply chain attack**, where compromised package versions distributed a cryptominer to tens of thousands of users — including ComfyUI users through the Impact-Pack dependency chain.

### The Broader Picture

This isn't an isolated problem. Our [security research](https://github.com/realmarauder/TensorTrap/tree/main/research_projects) into the ComfyUI ecosystem documented:

- **8 published CVEs** affecting ComfyUI and its extensions
- **4 major real-world attacks** (Nullbulge credential theft, Ultralytics cryptominer, Akira Stealer, Pickai backdoor)
- **700+ confirmed server compromises**
- **2,000+ custom node packages** with no mandatory security review
- **Zero runtime sandboxing** — every node runs with full system privileges

ComfyUI's architecture gives custom nodes unrestricted access to the filesystem, network, and Python runtime. Any node can inspect the entire workflow via hidden inputs. Nodes can dynamically create other nodes at runtime. There is no permission system, no capability restrictions, and no execution isolation.

### What We're Doing About It

[TensorTrap](https://github.com/realmarauder/TensorTrap) started as a model file security scanner — detecting malicious pickle files, polyglot attacks, and format exploits. With version 1.2.0 and the new [ComfyUI-TensorTrap](https://github.com/realmarauder/ComfyUI-TensorTrap) integration, we're expanding into workflow execution security:

- **Node Auditor**: Static analysis of installed custom node packages for dangerous code patterns (eval, exec, subprocess, pickle, network access, obfuscation)
- **Workflow Graph Analyzer**: Traces data flows through node connections to identify dangerous patterns — string outputs flowing into eval nodes, URLs in download nodes, code-like values in text inputs
- **Model Scanner**: Scans model files before loading — blocking execution if threats are detected

No other tool in the ecosystem performs workflow graph security analysis. Tools like ModelScan and Fickling scan model files. ComfyUI's own registry scanner checks node packages. But nobody is analyzing what happens when nodes connect together and the workflow executes. That's the gap TensorTrap fills.

### Responsible Disclosure

We've submitted a security advisory to the RES4LYF repository, filed issues on the affected supply chain packages, and notified ComfyUI's security review council. We follow a 90-day responsible disclosure timeline.

### What You Should Do

If you use ComfyUI:

1. **Be cautious with shared workflows** — A workflow from CivitAI or Discord can contain embedded payloads that execute when you run them
2. **Audit your installed nodes** — Install [ComfyUI-TensorTrap](https://github.com/realmarauder/ComfyUI-TensorTrap) and run the Audit Installed Nodes scan
3. **Check for RES4LYF** — If you have it installed and use the `Base64ToConditioning` node, be aware that any workflow using it is a potential RCE vector
4. **Set `WAS_BLOCK_AUTO_INSTALL=true`** — If you use WAS Node Suite, this prevents automatic pip installs
5. **Keep ComfyUI Manager updated** — v3.39.2+ includes security improvements

### Contact

For security inquiries or consulting on AI/ML infrastructure security:

Sean Michael
M2 Dynamics
smichael.us@gmail.com
https://m2dynamics.us

---

*TensorTrap is an open-source security scanner for AI/ML model files and workflows. Available at [github.com/realmarauder/TensorTrap](https://github.com/realmarauder/TensorTrap).*
