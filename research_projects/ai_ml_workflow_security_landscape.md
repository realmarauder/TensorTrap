# AI/ML Workflow Execution Security: Ecosystem Research

**Research Date:** 2026-03-27
**Scope:** Academic research, frameworks, platforms, tools, standards, and real-world incidents

---

## 1. Academic Research on AI Pipeline Security

### Key Papers and Reports

**"Supply-Chain Attacks in Machine Learning Frameworks"** (OpenReview)
- Covers backdoor injection, pipeline compromise, and model stealing attacks in ML frameworks
- Identifies that supply-chain attacks can inject backdoors during training (dataset/algorithm control), target model architecture directly, or target model checkpoints
- Attacks extend beyond models into pipeline components of real-world ML services
- Source: https://openreview.net/pdf?id=EH5PZW6aCr

**"Towards Secure MLOps: Surveying Attacks, Mitigation Strategies, and Research"** (arXiv, June 2025)
- Comprehensive survey of MLOps security covering the full ML lifecycle
- Source: https://arxiv.org/pdf/2506.02032

**"Inside the AI Supply Chain: Security Lessons from 10,000 Open-Source ML Projects"** (Mitiga)
- Large-scale empirical study of open-source ML project security posture
- Source: https://www.mitiga.io/blog/inside-the-ai-supply-chain-security-lessons-from-10-000-open-source-ml-projects

**"PickleBall: Secure Deserialization of Pickle-based Machine Learning Models"** (CCS 2025, Brown University)
- Proposes static analysis of ML library source code to compute custom policies for safe deserialization
- Successfully loads 79.8% of benign pickle-based models while rejecting 100% of malicious examples
- Source: https://arxiv.org/abs/2508.15987 / https://cs.brown.edu/~vpk/papers/pickleball.ccs25.pdf

**"Exploiting ML Models with Pickle File Attacks"** (Trail of Bits, 2024)
- Two-part series on practical exploitation of pickle-based ML models
- Source: https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/

**MLOps Platform Vulnerability Research** (JFrog, 2024)
- "From MLOps to MLOops: Exposing the Attack Surface of Machine Learning Platforms"
- Discovered 20+ supply chain vulnerabilities in MLOps platforms
- Found XSS flaw in MLFlow (CVE-2024-27132) that enables code execution via Jupyter Notebook context
- Source: https://jfrog.com/blog/from-mlops-to-mloops-exposing-the-attack-surface-of-machine-learning-platforms/
- Also: https://thehackernews.com/2024/08/researchers-identify-over-20-supply.html

**NIST AI 100-2 E2025: Adversarial Machine Learning Taxonomy** (March 2025)
- The definitive government taxonomy of adversarial ML attacks and mitigations
- Covers supervised, unsupervised, semi-supervised, federated, and reinforcement learning attacks
- 2025 edition integrates GenAI, LLM, RAG, and agentic AI attack taxonomies
- Source: https://csrc.nist.gov/pubs/ai/100/2/e2025/final

**HiddenLayer AI Threat Landscape Reports (2025, 2026)**
- 77% of companies identified breaches to their AI in the past year
- 45% of breaches traced to malware via public model repositories
- 97% of organizations use models from public repos; only 50% scan before deployment
- Only 32% actively monitoring AI systems; just 16% have run adversarial testing
- Source: https://hiddenlayer.com/innovation-hub/hiddenlayer-ai-threat-landscape-report-reveals-ai-breaches-on-the-rise/
- 2026 report: https://www.hiddenlayer.com/news/hiddenlayer-releases-the-2026-ai-threat-landscape-report-spotlighting-the-rise-of-agentic-ai-and-the-expanding-attack-surface-of-autonomous-systems

### CI/CD Pipeline Security in AI Context

**"Defensive Research, Weaponized: The 2025 State of Pipeline Security"** (BoostSecurity)
- Documents pattern of "pipeline parasitism" -- attackers living off CI/CD infrastructure
- Real-world examples: Ultralytics, Kong, tj-actions, GhostAction, Nx
- Source: https://boostsecurity.io/blog/defensive-research-weaponized-the-2025-state-of-pipeline-security

**2026 Software Supply Chain Security Report** (ReversingLabs)
- Open-source malware up 73%
- Attacks targeting developer tooling and AI development pipelines specifically
- Source: https://www.reversinglabs.com/sscs-report

---

## 2. MITRE ATLAS and AI Attack Frameworks

### Framework Overview

MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) is the ATT&CK-equivalent for AI/ML systems. As of October 2025:
- **15 tactics, 66 techniques, 46 sub-techniques**
- **26 mitigations, 33 real-world case studies**
- Source: https://atlas.mitre.org/

### AML.T0048: ML Supply Chain Compromise

The primary technique for AI supply chain attacks. Attack vectors include:

1. **ML Software Supply Chain** -- Compromising ML frameworks (PyTorch, TensorFlow) or open-source implementations
2. **Data Sources** -- Poisoning open-source training datasets
3. **Pre-trained Models** -- Embedding malware in model files (pickle deserialization)
4. **Hardware** -- Targeting specialized ML hardware/accelerators

Real-world case: LiteLLM supply chain attack (March 2026) -- AML.T0048 via ML software dependency compromise.

Sources:
- https://atlas.mitre.org/
- https://misp-galaxy.org/mitre-atlas-attack-pattern/
- https://repello.ai/blog/mitre-atlas-framework

### October 2025 Update: AI Agent Attack Techniques

MITRE ATLAS collaborated with **Zenity Labs** to add 14 new techniques focused on AI agents and GenAI:

- **AI Agent Context Poisoning** -- Manipulating agent LLM context to persistently influence behavior
- **Memory Manipulation** -- Altering LLM memory to persist malicious changes across sessions
- **Exfiltration via AI Agent Tool Invocation** -- Using agent tools (email, CRM, API) to exfiltrate data
- **Modify AI Agent Configuration** -- Changing config files to create persistent malicious behavior across all agents sharing that config

Key insight: AI agents differ from traditional AI models because they **act** -- browsing web, invoking tools, accessing APIs, authenticating to services, making decisions with limited human oversight.

Sources:
- https://zenity.io/blog/current-events/zenity-labs-and-mitre-atlas-collaborate-to-advances-ai-agent-security-with-the-first-release-of
- https://zenity.io/blog/current-events/mitre-atlas-ai-security
- https://labs.zenity.io/p/techniques-from-zenitys-genai-attacks-matrix-incorporated-into-mitre-atlas-to-track-emerging-ai-thr

### MITRE SAFE-AI Framework

Full report on securing AI systems:
- Source: https://atlas.mitre.org/pdf-files/SAFEAI_Full_Report.pdf

### MITRE ATLAS OpenClaw Investigation (February 2026)

- Source: https://www.mitre.org/sites/default/files/2026-02/PR-26-00176-1-MITRE-ATLAS-OpenClaw-Investigation.pdf

### Relevant Threat Categories for Workflow/Pipeline Manipulation

| ATLAS Tactic | Relevance to AI Workflows |
|---|---|
| Initial Access (AML.T0048) | Supply chain compromise of models, data, code |
| ML Attack Staging | Preparing poisoned models/data for deployment |
| Persistence | Backdoors in model weights, agent config modification |
| Exfiltration | Data theft via agent tool invocation, model extraction |
| Impact | Denial of ML service, model degradation |

---

## 3. Hugging Face Security

### Platform Scale

As of 2025, Hugging Face hosts:
- 2+ million models
- 500,000+ datasets
- 1+ million demo apps (Spaces)

### Pickle Scanning

Hugging Face uses **picklescan** to extract imports from pickle files via `pickletools.genops()` and compare against a blacklist. The platform displays vetted import lists on the Hub.

**Limitations discovered:**
- February 2025: Malicious models using "broken pickle" technique (**nullifAI**) evaded detection by inserting payloads at the beginning of the pickle stream before format validation occurs
- June 2025: Three zero-day vulnerabilities found in picklescan itself (fixed in v0.0.31, September 2025)
- Bypass techniques allow concealing malicious payloads in files with common PyTorch extensions

Sources:
- https://huggingface.co/docs/hub/en/security-pickle
- https://thehackernews.com/2025/02/malicious-ml-models-found-on-hugging.html
- https://jfrog.com/blog/unveiling-3-zero-day-vulnerabilities-in-picklescan/
- https://www.sonatype.com/blog/bypassing-picklescan-sonatype-discovers-four-vulnerabilities

### Protect AI Guardian Partnership

As of April 2025, Protect AI has scanned:
- **4.47 million unique model versions** across 1.41 million repositories
- Identified **352,000 unsafe/suspicious issues** across **51,700 models**
- Detection modules include: Archive slip, Joblib model, TensorFlow SavedModel backdoor, Llamafile malicious code
- Source: https://huggingface.co/blog/pai-6-month

### Known Malicious Model Incidents

1. **JFrog Silent Backdoor Discovery** -- Malicious models with silent backdoors targeting data scientists
   - Source: https://jfrog.com/blog/data-scientists-targeted-by-malicious-hugging-face-ml-models-with-silent-backdoor/

2. **nullifAI Broken Pickle Evasion** (February 2025) -- Models using broken pickle format to evade detection; removed within 24 hours
   - Source: https://www.helpnetsecurity.com/2025/02/10/malicious-ml-models-found-on-hugging-face-hub/

3. **100+ Malicious Code-Execution Models** -- Platform found riddled with models containing code execution payloads
   - Source: https://www.darkreading.com/application-security/hugging-face-ai-platform-100-malicious-code-execution-models

4. **Namespace Hijacking Risk** -- Deleted account namespaces can be reclaimed by malicious actors
   - Source: https://www.scworld.com/news/hugging-face-model-namespace-reuse-poses-ai-supply-chain-risk

5. **Safetensors Conversion Hijacking** -- HiddenLayer's "Silent Sabotage" research on hijacking the safetensors conversion process
   - Source: https://hiddenlayer.com/innovation-hub/silent-sabotage/

### Safetensors as Mitigation

- Developed by Hugging Face as a safe alternative to pickle serialization
- Stores only numerical tensors and metadata; cannot execute arbitrary code during deserialization
- Security audited by Hugging Face, EleutherAI, and Stability AI (no critical flaws found)
- Becoming the default format across the ecosystem
- Sources:
  - https://github.com/huggingface/safetensors
  - https://blog.eleuther.ai/safetensors-security-audit/

### Socket.dev Malware Scanning

Socket.dev announced experimental malware scanning for the Hugging Face ecosystem:
- Source: https://socket.dev/blog/announcing-experimental-malware-scanning-for-hugging-face

---

## 4. Other AI Platforms' Security Posture

### Replicate

**Critical Vulnerability Discovered (January 2024):**
- Wiz Research found a critical flaw in Replicate's container isolation
- In Kubernetes environments, containers within the same pod shared networks, enabling cross-container attacks
- An attacker gaining access to one container could attack other containers in the same pod, exposing customer models and proprietary data
- Replicate uses **Cog** containerization format for model packaging
- Issue was responsibly disclosed and promptly mitigated
- Sources:
  - https://www.wiz.io/blog/wiz-research-discovers-critical-vulnerability-in-replicate
  - https://www.darkreading.com/cloud-security/critical-flaw-in-replicate-ai-platform-exposes-customer-models-proprietary-data

### RunPod

- Achieved SOC2 compliance
- Implements automated scanning for vulnerabilities in container images before deployment
- Provides network isolation and encryption
- No publicly reported security compromises found
- Sources:
  - https://www.runpod.io/articles/guides/security-measures-ai-cloud-deployment
  - https://www.runpod.io/articles/guides/ai-model-deployment-security-protecting-machine-learning-assets-in-production-environments
  - https://www.runpod.io/legal/compliance

### Vast.ai

- Peer-to-peer GPU marketplace model creates unique security challenges
- Built security infrastructure over 6+ years
- Offers NVIDIA Confidential Computing for absolute security
- Has a vulnerability disclosure/bounty program
- **Key risk:** The marketplace model means user workloads run on third-party hosts, creating inherent trust concerns
- No publicly reported platform compromises found
- Sources:
  - https://docs.vast.ai/documentation/reference/faq/security
  - https://vast.ai/article/security-and-compliance-at-vast-ai
  - https://vast.ai/article/Absolute-Security-with-NVIDIA-Confidential-Computing
  - https://vast.ai/vulnerability-disclosure-policy

### NVIDIA Container Toolkit Vulnerability (CVE-2024-0132)

- Critical flaw affecting all platforms using NVIDIA GPU containers
- Allows container escape and full host access
- Impacts Vast.ai, RunPod, and any GPU cloud provider using NVIDIA containers
- Source: https://www.wiz.io/blog/wiz-research-critical-nvidia-ai-vulnerability

### Stability AI

- Co-sponsored the safetensors security audit with Hugging Face and EleutherAI
- Committed to shifting to safetensors as default model format
- No specific platform security incidents found publicly
- Source: https://blog.eleuther.ai/safetensors-security-audit/

### MLflow (Critical Vulnerabilities)

MLflow is widely used for ML experiment tracking and is a key MLOps component:

- **CVE-2024-0520** -- Command injection via HTTP dataset source, allowing RCE (fixed in v2.9.0)
- **CVE-2025-11201** -- Directory traversal RCE in tracking server model creation; **no authentication required**
- **CVE-2024-37056** -- Deserialization of untrusted data via malicious LightGBM model
- **CVE-2025-14279** -- DNS rebinding attack due to missing Origin header validation
- Sources:
  - https://github.com/advisories/GHSA-5q6c-ffvg-xcm9
  - https://zeropath.com/blog/cve-2025-11201-mlflow-directory-traversal-rce
  - https://securityboulevard.com/2024/01/protect-ai-report-surfaces-mlflow-security-vulnerabilities/

---

## 5. Python Package Supply Chain Attacks Targeting AI/ML

### Major Incidents

**Ultralytics YOLO Compromise (December 2024)** -- THE definitive AI supply chain attack case study:
- Ultralytics: 33.7k GitHub stars, 61M downloads, dependencies include **ComfyUI-Impact-Pack**
- Attack exploited GitHub Actions script injection to compromise build pipeline
- Exfiltrated PyPI API token and published trojanized versions (8.3.41, 8.3.42, 8.3.45, 8.3.46)
- Payload: XMRig Monero cryptocurrency miner
- Two attack phases: Dec 4-5 (via compromised CI) and Dec 7 (direct PyPI upload)
- Sources:
  - https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/
  - https://snyk.io/blog/ultralytics-ai-pwn-request-supply-chain-attack/
  - https://www.schneier.com/blog/archives/2024/12/ultralytics-supply-chain-attack.html
  - https://www.wiz.io/blog/ultralytics-ai-library-hacked-via-github-for-cryptomining

**ML-Targeted Typosquatting Campaign (March 2024):**
- 100+ malicious packages targeting PyTorch, Matplotlib, Selenium
- Names like "Matplotltib", "selennim", "PyToich"
- Payload: crypto wallet theft, browser credential stealing, persistence mechanism
- PyPI temporarily suspended all new user sign-ups
- Sources:
  - https://www.mend.io/blog/over-100-malicious-packages-target-popular-ml-pypi-libraries/
  - https://thehackernews.com/2024/03/pypi-halts-sign-ups-amid-surge-of.html

**LiteLLM Supply Chain Attack (March 2026):**
- TeamPCP cybercriminal group compromised BerryAI's LiteLLM library
- Credential stealer and malware dropper uploaded as compromised versions
- Expanding pattern of TeamPCP supply chain attacks
- Source: https://www.helpnetsecurity.com/2026/03/25/teampcp-supply-chain-attacks/

**Fake AI SDK Packages (2025):**
- Packages like `aliyun-ai-labs-snippets-sdk` and `aliyun-ai-labs-sdk` on PyPI
- Delivered infostealer payloads hidden inside PyTorch models
- Source: https://www.zscaler.com/blogs/security-research/malicious-pypi-packages-deliver-silentsync-rat

**Fake Cloud/AI Utilities (2025):**
- Packages like `acloud-client`, `enumer-iam`, `snapshot-photo`
- Token theft embedded in names engineered for credibility
- Source: https://www.mixmode.ai/blog/why-the-2025-pypi-attack-signals-a-new-era-in-cloud-risk

### Direct Relevance to ComfyUI Custom Nodes

ComfyUI custom nodes are **functionally equivalent to unvetted PyPI packages:**
- They are arbitrary Python code installed from GitHub repositories
- They execute with full system access on the host machine
- They can install additional pip dependencies at runtime
- They are not sandboxed or isolated in any way

**Documented ComfyUI malware incidents:**

1. **ComfyUI_LLMVISION** (June 2024) -- Keylogger/stealer disguised as an AI vision node; installed fake `openai` and `anthropic` packages from attacker's PyPI account; stole browser passwords, credit cards, browsing history; exfiltrated to Discord webhook
   - Source: https://gigazine.net/gsc_news/en/20240611-comfyui-llmvision-malware/

2. **ComfyUI-Upscaler-4K / Akira Stealer** (2025) -- Malicious nodes by `EliseiBorisov` in the Comfy Registry; bypassed registry scanners by hiding malicious logic in `/scripts/` folder; masqueraded as upscaler class
   - Source: https://github.com/Comfy-Org/ComfyUI/issues/11791

3. **Cryptocurrency miner node** -- Waited 30 days before activating to avoid detection
   - Source: https://apatero.com/blog/comfyui-custom-nodes-security-guide-protect-yourself-2025

4. **ComfyUI-Manager RCE** (CVE-2025-67303) -- Remote code execution vulnerability in the node manager itself
   - Source: https://blog.certcube.com/comfyui-manager-rce-cve-2025-67303/

**Snyk Labs Research: "Don't Get Too Comfortable: Hacking ComfyUI Through Custom Nodes"**
- Demonstrates how minor custom node vulnerabilities lead to full server compromise
- ComfyUI has no built-in authentication or authorization
- 1,300+ custom node extensions available, all executing arbitrary Python
- Source: https://labs.snyk.io/resources/hacking-comfyui-through-custom-nodes/

---

## 6. Existing Tools and Frameworks

### Pickle/Model Scanning Tools

| Tool | Developer | Description | Source |
|---|---|---|---|
| **Fickling** | Trail of Bits | Pickle decompiler, static analyzer, bytecode rewriter. Uses allowlist approach built from 3,000 HF models. 100% malicious detection, 99% safe classification. | https://github.com/trailofbits/fickling |
| **ModelScan** | Protect AI | Open-source model scanner supporting H5, Pickle, SavedModel formats (PyTorch, TensorFlow, Keras, Sklearn, XGBoost) | https://github.com/protectai/modelscan |
| **Guardian** | Protect AI | Enterprise-grade model scanner (commercial). Scanned 4.47M model versions on HF. | https://protectai.com/guardian |
| **PickleScan** | Community | Used by Hugging Face for platform-wide scanning. Has had bypass vulnerabilities. | (Used internally by HF) |
| **PickleBall** | Brown University | Academic tool: static analysis + dynamic enforcement for pickle deserialization | https://arxiv.org/abs/2508.15987 |

### LLM/AI Vulnerability Scanners

| Tool | Developer | Description | Source |
|---|---|---|---|
| **Garak** | NVIDIA | LLM vulnerability scanner (like nmap/Metasploit for LLMs). Probes for hallucination, data leakage, prompt injection, jailbreaks. Open source with long-term NVIDIA support. | https://github.com/NVIDIA/garak |
| **Agentic Radar** | SPLX AI | Security scanner for LLM agentic workflows. Provides workflow visualization, vulnerability mapping, CI/CD integration. | https://github.com/splx-ai/agentic-radar |
| **Agentic Security** | Community | Vulnerability scanner for agent workflows. Fuzzing, multi-step jailbreaks, reinforcement learning adaptive attacks. | https://github.com/msoedov/agentic_security |
| **Promptfoo** | Community | Red-teaming tool with MITRE ATLAS mapping | https://www.promptfoo.dev/docs/red-team/mitre-atlas/ |
| **LLM Guard** | Protect AI | Suite for detecting, redacting, sanitizing LLM prompts and responses | (Protect AI GitHub) |

### CI/CD and Pipeline Security

| Tool | Developer | Description | Source |
|---|---|---|---|
| **Raven** | Cycode | CI/CD pipeline security scanner, starts with GitHub Actions | https://cycode.com/blog/introducing-raven/ |
| **GitHub Taskflow Agent** | GitHub Security Lab | AI framework for automated security code audits. 80+ vulnerabilities found across 40+ repos. | https://github.blog/security/how-to-scan-for-vulnerabilities-with-github-security-labs-open-source-ai-powered-framework/ |
| **Snaike-MLFlow** | Community | MLflow-focused red team toolsuite | (GitHub) |
| **MCP-Scan** | Community | Security scanning for Model Context Protocol servers | (GitHub) |

### Curated Resource Lists

- **awesome-ai-security** (ottosulin): https://github.com/ottosulin/awesome-ai-security
- **Awesome-AI-Security** (TalEliyahu): https://github.com/TalEliyahu/Awesome-AI-Security
- **awesome-ml-security** (Trail of Bits): https://github.com/trailofbits/awesome-ml-security
- **awesome-MLSecOps**: https://github.com/RiccardoBiosas/awesome-MLSecOps
- **awesome-security-for-ai**: https://github.com/zmre/awesome-security-for-ai
- **OpenSSF AI/ML Security Working Group**: https://github.com/ossf/ai-ml-security

### Notable Gap: No AI Workflow Graph Security Analyzer Exists

No tool was found that specifically analyzes AI workflow graphs (like ComfyUI workflows) for security. Existing tools focus on:
- Model file scanning (pickle/serialization attacks)
- LLM prompt/output security
- CI/CD pipeline security
- General static analysis

**This represents an open research and tooling opportunity** -- analyzing node-based AI workflow DAGs for dangerous patterns, untrusted data flows, and supply chain risks at the workflow graph level.

---

## 7. Industry Standards and Guidelines

### OWASP Machine Learning Security Top 10

The ten categories:
1. **ML01: Input Manipulation Attack** (adversarial examples)
2. **ML02: Data Poisoning Attack**
3. **ML03: Model Inversion Attack**
4. **ML04: Membership Inference Attack**
5. **ML05: Model Theft**
6. **ML06: AI Supply Chain Attacks**
7. **ML07: Transfer Learning Attack**
8. **ML08: Model Skewing**
9. **ML09: Output Integrity Attack**
10. **ML10: Model Poisoning**

Source: https://owasp.org/www-project-machine-learning-security-top-10/

### OWASP Top 10 for LLM Applications (2025 Edition)

Released November 2024, covers:
- Prompt injection
- Data/model poisoning
- Supply chain vulnerabilities (LLM05 maps to ATLAS AML.T0048)
- Insecure output handling
- And more

Sources:
- https://owasp.org/www-project-top-10-for-large-language-model-applications/
- https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf
- https://genai.owasp.org/

### NIST AI Risk Management Framework (AI RMF)

- **AI RMF 1.0** -- Released January 2023, voluntary framework for trustworthy AI
- **NIST-AI-600-1** (July 2024) -- Generative AI Profile for the AI RMF
- **NIST AI 100-2 E2025** (March 2025) -- Adversarial Machine Learning taxonomy (updated annually)
- **NISTIR 8596** (December 2025 draft) -- Cybersecurity Framework Profile for AI, mapping CSF 2.0 to AI security

Sources:
- https://www.nist.gov/itl/ai-risk-management-framework
- https://csrc.nist.gov/pubs/ai/100/2/e2025/final
- https://www.nist.gov/news-events/news/2025/12/draft-nist-guidelines-rethink-cybersecurity-ai-era
- https://nvlpubs.nist.gov/nistpubs/ir/2025/NIST.IR.8596.iprd.pdf

### OpenSSF AI/ML Security Working Group

- Developing comprehensive security framework for ML and AI systems
- Adapting MITRE ATT&CK methodology with 80+ security techniques across 14 tactic categories
- Focused on Model Context Protocol (MCP) security
- Source: https://github.com/ossf/ai-ml-security

---

## Key Takeaways for TensorTrap

1. **The problem is validated at the highest levels**: MITRE, NIST, OWASP, and HiddenLayer all recognize AI supply chain attacks as a critical and growing threat category.

2. **No tool exists for workflow-level graph analysis**: While model scanning (Fickling, ModelScan) and LLM testing (Garak) are maturing, nobody is analyzing AI workflow DAGs for security. This is a clear gap.

3. **ComfyUI is a documented attack vector**: Multiple real-world malware incidents (LLMVISION, Akira Stealer, cryptominers), a Snyk Labs research paper, and a CVE on ComfyUI-Manager itself.

4. **The pickle problem is being solved but not solved yet**: Safetensors adoption is growing, but pickle remains dominant. Scanning tools have been repeatedly bypassed (nullifAI, picklescan CVEs).

5. **Platform security is inconsistent**: Replicate had a critical cross-tenant vulnerability. Vast.ai's P2P model creates inherent trust issues. RunPod has SOC2 but no public model scanning. None of these platforms analyze workflow graphs.

6. **PyPI supply chain attacks directly impact AI/ML**: The Ultralytics attack (which hit ComfyUI-Impact-Pack), LiteLLM compromise, and ML-targeted typosquatting campaigns prove the attack surface is real and actively exploited.

7. **MITRE ATLAS AML.T0048 is the canonical reference**: Maps directly to OWASP LLM05 and covers all vectors (software, data, models, hardware).

8. **The agentic AI expansion increases risk**: ATLAS's October 2025 update with Zenity adds 14 techniques specifically for AI agents that can act autonomously -- directly relevant to workflow execution engines.
