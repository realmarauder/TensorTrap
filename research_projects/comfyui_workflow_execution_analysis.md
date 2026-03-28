# Research: ComfyUI Workflow Execution Security Analysis

**Status:** Active Research
**Started:** 2026-03-27
**Researchers:** Sean Michael (M2 Dynamics) + Claude (Anthropic)
**Relevance:** TensorTrap feature development — next-generation workflow scanning

---

## Problem Statement

TensorTrap currently scans ComfyUI workflow JSON files for known dangerous node types (e.g., `ACE_ExpressionEval`, `HueAdjust`) that have published CVEs. However, this approach only catches known-bad nodes by name. It does not address a more fundamental attack vector:

**A workflow file can be completely clean — containing no malicious code, no eval statements, no suspicious patterns — while still producing malicious behavior when executed through the custom nodes it references.**

The workflow JSON is a *recipe*. The custom node packages are the *ingredients*. TensorTrap currently reads the recipe and checks for known poison. But if the ingredients themselves are compromised, or if a benign recipe combines benign ingredients in a dangerous way, the current scanner misses it entirely.

This is a critical gap for platforms like CivitAI, where users share workflows publicly and other users download and execute them — often installing whatever custom node packages the workflow requires — without fully understanding the execution implications.

## Threat Model

### Attack Surface

ComfyUI's architecture creates a unique attack surface:

1. **Custom Node Packages** — Third-party Python code installed into ComfyUI's `custom_nodes/` directory. Each package can define arbitrary node types with arbitrary Python execution logic. There is no sandboxing, code review gate, or permission system. Any installed node has full access to the host system.

2. **Workflow JSON Files** — Declarative descriptions of node graphs. They specify which nodes to use, how they connect, and what input values to provide. Workflows are shared on CivitAI, Reddit, Discord, and other platforms.

3. **ComfyUI Manager** — A package manager that installs custom nodes from GitHub repositories. Users install packages to satisfy workflow requirements, often without reviewing the source code.

### Attack Vectors

#### Vector 1: Malicious Custom Node Packages

A custom node package that appears to provide useful functionality (e.g., image processing, prompt enhancement) but contains hidden malicious code:

- Backdoor that activates on specific inputs or dates
- Data exfiltration (sending generated images, prompts, or system info to external servers)
- Cryptocurrency mining running in background threads
- Reverse shell triggered by specific workflow configurations
- File system access (reading SSH keys, browser cookies, credentials)

**Detection challenge:** The malicious code lives in the installed Python package, not in the workflow. TensorTrap would need to scan custom node source code, not just workflow JSON.

#### Vector 2: Input Injection via Workflow Values

Some custom nodes accept string inputs that are processed unsafely:

- Nodes that pass string inputs to `eval()`, `exec()`, or `subprocess`
- Template rendering nodes that allow code injection via Jinja2 or similar
- Nodes that construct file paths from user input without sanitization
- Nodes that use string inputs as format strings (`str.format()` or f-strings with user data)

**Detection challenge:** The workflow JSON contains the malicious input value, but it only looks like a text string. The danger depends on how the receiving node processes that string — which requires understanding the node's implementation.

#### Vector 3: Execution Graph Exploitation

Two individually safe nodes can create a dangerous combination:

- Node A generates a Python code string as "text output" (seemingly benign)
- Node B accepts text input and executes it (e.g., a "script runner" node)
- The workflow connects A's output to B's input
- Neither node is flagged individually, but the connection creates an exploit

**Detection challenge:** Requires analyzing the workflow as a directed graph, understanding what each node produces and consumes, and identifying dangerous data flows.

#### Vector 4: Workflow-Triggered Downloads

Some nodes download files from URLs specified in workflow inputs:

- Model loader nodes that accept URL inputs
- Image/video download nodes
- Nodes that fetch prompts or configurations from remote servers

A malicious workflow could:
- Point download URLs to compromised model files (pickle exploits)
- Fetch and execute remote scripts
- Redirect to URLs that exploit browser vulnerabilities

**Detection challenge:** Requires identifying nodes that perform network requests and analyzing whether the URLs in the workflow are trusted.

#### Vector 5: Supply Chain via ComfyUI Manager

The most insidious vector:

1. Attacker publishes a useful custom node package on GitHub
2. Package gains popularity and is added to ComfyUI Manager's registry
3. Attacker pushes a malicious update (or the GitHub account is compromised)
4. Users who update their nodes automatically receive the malicious code
5. Existing workflows that use the node now become attack vectors

**Detection challenge:** This is a supply chain attack. The workflow was safe when created, the node was safe when first installed, but an update introduces the vulnerability.

## Research Plan

### Phase 1: Custom Node Landscape Survey

**Objective:** Understand the scope of the custom node ecosystem.

- Enumerate the most popular ComfyUI custom node packages (by install count, GitHub stars)
- Categorize nodes by risk level based on their capabilities (file I/O, network access, code execution, subprocess calls)
- Identify nodes that accept arbitrary string inputs and how they process them
- Document which nodes use `eval()`, `exec()`, `subprocess`, `os.system()`, or `importlib`
- Survey ComfyUI Manager's registry for the total number of packages and any existing vetting process

### Phase 2: Known Vulnerability Analysis

**Objective:** Catalog existing ComfyUI security incidents and CVEs.

- Compile all known ComfyUI-related CVEs (CVE-2024-21576, CVE-2024-21577, etc.)
- Research any reported incidents of malicious custom nodes or workflows
- Analyze how the ComfyUI community currently handles security (if at all)
- Review ComfyUI's own security model and any built-in protections
- Check if any other tools scan ComfyUI workflows for security issues

### Phase 3: Dangerous Pattern Identification

**Objective:** Build a taxonomy of dangerous node behaviors and workflow patterns.

- Static analysis patterns: What does dangerous custom node code look like?
- Workflow graph patterns: What connection patterns create exploitation opportunities?
- Input injection patterns: What input values in workflows could be weaponized?
- Network patterns: Which nodes make external requests and how?
- Identify "capability escalation" patterns where benign nodes enable dangerous ones

### Phase 4: Proof of Concept

**Objective:** Demonstrate the attack vectors with controlled examples.

- Create a benign-looking custom node with a hidden capability
- Create a clean workflow that becomes dangerous through node interaction
- Create a workflow with injection inputs that exploit known node behaviors
- Document each PoC with detection signatures that TensorTrap could use

### Phase 5: TensorTrap Feature Design

**Objective:** Design the scanning capabilities needed to address these threats.

Potential features:
- **Custom node source scanner**: Analyze Python code in `custom_nodes/` for dangerous patterns (similar to how we scan pickle files for dangerous imports)
- **Workflow execution graph analyzer**: Build the node graph from workflow JSON and trace data flows to identify dangerous connections
- **Node capability database**: Maintain a database of known node types and their security-relevant capabilities (network access, file I/O, code execution)
- **Input value analysis**: Check workflow input values against known injection patterns for specific node types
- **Dependency auditor**: Check installed custom node packages against known vulnerabilities

### Phase 6: Implementation

**Objective:** Build and ship the features.

- Integrate new scanners into TensorTrap's existing architecture
- Add results to CLI output, web dashboard, and report generation
- Ensure backward compatibility with existing scanning functionality
- Write tests for all new detection capabilities
- Benchmark performance impact

## Expected Outcomes

1. A comprehensive understanding of ComfyUI's security attack surface
2. A catalog of dangerous patterns that can be detected statically
3. Proof-of-concept demonstrations of each attack vector
4. New TensorTrap scanning capabilities that address workflow execution security
5. Published research that benefits the broader AI/ML security community

## Why This Matters

The AI model security space currently focuses on *file format* attacks — malicious pickle files, polyglot images, etc. TensorTrap is strong here. But the next frontier is *workflow execution* security — where the danger isn't in any single file but in how components interact at runtime.

CivitAI alone has millions of users sharing workflows and custom nodes. Other platforms (Hugging Face Spaces, Replicate, RunPod) have similar dynamics. As AI tools become more modular and workflow-driven, the attack surface shifts from "don't load this file" to "don't run this pipeline."

No one is addressing this systematically yet. TensorTrap is positioned to be the first.

---

*This research is conducted by M2 Dynamics as part of TensorTrap's ongoing security research program.*
