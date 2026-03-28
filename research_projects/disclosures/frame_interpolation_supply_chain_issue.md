# GitHub Issue: Supply Chain Risk — os.system() pip installs in install.py

**Repository:** https://github.com/Fannovel16/ComfyUI-Frame-Interpolation
**File:** [`install.py`, lines 46-56](https://github.com/Fannovel16/ComfyUI-Frame-Interpolation/blob/main/install.py#L46-L56)

---

**Title:** Security: os.system() pip installs create supply chain attack surface

**Body:**

## Summary

The `install.py` script uses `os.system()` to run pip install commands, including reading package names from `requirements-no-cupy.txt`. This creates a supply chain attack surface where a compromised requirements file or typosquatted package could install malware.

## Affected Code

[`install.py:46`](https://github.com/Fannovel16/ComfyUI-Frame-Interpolation/blob/main/install.py#L46) — `os.system()` pip uninstall:
```python
os.system(f'"{sys.executable}" {s_param} -m pip uninstall -y cupy-wheel cupy-cuda102 ...')
```

[`install.py:50`](https://github.com/Fannovel16/ComfyUI-Frame-Interpolation/blob/main/install.py#L50) — `os.system()` pip install with dynamic package name:
```python
os.system(f'"{sys.executable}" {s_param} -m pip install {cupy_package}')
```

[`install.py:52-56`](https://github.com/Fannovel16/ComfyUI-Frame-Interpolation/blob/main/install.py#L52-L56) — `os.system()` pip install from requirements file:
```python
with open(Path(__file__).parent / "requirements-no-cupy.txt", 'r') as f:
    for package in f.readlines():
        package = package.strip()
        os.system(f'"{sys.executable}" {s_param} -m pip install {package}')
```

## Why This Matters

1. **os.system() is a shell injection vector** — if any package name or variable contains shell metacharacters, arbitrary commands execute
2. **Requirements file is a single point of compromise** — a malicious commit changing one package name in `requirements-no-cupy.txt` installs malware on every user's machine
3. **No integrity verification** — packages are installed without hash pinning or version locking
4. **This exact pattern was exploited** in the Ultralytics supply chain attack (Dec 2024), which affected ComfyUI-Impact-Pack users

## Real-World Precedent

The December 2024 Ultralytics attack compromised packages via GitHub Actions, injecting a cryptominer that affected ComfyUI users through the Impact-Pack dependency chain. The attack vector was nearly identical — compromised packages installed via pip at runtime.

## Recommended Fix

1. **Use subprocess instead of os.system** to avoid shell injection:
```python
subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
```

2. **Pin package versions with hashes** in requirements.txt:
```
cupy-cuda12x==13.0.0 --hash=sha256:abc123...
```

3. **Consider using `WAS_BLOCK_AUTO_INSTALL`-style opt-in** (as WAS Node Suite does)

## Discovery

Found by [TensorTrap](https://github.com/realmarauder/TensorTrap) automated node auditor during security review of ComfyUI custom node packages.
