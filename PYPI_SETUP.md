# PyPI Publishing Setup Guide

## One-Time Setup Steps

### 1. Create PyPI Account

If you do not have one: https://pypi.org/account/register/

### 2. Configure Trusted Publishing (Recommended)

Trusted publishing eliminates the need for API tokens. PyPI verifies the GitHub Actions workflow directly.

**On PyPI:**
1. Go to https://pypi.org/manage/account/publishing/
2. Click "Add a new pending publisher"
3. Fill in:
   - PyPI Project Name: `tensortrap`
   - Owner: `realmarauder`
   - Repository name: `TensorTrap`
   - Workflow name: `publish-pypi.yml`
   - Environment name: `pypi`
4. Click "Add"

**Repeat for TestPyPI:**
1. Go to https://test.pypi.org/manage/account/publishing/
2. Same settings but environment name: `testpypi`

### 3. Create GitHub Environments

In your GitHub repository:
1. Go to Settings > Environments
2. Create environment named `testpypi`
3. Create environment named `pypi`
4. Optionally add protection rules (require approval for production)

### 4. Verify pyproject.toml

Ensure these fields are correct in pyproject.toml:

```toml
[project]
name = "tensortrap"
version = "0.1.0"  # Update for each release
description = "Security scanner for AI/ML model files"
readme = "README.md"
license = {text = "MIT"}
requires-python = ">=3.10"
authors = [
    {name = "M2 Dynamics", email = "contact@m2dynamics.us"}
]
keywords = [
    "security",
    "ai", 
    "ml",
    "machine-learning",
    "scanner",
    "pickle",
    "safetensors",
    "gguf",
    "malware",
    "comfyui"
]
classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "Intended Audience :: Science/Research",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Topic :: Security",
    "Topic :: Scientific/Engineering :: Artificial Intelligence",
    "Environment :: Console",
    "Operating System :: OS Independent",
]

[project.urls]
Homepage = "https://github.com/realmarauder/TensorTrap"
Documentation = "https://github.com/realmarauder/TensorTrap#readme"
Repository = "https://github.com/realmarauder/TensorTrap"
Issues = "https://github.com/realmarauder/TensorTrap/issues"
Changelog = "https://github.com/realmarauder/TensorTrap/blob/main/CHANGELOG.md"

[project.scripts]
tensortrap = "tensortrap.cli:app"
```

## Publishing Process

### First Release

```bash
# Ensure version in pyproject.toml is correct
# Commit all changes
git add -A
git commit -m "Prepare v0.1.0 release"

# Create and push tag
git tag v0.1.0
git push origin main
git push origin v0.1.0
```

The GitHub Action will:
1. Build the package
2. Publish to TestPyPI first
3. If successful, publish to PyPI

### Subsequent Releases

1. Update version in pyproject.toml
2. Update CHANGELOG.md
3. Commit changes
4. Create new tag: `git tag v0.1.1`
5. Push: `git push origin main && git push origin v0.1.1`

## Verification

After publishing:

```bash
# Test installation from PyPI
pip install tensortrap

# Or with pipx (recommended)
pipx install tensortrap

# Verify
tensortrap --version
tensortrap scan --help
```

## Troubleshooting

**"Project does not exist"**: The trusted publisher must be configured BEFORE the first publish. Create the pending publisher on PyPI first.

**"Environment not found"**: Create the `pypi` and `testpypi` environments in GitHub repository settings.

**Version conflict**: PyPI does not allow overwriting versions. Bump the version number for any fix.

## Alternative: API Token (Fallback)

If trusted publishing fails:

1. Create token at https://pypi.org/manage/account/token/
2. Add as repository secret: Settings > Secrets > Actions > New secret
   - Name: `PYPI_API_TOKEN`
   - Value: (paste token)
3. Modify workflow to use token instead of trusted publishing
