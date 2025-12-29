# TensorTrap Enhanced Detection System

Multi-tier context analysis for reducing false positives while maintaining threat detection capability.

## Philosophy

> **"Better to alert and investigate than miss a real threat"**

This enhancement does NOT reduce detection sensitivity. It adds intelligence to classify findings by confidence level, helping users prioritize real threats over noise.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│ TIER 1: Pattern Detection (Existing Scanners)                          │
│                                                                         │
│ • polyglot_scanner.py - ASP, archives, scripts                         │
│ • pickle_scanner.py - Pickle exploits                                  │
│ • safetensors_scanner.py - Safetensor attacks                          │
│                                                                         │
│ Output: Raw findings with CRITICAL/HIGH/MEDIUM/INFO severity           │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ TIER 2: Context Analysis (context_analyzer.py) [NEW]                   │
│                                                                         │
│ • Entropy analysis - detect compressed regions                         │
│ • Archive structure validation - verify ZIP/RAR/7z headers             │
│ • AI metadata detection - ComfyUI, Stable Diffusion, Topaz             │
│ • Executable context - look for real code patterns                     │
│                                                                         │
│ Output: Confidence score 0.0-1.0 → CRITICAL-HIGH/MEDIUM/LOW            │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ TIER 3: External Validation (external_validators.py) [NEW, OPTIONAL]   │
│                                                                         │
│ • exiftool - extract actual EXIF fields, verify metadata threats       │
│ • binwalk - confirm extractable archives                               │
│                                                                         │
│ Only runs on CRITICAL-MEDIUM and CRITICAL-HIGH findings                │
│ Gracefully skips if tools not installed                                │
│                                                                         │
│ Output: CONFIRMED / NOT_CONFIRMED / TOOL_UNAVAILABLE                   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Files to Add

```
src/tensortrap/scanner/
├── __init__.py              # Updated with new exports
├── context_analyzer.py      # NEW: Tier 2 context analysis
├── external_validators.py   # NEW: Tier 3 external tool validation
├── integration.py           # NEW: Integration examples and helpers
├── polyglot_scanner.py      # MODIFY: Add context analysis calls
├── pickle_scanner.py        # Existing
└── ...                      # Existing scanners
```

---

## Context Analysis Details

### Entropy Analysis

Compressed image/video data has high entropy (close to 8.0 bits/byte). Pattern matches in these regions are likely random byte coincidences.

```python
# High entropy = compressed/encrypted data = likely false positive
if entropy > 7.0:
    confidence *= 0.2
    reasons.append("pattern in high-entropy region")
```

### Archive Structure Validation

Finding `PK` bytes (ZIP signature) is not enough. We validate the full ZIP local file header structure:

- Version field is reasonable (< 100)
- Compression method is valid (0-99)
- Filename length is sane (< 1024)
- Filename is valid UTF-8 or CP437
- End of Central Directory exists

If structure is invalid → confidence drops to 10%

### AI Metadata Detection

Scans first 64KB for signatures from:

- **ComfyUI**: `class_type`, `KSampler`, `CLIPTextEncode`, `VAEDecode`
- **Stable Diffusion**: `Steps:`, `Sampler:`, `CFG Scale:`, `Seed:`
- **Topaz**: `Topaz Photo AI`, `Topaz Gigapixel`
- **Others**: InvokeAI, Midjourney, DALL-E

If AI metadata detected → confidence drops to 15%

### Executable Context

Looks for actual code patterns near the match:

- ASP: `response.write`, `request(`, `server.execute`
- PHP: `<?php`, `$_GET[`, `eval(`
- JavaScript: `<script>`, `javascript:`, event handlers
- Shell: `/bin/sh`, `subprocess.`

If executable patterns found → confidence increases to 90%+

---

## Confidence Levels

| Level | Score | Meaning | Action |
|-------|-------|---------|--------|
| **HIGH** | ≥90% | Likely real threat | QUARANTINE immediately |
| **MEDIUM** | 50-90% | Needs investigation | Manual review |
| **LOW** | <50% | Probable false positive | Review if concerned |

### Severity Format

Original severity gets confidence suffix:

- `CRITICAL` → `CRITICAL-HIGH`, `CRITICAL-MEDIUM`, or `CRITICAL-LOW`
- `HIGH` → `HIGH-HIGH`, `HIGH-MEDIUM`, or `HIGH-LOW`

---

## External Validation

### exiftool Validator

Extracts actual EXIF/XMP/IPTC metadata fields and scans for executable patterns:

- ASP delimiters: `<%...%>`
- Script tags: `<script>`
- PHP tags: `<?php`
- Event handlers: `onclick=`

If pattern exists in real metadata field → CONFIRMED
If pattern was binary coincidence → NOT_CONFIRMED

### binwalk Validator

Runs `binwalk -B` to detect archive signatures, filtering out known false positives:

- StuffIt (common in PNG)
- Qualcomm device tree
- Intel microcode signatures

Then attempts extraction with `binwalk -e`:

- If files extracted → CONFIRMED
- If extraction fails → NOT_CONFIRMED

### Installation

```bash
# Debian/Ubuntu
sudo apt install libimage-exiftool-perl binwalk

# Fedora
sudo dnf install perl-Image-ExifTool binwalk

# macOS
brew install exiftool binwalk
```

If tools are missing, validators return `TOOL_UNAVAILABLE` and do not block scanning.

---

## Integration Steps

### 1. Add Files

Copy these files to `src/tensortrap/scanner/`:

- `context_analyzer.py`
- `external_validators.py`
- `integration.py`

### 2. Update polyglot_scanner.py

```python
from .context_analyzer import ContextAnalyzer

class PolyglotScanner:
    def __init__(self, use_context_analysis: bool = True, ...):
        self.use_context_analysis = use_context_analysis
        self._context_analyzer = ContextAnalyzer() if use_context_analysis else None
    
    def _process_findings(self, findings, file_data, filepath):
        if not self._context_analyzer:
            return findings
        
        for finding in findings:
            if finding['severity'].lower() in ['critical', 'high']:
                result = self._context_analyzer.analyze(
                    file_data=file_data,
                    match_offset=finding.get('offset', 0),
                    pattern_name=finding['pattern'],
                    file_format=self._detect_format(filepath),
                    original_severity=finding['severity'],
                    filepath=filepath,
                )
                finding['context_analysis'] = result.to_dict()
                finding['adjusted_severity'] = result.adjusted_severity
                finding['confidence'] = result.confidence_score
                finding['recommended_action'] = result.recommended_action
        
        return findings
```

### 3. Update CLI

```python
@click.option(
    "--context-analysis/--no-context-analysis",
    default=True,
    help="Run context analysis on critical findings",
)
@click.option(
    "--external-validation/--no-external-validation",
    default=True,
    help="Run external tool validation (requires exiftool, binwalk)",
)
@click.option(
    "--confidence-threshold",
    type=float,
    default=0.5,
    help="Minimum confidence to report as actionable (0.0-1.0)",
)
```

### 4. Update Report Format

**Old:**
```
!! [CRITICAL] Suspicious pattern in image metadata: asp_code
    Action: DO NOT LOAD this file.
```

**New:**
```
   [CRITICAL-LOW] Suspicious pattern in image metadata: asp_code
    Confidence: 15% (pattern in high-entropy region; AI metadata detected)
    Action: REVIEW - Likely false positive, verify if concerned

!! [CRITICAL-HIGH] Archive embedded in image: ZIP at offset 12345
    Confidence: 95% (valid ZIP structure confirmed)
    Action: QUARANTINE - Isolate this file immediately
    External (binwalk): CONFIRMED
```

---

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `--context-analysis` | `True` | Enable Tier 2 analysis |
| `--no-context-analysis` | - | Disable Tier 2 (raw patterns only) |
| `--external-validation` | `True` | Enable Tier 3 (exiftool/binwalk) |
| `--no-external-validation` | - | Disable Tier 3 |
| `--confidence-threshold` | `0.5` | Minimum confidence to report |
| `--entropy-threshold` | `7.0` | Entropy above this = compressed |

---

## JSON Output Changes

```json
{
  "filepath": "/path/to/file.png",
  "severity": "CRITICAL",
  "adjusted_severity": "CRITICAL-LOW",
  "pattern": "asp_code",
  "offset": 668969,
  "confidence": 0.15,
  "recommended_action": "REVIEW - Likely false positive",
  "context_analysis": {
    "confidence_score": 0.15,
    "confidence_level": "LOW",
    "confidence_percent": "15%",
    "reasons": [
      "pattern in high-entropy region (7.82 bits/byte)",
      "AI generation metadata detected (ComfyUI/SD/Topaz)"
    ],
    "context_data": {
      "entropy": {"entropy": 7.82, "is_compressed": true},
      "ai_metadata_detected": true
    }
  },
  "external_validation": {
    "status": "not_confirmed",
    "tool_name": "exiftool",
    "tool_available": true,
    "details": "No executable patterns found in metadata fields"
  }
}
```

---

## Testing

### Test Cases

1. **AI-Generated Images (ComfyUI/SD)**
   - Should score: CRITICAL-LOW
   - Reason: "AI generation metadata detected"

2. **Actual Polyglot (PHP in JPEG)**
   - Should score: CRITICAL-HIGH
   - Reason: "executable code patterns detected"

3. **Random ZIP Signature in PNG**
   - Should score: CRITICAL-LOW
   - Reason: "invalid archive structure"

4. **Real Embedded Archive**
   - Should score: CRITICAL-HIGH
   - External: CONFIRMED

### Running Tests

```bash
# Create test files
mkdir -p tests/samples

# Test with known AI image
tensortrap scan tests/samples/comfyui_output.png --verbose

# Test with crafted polyglot
tensortrap scan tests/samples/php_in_jpeg.jpg --verbose

# Compare with/without context analysis
tensortrap scan tests/samples/ --no-context-analysis > raw.txt
tensortrap scan tests/samples/ --context-analysis > analyzed.txt
diff raw.txt analyzed.txt
```

---

## Benefits

| Aspect | Before | After |
|--------|--------|-------|
| False positives | 275 CRITICAL | 275 CRITICAL-LOW |
| Real threats | Detected | Detected (CRITICAL-HIGH) |
| User action | Panic at 275 alerts | Focus on HIGH confidence |
| AI images | Flagged as threats | Recognized as safe |
| Sensitivity | High | High (unchanged) |

---

## Files Reference

| File | Size | Purpose |
|------|------|---------|
| `context_analyzer.py` | ~18KB | Core context analysis |
| `external_validators.py` | ~12KB | exiftool/binwalk validators |
| `integration.py` | ~10KB | Integration examples |
| `__init__.py` | ~1KB | Module exports |

---

## Next Steps

1. Copy files to `src/tensortrap/scanner/`
2. Modify `polyglot_scanner.py` to call context analyzer
3. Update CLI with new flags
4. Update report generators
5. Add unit tests
6. Update documentation
7. Release as v0.3.0

---

## Questions?

See `integration.py` for complete code examples and the `EXAMPLE_OUTPUT` constant for expected report format.
