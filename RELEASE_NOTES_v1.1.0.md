# TensorTrap v1.1.0 Release Notes

## Performance Release 🚀

This release brings massive performance improvements, reducing scan times for large model files from several minutes to just seconds. Big thanks to [@JustMaier](https://github.com/JustMaier) for the contribution!

### Highlights

- **>100x faster scanning** for large files (2GB file: 4-5 min → ~2.2 sec)
- All 151 security tests passing - no detection regressions
- Defense-in-depth scanning fully preserved

---

## What's New

### Streaming Pickle Parser

The new streaming parser intelligently traverses pickle files, skipping over binary tensor data while still examining every security-relevant opcode. This means we're not wasting time parsing gigabytes of weight data, but we're still catching any `GLOBAL`, `REDUCE`, `BUILD`, or other dangerous opcodes no matter where they hide.

### File Data Caching

Files are now read once and the data is threaded through all scanner functions. Previously, the same file could be read multiple times by different scanners - now it's cached in memory for the duration of the scan.

### ZIP Header Optimization

Switched from byte-by-byte searching to Python's optimized `find()` method for locating ZIP headers. Simple change, big speedup.

### Unknown Opcode Detection (Security Enhancement)

The scanner now flags unknown pickle opcodes as HIGH severity findings. This catches potential evasion attempts using newer pickle protocol features or malformed opcodes.

---

## Breaking Changes

### `compute_hash` Default Changed

The `scan_file()` function's `compute_hash` parameter now defaults to `False` instead of `True`.

**Before (v1.0.x):**
```python
result = scan_file("model.pt")  # Hash computed by default
```

**After (v1.1.0):**
```python
result = scan_file("model.pt")  # No hash computed
result = scan_file("model.pt", compute_hash=True)  # Explicitly request hash
```

If your code relies on `result.file_hash` being populated, update your calls to pass `compute_hash=True`.

---

## Migration Guide

### For API Users

1. If you need file hashes, explicitly pass `compute_hash=True`:
   ```python
   from tensortrap import scan_file
   result = scan_file("model.pt", compute_hash=True)
   ```

2. The `is_valid_pickle()` function now performs a quick header check rather than full validation. It no longer requires a STOP opcode at the end. This shouldn't affect most users, but if you were relying on it for strict validation, be aware of this change.

### For CLI Users

No changes required - the CLI behavior is unchanged.

---

## Technical Details

### Files Changed
- `src/tensortrap/formats/pickle_parser.py` - New streaming parser
- `src/tensortrap/scanner/engine.py` - FileDataCache, ScanOptions dataclass
- `src/tensortrap/formats/pytorch_zip.py` - ZIP optimization, data pass-through
- `src/tensortrap/scanner/pickle_scanner.py` - Unknown opcode detection
- `src/tensortrap/scanner/polyglot_scanner.py` - Bytes-based API refactor
- `src/tensortrap/scanner/obfuscation.py` - Precompiled regex patterns

### Security Posture

| Check | Status |
|-------|--------|
| All security-relevant opcodes scanned | ✅ |
| GLOBAL/REDUCE/BUILD detection | ✅ |
| Concatenated pickle detection | ✅ |
| Unknown opcode flagging | ✅ (NEW) |
| Polyglot scanning | ✅ |
| Obfuscation detection | ✅ |
| Test suite | 151/151 passing |

---

## Contributors

- [@JustMaier](https://github.com/JustMaier) - Performance optimizations

---

## Full Changelog

See PR #28 for the complete diff.
