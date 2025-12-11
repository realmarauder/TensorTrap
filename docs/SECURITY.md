# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in TensorTrap, please report it responsibly:

1. **Do not** open a public issue
2. Email security@m2dynamics.us with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes

We will respond within 48 hours and work with you to:
- Confirm the vulnerability
- Develop a fix
- Coordinate disclosure

## Security Design Principles

TensorTrap is designed with security as the primary concern:

### Pickle Analysis
- **Never uses `pickle.load()`** - all analysis is done via `pickletools.genops()` which safely parses bytecode without executing it
- Dangerous opcodes are identified by pattern matching, not execution

### Input Validation
- All file inputs are validated before processing
- File size limits prevent resource exhaustion
- Header sizes are sanity-checked

### No External Network Calls
- TensorTrap operates entirely offline
- No telemetry or external connections

## Known Limitations

- Obfuscated pickle payloads may evade detection
- Novel attack patterns not in our signatures may not be detected
- GGUF Jinja template analysis is pattern-based, not a full parser

## Security Updates

Security updates are released as patch versions (e.g., 0.1.1) and announced via GitHub releases.
