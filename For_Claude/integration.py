"""
Scanner Integration Module

Shows how to integrate context_analyzer.py and external_validators.py
into the existing TensorTrap scanner workflow.

This file provides:
1. Integration points for polyglot_scanner.py
2. CLI flag additions
3. Report format changes
4. Complete workflow example
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# Import the new modules
from .context_analyzer import ContextAnalyzer, ContextAnalysisResult
from .external_validators import ExternalValidationRunner


# =============================================================================
# INTEGRATION POINT 1: Modify polyglot_scanner.py
# =============================================================================

"""
In src/tensortrap/scanner/polyglot_scanner.py, add context analysis
after pattern detection:

```python
from .context_analyzer import ContextAnalyzer

class PolyglotScanner:
    def __init__(self, use_context_analysis: bool = True, ...):
        self.use_context_analysis = use_context_analysis
        self._context_analyzer = ContextAnalyzer() if use_context_analysis else None
    
    def scan_file(self, filepath: Path) -> ScanResult:
        # Read file data
        with open(filepath, 'rb') as f:
            file_data = f.read()
        
        # Stage 1: Pattern detection (existing code)
        raw_findings = self._detect_patterns(file_data, filepath)
        
        # Stage 2: Context analysis (NEW)
        if self._context_analyzer and raw_findings:
            analyzed_findings = []
            for finding in raw_findings:
                if finding['severity'].lower() in ['critical', 'high']:
                    context_result = self._context_analyzer.analyze(
                        file_data=file_data,
                        match_offset=finding.get('offset', 0),
                        pattern_name=finding['pattern'],
                        file_format=self._detect_format(filepath),
                        original_severity=finding['severity'],
                        filepath=filepath,
                    )
                    finding['context_analysis'] = context_result.to_dict()
                    finding['adjusted_severity'] = context_result.adjusted_severity
                    finding['confidence'] = context_result.confidence_score
                    finding['recommended_action'] = context_result.recommended_action
                analyzed_findings.append(finding)
            raw_findings = analyzed_findings
        
        return ScanResult(filepath=filepath, findings=raw_findings)
```
"""


# =============================================================================
# INTEGRATION POINT 2: Add CLI flags in cli.py
# =============================================================================

"""
In src/tensortrap/cli.py, add new options:

```python
@click.option(
    "--context-analysis/--no-context-analysis",
    default=True,
    help="Run context analysis on critical findings (default: enabled)",
)
@click.option(
    "--external-validation/--no-external-validation",
    default=True,
    help="Run external tool validation on medium/high confidence findings",
)
@click.option(
    "--confidence-threshold",
    type=float,
    default=0.5,
    help="Minimum confidence to report as actionable (0.0-1.0, default: 0.5)",
)
@click.option(
    "--entropy-threshold",
    type=float,
    default=7.0,
    help="Entropy above this is considered compressed data (default: 7.0)",
)
def scan(
    path,
    context_analysis,
    external_validation,
    confidence_threshold,
    entropy_threshold,
    ...
):
    scanner = TensorTrapScanner(
        use_context_analysis=context_analysis,
        use_external_validation=external_validation,
        confidence_threshold=confidence_threshold,
        entropy_threshold=entropy_threshold,
        ...
    )
```
"""


# =============================================================================
# INTEGRATION POINT 3: Update report generators
# =============================================================================

"""
In src/tensortrap/reporters/txt_reporter.py:

```python
def format_finding(finding: dict) -> str:
    # Get adjusted severity if available
    severity = finding.get('adjusted_severity', finding.get('severity', 'UNKNOWN'))
    message = finding.get('message', '')
    
    # Determine marker
    if 'CRITICAL-HIGH' in severity:
        marker = "!!"
        color = RED
    elif 'CRITICAL-MEDIUM' in severity:
        marker = "* "
        color = YELLOW
    elif 'CRITICAL-LOW' in severity:
        marker = "  "
        color = GREEN
    else:
        marker = "  "
        color = WHITE
    
    lines = [f"  {marker} [{severity}] {message}"]
    
    # Add confidence info
    if 'context_analysis' in finding:
        ctx = finding['context_analysis']
        confidence_pct = ctx.get('confidence_percent', 'N/A')
        reasons = ctx.get('reasons', [])
        lines.append(f"      Confidence: {confidence_pct} ({'; '.join(reasons)})")
    
    # Add recommended action
    if 'recommended_action' in finding:
        lines.append(f"      Action: {finding['recommended_action']}")
    
    # Add external validation if present
    if 'external_validation' in finding:
        ext = finding['external_validation']
        status = ext.get('status', 'unknown')
        tool = ext.get('tool_name', 'unknown')
        lines.append(f"      External ({tool}): {status.upper()}")
    
    return '\\n'.join(lines)
```
"""


# =============================================================================
# INTEGRATION POINT 4: Full workflow integration
# =============================================================================

@dataclass
class EnhancedScanResult:
    """Enhanced scan result with context analysis and external validation."""
    filepath: Path
    format: str
    is_safe: bool
    max_severity: str
    findings: List[Dict[str, Any]]
    context_analysis_enabled: bool = True
    external_validation_enabled: bool = True
    validation_summary: Dict[str, Any] = field(default_factory=dict)


class EnhancedScanner:
    """
    Example scanner showing full integration of context analysis
    and external validation.
    """
    
    def __init__(
        self,
        use_context_analysis: bool = True,
        use_external_validation: bool = True,
        entropy_threshold: float = 7.0,
        confidence_threshold: float = 0.5,
    ):
        self.use_context_analysis = use_context_analysis
        self.use_external_validation = use_external_validation
        self.confidence_threshold = confidence_threshold
        
        # Initialize analyzers
        self._context_analyzer = ContextAnalyzer(
            entropy_threshold=entropy_threshold,
        ) if use_context_analysis else None
        
        self._external_runner = ExternalValidationRunner(
            enabled=use_external_validation,
        ) if use_external_validation else None
    
    def scan_file(self, filepath: Path) -> EnhancedScanResult:
        """
        Scan a file with full analysis pipeline.
        
        Pipeline:
            1. Pattern detection (existing scanner)
            2. Context analysis (entropy, structure, AI metadata)
            3. External validation (exiftool, binwalk)
            4. Final severity assignment
        """
        # Read file
        with open(filepath, 'rb') as f:
            file_data = f.read()
        
        file_format = self._detect_format(filepath)
        
        # Stage 1: Pattern detection
        # (This would call existing scanner code)
        raw_findings = self._mock_pattern_detection(file_data, filepath)
        
        # Stage 2: Context analysis
        if self._context_analyzer and raw_findings:
            for finding in raw_findings:
                if finding.get('severity', '').lower() in ['critical', 'high']:
                    result = self._context_analyzer.analyze(
                        file_data=file_data,
                        match_offset=finding.get('offset', 0),
                        pattern_name=finding.get('pattern', ''),
                        file_format=file_format,
                        original_severity=finding['severity'],
                        filepath=filepath,
                    )
                    finding['context_analysis'] = result.to_dict()
                    finding['adjusted_severity'] = result.adjusted_severity
                    finding['confidence'] = result.confidence_score
                    finding['recommended_action'] = result.recommended_action
        
        # Stage 3: External validation (only for MEDIUM/HIGH confidence)
        if self._external_runner and raw_findings:
            for finding in raw_findings:
                ctx = finding.get('context_analysis', {})
                confidence_level = ctx.get('confidence_level', 'LOW')
                
                if confidence_level in ['MEDIUM', 'HIGH']:
                    ext_result = self._external_runner.validate_finding(
                        filepath=filepath,
                        pattern_name=finding.get('pattern', ''),
                        confidence_level=confidence_level,
                        offset=finding.get('offset'),
                    )
                    if ext_result:
                        finding['external_validation'] = ext_result.to_dict()
                        
                        # Adjust if external tool disagrees
                        if ext_result.status.value == 'not_confirmed':
                            finding['adjusted_severity'] = finding['adjusted_severity'].replace(
                                '-HIGH', '-LOW'
                            ).replace('-MEDIUM', '-LOW')
                            finding['external_override'] = True
        
        # Calculate final status
        max_severity = self._calculate_max_severity(raw_findings)
        is_safe = self._is_safe(raw_findings)
        
        # Build validation summary
        summary = self._build_summary(raw_findings)
        
        return EnhancedScanResult(
            filepath=filepath,
            format=file_format,
            is_safe=is_safe,
            max_severity=max_severity,
            findings=raw_findings,
            context_analysis_enabled=self.use_context_analysis,
            external_validation_enabled=self.use_external_validation,
            validation_summary=summary,
        )
    
    def _detect_format(self, filepath: Path) -> str:
        """Detect file format from extension."""
        ext = filepath.suffix.lower()
        image_exts = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.tiff', '.svg'}
        video_exts = {'.mp4', '.mkv', '.avi', '.mov', '.webm', '.flv'}
        
        if ext in image_exts:
            return 'image'
        elif ext in video_exts:
            return 'video'
        else:
            return 'unknown'
    
    def _mock_pattern_detection(
        self,
        file_data: bytes,
        filepath: Path,
    ) -> List[Dict[str, Any]]:
        """
        Mock pattern detection for example.
        In real implementation, this calls existing scanner code.
        """
        # This is a placeholder - real implementation uses existing scanners
        return []
    
    def _calculate_max_severity(self, findings: List[Dict[str, Any]]) -> str:
        """Calculate maximum severity from findings."""
        severity_order = {
            'critical-high': 10,
            'critical-medium': 9,
            'critical-low': 8,
            'high-high': 7,
            'high-medium': 6,
            'high-low': 5,
            'medium': 4,
            'low': 3,
            'info': 2,
        }
        
        max_level = 0
        max_sev = 'info'
        
        for finding in findings:
            sev = finding.get('adjusted_severity', finding.get('severity', 'info'))
            level = severity_order.get(sev.lower(), 0)
            if level > max_level:
                max_level = level
                max_sev = sev
        
        return max_sev
    
    def _is_safe(self, findings: List[Dict[str, Any]]) -> bool:
        """Determine if file is safe based on findings."""
        for finding in findings:
            sev = finding.get('adjusted_severity', finding.get('severity', ''))
            # Only HIGH confidence critical/high findings make it unsafe
            if any(x in sev.upper() for x in ['CRITICAL-HIGH', 'HIGH-HIGH']):
                return False
            # MEDIUM confidence needs investigation but not auto-unsafe
            if 'CRITICAL-MEDIUM' in sev.upper():
                return False
        return True
    
    def _build_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build validation summary statistics."""
        summary = {
            'total_findings': len(findings),
            'by_confidence': {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
            'context_analyzed': 0,
            'externally_validated': 0,
            'external_overrides': 0,
        }
        
        for finding in findings:
            ctx = finding.get('context_analysis', {})
            if ctx:
                summary['context_analyzed'] += 1
                level = ctx.get('confidence_level', 'LOW')
                summary['by_confidence'][level] = summary['by_confidence'].get(level, 0) + 1
            
            if finding.get('external_validation'):
                summary['externally_validated'] += 1
            
            if finding.get('external_override'):
                summary['external_overrides'] += 1
        
        return summary


# =============================================================================
# EXAMPLE USAGE
# =============================================================================

def example_usage():
    """Example of using the enhanced scanner."""
    
    # Create scanner with full pipeline
    scanner = EnhancedScanner(
        use_context_analysis=True,
        use_external_validation=True,
        entropy_threshold=7.0,
        confidence_threshold=0.5,
    )
    
    # Check available external tools
    if scanner._external_runner:
        tools = scanner._external_runner.get_available_tools()
        print("External tools:")
        for tool, available in tools.items():
            status = "✓" if available else "✗"
            print(f"  {status} {tool}")
    
    # Scan a file
    # result = scanner.scan_file(Path("/path/to/file.png"))
    # print(f"Safe: {result.is_safe}")
    # print(f"Max severity: {result.max_severity}")


# =============================================================================
# REPORT FORMAT EXAMPLE
# =============================================================================

EXAMPLE_OUTPUT = """
================================================================================
TENSORTRAP SECURITY SCAN REPORT (Enhanced)
================================================================================
Scan Target: /home/user/images/
Context Analysis: Enabled
External Validation: Enabled (exiftool: ✓, binwalk: ✓)

--------------------------------------------------------------------------------
File: /home/user/images/ai_generated.png
Format: image
Status: SAFE

Findings:
     [CRITICAL-LOW] Suspicious pattern in image metadata: asp_code
      Confidence: 15% (pattern in high-entropy region; AI metadata detected)
      Action: REVIEW - Likely false positive, verify if concerned
      Context: ComfyUI workflow detected in EXIF

--------------------------------------------------------------------------------
File: /home/user/images/suspicious.jpg
Format: image  
Status: THREATS DETECTED

Findings:
  !! [CRITICAL-HIGH] Archive embedded in image: ZIP at offset 12345
      Confidence: 95% (valid ZIP structure confirmed)
      Action: QUARANTINE - Isolate this file immediately
      External (binwalk): CONFIRMED
      Archive contains: 5 files

--------------------------------------------------------------------------------
File: /home/user/images/uncertain.png
Format: image
Status: NEEDS INVESTIGATION

Findings:
  *  [CRITICAL-MEDIUM] Embedded archive signature detected
      Confidence: 65% (archive signature found, extraction failed)
      Action: INVESTIGATE - Manual review recommended
      External (binwalk): NOT_CONFIRMED

================================================================================
SUMMARY
================================================================================
Total files: 3
Safe: 1
Threats: 1
Needs investigation: 1

Context Analysis:
  Total analyzed: 3
  High confidence: 1
  Medium confidence: 1  
  Low confidence: 1

External Validation:
  Validated: 2
  Confirmed: 1
  Not confirmed: 1
  Overrides: 1
================================================================================
"""

if __name__ == "__main__":
    example_usage()
    print(EXAMPLE_OUTPUT)
