#!/usr/bin/env python3
"""
TensorTrap Benchmark Test Suite
================================
Generates test cases and compares detection rates against picklescan.

Usage:
    python benchmark_tensortrap.py --setup      # Install dependencies and generate test files
    python benchmark_tensortrap.py --run        # Run benchmarks
    python benchmark_tensortrap.py --report     # Generate comparison report

Requirements:
    pip install picklescan fickling
    git clone https://github.com/corkami/mitra.git
"""

import os
import sys
import json
import pickle
import struct
import hashlib
import subprocess
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Any

# Configuration
BENCHMARK_DIR = Path("./benchmark_tests")
RESULTS_DIR = Path("./benchmark_results")
MALICIOUS_SAMPLES_DIR = BENCHMARK_DIR / "malicious"
POLYGLOT_SAMPLES_DIR = BENCHMARK_DIR / "polyglots"
BENIGN_SAMPLES_DIR = BENCHMARK_DIR / "benign"


class MaliciousSampleGenerator:
    """Generates malicious pickle samples for testing detection."""
    
    @staticmethod
    def create_basic_exec(output_path: Path) -> dict:
        """CVE-style: Basic os.system execution."""
        class MaliciousPickle:
            def __reduce__(self):
                import os
                return (os.system, ("echo 'malicious payload executed'",))
        
        with open(output_path, 'wb') as f:
            pickle.dump(MaliciousPickle(), f)
        
        return {
            "name": "basic_os_system",
            "description": "Basic os.system() arbitrary command execution",
            "cve": None,
            "expected_detection": True,
            "bypass_technique": None
        }
    
    @staticmethod
    def create_subprocess_popen(output_path: Path) -> dict:
        """subprocess.Popen execution."""
        class MaliciousPickle:
            def __reduce__(self):
                import subprocess
                return (subprocess.Popen, (["echo", "malicious"],))
        
        with open(output_path, 'wb') as f:
            pickle.dump(MaliciousPickle(), f)
        
        return {
            "name": "subprocess_popen",
            "description": "subprocess.Popen arbitrary command execution",
            "cve": None,
            "expected_detection": True,
            "bypass_technique": None
        }
    
    @staticmethod
    def create_eval_exec(output_path: Path) -> dict:
        """builtins.eval execution."""
        class MaliciousPickle:
            def __reduce__(self):
                return (eval, ("__import__('os').system('echo pwned')",))
        
        with open(output_path, 'wb') as f:
            pickle.dump(MaliciousPickle(), f)
        
        return {
            "name": "builtins_eval",
            "description": "builtins.eval() code execution",
            "cve": None,
            "expected_detection": True,
            "bypass_technique": None
        }
    
    @staticmethod
    def create_pip_main_bypass(output_path: Path) -> dict:
        """CVE-2025-1716: pip.main() bypass that evades some scanners."""
        # This creates a pickle that references pip._internal.main
        # which some scanners do not flag as dangerous
        
        # Manual pickle construction for pip.main bypass
        # GLOBAL opcode followed by pip._internal.main
        pickle_data = (
            b'\x80\x04'  # Protocol 4
            b'\x95\x30\x00\x00\x00\x00\x00\x00\x00'  # Frame
            b'\x8c\x0cpip._internal'  # Module: pip._internal  
            b'\x8c\x04main'  # Attribute: main
            b'\x93'  # STACK_GLOBAL
            b'\x8c\x07install'  # Argument
            b'\x85'  # TUPLE1
            b'\x52'  # REDUCE
            b'.'  # STOP
        )
        
        with open(output_path, 'wb') as f:
            f.write(pickle_data)
        
        return {
            "name": "pip_main_bypass",
            "description": "CVE-2025-1716: pip.main() bypass - installs arbitrary packages",
            "cve": "CVE-2025-1716",
            "expected_detection": True,
            "bypass_technique": "pip.main() not in standard dangerous imports list"
        }
    
    @staticmethod
    def create_runpy_bypass(output_path: Path) -> dict:
        """runpy.run_module bypass - less commonly flagged."""
        class MaliciousPickle:
            def __reduce__(self):
                import runpy
                return (runpy.run_module, ("http.server",))
        
        with open(output_path, 'wb') as f:
            pickle.dump(MaliciousPickle(), f)
        
        return {
            "name": "runpy_bypass",
            "description": "runpy.run_module() - runs arbitrary Python modules",
            "cve": None,
            "expected_detection": True,
            "bypass_technique": "runpy not always in dangerous imports list"
        }
    
    @staticmethod
    def create_code_execution(output_path: Path) -> dict:
        """code.InteractiveInterpreter bypass."""
        pickle_data = (
            b'\x80\x04'
            b'\x8c\x04code'
            b'\x8c\x16InteractiveInterpreter'
            b'\x93'
            b')'
            b'\x81'
            b'.'
        )
        
        with open(output_path, 'wb') as f:
            f.write(pickle_data)
        
        return {
            "name": "code_interpreter",
            "description": "code.InteractiveInterpreter instantiation",
            "cve": None,
            "expected_detection": True,
            "bypass_technique": "code module less commonly flagged"
        }


class NullifAIBypassGenerator:
    """Generates nullifAI-style bypass samples (CVE-2025-1889 related)."""
    
    @staticmethod
    def create_7z_compressed_pickle(output_path: Path) -> dict:
        """Malicious pickle compressed with 7z to evade scanning."""
        # Create malicious pickle
        class MaliciousPickle:
            def __reduce__(self):
                import os
                return (os.system, ("echo '7z bypass'",))
        
        temp_pickle = output_path.with_suffix('.pkl.tmp')
        with open(temp_pickle, 'wb') as f:
            pickle.dump(MaliciousPickle(), f)
        
        # Compress with 7z (requires 7z installed)
        try:
            subprocess.run(['7z', 'a', str(output_path), str(temp_pickle)], 
                         capture_output=True, check=True)
            temp_pickle.unlink()
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Fallback: create a mock 7z header + pickle
            with open(temp_pickle, 'rb') as f:
                pickle_data = f.read()
            
            # 7z magic signature
            sevenz_magic = b"7z\xbc\xaf'\x1c"
            
            with open(output_path, 'wb') as f:
                f.write(sevenz_magic)
                f.write(b'\x00' * 26)  # Header padding
                f.write(pickle_data)
            
            temp_pickle.unlink()
        
        return {
            "name": "nullifai_7z_bypass",
            "description": "NullifAI: Pickle compressed with 7z to evade pattern matching",
            "cve": "CVE-2025-1889",
            "expected_detection": True,
            "bypass_technique": "7z compression hides pickle opcodes from scanners"
        }
    
    @staticmethod
    def create_magic_byte_mismatch(output_path: Path) -> dict:
        """File with PNG magic bytes but contains pickle data."""
        # PNG magic bytes
        png_magic = b'\x89PNG\r\n\x1a\n'
        
        # Create malicious pickle
        class MaliciousPickle:
            def __reduce__(self):
                import os
                return (os.system, ("echo 'magic mismatch'",))
        
        import io
        pickle_buffer = io.BytesIO()
        pickle.dump(MaliciousPickle(), pickle_buffer)
        pickle_data = pickle_buffer.getvalue()
        
        # Combine: PNG header + padding + pickle
        with open(output_path, 'wb') as f:
            f.write(png_magic)
            f.write(b'\x00' * 100)  # Fake PNG chunks
            f.write(pickle_data)
        
        return {
            "name": "magic_byte_mismatch",
            "description": "CVE-2025-1889: PNG magic bytes with pickle content",
            "cve": "CVE-2025-1889",
            "expected_detection": True,
            "bypass_technique": "Scanners checking only magic bytes skip pickle analysis"
        }
    
    @staticmethod
    def create_zip_append_bypass(output_path: Path) -> dict:
        """Malicious pickle appended after valid ZIP archive."""
        import zipfile
        import io
        
        # Create valid ZIP
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr('readme.txt', 'This is a legitimate file')
        
        zip_data = zip_buffer.getvalue()
        
        # Create malicious pickle
        class MaliciousPickle:
            def __reduce__(self):
                import os
                return (os.system, ("echo 'zip append bypass'",))
        
        pickle_buffer = io.BytesIO()
        pickle.dump(MaliciousPickle(), pickle_buffer)
        pickle_data = pickle_buffer.getvalue()
        
        # Combine: ZIP + pickle
        with open(output_path, 'wb') as f:
            f.write(zip_data)
            f.write(pickle_data)
        
        return {
            "name": "zip_append_bypass",
            "description": "NullifAI: Malicious pickle appended after valid ZIP",
            "cve": None,
            "expected_detection": True,
            "bypass_technique": "Scanners stop at ZIP end-of-central-directory"
        }


class PolyglotGenerator:
    """Generates polyglot test files."""
    
    @staticmethod
    def create_jpg_pickle_polyglot(output_path: Path) -> dict:
        """Creates a file that is valid as both JPEG and contains pickle."""
        # Minimal JPEG header
        jpeg_header = bytes([
            0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46,
            0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x00
        ])
        
        # JPEG comment segment to hide pickle
        # FF FE = comment marker, followed by 2-byte length
        class MaliciousPickle:
            def __reduce__(self):
                import os
                return (os.system, ("echo 'jpg polyglot'",))
        
        import io
        pickle_buffer = io.BytesIO()
        pickle.dump(MaliciousPickle(), pickle_buffer)
        pickle_data = pickle_buffer.getvalue()
        
        # Construct polyglot
        comment_length = len(pickle_data) + 2
        comment_marker = bytes([0xFF, 0xFE]) + struct.pack('>H', comment_length)
        
        # Minimal JPEG end
        jpeg_end = bytes([0xFF, 0xD9])
        
        with open(output_path, 'wb') as f:
            f.write(jpeg_header)
            f.write(comment_marker)
            f.write(pickle_data)
            f.write(jpeg_end)
        
        return {
            "name": "jpg_pickle_polyglot",
            "description": "Valid JPEG containing pickle payload in comment segment",
            "cve": None,
            "expected_detection": True,
            "bypass_technique": "Image viewers show image, pickle loaders execute code"
        }
    
    @staticmethod
    def create_double_extension(output_path: Path) -> dict:
        """Creates file with double extension obfuscation."""
        # Create malicious pickle with .pkl.png name
        actual_path = output_path.parent / (output_path.stem + ".pkl.png")
        
        class MaliciousPickle:
            def __reduce__(self):
                import os
                return (os.system, ("echo 'double extension'",))
        
        with open(actual_path, 'wb') as f:
            pickle.dump(MaliciousPickle(), f)
        
        return {
            "name": "double_extension",
            "description": "Pickle file disguised with .pkl.png extension",
            "cve": None,
            "expected_detection": True,
            "bypass_technique": "Users see .png, systems may process as pickle",
            "actual_path": str(actual_path)
        }


class BenignSampleGenerator:
    """Generates benign samples for false positive testing."""
    
    @staticmethod
    def create_simple_model(output_path: Path) -> dict:
        """Creates a simple, benign pickle (like a basic ML model)."""
        model_data = {
            'weights': [0.1, 0.2, 0.3, 0.4, 0.5],
            'bias': 0.01,
            'config': {'layers': 3, 'activation': 'relu'}
        }
        
        with open(output_path, 'wb') as f:
            pickle.dump(model_data, f)
        
        return {
            "name": "benign_model",
            "description": "Simple benign pickle representing ML model weights",
            "expected_detection": False,
            "category": "benign"
        }
    
    @staticmethod
    def create_numpy_array(output_path: Path) -> dict:
        """Creates a pickle containing numpy-like data structure."""
        # Simulating numpy array pickle without numpy dependency
        data = {
            'shape': (100, 100),
            'dtype': 'float32',
            'data': [0.0] * 10000
        }
        
        with open(output_path, 'wb') as f:
            pickle.dump(data, f)
        
        return {
            "name": "numpy_like_array",
            "description": "Benign pickle with numpy-like array structure",
            "expected_detection": False,
            "category": "benign"
        }


class BenchmarkRunner:
    """Runs TensorTrap and picklescan against test samples."""
    
    def __init__(self, tensortrap_path: str = "tensortrap"):
        self.tensortrap_path = tensortrap_path
        self.results = []
    
    def run_picklescan(self, file_path: Path) -> dict:
        """Run picklescan on a file."""
        try:
            result = subprocess.run(
                ['picklescan', '-p', str(file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            detected = 'FOUND' in result.stdout or result.returncode != 0
            
            return {
                "tool": "picklescan",
                "detected": detected,
                "output": result.stdout,
                "error": result.stderr,
                "returncode": result.returncode
            }
        except FileNotFoundError:
            return {"tool": "picklescan", "error": "picklescan not installed"}
        except subprocess.TimeoutExpired:
            return {"tool": "picklescan", "error": "timeout"}
    
    def run_tensortrap(self, file_path: Path) -> dict:
        """Run TensorTrap on a file."""
        try:
            result = subprocess.run(
                [self.tensortrap_path, 'scan', str(file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )

            # Parse TensorTrap output for detection
            output = result.stdout.lower()
            detected = any(level in output for level in ['critical', 'high', 'medium'])

            return {
                "tool": "tensortrap",
                "detected": detected,
                "output": result.stdout,
                "error": result.stderr,
                "returncode": result.returncode
            }
        except FileNotFoundError:
            return {"tool": "tensortrap", "error": "tensortrap not found"}
        except subprocess.TimeoutExpired:
            return {"tool": "tensortrap", "error": "timeout"}
    
    def benchmark_file(self, file_path: Path, metadata: dict) -> dict:
        """Run all scanners on a single file."""
        picklescan_result = self.run_picklescan(file_path)
        tensortrap_result = self.run_tensortrap(file_path)
        
        result = {
            "file": str(file_path),
            "metadata": metadata,
            "picklescan": picklescan_result,
            "tensortrap": tensortrap_result,
            "timestamp": datetime.now().isoformat()
        }
        
        self.results.append(result)
        return result
    
    def generate_report(self) -> dict:
        """Generate comparison report from results."""
        report = {
            "summary": {
                "total_samples": len(self.results),
                "picklescan_detections": 0,
                "tensortrap_detections": 0,
                "picklescan_false_negatives": 0,
                "tensortrap_false_negatives": 0,
                "picklescan_false_positives": 0,
                "tensortrap_false_positives": 0,
            },
            "bypass_detection": [],
            "false_positives": [],
            "detailed_results": self.results
        }
        
        for result in self.results:
            expected = result["metadata"].get("expected_detection", True)
            ps_detected = result["picklescan"].get("detected", False)
            tt_detected = result["tensortrap"].get("detected", False)
            
            if ps_detected:
                report["summary"]["picklescan_detections"] += 1
            if tt_detected:
                report["summary"]["tensortrap_detections"] += 1
            
            # Check for false negatives (should detect but did not)
            if expected and not ps_detected:
                report["summary"]["picklescan_false_negatives"] += 1
                if result["metadata"].get("bypass_technique"):
                    report["bypass_detection"].append({
                        "file": result["file"],
                        "bypass": result["metadata"]["bypass_technique"],
                        "picklescan_missed": True,
                        "tensortrap_caught": tt_detected
                    })
            
            if expected and not tt_detected:
                report["summary"]["tensortrap_false_negatives"] += 1
            
            # Check for false positives (should not detect but did)
            if not expected and ps_detected:
                report["summary"]["picklescan_false_positives"] += 1
                report["false_positives"].append({
                    "file": result["file"],
                    "tool": "picklescan"
                })
            
            if not expected and tt_detected:
                report["summary"]["tensortrap_false_positives"] += 1
                report["false_positives"].append({
                    "file": result["file"],
                    "tool": "tensortrap"
                })
        
        return report


def setup_test_environment():
    """Set up directories and install dependencies."""
    print("Setting up benchmark test environment...")
    
    # Create directories
    for dir_path in [BENCHMARK_DIR, RESULTS_DIR, MALICIOUS_SAMPLES_DIR, 
                     POLYGLOT_SAMPLES_DIR, BENIGN_SAMPLES_DIR]:
        dir_path.mkdir(parents=True, exist_ok=True)
    
    print(f"Created directories in {BENCHMARK_DIR}")
    
    # Check for picklescan
    try:
        subprocess.run(['picklescan', '--help'], capture_output=True, check=True)
        print("✓ picklescan is installed")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("✗ picklescan not found. Install with: pip install picklescan")
    
    # Generate test samples
    print("\nGenerating malicious samples...")
    
    malicious_gen = MaliciousSampleGenerator()
    samples_metadata = []
    
    # Basic malicious samples
    samples = [
        (malicious_gen.create_basic_exec, "basic_exec.pkl"),
        (malicious_gen.create_subprocess_popen, "subprocess_popen.pkl"),
        (malicious_gen.create_eval_exec, "eval_exec.pkl"),
        (malicious_gen.create_pip_main_bypass, "pip_main_bypass.pkl"),
        (malicious_gen.create_runpy_bypass, "runpy_bypass.pkl"),
        (malicious_gen.create_code_execution, "code_execution.pkl"),
    ]
    
    for generator, filename in samples:
        path = MALICIOUS_SAMPLES_DIR / filename
        metadata = generator(path)
        metadata["path"] = str(path)
        samples_metadata.append(metadata)
        print(f"  Created: {filename}")
    
    # NullifAI bypass samples
    print("\nGenerating NullifAI bypass samples...")
    nullifai_gen = NullifAIBypassGenerator()
    
    bypass_samples = [
        (nullifai_gen.create_7z_compressed_pickle, "nullifai_7z.7z"),
        (nullifai_gen.create_magic_byte_mismatch, "magic_mismatch.png"),
        (nullifai_gen.create_zip_append_bypass, "zip_append.zip"),
    ]
    
    for generator, filename in bypass_samples:
        path = MALICIOUS_SAMPLES_DIR / filename
        metadata = generator(path)
        metadata["path"] = str(path)
        samples_metadata.append(metadata)
        print(f"  Created: {filename}")
    
    # Polyglot samples
    print("\nGenerating polyglot samples...")
    polyglot_gen = PolyglotGenerator()
    
    polyglot_samples = [
        (polyglot_gen.create_jpg_pickle_polyglot, "jpg_polyglot.jpg"),
        (polyglot_gen.create_double_extension, "model"),
    ]
    
    for generator, filename in polyglot_samples:
        path = POLYGLOT_SAMPLES_DIR / filename
        metadata = generator(path)
        if "actual_path" not in metadata:
            metadata["path"] = str(path)
        samples_metadata.append(metadata)
        print(f"  Created: {filename}")
    
    # Benign samples
    print("\nGenerating benign samples...")
    benign_gen = BenignSampleGenerator()
    
    benign_samples = [
        (benign_gen.create_simple_model, "benign_model.pkl"),
        (benign_gen.create_numpy_array, "numpy_array.pkl"),
    ]
    
    for generator, filename in benign_samples:
        path = BENIGN_SAMPLES_DIR / filename
        metadata = generator(path)
        metadata["path"] = str(path)
        samples_metadata.append(metadata)
        print(f"  Created: {filename}")
    
    # Save metadata
    metadata_path = BENCHMARK_DIR / "samples_metadata.json"
    with open(metadata_path, 'w') as f:
        json.dump(samples_metadata, f, indent=2)
    
    print(f"\n✓ Generated {len(samples_metadata)} test samples")
    print(f"✓ Metadata saved to {metadata_path}")
    
    return samples_metadata


def run_benchmarks(tensortrap_path: str = "tensortrap"):
    """Run benchmarks on all test samples."""
    print("Running benchmarks...")
    
    # Load metadata
    metadata_path = BENCHMARK_DIR / "samples_metadata.json"
    if not metadata_path.exists():
        print("No test samples found. Run with --setup first.")
        return None
    
    with open(metadata_path) as f:
        samples_metadata = json.load(f)
    
    runner = BenchmarkRunner(tensortrap_path)
    
    for metadata in samples_metadata:
        # Handle both 'path' and 'actual_path' keys
        path_str = metadata.get("actual_path") or metadata.get("path")
        if not path_str:
            print(f"Skipping (no path in metadata): {metadata.get('name', 'unknown')}")
            continue

        path = Path(path_str)
        if path.exists():
            print(f"Testing: {path.name}...")
            runner.benchmark_file(path, metadata)
        else:
            print(f"Skipping (not found): {path}")
    
    # Generate and save report
    report = runner.generate_report()
    
    report_path = RESULTS_DIR / f"benchmark_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n✓ Report saved to {report_path}")
    
    return report


def print_report(report: dict):
    """Print formatted report to console."""
    print("\n" + "=" * 60)
    print("TENSORTRAP BENCHMARK REPORT")
    print("=" * 60)
    
    summary = report["summary"]
    print(f"\nTotal Samples: {summary['total_samples']}")
    print(f"\nDetection Rates:")
    print(f"  Picklescan: {summary['picklescan_detections']}/{summary['total_samples']}")
    print(f"  TensorTrap: {summary['tensortrap_detections']}/{summary['total_samples']}")
    
    print(f"\nFalse Negatives (missed threats):")
    print(f"  Picklescan: {summary['picklescan_false_negatives']}")
    print(f"  TensorTrap: {summary['tensortrap_false_negatives']}")
    
    print(f"\nFalse Positives (benign flagged as malicious):")
    print(f"  Picklescan: {summary['picklescan_false_positives']}")
    print(f"  TensorTrap: {summary['tensortrap_false_positives']}")
    
    if report["bypass_detection"]:
        print(f"\n" + "-" * 60)
        print("BYPASS TECHNIQUES DETECTED:")
        print("-" * 60)
        for bypass in report["bypass_detection"]:
            status = "✓ TensorTrap caught" if bypass["tensortrap_caught"] else "✗ Both missed"
            print(f"  {bypass['bypass']}")
            print(f"    Picklescan: MISSED | {status}")
    
    print("\n" + "=" * 60)


def main():
    parser = argparse.ArgumentParser(description="TensorTrap Benchmark Suite")
    parser.add_argument('--setup', action='store_true', 
                       help='Set up test environment and generate samples')
    parser.add_argument('--run', action='store_true',
                       help='Run benchmarks')
    parser.add_argument('--report', action='store_true',
                       help='Generate markdown report from latest results')
    parser.add_argument('--tensortrap', default='tensortrap',
                       help='Path to TensorTrap executable')
    
    args = parser.parse_args()
    
    if args.setup:
        setup_test_environment()
    
    if args.run:
        report = run_benchmarks(args.tensortrap)
        if report:
            print_report(report)
    
    if args.report:
        # Find latest report
        reports = list(RESULTS_DIR.glob("benchmark_report_*.json"))
        if reports:
            latest = max(reports, key=lambda p: p.stat().st_mtime)
            with open(latest) as f:
                report = json.load(f)
            print_report(report)
        else:
            print("No benchmark reports found. Run with --run first.")
    
    if not any([args.setup, args.run, args.report]):
        parser.print_help()


if __name__ == "__main__":
    main()
