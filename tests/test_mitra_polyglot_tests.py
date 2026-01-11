#!/usr/bin/env python3
"""
TensorTrap Polyglot Test Suite Using Mitra
==========================================

This script generates polyglot test files using Ange Albertini's mitra tool
(the same tool used by Oak Ridge National Laboratory in their polyglot research).

These test cases demonstrate TensorTrap's polyglot detection capabilities.

Prerequisites:
    git clone https://github.com/corkami/mitra.git
    pip install picklescan  # For comparison testing

Usage:
    python mitra_polyglot_tests.py --setup     # Clone mitra and prepare environment
    python mitra_polyglot_tests.py --generate  # Generate polyglot test files
    python mitra_polyglot_tests.py --test      # Run TensorTrap against test files
    python mitra_polyglot_tests.py --report    # Generate detection report
"""

import os
import sys
import json
import pickle
import struct
import shutil
import hashlib
import subprocess
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple, Optional

# Configuration
MITRA_REPO = "https://github.com/corkami/mitra.git"
MITRA_DIR = Path("./mitra")
TEST_DIR = Path("./polyglot_tests")
RESULTS_DIR = Path("./polyglot_results")
DONOR_DIR = TEST_DIR / "donors"
POLYGLOT_DIR = TEST_DIR / "polyglots"


class DonorFileGenerator:
    """Generates donor files for polyglot creation."""
    
    @staticmethod
    def create_benign_pickle(path: Path) -> dict:
        """Create a benign pickle file."""
        data = {
            'model_name': 'test_model',
            'weights': [0.1, 0.2, 0.3],
            'config': {'layers': 3}
        }
        with open(path, 'wb') as f:
            pickle.dump(data, f)
        return {'type': 'pickle', 'content': 'benign', 'path': str(path)}
    
    @staticmethod
    def create_malicious_pickle(path: Path) -> dict:
        """Create a malicious pickle file with os.system payload."""
        class Exploit:
            def __reduce__(self):
                import os
                return (os.system, ("echo 'polyglot payload executed'",))
        
        with open(path, 'wb') as f:
            pickle.dump(Exploit(), f)
        return {'type': 'pickle', 'content': 'malicious', 'path': str(path)}
    
    @staticmethod
    def create_minimal_png(path: Path) -> dict:
        """Create a minimal valid PNG file."""
        # Minimal 1x1 white PNG
        png_data = bytes([
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,  # PNG signature
            0x00, 0x00, 0x00, 0x0D,  # IHDR length
            0x49, 0x48, 0x44, 0x52,  # IHDR
            0x00, 0x00, 0x00, 0x01,  # width: 1
            0x00, 0x00, 0x00, 0x01,  # height: 1
            0x08, 0x02,              # bit depth: 8, color type: RGB
            0x00, 0x00, 0x00,        # compression, filter, interlace
            0x90, 0x77, 0x53, 0xDE,  # CRC
            0x00, 0x00, 0x00, 0x0C,  # IDAT length
            0x49, 0x44, 0x41, 0x54,  # IDAT
            0x08, 0xD7, 0x63, 0xF8, 0xFF, 0xFF, 0xFF, 0x00,
            0x05, 0xFE, 0x02, 0xFE,  # compressed data + CRC
            0x00, 0x00, 0x00, 0x00,  # IEND length
            0x49, 0x45, 0x4E, 0x44,  # IEND
            0xAE, 0x42, 0x60, 0x82,  # CRC
        ])
        with open(path, 'wb') as f:
            f.write(png_data)
        return {'type': 'png', 'content': 'minimal_image', 'path': str(path)}
    
    @staticmethod
    def create_minimal_jpeg(path: Path) -> dict:
        """Create a minimal valid JPEG file."""
        # Minimal 1x1 JPEG
        jpeg_data = bytes([
            0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46,
            0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43,
            0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08,
            0x07, 0x07, 0x07, 0x09, 0x09, 0x08, 0x0A, 0x0C,
            0x14, 0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12,
            0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D,
            0x1A, 0x1C, 0x1C, 0x20, 0x24, 0x2E, 0x27, 0x20,
            0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29,
            0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27,
            0x39, 0x3D, 0x38, 0x32, 0x3C, 0x2E, 0x33, 0x34,
            0x32, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01,
            0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0xFF, 0xC4,
            0x00, 0x1F, 0x00, 0x00, 0x01, 0x05, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0xFF,
            0xC4, 0x00, 0xB5, 0x10, 0x00, 0x02, 0x01, 0x03,
            0x03, 0x02, 0x04, 0x03, 0x05, 0x05, 0x04, 0x04,
            0x00, 0x00, 0x01, 0x7D, 0x01, 0x02, 0x03, 0x00,
            0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06,
            0x13, 0x51, 0x61, 0x07, 0x22, 0x71, 0x14, 0x32,
            0x81, 0x91, 0xA1, 0x08, 0x23, 0x42, 0xB1, 0xC1,
            0x15, 0x52, 0xD1, 0xF0, 0x24, 0x33, 0x62, 0x72,
            0x82, 0x09, 0x0A, 0x16, 0x17, 0x18, 0x19, 0x1A,
            0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x34, 0x35,
            0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45,
            0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00,
            0x3F, 0x00, 0x7F, 0xFF, 0xD9
        ])
        with open(path, 'wb') as f:
            f.write(jpeg_data)
        return {'type': 'jpeg', 'content': 'minimal_image', 'path': str(path)}
    
    @staticmethod
    def create_minimal_pdf(path: Path) -> dict:
        """Create a minimal valid PDF file."""
        pdf_content = b"""%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj
xref
0 4
0000000000 65535 f 
0000000009 00000 n 
0000000052 00000 n 
0000000101 00000 n 
trailer<</Size 4/Root 1 0 R>>
startxref
166
%%EOF"""
        with open(path, 'wb') as f:
            f.write(pdf_content)
        return {'type': 'pdf', 'content': 'minimal_document', 'path': str(path)}
    
    @staticmethod
    def create_minimal_zip(path: Path) -> dict:
        """Create a minimal ZIP file."""
        import zipfile
        with zipfile.ZipFile(path, 'w') as zf:
            zf.writestr('readme.txt', 'Test archive')
        return {'type': 'zip', 'content': 'minimal_archive', 'path': str(path)}
    
    @staticmethod
    def create_pytorch_model(path: Path) -> dict:
        """Create a minimal PyTorch-like model file."""
        import zipfile
        import io
        
        # Create benign pickle
        model_data = {'state_dict': {'weight': [0.1, 0.2]}}
        pickle_bytes = pickle.dumps(model_data)
        
        with zipfile.ZipFile(path, 'w') as zf:
            zf.writestr('archive/data.pkl', pickle_bytes)
            zf.writestr('archive/version', '3')
        
        return {'type': 'pytorch', 'content': 'benign_model', 'path': str(path)}


class MitraPolyglotGenerator:
    """Generates polyglots using the mitra tool."""
    
    def __init__(self, mitra_path: Path):
        self.mitra_path = mitra_path
        self.mitra_script = mitra_path / "mitra.py"
    
    def is_available(self) -> bool:
        """Check if mitra is available."""
        return self.mitra_script.exists()
    
    def generate_polyglot(self, file1: Path, file2: Path, output_dir: Path) -> List[Path]:
        """Generate polyglots from two files using mitra."""
        if not self.is_available():
            raise RuntimeError("Mitra not found. Run --setup first.")
        
        # Run mitra
        result = subprocess.run(
            ['python', str(self.mitra_script), str(file1), str(file2), '-o', str(output_dir)],
            capture_output=True,
            text=True,
            cwd=str(self.mitra_path)
        )
        
        if result.returncode != 0:
            print(f"Mitra warning: {result.stderr}")
        
        # Find generated files
        generated = []
        for f in output_dir.iterdir():
            if f.is_file() and f.stat().st_mtime > (datetime.now().timestamp() - 60):
                generated.append(f)
        
        return generated


class ManualPolyglotGenerator:
    """Generates polyglots manually (fallback if mitra unavailable)."""
    
    @staticmethod
    def create_png_pickle_stack(png_path: Path, pickle_path: Path, output_path: Path) -> dict:
        """Stack: PNG followed by pickle data (append attack)."""
        with open(png_path, 'rb') as f:
            png_data = f.read()
        with open(pickle_path, 'rb') as f:
            pickle_data = f.read()
        
        with open(output_path, 'wb') as f:
            f.write(png_data)
            f.write(pickle_data)
        
        return {
            'name': 'png_pickle_stack',
            'type': 'stack',
            'format1': 'png',
            'format2': 'pickle',
            'description': 'PNG with pickle data appended after IEND',
            'attack_vector': 'Image viewers show image, pickle loaders execute payload',
            'path': str(output_path)
        }
    
    @staticmethod
    def create_jpeg_pickle_parasite(jpeg_path: Path, pickle_path: Path, output_path: Path) -> dict:
        """Parasite: Pickle hidden in JPEG comment segment."""
        with open(jpeg_path, 'rb') as f:
            jpeg_data = f.read()
        with open(pickle_path, 'rb') as f:
            pickle_data = f.read()
        
        # Find end of JPEG header (after SOI marker)
        # Insert comment segment (FF FE) with pickle data
        soi_end = 2  # After 0xFFD8
        
        # Build comment segment
        comment_length = len(pickle_data) + 2  # +2 for length bytes
        if comment_length > 65535:
            raise ValueError("Pickle too large for single comment segment")
        
        comment_segment = bytes([0xFF, 0xFE]) + struct.pack('>H', comment_length) + pickle_data
        
        # Insert comment after SOI
        polyglot = jpeg_data[:soi_end] + comment_segment + jpeg_data[soi_end:]
        
        with open(output_path, 'wb') as f:
            f.write(polyglot)
        
        return {
            'name': 'jpeg_pickle_parasite',
            'type': 'parasite',
            'format1': 'jpeg',
            'format2': 'pickle',
            'description': 'Pickle hidden in JPEG comment segment',
            'attack_vector': 'Valid JPEG image with embedded malicious pickle',
            'path': str(output_path)
        }
    
    @staticmethod
    def create_pdf_pickle_stack(pdf_path: Path, pickle_path: Path, output_path: Path) -> dict:
        """Stack: PDF with pickle appended after %%EOF."""
        with open(pdf_path, 'rb') as f:
            pdf_data = f.read()
        with open(pickle_path, 'rb') as f:
            pickle_data = f.read()
        
        with open(output_path, 'wb') as f:
            f.write(pdf_data)
            f.write(b'\n')  # Separator
            f.write(pickle_data)
        
        return {
            'name': 'pdf_pickle_stack',
            'type': 'stack',
            'format1': 'pdf',
            'format2': 'pickle',
            'description': 'PDF with pickle data appended after %%EOF',
            'attack_vector': 'PDF viewers show document, pickle loaders execute payload',
            'path': str(output_path)
        }
    
    @staticmethod
    def create_zip_pickle_prepend(zip_path: Path, pickle_path: Path, output_path: Path) -> dict:
        """Prepend pickle before ZIP (ZIP tolerates leading data)."""
        with open(zip_path, 'rb') as f:
            zip_data = f.read()
        with open(pickle_path, 'rb') as f:
            pickle_data = f.read()
        
        with open(output_path, 'wb') as f:
            f.write(pickle_data)
            f.write(zip_data)
        
        return {
            'name': 'pickle_zip_prepend',
            'type': 'stack',
            'format1': 'pickle',
            'format2': 'zip',
            'description': 'Pickle prepended before ZIP (ZIP tolerates leading garbage)',
            'attack_vector': 'ZIP tools open archive, pickle loaders execute payload first',
            'path': str(output_path)
        }
    
    @staticmethod
    def create_magic_mismatch(pickle_path: Path, output_path: Path, fake_magic: bytes, 
                              fake_ext: str) -> dict:
        """Create file with misleading magic bytes."""
        with open(pickle_path, 'rb') as f:
            pickle_data = f.read()
        
        # Prepend fake magic bytes
        with open(output_path, 'wb') as f:
            f.write(fake_magic)
            f.write(b'\x00' * (64 - len(fake_magic)))  # Padding
            f.write(pickle_data)
        
        return {
            'name': f'magic_mismatch_{fake_ext}',
            'type': 'magic_mismatch',
            'format1': fake_ext,
            'format2': 'pickle',
            'description': f'Pickle with {fake_ext.upper()} magic bytes prepended',
            'attack_vector': 'File type detection sees wrong format, pickle executes',
            'path': str(output_path)
        }


def setup_environment():
    """Set up test environment and clone mitra."""
    print("Setting up polyglot test environment...")
    
    # Create directories
    for d in [TEST_DIR, RESULTS_DIR, DONOR_DIR, POLYGLOT_DIR]:
        d.mkdir(parents=True, exist_ok=True)
    
    # Clone mitra if not present
    if not MITRA_DIR.exists():
        print(f"Cloning mitra from {MITRA_REPO}...")
        result = subprocess.run(
            ['git', 'clone', MITRA_REPO, str(MITRA_DIR)],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            print(f"Warning: Failed to clone mitra: {result.stderr}")
            print("Will use manual polyglot generation instead.")
        else:
            print("Mitra cloned successfully.")
    else:
        print("Mitra already present.")
    
    # Generate donor files
    print("\nGenerating donor files...")
    donor_gen = DonorFileGenerator()
    
    donors = [
        (donor_gen.create_benign_pickle, DONOR_DIR / "benign.pkl"),
        (donor_gen.create_malicious_pickle, DONOR_DIR / "malicious.pkl"),
        (donor_gen.create_minimal_png, DONOR_DIR / "minimal.png"),
        (donor_gen.create_minimal_jpeg, DONOR_DIR / "minimal.jpg"),
        (donor_gen.create_minimal_pdf, DONOR_DIR / "minimal.pdf"),
        (donor_gen.create_minimal_zip, DONOR_DIR / "minimal.zip"),
        (donor_gen.create_pytorch_model, DONOR_DIR / "model.pt"),
    ]
    
    donor_metadata = []
    for generator, path in donors:
        meta = generator(path)
        donor_metadata.append(meta)
        print(f"  Created: {path.name}")
    
    # Save metadata
    with open(TEST_DIR / "donors.json", 'w') as f:
        json.dump(donor_metadata, f, indent=2)
    
    print(f"\n✓ Setup complete. {len(donor_metadata)} donor files created.")


def generate_polyglots():
    """Generate polyglot test files."""
    print("Generating polyglot test files...")
    
    if not DONOR_DIR.exists():
        print("Donor files not found. Run --setup first.")
        return
    
    # Try mitra first
    mitra_gen = MitraPolyglotGenerator(MITRA_DIR)
    manual_gen = ManualPolyglotGenerator()
    
    polyglot_metadata = []
    
    # Manual polyglots (guaranteed to work)
    print("\nGenerating manual polyglots...")
    
    malicious_pkl = DONOR_DIR / "malicious.pkl"
    benign_pkl = DONOR_DIR / "benign.pkl"
    
    manual_tests = [
        # Stacks
        (manual_gen.create_png_pickle_stack, 
         DONOR_DIR / "minimal.png", malicious_pkl, 
         POLYGLOT_DIR / "stack_png_pickle.png"),
        
        (manual_gen.create_pdf_pickle_stack,
         DONOR_DIR / "minimal.pdf", malicious_pkl,
         POLYGLOT_DIR / "stack_pdf_pickle.pdf"),
        
        (manual_gen.create_zip_pickle_prepend,
         DONOR_DIR / "minimal.zip", malicious_pkl,
         POLYGLOT_DIR / "prepend_pickle_zip.zip"),
        
        # Parasites
        (manual_gen.create_jpeg_pickle_parasite,
         DONOR_DIR / "minimal.jpg", malicious_pkl,
         POLYGLOT_DIR / "parasite_jpeg_pickle.jpg"),
    ]
    
    for generator, file1, file2, output in manual_tests:
        try:
            meta = generator(file1, file2, output)
            polyglot_metadata.append(meta)
            print(f"  Created: {output.name} ({meta['type']})")
        except Exception as e:
            print(f"  Failed: {output.name} - {e}")
    
    # Magic mismatch tests
    print("\nGenerating magic mismatch tests...")
    
    magic_tests = [
        (b'\x89PNG\r\n\x1a\n', 'png', POLYGLOT_DIR / "mismatch_png_pickle.png"),
        (b'\xff\xd8\xff\xe0', 'jpeg', POLYGLOT_DIR / "mismatch_jpeg_pickle.jpg"),
        (b'%PDF-1.4', 'pdf', POLYGLOT_DIR / "mismatch_pdf_pickle.pdf"),
        (b'PK\x03\x04', 'zip', POLYGLOT_DIR / "mismatch_zip_pickle.zip"),
        (b'7z\xbc\xaf\x27\x1c', '7z', POLYGLOT_DIR / "mismatch_7z_pickle.7z"),
    ]
    
    for magic, ext, output in magic_tests:
        try:
            meta = manual_gen.create_magic_mismatch(malicious_pkl, output, magic, ext)
            polyglot_metadata.append(meta)
            print(f"  Created: {output.name}")
        except Exception as e:
            print(f"  Failed: {output.name} - {e}")
    
    # Mitra polyglots (if available)
    if mitra_gen.is_available():
        print("\nGenerating mitra polyglots...")
        
        mitra_pairs = [
            (DONOR_DIR / "minimal.png", DONOR_DIR / "minimal.pdf"),
            (DONOR_DIR / "minimal.jpg", DONOR_DIR / "minimal.zip"),
        ]
        
        mitra_output = POLYGLOT_DIR / "mitra"
        mitra_output.mkdir(exist_ok=True)
        
        for f1, f2 in mitra_pairs:
            try:
                generated = mitra_gen.generate_polyglot(f1, f2, mitra_output)
                for g in generated:
                    polyglot_metadata.append({
                        'name': g.name,
                        'type': 'mitra_generated',
                        'format1': f1.suffix,
                        'format2': f2.suffix,
                        'description': f'Mitra-generated polyglot from {f1.name} and {f2.name}',
                        'path': str(g)
                    })
                    print(f"  Created: {g.name}")
            except Exception as e:
                print(f"  Mitra failed for {f1.name}+{f2.name}: {e}")
    else:
        print("\nMitra not available. Skipping mitra-generated polyglots.")
    
    # Save metadata
    with open(TEST_DIR / "polyglots.json", 'w') as f:
        json.dump(polyglot_metadata, f, indent=2)
    
    print(f"\n✓ Generated {len(polyglot_metadata)} polyglot test files.")


def run_tests(tensortrap_path: str = "tensortrap"):
    """Run TensorTrap against polyglot test files."""
    print("Running TensorTrap polyglot detection tests...")
    
    metadata_path = TEST_DIR / "polyglots.json"
    if not metadata_path.exists():
        print("Polyglot files not found. Run --generate first.")
        return None
    
    with open(metadata_path) as f:
        polyglots = json.load(f)
    
    results = []
    
    for poly in polyglots:
        path = Path(poly['path'])
        if not path.exists():
            print(f"  Skipping (not found): {path}")
            continue
        
        print(f"  Testing: {path.name}...")
        
        # Run TensorTrap
        try:
            tt_result = subprocess.run(
                [tensortrap_path, 'scan', str(path)],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            tt_output = tt_result.stdout.lower()
            tt_detected = any(level in tt_output for level in ['critical', 'high', 'medium', 'polyglot', 'mismatch'])
            
            tt_data = {
                'detected': tt_detected,
                'output': tt_result.stdout[:500],
                'returncode': tt_result.returncode
            }
        except Exception as e:
            tt_data = {'detected': False, 'error': str(e)}
        
        # Run picklescan for comparison
        try:
            ps_result = subprocess.run(
                ['picklescan', '-p', str(path)],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            ps_detected = 'FOUND' in ps_result.stdout or ps_result.returncode != 0
            
            ps_data = {
                'detected': ps_detected,
                'output': ps_result.stdout[:500],
                'returncode': ps_result.returncode
            }
        except Exception as e:
            ps_data = {'detected': False, 'error': str(e)}
        
        results.append({
            'file': str(path),
            'metadata': poly,
            'tensortrap': tt_data,
            'picklescan': ps_data,
            'timestamp': datetime.now().isoformat()
        })
    
    # Save results
    results_path = RESULTS_DIR / f"polyglot_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(results_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n✓ Results saved to {results_path}")
    
    return results


def generate_report(results: List[dict] = None):
    """Generate detection report from results."""
    if results is None:
        # Load most recent results
        result_files = list(RESULTS_DIR.glob("polyglot_results_*.json"))
        if not result_files:
            print("No results found. Run --test first.")
            return
        
        latest = max(result_files, key=lambda p: p.stat().st_mtime)
        with open(latest) as f:
            results = json.load(f)
    
    print("\n" + "=" * 70)
    print("TENSORTRAP POLYGLOT DETECTION REPORT")
    print("=" * 70)
    
    # Summary statistics
    total = len(results)
    tt_detected = sum(1 for r in results if r['tensortrap'].get('detected'))
    ps_detected = sum(1 for r in results if r['picklescan'].get('detected'))
    
    print(f"\nTotal polyglot samples: {total}")
    print(f"\nDetection rates:")
    print(f"  TensorTrap: {tt_detected}/{total} ({100*tt_detected/total:.1f}%)")
    print(f"  Picklescan: {ps_detected}/{total} ({100*ps_detected/total:.1f}%)")
    
    # Detailed results
    print(f"\n{'-' * 70}")
    print("DETAILED RESULTS")
    print(f"{'-' * 70}")
    
    for r in results:
        meta = r['metadata']
        tt = r['tensortrap']
        ps = r['picklescan']
        
        tt_status = "✓ DETECTED" if tt.get('detected') else "✗ MISSED"
        ps_status = "✓ DETECTED" if ps.get('detected') else "✗ MISSED"
        
        print(f"\n{meta['name']}")
        print(f"  Type: {meta['type']} ({meta.get('format1', '?')} + {meta.get('format2', '?')})")
        print(f"  TensorTrap: {tt_status}")
        print(f"  Picklescan: {ps_status}")
        
        if tt.get('detected') and not ps.get('detected'):
            print(f"  → TensorTrap advantage: Detected polyglot that picklescan missed")
    
    # Summary by type
    print(f"\n{'-' * 70}")
    print("DETECTION BY POLYGLOT TYPE")
    print(f"{'-' * 70}")
    
    types = {}
    for r in results:
        ptype = r['metadata']['type']
        if ptype not in types:
            types[ptype] = {'total': 0, 'tt': 0, 'ps': 0}
        types[ptype]['total'] += 1
        if r['tensortrap'].get('detected'):
            types[ptype]['tt'] += 1
        if r['picklescan'].get('detected'):
            types[ptype]['ps'] += 1
    
    for ptype, counts in types.items():
        print(f"\n{ptype}:")
        print(f"  TensorTrap: {counts['tt']}/{counts['total']}")
        print(f"  Picklescan: {counts['ps']}/{counts['total']}")
    
    print("\n" + "=" * 70)


def main():
    parser = argparse.ArgumentParser(description="TensorTrap Polyglot Test Suite")
    parser.add_argument('--setup', action='store_true', help='Set up environment and clone mitra')
    parser.add_argument('--generate', action='store_true', help='Generate polyglot test files')
    parser.add_argument('--test', action='store_true', help='Run tests against polyglots')
    parser.add_argument('--report', action='store_true', help='Generate detection report')
    parser.add_argument('--tensortrap', default='tensortrap', help='Path to TensorTrap')
    parser.add_argument('--all', action='store_true', help='Run all steps')
    
    args = parser.parse_args()
    
    if args.all:
        args.setup = args.generate = args.test = args.report = True
    
    if args.setup:
        setup_environment()
    
    if args.generate:
        generate_polyglots()
    
    if args.test:
        results = run_tests(args.tensortrap)
        if results and args.report:
            generate_report(results)
    elif args.report:
        generate_report()
    
    if not any([args.setup, args.generate, args.test, args.report]):
        parser.print_help()


if __name__ == "__main__":
    main()
