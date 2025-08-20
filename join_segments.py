# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""
Join .segment files into a single .bin image with gaps filled by 0xFF.

Expected filename format:
<MODULE_NAME>_<firmware>_<firmware_no>_<unk>_<unk>_hex_<starting_address_hex>.segment
Example:
MyECU_AB12_0034_X_Y_hex_0x00020230.segment

Usage:
  python join_segments.py path/to/any_one.segment [-o output.bin] [--dry-run] [-v]

Behavior:
- Finds all files in the same directory whose names start with the same base
  (everything before "_hex_") and end with ".segment".
- Extracts the start address from the "_hex_<addr>" part.
- Reads content as either ASCII hex (auto-detected) or raw binary.
- Creates a single output from address 0x0000 to the end of the highest segment,
  filling gaps with 0xFF and writing each segment at its start offset.
"""

from __future__ import annotations
import argparse
import re
from pathlib import Path
from typing import List, Tuple

HEX_BLOCK_RE = re.compile(r'^[\s,0-9A-Fa-fx]+$')
NAME_RE = re.compile(r'^(?P<base>.+)_hex_(?P<addr>0x[0-9A-Fa-f]+)\.segment$')

def parse_name(filename: str) -> Tuple[str, int]:
    """Return (base, start_addr) from a segment filename."""
    m = NAME_RE.match(filename)
    if not m:
        raise ValueError(f"Filename does not match expected pattern: {filename}")
    base = m.group('base')
    addr_str = m.group('addr')
    start = int(addr_str, 16)
    return base, start

def looks_like_ascii_hex(b: bytes) -> bool:
    """Heuristic: True if content appears to be ASCII hex with optional '0x', commas, and whitespace."""
    try:
        s = b.decode('ascii')
    except UnicodeDecodeError:
        return False
    return bool(HEX_BLOCK_RE.fullmatch(s))

def bytes_from_ascii_hex(b: bytes) -> bytes:
    """Convert flexible ASCII hex into raw bytes. Accepts whitespace, commas, and '0x' prefixes."""
    s = b.decode('ascii')
    # Remove 0x/0X prefixes
    s = re.sub(r'0x', '', s, flags=re.IGNORECASE)
    # Keep only hex digits and whitespace/commas
    s = re.sub(r'[^0-9A-Fa-f]', '', s)
    if len(s) == 0:
        return b''
    if len(s) % 2 == 1:
        # If odd number of nibbles, pad a leading zero
        s = '0' + s
    return bytes.fromhex(s)

def load_segment_bytes(path: Path) -> bytes:
    data = path.read_bytes()
    if looks_like_ascii_hex(data):
        return bytes_from_ascii_hex(data)
    return data  # treat as raw binary

def collect_segments(anchor: Path) -> Tuple[str, List[Tuple[Path, int, int]]]:
    """
    From one anchor .segment file, find all peer segments with the same base.
    Returns (base, [(path, start_addr, length), ...]) sorted by start address.
    """
    base, _ = parse_name(anchor.name)
    directory = anchor.parent
    candidates = list(directory.glob(f"{base}_hex_*.segment"))
    segments: List[Tuple[Path, int, int]] = []

    for p in candidates:
        try:
            _, start = parse_name(p.name)
            size = p.stat().st_size
            segments.append((p, start, size))
        except Exception:
            # Skip anything that doesn't match exactly
            continue

    if not segments:
        raise RuntimeError(f"No matching segments found for base '{base}' in {directory}")

    # Sort by start addr
    segments.sort(key=lambda t: t[1])
    return base, segments

def stitch(segments_meta: List[Tuple[Path, int, int]], verbose: bool=False) -> Tuple[bytearray, int]:
    """
    Read and place all segments into a single bytearray padded with 0xFF.
    Returns (image, highest_end).
    """
    # Load data to know exact lengths in bytes (ASCII hex files shrink)
    loaded = []
    highest_end = 0
    for p, start, _declared_size in segments_meta:
        seg_bytes = load_segment_bytes(p)
        end = start + len(seg_bytes)
        highest_end = max(highest_end, end)
        loaded.append((p, start, seg_bytes))
        if verbose:
            print(f"[+] Will place {p.name}: start=0x{start:08X}, len=0x{len(seg_bytes):X} ({len(seg_bytes)} bytes), end=0x{end:08X}")

    image = bytearray([0xFF]) * highest_end

    # Write with overlap checking
    for p, start, seg in loaded:
        for i, b in enumerate(seg):
            off = start + i
            prev = image[off]
            if prev != 0xFF and prev != b:
                print(f"[!] Overlap mismatch at 0x{off:08X}: existing=0x{prev:02X}, new=0x{b:02X} from {p.name}")
            image[off] = b

    return image, highest_end

def default_output_name(base: str) -> str:
    # Convert base to a safe filename and append .bin
    return f"{base}.bin"

def main():
    ap = argparse.ArgumentParser(description="Join .segment files into a single .bin (gaps -> 0xFF).")
    ap.add_argument("anchor", type=Path, help="Path to any one .segment file in the set.")
    ap.add_argument("-o", "--out", type=Path, help="Output .bin path (default: <base>.bin in same directory).")
    ap.add_argument("--dry-run", action="store_true", help="Discover and report plan without writing output.")
    ap.add_argument("-v", "--verbose", action="store_true", help="Verbose logging.")
    args = ap.parse_args()

    if not args.anchor.exists():
        raise SystemExit(f"Anchor file not found: {args.anchor}")

    try:
        base, segments_meta = collect_segments(args.anchor)
    except Exception as e:
        raise SystemExit(str(e))

    # Show a neat summary
    print(f"Base: '{base}'")
    print(f"Directory: {args.anchor.parent}")
    print(f"Found {len(segments_meta)} segment file(s):")
    for p, start, _decl in segments_meta:
        print(f"  - {p.name} @ 0x{start:08X}")

    # Stitch (compute size even in dry-run to report)
    image, highest_end = stitch(segments_meta, verbose=args.verbose)

    print(f"\nOutput range: 0x00000000 .. 0x{highest_end:08X} (size {highest_end} bytes)")
    if args.dry_run:
        print("[DRY-RUN] Skipping write.")
        return

    out_path = args.out
    if out_path is None:
        out_path = args.anchor.parent / default_output_name(base)

    out_path.write_bytes(image)
    print(f"[OK] Wrote {len(image)} bytes to: {out_path}")

if __name__ == "__main__":
    main()
