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