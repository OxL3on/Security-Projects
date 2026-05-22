#!/usr/bin/env python3

import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


def create_test_image_no_root(image_path="test_disk.img", size_mb=10):
    """Create a FAT32 image and populate it using mtools (no sudo)."""
    print(f"[*] Creating {size_mb}MB FAT32 image: {image_path}")
    # Create empty image
    subprocess.run(
        f"dd if=/dev/zero of={image_path} bs=1M count={size_mb}",
        shell=True,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    # Format as FAT32
    subprocess.run(
        f"mkfs.fat -F32 {image_path}",
        shell=True,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Use mtools to copy files into the image (no mount required)
    # Create a temp directory with test files
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        # Create test files
        files = {
            "confidential.txt": b"Top secret: launch codes 12345",
            "report.docx": b"Q1 Sales: +15% growth",
            "password.kdbx": b"encrypted password database content",
            "notes.md": b"# Meeting notes\nBudget approved.",
        }
        for fname, content in files.items():
            (tmpdir / fname).write_bytes(content)
            print(f"    Created: {fname} ({len(content)} bytes)")

        # Copy all files into the FAT32 image using mcopy
        subprocess.run(
            f"mcopy -i {image_path} {tmpdir}/* ::/",
            shell=True,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Now delete two files "accidentally" using mdel
        subprocess.run(
            f"mdel -i {image_path} ::/confidential.txt",
            shell=True,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            f"mdel -i {image_path} ::/password.kdbx",
            shell=True,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print("    Deleted: confidential.txt, password.kdbx")

    print("[*] Test image ready. Deleted files are recoverable.\n")
    return image_path


# ----------------------------------------------------------------------
# 2. FAT32 Recovery Engine – With proper FAT table parsing
# ----------------------------------------------------------------------
class FAT32Recover:
    def __init__(self, image_path):
        self.img = open(image_path, "rb")
        self.sector_size = 512
        self.read_boot_sector()
        self.load_fat_table()

    def read_boot_sector(self):
        self.img.seek(0)
        data = self.img.read(512)
        if data[510] != 0x55 or data[511] != 0xAA:
            raise ValueError("Not a valid FAT32 boot sector")

        self.sector_size = struct.unpack("<H", data[11:13])[0]
        self.sectors_per_cluster = data[13]
        self.reserved_sectors = struct.unpack("<H", data[14:16])[0]
        self.fat_size_sectors = struct.unpack("<I", data[36:40])[0]  # sectors per FAT
        self.root_cluster = struct.unpack("<I", data[44:48])[0]

        # Data area start sector
        self.data_start = self.reserved_sectors + (self.fat_size_sectors * 2)
        self.bytes_per_cluster = self.sector_size * self.sectors_per_cluster
        self.cluster_count = (
            os.path.getsize(self.img.name) - self.data_start * self.sector_size
        ) // self.bytes_per_cluster

        print(f"[FS] Bytes per cluster: {self.bytes_per_cluster}")
        print(f"[FS] Root cluster: {self.root_cluster}")
        print(f"[FS] Total clusters: {self.cluster_count}")

    def load_fat_table(self):
        """Load the first FAT into memory as a list of 32-bit entries."""
        fat_start = self.reserved_sectors * self.sector_size
        self.img.seek(fat_start)
        fat_size_bytes = self.fat_size_sectors * self.sector_size
        fat_data = self.img.read(fat_size_bytes)
        # Each FAT entry is 4 bytes (little-endian)
        self.fat = []
        for i in range(0, len(fat_data), 4):
            entry = struct.unpack("<I", fat_data[i : i + 4])[0]
            self.fat.append(entry & 0x0FFFFFFF)  # mask to 28 bits

    def next_cluster(self, cluster):
        """Return the next cluster in the chain, or None if end."""
        if cluster >= len(self.fat):
            return None
        next_cl = self.fat[cluster]
        if next_cl >= 0x0FFFFFF8:  # end-of-chain marker
            return None
        return next_cl

    def cluster_to_sector(self, cluster):
        return self.data_start + (cluster - 2) * self.sectors_per_cluster

    def read_cluster(self, cluster):
        sector = self.cluster_to_sector(cluster)
        self.img.seek(sector * self.sector_size)
        return self.img.read(self.bytes_per_cluster)

    def parse_directory_entry(self, data, offset):
        """Parse 32-byte directory entry."""
        if offset + 32 > len(data):
            return None
        entry = data[offset : offset + 32]
        first_byte = entry[0]
        if first_byte == 0x00:
            return None  # end of directory
        if first_byte == 0xE5:
            is_deleted = True
            # Reconstruct name (first char overwritten with 0xE5)
            raw_name = bytearray(entry[0:8])
            if raw_name[0] == 0xE5:
                raw_name[0] = ord("?")
            name = raw_name.decode("ascii", errors="ignore").strip()
            ext = entry[8:11].decode("ascii", errors="ignore").strip()
        else:
            is_deleted = False
            name = entry[0:8].decode("ascii", errors="ignore").strip()
            ext = entry[8:11].decode("ascii", errors="ignore").strip()

        full_name = f"{name}.{ext}".strip(".")
        attr = entry[11]
        is_dir = (attr & 0x10) != 0
        size = struct.unpack("<I", entry[28:32])[0]
        cluster_low = struct.unpack("<H", entry[26:28])[0]
        cluster_high = struct.unpack("<H", entry[20:22])[0]
        start_cluster = (cluster_high << 16) | cluster_low

        return {
            "name": full_name,
            "deleted": is_deleted,
            "is_dir": is_dir,
            "size": size,
            "start_cluster": start_cluster,
        }

    def scan_deleted_files(self):
        """Walk the root directory and return all deleted file entries."""
        deleted = []
        clusters_to_scan = [self.root_cluster]
        while clusters_to_scan:
            cluster = clusters_to_scan.pop(0)
            data = self.read_cluster(cluster)
            offset = 0
            while offset < len(data):
                entry = self.parse_directory_entry(data, offset)
                if entry is None:
                    break
                if entry["deleted"] and not entry["is_dir"] and entry["size"] > 0:
                    deleted.append(entry)
                    print(
                        f"[FOUND] Deleted file: {entry['name']} ({entry['size']} bytes, start cluster {entry['start_cluster']})"
                    )
                elif (
                    not entry["deleted"]
                    and entry["is_dir"]
                    and entry["name"] not in [".", ".."]
                ):
                    clusters_to_scan.append(entry["start_cluster"])
                offset += 32
        return deleted

    def recover_file(self, entry, output_dir="recovered"):
        """Recover a file by following the FAT cluster chain."""
        if entry["start_cluster"] == 0:
            print(f"    SKIP: {entry['name']} has invalid start cluster")
            return False

        out_path = Path(output_dir) / entry["name"]
        out_path.parent.mkdir(parents=True, exist_ok=True)

        remaining = entry["size"]
        cluster = entry["start_cluster"]
        data = bytearray()

        # Follow the FAT chain
        while remaining > 0 and cluster is not None and cluster < 0x0FFFFFF8:
            cluster_data = self.read_cluster(cluster)
            chunk = cluster_data[: min(remaining, len(cluster_data))]
            data.extend(chunk)
            remaining -= len(chunk)
            cluster = self.next_cluster(cluster)

        if len(data) > 0:
            out_path.write_bytes(data)
            print(f"    RECOVERED: {out_path} ({len(data)}/{entry['size']} bytes)")
            return True
        else:
            print(f"    FAILED: {entry['name']} - no data recovered")
            return False

    def close(self):
        self.img.close()


# ----------------------------------------------------------------------
# 3. Main – no root needed for recovery, only for image creation (optional)
# ----------------------------------------------------------------------
def main():
    print("=" * 60)
    print("FAT32 DATA RECOVERY – CORRECTED VERSION")
    print("= FAT chain traversal | No mount required")
    print("=" * 60)

    image_path = "test_disk.img"
    if not os.path.exists(image_path):
        # Check if mtools is installed
        if (
            subprocess.run("which mcopy", shell=True, capture_output=True).returncode
            != 0
        ):
            print("[!] mtools not installed. Install with: sudo pacman -S mtools")
            sys.exit(1)
        create_test_image_no_root(image_path, size_mb=10)
    else:
        print(f"[*] Using existing image: {image_path}")

    print("\n[*] Starting FAT32 recovery scan...")
    recover = FAT32Recover(image_path)
    deleted_files = recover.scan_deleted_files()

    if not deleted_files:
        print("[!] No deleted files found.")
        recover.close()
        return

    print(f"\n[*] Found {len(deleted_files)} deleted file(s). Attempting recovery...")
    output_dir = "recovered_data"
    recovered_count = 0
    for entry in deleted_files:
        if recover.recover_file(entry, output_dir):
            recovered_count += 1

    recover.close()
    print(
        f"\n[+] Recovery complete: {recovered_count}/{len(deleted_files)} files saved to '{output_dir}/'"
    )
    print("[*] Verify: ls -la recovered_data/")


if __name__ == "__main__":
    main()
