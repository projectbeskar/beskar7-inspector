//! Disk collector: the report's `disks[]`, one entry **per fixed block device**.
//!
//! Source: **`/sys/block`** — the kernel's view of whole block devices (the
//! firmware SMBIOS tables don't enumerate storage). Each `/sys/block/<dev>`
//! directory is one device; its `device/` link, `size`, `removable`,
//! `device/model`, `device/serial` and `queue/rotational` attributes give every
//! field the contract needs without shelling out to `lsblk`/`smartctl`.
//!
//! Only **fixed, real** disks are reported: virtual devices (loop, ram, dm-*,
//! md*, which have no backing `device` link) and removable media (optical, USB —
//! `removable` == `1`) are filtered out, so `disks[].sizeGB` sums to the host's
//! real fixed storage (contract §6.1). `sizeGB` is decimal GB (the `size`
//! attribute is in 512-byte sectors), matching the controller's `MinDiskGB`
//! summation and the golden fixture (a 960 GB NVMe reports `960`).

use std::ffi::OsStr;
use std::fs;
use std::path::Path;

use super::read_trimmed;
use crate::report::Disk;

/// Kernel block-device directory: one subdirectory per whole device.
const SYSFS_BLOCK: &str = "/sys/block";

/// `size` attribute unit: Linux reports block-device size in 512-byte sectors
/// regardless of the device's physical sector size.
const BYTES_PER_SECTOR: u64 = 512;
/// Decimal GB (the contract's `sizeGB` is decimal, not GiB — a "960GB" NVMe
/// reports 960, not 894).
const BYTES_PER_GB: u64 = 1_000_000_000;

const REMOVABLE_TRUE: &str = "1";
const ROTATIONAL_SSD: &str = "0";

const TYPE_NVME: &str = "NVMe";
const TYPE_SSD: &str = "SSD";
const TYPE_HDD: &str = "HDD";

/// Collect one [`Disk`] per fixed block device from the live `/sys/block`.
pub fn collect() -> Vec<Disk> {
    collect_from(Path::new(SYSFS_BLOCK))
}

/// Enumerate `block_dir` (a `/sys/block`-shaped directory), in stable name order
/// so the report is deterministic. Unreadable directories yield no disks rather
/// than an error — a host with no enumerable block devices is degenerate, not
/// fatal, for inspection.
fn collect_from(block_dir: &Path) -> Vec<Disk> {
    let Ok(entries) = fs::read_dir(block_dir) else {
        return Vec::new();
    };
    let mut names: Vec<_> = entries.flatten().map(|e| e.file_name()).collect();
    names.sort();
    names
        .iter()
        .filter_map(|name| decode(block_dir, name))
        .collect()
}

/// Decode one `/sys/block/<name>` entry, or `None` when it is not a fixed disk
/// (virtual device, removable media, or no readable size).
fn decode(block_dir: &Path, name: &OsStr) -> Option<Disk> {
    let name = name.to_str()?;
    let dev = block_dir.join(name);

    // Virtual devices (loop, ram, dm-*, md*, zram*) have no backing `device`
    // link; real disks (SATA/SAS via SCSI, NVMe namespaces) always do.
    if !dev.join("device").exists() {
        return None;
    }
    // Removable media (optical drives, USB sticks) is not fixed host storage.
    if read_trimmed(&dev.join("removable")).as_deref() == Some(REMOVABLE_TRUE) {
        return None;
    }

    let sectors: u64 = read_trimmed(&dev.join("size"))?.parse().ok()?;
    if sectors == 0 {
        return None; // a slot with no media (e.g. an empty card reader)
    }

    Some(Disk {
        name: format!("/dev/{name}"),
        model: read_trimmed(&dev.join("device/model")).unwrap_or_default(),
        size_gb: sectors * BYTES_PER_SECTOR / BYTES_PER_GB,
        disk_type: disk_type(name, read_trimmed(&dev.join("queue/rotational")).as_deref())
            .to_string(),
        serial_number: serial(&dev),
    })
}

/// Classify the device: NVMe by name (its namespaces are `nvmeXnY`), otherwise
/// SSD/HDD from the kernel's `rotational` flag (`0` ⇒ solid-state). An absent
/// flag is treated as rotational (HDD) — the conservative default.
fn disk_type(name: &str, rotational: Option<&str>) -> &'static str {
    if name.starts_with("nvme") {
        TYPE_NVME
    } else if rotational == Some(ROTATIONAL_SSD) {
        TYPE_SSD
    } else {
        TYPE_HDD
    }
}

/// Serial number, best-effort: the SCSI/NVMe `device/serial` attribute, falling
/// back to the SCSI `device/wwid` (a stable world-wide identifier) and finally
/// "" when neither is exposed. The report field is `omitempty` on the controller
/// side, so an empty serial is harmless.
fn serial(dev: &Path) -> String {
    read_trimmed(&dev.join("device/serial"))
        .or_else(|| read_trimmed(&dev.join("device/wwid")))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::testutil::{write, Scratch};

    /// A fixed NVMe namespace mirroring the golden fixture's disks: `device/`
    /// present, not removable, size in 512-byte sectors, model + serial set.
    fn write_nvme(root: &Path, name: &str, sectors: u64, model: &str, serial: &str) {
        write(root, &format!("{name}/size"), &format!("{sectors}\n"));
        write(root, &format!("{name}/removable"), "0\n");
        write(root, &format!("{name}/device/model"), &format!("{model}\n"));
        write(
            root,
            &format!("{name}/device/serial"),
            &format!("{serial}\n"),
        );
    }

    #[test]
    fn reproduces_the_golden_nvme_disks() {
        // 960 GB = 1_875_000_000 sectors * 512 B / 1e9 = 960 (decimal GB).
        let s = Scratch::new("golden");
        let model = "Dell Ent NVMe AGN MU U.2 960GB";
        write_nvme(s.path(), "nvme0n1", 1_875_000_000, model, "S64XNE0R301234");
        write_nvme(s.path(), "nvme1n1", 1_875_000_000, model, "S64XNE0R305678");
        let disks = collect_from(s.path());
        assert_eq!(
            disks,
            vec![
                Disk {
                    name: "/dev/nvme0n1".into(),
                    model: model.into(),
                    size_gb: 960,
                    disk_type: "NVMe".into(),
                    serial_number: "S64XNE0R301234".into(),
                },
                Disk {
                    name: "/dev/nvme1n1".into(),
                    model: model.into(),
                    size_gb: 960,
                    disk_type: "NVMe".into(),
                    serial_number: "S64XNE0R305678".into(),
                },
            ]
        );
    }

    #[test]
    fn virtual_and_removable_devices_are_filtered() {
        let s = Scratch::new("filter");
        write_nvme(s.path(), "nvme0n1", 1_875_000_000, "Real NVMe", "SER1");
        // loop device: a `size` but no `device/` link -> virtual, skipped.
        write(s.path(), "loop0/size", "204800\n");
        // optical drive: has a `device/` link but is removable -> skipped.
        write(s.path(), "sr0/size", "2097152\n");
        write(s.path(), "sr0/removable", "1\n");
        write(s.path(), "sr0/device/model", "DVD-ROM\n");
        // empty card reader: `device/` link present but zero size -> skipped.
        write(s.path(), "mmcblk0/size", "0\n");
        write(s.path(), "mmcblk0/removable", "0\n");
        write(s.path(), "mmcblk0/device/model", "Reader\n");

        let disks = collect_from(s.path());
        assert_eq!(disks.len(), 1);
        assert_eq!(disks[0].name, "/dev/nvme0n1");
    }

    #[test]
    fn ssd_and_hdd_are_classified_from_rotational() {
        let s = Scratch::new("rota");
        // SATA SSD: rotational 0.
        write(s.path(), "sda/size", "1953525168\n"); // ~1 TB
        write(s.path(), "sda/removable", "0\n");
        write(s.path(), "sda/device/model", "Samsung SSD 870\n");
        write(s.path(), "sda/device/serial", "S5SSNF0\n");
        write(s.path(), "sda/queue/rotational", "0\n");
        // Spinning HDD: rotational 1.
        write(s.path(), "sdb/size", "3907029168\n"); // ~2 TB
        write(s.path(), "sdb/removable", "0\n");
        write(s.path(), "sdb/device/model", "WDC WD20\n");
        write(s.path(), "sdb/queue/rotational", "1\n");

        let disks = collect_from(s.path());
        assert_eq!(disks.len(), 2);
        assert_eq!(disks[0].name, "/dev/sda");
        assert_eq!(disks[0].disk_type, "SSD");
        assert_eq!(disks[0].size_gb, 1000); // 1953525168*512/1e9 = 1000
        assert_eq!(disks[1].name, "/dev/sdb");
        assert_eq!(disks[1].disk_type, "HDD");
        assert_eq!(disks[1].size_gb, 2000);
    }

    #[test]
    fn missing_rotational_defaults_to_hdd() {
        let s = Scratch::new("norota");
        write(s.path(), "sda/size", "1000000000\n");
        write(s.path(), "sda/removable", "0\n");
        write(s.path(), "sda/device/model", "Mystery\n");
        let disks = collect_from(s.path());
        assert_eq!(disks[0].disk_type, "HDD");
    }

    #[test]
    fn serial_falls_back_to_wwid_then_empty() {
        let s = Scratch::new("serial");
        // No `device/serial`, but a `device/wwid`.
        write(s.path(), "sda/size", "1000000000\n");
        write(s.path(), "sda/removable", "0\n");
        write(s.path(), "sda/device/model", "Disk A\n");
        write(s.path(), "sda/device/wwid", "naa.5000c500abcdef01\n");
        write(s.path(), "sda/queue/rotational", "0\n");
        // Neither serial nor wwid: serial is "".
        write(s.path(), "sdb/size", "1000000000\n");
        write(s.path(), "sdb/removable", "0\n");
        write(s.path(), "sdb/device/model", "Disk B\n");
        write(s.path(), "sdb/queue/rotational", "1\n");

        let disks = collect_from(s.path());
        assert_eq!(disks[0].serial_number, "naa.5000c500abcdef01");
        assert_eq!(disks[1].serial_number, "");
    }

    #[test]
    fn missing_block_dir_yields_no_disks() {
        let disks = collect_from(Path::new("/nonexistent/sys/block"));
        assert!(disks.is_empty());
    }
}
