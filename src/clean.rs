//! Clean mode (contract v4.4 §9.3): wipe the metadata of every eligible disk of a
//! released host before the controller makes it `Available` again.
//!
//! For each whole disk [`crate::target_disk::wipe_candidates`] returns, the first
//! and last [`WIPE_EDGE_BYTES`] of the disk and of every partition on it are
//! zeroed through one exclusive, identity-verified fd on the whole-disk node. That
//! removes the partition table and its GPT backup, `COS_OEM` with the previous
//! join secret, and the filesystem, RAID and LVM signatures kept at either end of
//! a partition. It is **not** a secure erase: the data blocks in between stay.
//!
//! The initramfs ships no `wipefs`, so the wipe is native. Every decision is a pure
//! function ([`wipe_ranges`], [`zero_ranges`], [`partitions`], [`settle`]) tested
//! on temp files; only [`wipe_all_disks`] touches real devices, and it refuses to
//! run unless the process is PID 1, the initramfs `/init`.

use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;

use crate::deploy;
use crate::probe::read_trimmed;
use crate::target_disk::{self, TargetDisk};

/// How much of each end of a disk and of each partition is zeroed.
pub const WIPE_EDGE_BYTES: u64 = 8 * 1024 * 1024;

/// Kernel whole-block-device directory.
const SYSFS_BLOCK: &str = "/sys/block";
/// Linux reports partition `start` and `size` in 512-byte sectors.
const BYTES_PER_SECTOR: u64 = 512;
/// Size of the zero buffer written per call.
const ZERO_CHUNK: usize = 1024 * 1024;
/// The only process allowed to wipe: the initramfs `/init`.
const INIT_PID: u32 = 1;
/// Consecutive identical disk listings that count as settled.
const SETTLE_STABLE_READS: u32 = 3;
/// Upper bound on disk listings before wiping whatever is there.
const SETTLE_MAX_READS: u32 = 15;
/// Pause between disk listings while drivers finish probing.
const SETTLE_INTERVAL: Duration = Duration::from_secs(1);

/// A byte range on a disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extent {
    /// Offset in bytes from the start of the disk.
    pub start: u64,
    /// Length in bytes.
    pub len: u64,
}

impl Extent {
    fn end(&self) -> u64 {
        self.start.saturating_add(self.len)
    }
}

/// Why a disk could not be wiped. Carries only device names and errnos (§9).
#[derive(Debug, thiserror::Error)]
pub enum CleanError {
    /// The wipe was asked for outside the initramfs.
    #[error("refusing to wipe disks: not running as PID 1")]
    NotInit,
    /// No eligible disk was found, so nothing can be reported as wiped.
    #[error("no eligible disk found to wipe")]
    NoDisks,
    /// One or more disks failed; the others were wiped.
    #[error("wiping failed on {}", .0.join("; "))]
    Disks(Vec<String>),
}

/// Wipe every eligible disk and return their kernel names. Refuses unless the
/// process is PID 1, so running the binary on a workstation cannot wipe it.
pub fn wipe_all_disks() -> Result<Vec<String>, CleanError> {
    require_init(std::process::id())?;
    let disks = settled_candidates();
    if disks.is_empty() {
        return Err(CleanError::NoDisks);
    }
    let block = Path::new(SYSFS_BLOCK);
    let failures: Vec<String> = disks
        .iter()
        .filter_map(|disk| {
            wipe_disk(block, disk)
                .err()
                .map(|e| format!("/dev/{}: {e}", disk.kname))
        })
        .collect();
    if !failures.is_empty() {
        return Err(CleanError::Disks(failures));
    }
    Ok(disks.into_iter().map(|d| d.kname).collect())
}

/// Only the initramfs `/init` may wipe.
fn require_init(pid: u32) -> Result<(), CleanError> {
    if pid == INIT_PID {
        Ok(())
    } else {
        Err(CleanError::NotInit)
    }
}

/// The disks a wipe would touch and the ranges on each, read-only (for `--dry-run`).
pub fn plan() -> Vec<(TargetDisk, Vec<Extent>)> {
    let block = Path::new(SYSFS_BLOCK);
    target_disk::wipe_candidates()
        .into_iter()
        .map(|disk| {
            let ranges = wipe_ranges(disk.size_bytes, &partitions(block, &disk.kname));
            (disk, ranges)
        })
        .collect()
}

/// The wipe candidates once their listing has stopped changing, so a disk whose
/// driver is still probing is not skipped.
fn settled_candidates() -> Vec<TargetDisk> {
    let names = settle(
        || {
            target_disk::wipe_candidates()
                .into_iter()
                .map(|d| d.kname)
                .collect()
        },
        std::thread::sleep,
    );
    target_disk::wipe_candidates()
        .into_iter()
        .filter(|d| names.contains(&d.kname))
        .collect()
}

/// Read `list` until it returns the same names [`SETTLE_STABLE_READS`] times in a
/// row, or [`SETTLE_MAX_READS`] times in all, and return the last listing.
fn settle(mut list: impl FnMut() -> Vec<String>, mut sleep: impl FnMut(Duration)) -> Vec<String> {
    let mut last = list();
    let mut stable = 1;
    for _ in 1..SETTLE_MAX_READS {
        if stable >= SETTLE_STABLE_READS {
            break;
        }
        sleep(SETTLE_INTERVAL);
        let next = list();
        stable = if next == last { stable + 1 } else { 1 };
        last = next;
    }
    last
}

/// Zero the wipe ranges of `disk` through one exclusive, identity-verified fd,
/// then ask the kernel to drop the partitions it no longer has.
fn wipe_disk(block_dir: &Path, disk: &TargetDisk) -> Result<(), String> {
    let ranges = wipe_ranges(disk.size_bytes, &partitions(block_dir, &disk.kname));
    let path = disk.dev_path();
    // O_EXCL fails with EBUSY on a disk that is mounted or otherwise held.
    let mut file = OpenOptions::new()
        .write(true)
        .custom_flags(nix::libc::O_EXCL)
        .open(&path)
        .map_err(|e| format!("open: {e}"))?;
    deploy::verify_node_identity(&file, &path, &disk.dev_number).map_err(|e| e.to_string())?;
    zero_ranges(&mut file, &ranges).map_err(|e| format!("zeroing: {e}"))?;
    file.sync_all().map_err(|e| format!("flushing: {e}"))?;
    drop(file);
    // The wipe already happened; a busy re-read only leaves stale partition nodes.
    if let Err(e) = deploy::reread_partition_table(disk) {
        eprintln!("beskar7-inspector: warning: {e}");
    }
    Ok(())
}

/// The partitions of whole disk `kname` under a `/sys/block`-shaped `block_dir`,
/// as byte extents. Unreadable entries are skipped.
pub(crate) fn partitions(block_dir: &Path, kname: &str) -> Vec<Extent> {
    let Ok(entries) = std::fs::read_dir(block_dir.join(kname)) else {
        return Vec::new();
    };
    let mut parts: Vec<Extent> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|dir| dir.join("partition").exists())
        .filter_map(|dir| {
            let sectors = |attr: &str| read_trimmed(&dir.join(attr))?.parse::<u64>().ok();
            Some(Extent {
                start: sectors("start")?.checked_mul(BYTES_PER_SECTOR)?,
                len: sectors("size")?.checked_mul(BYTES_PER_SECTOR)?,
            })
        })
        .collect();
    parts.sort_by_key(|p| p.start);
    parts
}

/// The head and tail [`WIPE_EDGE_BYTES`] of the disk and of each partition,
/// clipped to the disk, sorted and merged.
pub(crate) fn wipe_ranges(disk_size: u64, parts: &[Extent]) -> Vec<Extent> {
    let whole = Extent {
        start: 0,
        len: disk_size,
    };
    let mut ranges: Vec<Extent> = std::iter::once(whole)
        .chain(parts.iter().copied())
        .flat_map(edges)
        .filter_map(|r| clip(r, disk_size))
        .collect();
    ranges.sort_by_key(|r| r.start);
    merge(ranges)
}

/// The head and tail edges of `region`; one range when the region is shorter than both.
fn edges(region: Extent) -> Vec<Extent> {
    let edge = region.len.min(WIPE_EDGE_BYTES);
    if edge == 0 {
        return Vec::new();
    }
    let head = Extent {
        start: region.start,
        len: edge,
    };
    let tail = Extent {
        start: region.end() - edge,
        len: edge,
    };
    vec![head, tail]
}

/// `range` cut to end at `disk_size`, or `None` when nothing of it is on the disk.
fn clip(range: Extent, disk_size: u64) -> Option<Extent> {
    if range.start >= disk_size {
        return None;
    }
    Some(Extent {
        start: range.start,
        len: range.end().min(disk_size) - range.start,
    })
}

/// Merge sorted ranges that overlap or touch.
fn merge(sorted: Vec<Extent>) -> Vec<Extent> {
    let mut out: Vec<Extent> = Vec::with_capacity(sorted.len());
    for r in sorted {
        match out.last_mut() {
            Some(last) if r.start <= last.end() => {
                last.len = last.end().max(r.end()) - last.start;
            }
            _ => out.push(r),
        }
    }
    out
}

/// Write zeros over every range of `dev`.
pub(crate) fn zero_ranges<D: Write + Seek>(dev: &mut D, ranges: &[Extent]) -> std::io::Result<()> {
    let zeros = vec![0u8; ZERO_CHUNK];
    for range in ranges {
        dev.seek(SeekFrom::Start(range.start))?;
        let mut left = range.len;
        while left > 0 {
            let n = left.min(ZERO_CHUNK as u64) as usize;
            dev.write_all(&zeros[..n])?;
            left -= n as u64;
        }
    }
    dev.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::testutil::{write, Scratch};
    use std::io::Read;

    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;

    fn ext(start: u64, len: u64) -> Extent {
        Extent { start, len }
    }

    #[test]
    fn wipe_ranges_cover_both_ends_of_the_disk() {
        let ranges = wipe_ranges(GIB, &[]);
        assert_eq!(ranges, [ext(0, 8 * MIB), ext(GIB - 8 * MIB, 8 * MIB)]);
    }

    #[test]
    fn wipe_ranges_cover_both_ends_of_every_partition() {
        // GPT disk: ESP at 1 MiB (512 MiB), data from 513 MiB to the backup GPT.
        let esp = ext(MIB, 512 * MIB);
        let data = ext(513 * MIB, GIB - 513 * MIB - MIB);
        let ranges = wipe_ranges(GIB, &[esp, data]);
        assert_eq!(
            ranges,
            [
                ext(0, 9 * MIB),             // disk head + ESP head, merged
                ext(505 * MIB, 16 * MIB),    // ESP tail + data head, merged
                ext(GIB - 9 * MIB, 9 * MIB), // data tail + disk tail, merged
            ]
        );
    }

    #[test]
    fn a_small_disk_is_zeroed_whole_once() {
        assert_eq!(wipe_ranges(4 * MIB, &[]), [ext(0, 4 * MIB)]);
    }

    #[test]
    fn a_partition_past_the_disk_end_is_clipped() {
        let ranges = wipe_ranges(64 * MIB, &[ext(60 * MIB, 40 * MIB)]);
        assert!(ranges.iter().all(|r| r.end() <= 64 * MIB), "{ranges:?}");
    }

    #[test]
    fn an_empty_disk_has_nothing_to_wipe() {
        assert!(wipe_ranges(0, &[]).is_empty());
    }

    #[test]
    fn zero_ranges_zeroes_exactly_the_ranges() {
        let s = Scratch::new("clean-zero");
        let path = s.path().join("disk.img");
        let size = 32 * MIB as usize;
        std::fs::write(&path, vec![0xAAu8; size]).unwrap();

        let ranges = wipe_ranges(size as u64, &[ext(MIB, 20 * MIB)]);
        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        zero_ranges(&mut file, &ranges).unwrap();
        drop(file);

        let mut bytes = Vec::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes.len(), size, "the image must not grow");
        for (i, b) in bytes.iter().enumerate() {
            let wiped = ranges
                .iter()
                .any(|r| (i as u64) >= r.start && (i as u64) < r.end());
            assert_eq!(*b == 0, wiped, "byte {i}");
        }
    }

    #[test]
    fn partitions_are_read_from_sysfs_in_bytes() {
        let s = Scratch::new("clean-parts");
        let root = s.path();
        write(root, "sda/size", "2097152\n");
        write(root, "sda/sda2/partition", "2\n");
        write(root, "sda/sda2/start", "1050624\n");
        write(root, "sda/sda2/size", "1044480\n");
        write(root, "sda/sda1/partition", "1\n");
        write(root, "sda/sda1/start", "2048\n");
        write(root, "sda/sda1/size", "1048576\n");
        write(root, "sda/queue/rotational", "0\n"); // not a partition

        assert_eq!(
            partitions(root, "sda"),
            [
                ext(2048 * 512, 1048576 * 512),
                ext(1050624 * 512, 1044480 * 512)
            ]
        );
    }

    #[test]
    fn settle_waits_for_a_late_disk() {
        let listings = [
            vec!["sda"],
            vec!["sda", "sdb"],
            vec!["sda", "sdb"],
            vec!["sda", "sdb"],
        ];
        let mut n = 0;
        let mut sleeps = 0;
        let names = settle(
            || {
                let l = listings[n.min(listings.len() - 1)]
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
                n += 1;
                l
            },
            |_| sleeps += 1,
        );
        assert_eq!(names, ["sda", "sdb"]);
        assert_eq!(sleeps, 3);
    }

    #[test]
    fn settle_gives_up_after_the_read_budget() {
        let mut n = 0u32;
        let names = settle(
            || {
                n += 1;
                vec![format!("sd{n}")]
            },
            |_| {},
        );
        assert_eq!(n, SETTLE_MAX_READS);
        assert_eq!(names, [format!("sd{SETTLE_MAX_READS}")]);
    }

    #[test]
    fn only_pid_1_may_wipe() {
        // Pure check: no test calls wipe_all_disks, which would reach real devices.
        assert!(require_init(INIT_PID).is_ok());
        assert!(matches!(require_init(4242), Err(CleanError::NotInit)));
    }
}
