//! Phase 2 deploy — write the digest-verified target image to the selected disk
//! (contract §9.1 steps 5.1–5.2).
//!
//! This is the **destructive** half of provisioning's first step: stream the
//! whole-disk OS image (`beskar7.target`) straight onto the block device chosen by
//! [`crate::target_disk`], verifying it against `beskar7.target-digest` as it goes.
//! The `COS_OEM` inject + `reboot(2)` (steps 5.3–5.5) follow in a later module.
//!
//! ## What this module guarantees
//!   * **Identity before write (TOCTOU guard, §5).** The device is opened by its
//!     `/dev/<kname>` path, then the opened node's `st_rdev` is checked against the
//!     `major:minor` recorded at selection time ([`TargetDisk::dev_number`]). If a
//!     `/dev` node was repointed between selection and open (udev re-enumeration,
//!     hot-plug, a hostile actor with device-node control), the write is refused —
//!     so the device validated by `target_disk` is provably the device written.
//!     The opened node is also required to be a block device, and is opened
//!     `O_EXCL` (exclusive block-device open) so a disk that is mounted or held by
//!     another writer — outside `target_disk`'s system-backing exclusion — fails
//!     with `EBUSY` rather than being clobbered.
//!   * **Bounded, RAM-free, digest-gated write (§8.1).** The image is streamed to
//!     the device by [`crate::image::ImageFetcher::fetch_to`], which hashes the
//!     bytes incrementally (never buffering the multi-GB body) and returns `Ok`
//!     **only** on a full-length digest match. The size bound is the smaller of
//!     the build maximum and the disk's own capacity — a whole-disk image larger
//!     than the disk can never deploy. On any digest mismatch, short read, or
//!     size breach the call fails and the caller MUST NOT proceed to mount/inject/
//!     reboot; the unbootable disk is recovered on the next provisioning attempt.
//!
//! Re-reading the partition table and locating `COS_OEM` are step 5.3's job (the
//! next module), deliberately not here: this module only lays the image down and
//! flushes it to stable storage.
//!
//! ## Secret hygiene (§9)
//! No secrets pass through here — the image and its digest are public; the CAPI
//! join secret arrives separately and is injected in step 5.3. [`DeployError`]
//! carries only device paths and `major:minor` numbers (all non-secret), so a
//! logged error cannot leak anything sensitive.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};

use crate::image::{ImageError, ImageFetcher, Sha256Digest};
use crate::target_disk::TargetDisk;

/// Errors from the whole-disk write. All variants carry only non-secret material
/// (device paths, `major:minor` numbers, public digests), so logging a
/// `DeployError` in full is safe (§9).
#[derive(Debug, thiserror::Error)]
pub enum DeployError {
    /// The target `/dev` node could not be opened for writing (e.g. it is held
    /// exclusively, or permission was denied).
    #[error("opening target disk {path} for writing")]
    OpenTarget {
        /// The `/dev/<kname>` path.
        path: String,
        /// The underlying open error.
        #[source]
        source: std::io::Error,
    },
    /// The opened target node is not a block device — refuse to write.
    #[error("target {path} is not a block device — refusing to write")]
    NotABlockDevice {
        /// The `/dev/<kname>` path.
        path: String,
    },
    /// The target's metadata could not be read to verify its identity.
    #[error("reading target disk {path} metadata")]
    Stat {
        /// The `/dev/<kname>` path.
        path: String,
        /// The underlying stat error.
        #[source]
        source: std::io::Error,
    },
    /// The selected disk carried no `major:minor` to verify against, so device
    /// identity cannot be confirmed — refuse to write rather than risk the wrong
    /// device (§5).
    #[error("target disk {path} has no recorded device number; cannot verify identity — refusing to write")]
    NoDeviceNumber {
        /// The `/dev/<kname>` path.
        path: String,
    },
    /// The opened node's `st_rdev` does not match the device selected — the `/dev`
    /// node was repointed since selection. Refuse to write (§5 TOCTOU guard).
    #[error("target disk {path} identity changed since selection (expected dev {expected}, found {found}) — refusing to write")]
    DeviceIdentityMismatch {
        /// The `/dev/<kname>` path.
        path: String,
        /// The `major:minor` recorded at selection time.
        expected: String,
        /// The `major:minor` of the node actually opened.
        found: String,
    },
    /// Building the image fetcher, streaming, or the digest verification failed
    /// (see [`ImageError`]). A [`ImageError::DigestMismatch`] here means the bytes
    /// on disk did not match `beskar7.target-digest`: the caller MUST NOT mount,
    /// inject, or reboot.
    #[error(transparent)]
    Image(#[from] ImageError),
    /// Flushing the written image to stable storage failed.
    #[error("flushing target disk to stable storage")]
    Sync(#[source] std::io::Error),
}

/// Stream `image_url` onto `target`, verifying it against `target_digest`, and
/// flush it to stable storage (contract §9.1 steps 5.1–5.2). `build_max_bytes` is
/// the §8.1 build-default ceiling; the effective cap is the smaller of it and the
/// disk's capacity. Returns the number of bytes written on a verified match.
///
/// On a verified-matching digest this leaves the whole-disk image on the device,
/// flushed; the caller may then proceed to step 5.3 (re-read partitions, mount
/// `COS_OEM`, inject). On **any** error — including a digest mismatch — the caller
/// MUST NOT proceed; the (unverified, non-secret) bytes on disk are never booted
/// and are overwritten on the next attempt (§8.1).
pub fn write_image(
    target: &TargetDisk,
    image_url: &str,
    target_digest: &str,
    build_max_bytes: u64,
) -> Result<u64, DeployError> {
    let digest = Sha256Digest::parse(target_digest)?;
    let cap = effective_max_bytes(build_max_bytes, target.size_bytes);
    let path = target.dev_path();

    // O_EXCL on a block device is the kernel's *exclusive* open: it fails with
    // EBUSY if the device is mounted or already held by another opener. Selection
    // already excludes system-backing disks, but this is defense-in-depth against
    // clobbering a mounted-but-not-system disk (an operator data disk) — a clean
    // unmounted spare opens fine.
    let mut file = OpenOptions::new()
        .write(true)
        .custom_flags(nix::libc::O_EXCL)
        .open(&path)
        .map_err(|source| DeployError::OpenTarget {
            path: path.clone(),
            source,
        })?;
    verify_target_identity(&file, target)?;

    let fetcher = ImageFetcher::new()?;
    let written = fetcher.fetch_to(image_url, &digest, cap, &mut file)?;
    file.sync_all().map_err(DeployError::Sync)?;
    Ok(written)
}

/// The effective write ceiling: the smaller of the build maximum and the disk's
/// capacity (§8.1 — a whole-disk image larger than the disk can never deploy). A
/// `0` capacity (unknown) falls back to the build maximum, leaving the image
/// fetcher's own backstop as the only bound.
fn effective_max_bytes(build_max: u64, disk_capacity: u64) -> u64 {
    if disk_capacity == 0 {
        build_max
    } else {
        build_max.min(disk_capacity)
    }
}

/// Confirm the opened `file` is the block device selected: it must be a block
/// device, and its `st_rdev` must equal `target.dev_number` (the `major:minor`
/// recorded at selection). Refuses on any mismatch or when no device number was
/// recorded (§5 TOCTOU guard).
fn verify_target_identity(file: &File, target: &TargetDisk) -> Result<(), DeployError> {
    let path = target.dev_path();
    if target.dev_number.is_empty() {
        return Err(DeployError::NoDeviceNumber { path });
    }
    let meta = file.metadata().map_err(|source| DeployError::Stat {
        path: path.clone(),
        source,
    })?;
    if !meta.file_type().is_block_device() {
        return Err(DeployError::NotABlockDevice { path });
    }
    match rdev_matches(meta.rdev(), &target.dev_number) {
        Ok(()) => Ok(()),
        Err(found) => Err(DeployError::DeviceIdentityMismatch {
            path,
            expected: target.dev_number.clone(),
            found,
        }),
    }
}

/// Compare a raw `st_rdev` against an expected `"major:minor"` string (as
/// `/sys/block/<kname>/dev` renders it). `Ok(())` on a match; `Err(found)` carries
/// the actual `"major:minor"` for the mismatch diagnostic.
fn rdev_matches(rdev: u64, expected: &str) -> Result<(), String> {
    let found = format!(
        "{}:{}",
        nix::sys::stat::major(rdev),
        nix::sys::stat::minor(rdev)
    );
    if found == expected {
        Ok(())
    } else {
        Err(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;

    #[test]
    fn effective_max_is_capped_by_a_small_disk() {
        // A disk smaller than the build max caps the write to the disk size — a
        // whole-disk image larger than the disk can never deploy (§8.1).
        let disk = 8 * GIB; // < 16 GiB build max
        assert_eq!(effective_max_bytes(16 * GIB, disk), disk);
    }

    #[test]
    fn effective_max_is_the_build_max_when_disk_is_larger() {
        // A 480 GB disk dwarfs the 16 GiB build max, which stays in force.
        let disk = 480 * 1_000_000_000;
        assert_eq!(effective_max_bytes(16 * GIB, disk), 16 * GIB);
    }

    #[test]
    fn effective_max_falls_back_to_build_max_for_unknown_capacity() {
        assert_eq!(effective_max_bytes(16 * GIB, 0), 16 * GIB);
    }

    #[test]
    fn rdev_matches_accepts_the_recorded_major_minor() {
        // makedev encodes the same major:minor sysfs reports, so a round trip
        // through the kernel's dev_t must compare equal.
        let rdev = nix::sys::stat::makedev(259, 0);
        assert!(rdev_matches(rdev, "259:0").is_ok());
    }

    #[test]
    fn rdev_mismatch_reports_the_found_major_minor() {
        let rdev = nix::sys::stat::makedev(8, 0);
        // The device was selected as 8:0 but the opened node is now 8:16.
        let opened = nix::sys::stat::makedev(8, 16);
        match rdev_matches(opened, "8:0") {
            Err(found) => assert_eq!(found, "8:16"),
            Ok(()) => panic!("expected a mismatch"),
        }
        // Sanity: the matching case for the same recorded value still passes.
        assert!(rdev_matches(rdev, "8:0").is_ok());
    }

    #[test]
    fn no_device_number_refuses_identity() {
        // An empty dev_number means selection could not read /sys/block/<k>/dev;
        // verify_target_identity must refuse before any write. We exercise the
        // pre-metadata guard directly via a TargetDisk with no dev_number by
        // checking the rdev helper is never the thing that passes it.
        let target = TargetDisk {
            kname: "nvme0n1".into(),
            size_bytes: 480 * 1_000_000_000,
            dev_number: String::new(),
        };
        // Open /dev/null as a stand-in File; the empty-dev_number guard fires
        // before metadata is inspected, so the node's nature is irrelevant.
        let f = File::open("/dev/null").expect("/dev/null opens");
        let err = verify_target_identity(&f, &target).unwrap_err();
        assert!(
            matches!(err, DeployError::NoDeviceNumber { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn non_block_device_is_refused() {
        // /dev/null is a *character* device: identity verification must reject it
        // as not-a-block-device rather than write to it.
        let target = TargetDisk {
            kname: "null".into(),
            size_bytes: 0,
            dev_number: "1:3".into(), // /dev/null is char 1:3, but it's not a block dev
        };
        let f = File::open("/dev/null").expect("/dev/null opens");
        let err = verify_target_identity(&f, &target).unwrap_err();
        assert!(
            matches!(err, DeployError::NotABlockDevice { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn invalid_digest_is_rejected_before_opening_anything() {
        // write_image parses the digest first, so a malformed digest fails fast
        // without touching the (here nonexistent) device.
        let target = TargetDisk {
            kname: "does-not-exist-zzz".into(),
            size_bytes: 1024,
            dev_number: "8:0".into(),
        };
        let err = write_image(&target, "http://example/img.raw", "not-a-digest", 1024).unwrap_err();
        assert!(
            matches!(err, DeployError::Image(ImageError::InvalidDigestFormat)),
            "got {err:?}"
        );
    }
}
