//! CPU collector: the report's `cpus[]`, one entry **per physical CPU package**.
//!
//! Source: **SMBIOS Type 4 (Processor Information)** — one structure per socket.
//! Contract §6.1 is explicit that the controller sums `cpus[].cores` for
//! `MinCPUCores`, so the inspector MUST emit one entry per package with that
//! package's real core count — never one per logical processor, never the
//! per-socket count repeated. SMBIOS Type 4 is naturally per-package, which is
//! exactly that shape. (The legacy bash inspector over-counted here.)
//!
//! Empty sockets and non-central processors (math/DSP/video co-processors) are
//! filtered out. Field offsets are DSP0134 §7.5, measured from the structure
//! start.

use super::cleaned;
use crate::report::Cpu;
use crate::smbios::Structure;

/// SMBIOS structure type: Processor Information (DSP0134 §7.5).
const TYPE_PROCESSOR: u8 = 4;
/// Processor Type enum value for a central processor (CPU); other values are
/// math/DSP/video co-processors we do not report as CPUs.
const PROCESSOR_TYPE_CENTRAL: u8 = 3;
/// Processor Status bit 6: CPU Socket Populated.
const STATUS_POPULATED: u8 = 0x40;
/// Sentinel in the 1-byte core/thread counts meaning "use the 2-byte field".
const COUNT_USE_EXTENDED: u8 = 0xFF;
/// SMBIOS "unknown" sentinel for the Current Speed word.
const SPEED_UNKNOWN: u16 = 0xFFFF;

const OFF_SOCKET_DESIGNATION: usize = 0x04; // string
const OFF_PROCESSOR_TYPE: usize = 0x05; // byte
const OFF_MANUFACTURER: usize = 0x07; // string
const OFF_VERSION: usize = 0x10; // string
const OFF_CURRENT_SPEED: usize = 0x16; // word, MHz
const OFF_STATUS: usize = 0x18; // byte
const OFF_CORE_COUNT: usize = 0x23; // byte (2.5+)
const OFF_THREAD_COUNT: usize = 0x25; // byte (2.5+)
const OFF_CORE_COUNT_2: usize = 0x2A; // word (3.0+)
const OFF_THREAD_COUNT_2: usize = 0x2E; // word (3.0+)

/// Collect one [`Cpu`] per populated central-processor package.
pub fn collect(structures: &[Structure]) -> Vec<Cpu> {
    structures
        .iter()
        .filter(|s| s.header_type == TYPE_PROCESSOR)
        .filter(|s| is_central_populated(s))
        .map(decode)
        .collect()
}

/// True for a populated central processor. Non-CPU processor types are excluded;
/// the socket-populated bit is honoured when the Status byte is present (older
/// structures without it are assumed populated).
fn is_central_populated(s: &Structure) -> bool {
    if s.byte(OFF_PROCESSOR_TYPE) != Some(PROCESSOR_TYPE_CENTRAL) {
        return false;
    }
    match s.byte(OFF_STATUS) {
        Some(status) => status & STATUS_POPULATED != 0,
        None => true,
    }
}

fn decode(s: &Structure) -> Cpu {
    Cpu {
        id: cleaned(s.string(OFF_SOCKET_DESIGNATION)),
        vendor: cleaned(s.string(OFF_MANUFACTURER)),
        model: cleaned(s.string(OFF_VERSION)),
        cores: count(s, OFF_CORE_COUNT, OFF_CORE_COUNT_2),
        threads: count(s, OFF_THREAD_COUNT, OFF_THREAD_COUNT_2),
        frequency: frequency(s.word(OFF_CURRENT_SPEED)),
    }
}

/// A core/thread count: the 1-byte field, falling back to the 2-byte field when
/// the byte holds the `0xFF` "use extended" sentinel (a package with ≥256
/// cores/threads). `0` when neither field is present.
fn count(s: &Structure, byte_off: usize, word_off: usize) -> u32 {
    match s.byte(byte_off) {
        Some(COUNT_USE_EXTENDED) => s.word(word_off).map(u32::from).unwrap_or(0),
        Some(n) => u32::from(n),
        None => 0,
    }
}

/// Render Current Speed (MHz) as e.g. `"2.0GHz"`. `0`/absent and the SMBIOS
/// "unknown" sentinel both yield "".
fn frequency(mhz: Option<u16>) -> String {
    match mhz {
        Some(0) | Some(SPEED_UNKNOWN) | None => String::new(),
        Some(m) => format!("{:.1}GHz", f64::from(m) / 1000.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smbios::{encode_structure, parse_table};

    /// Build a Type 4 structure. `formatted` spans offsets 0x04..=0x27 (36 bytes)
    /// so the 2.5+ byte core/thread counts at 0x23/0x25 are always present.
    // Positional params mirror the SMBIOS fields under test; a struct would add
    // ceremony without aiding readability of a byte-layout fixture builder.
    #[allow(clippy::too_many_arguments)]
    fn processor(
        handle: u16,
        socket: &str,
        vendor: &str,
        model: &str,
        current_mhz: u16,
        cores: u8,
        threads: u8,
        populated: bool,
    ) -> Vec<u8> {
        let mut f = vec![0u8; 36]; // offsets 0x04..=0x27
        let put_word = |f: &mut [u8], off: usize, v: u16| {
            let b = v.to_le_bytes();
            f[off - 4] = b[0];
            f[off - 3] = b[1];
        };
        f[OFF_SOCKET_DESIGNATION - 4] = 1; // string #1
        f[OFF_PROCESSOR_TYPE - 4] = PROCESSOR_TYPE_CENTRAL;
        f[OFF_MANUFACTURER - 4] = 2; // string #2
        f[OFF_VERSION - 4] = 3; // string #3
        put_word(&mut f, OFF_CURRENT_SPEED, current_mhz);
        f[OFF_STATUS - 4] = if populated {
            STATUS_POPULATED | 0x01
        } else {
            0x01
        };
        f[OFF_CORE_COUNT - 4] = cores;
        f[OFF_CORE_COUNT + 1 - 4] = cores; // core enabled @0x24
        f[OFF_THREAD_COUNT - 4] = threads;
        encode_structure(TYPE_PROCESSOR, handle, &f, &[socket, vendor, model])
    }

    fn table(blobs: &[Vec<u8>]) -> Vec<Structure> {
        let mut raw = Vec::new();
        for b in blobs {
            raw.extend_from_slice(b);
        }
        raw.extend(encode_structure(127, 0x7f00, &[], &[]));
        parse_table(&raw).expect("valid table")
    }

    #[test]
    fn reproduces_the_golden_dual_socket_cpus() {
        // Two populated sockets matching the golden fixture's cpus[].
        let model = "Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz";
        let structures = table(&[
            processor(0x0040, "CPU.Socket.1", "Intel", model, 2000, 32, 64, true),
            processor(0x0041, "CPU.Socket.2", "Intel", model, 2000, 32, 64, true),
        ]);
        let cpus = collect(&structures);
        assert_eq!(
            cpus,
            vec![
                Cpu {
                    id: "CPU.Socket.1".into(),
                    vendor: "Intel".into(),
                    model: model.into(),
                    cores: 32,
                    threads: 64,
                    frequency: "2.0GHz".into(),
                },
                Cpu {
                    id: "CPU.Socket.2".into(),
                    vendor: "Intel".into(),
                    model: model.into(),
                    cores: 32,
                    threads: 64,
                    frequency: "2.0GHz".into(),
                },
            ]
        );
    }

    #[test]
    fn empty_socket_is_skipped() {
        let structures = table(&[
            processor(0x0040, "CPU1", "Intel", "Xeon", 2000, 32, 64, true),
            processor(0x0041, "CPU2", "Intel", "Xeon", 0, 0, 0, false), // unpopulated
        ]);
        let cpus = collect(&structures);
        assert_eq!(cpus.len(), 1);
        assert_eq!(cpus[0].id, "CPU1");
    }

    #[test]
    fn non_central_processor_is_skipped() {
        // A co-processor: Processor Type != 3.
        let mut f = vec![0u8; 36];
        f[OFF_PROCESSOR_TYPE - 4] = 5; // DSP
        f[OFF_STATUS - 4] = STATUS_POPULATED | 0x01;
        let coproc = encode_structure(TYPE_PROCESSOR, 0x0042, &f, &[]);
        let structures = table(&[
            processor(0x0040, "CPU1", "Intel", "Xeon", 2000, 8, 16, true),
            coproc,
        ]);
        let cpus = collect(&structures);
        assert_eq!(cpus.len(), 1);
        assert_eq!(cpus[0].id, "CPU1");
    }

    #[test]
    fn extended_core_thread_counts_are_used_past_255() {
        // 1-byte counts hold 0xFF -> read the 2-byte fields at 0x2A / 0x2E.
        let mut f = vec![0u8; 48]; // through 0x2F so the word fields exist
        f[OFF_SOCKET_DESIGNATION - 4] = 1;
        f[OFF_PROCESSOR_TYPE - 4] = PROCESSOR_TYPE_CENTRAL;
        f[OFF_STATUS - 4] = STATUS_POPULATED | 0x01;
        f[OFF_CORE_COUNT - 4] = COUNT_USE_EXTENDED;
        f[OFF_THREAD_COUNT - 4] = COUNT_USE_EXTENDED;
        let core2 = 288u16.to_le_bytes();
        f[OFF_CORE_COUNT_2 - 4] = core2[0];
        f[OFF_CORE_COUNT_2 + 1 - 4] = core2[1];
        let thread2 = 576u16.to_le_bytes();
        f[OFF_THREAD_COUNT_2 - 4] = thread2[0];
        f[OFF_THREAD_COUNT_2 + 1 - 4] = thread2[1];
        let big = encode_structure(TYPE_PROCESSOR, 0x0040, &f, &["CPU1"]);
        let structures = table(&[big]);
        let cpus = collect(&structures);
        assert_eq!(cpus[0].cores, 288);
        assert_eq!(cpus[0].threads, 576);
    }

    #[test]
    fn unknown_current_speed_yields_empty_frequency() {
        let structures = table(&[processor(
            0x0040, "CPU1", "Intel", "Xeon", 0xFFFF, 8, 16, true,
        )]);
        assert_eq!(collect(&structures)[0].frequency, "");
    }

    #[test]
    fn fractional_ghz_is_rendered() {
        let structures = table(&[processor(0x0040, "CPU1", "AMD", "EPYC", 2450, 24, 48, true)]);
        assert_eq!(collect(&structures)[0].frequency, "2.5GHz");
    }
}
