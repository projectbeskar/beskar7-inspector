//! Memory collector: the report's `memory[]`, one entry **per populated DIMM**.
//!
//! Source: **SMBIOS Type 17 (Memory Device)** — one structure per slot. Empty
//! slots (Size 0) are skipped so the report carries only populated DIMMs
//! (contract §6.1).
//!
//! Capacity is emitted with an IEC unit suffix (`"32GiB"`/`"512MiB"`), which the
//! controller's `parseMemoryCapacityGB` accepts; a bare integer would be
//! rejected (§6.1). SMBIOS reports DIMM size in binary MB (== MiB), so the
//! conversion is exact. Field offsets are DSP0134 §7.18, measured from the
//! structure start.

use super::cleaned;
use crate::report::MemoryModule;
use crate::smbios::Structure;

/// SMBIOS structure type: Memory Device (DSP0134 §7.18).
const TYPE_MEMORY_DEVICE: u8 = 17;

const OFF_SIZE: usize = 0x0C; // word
const OFF_DEVICE_LOCATOR: usize = 0x10; // string
const OFF_MEMORY_TYPE: usize = 0x12; // byte
const OFF_SPEED: usize = 0x15; // word, MT/s (2.3+)
const OFF_EXTENDED_SIZE: usize = 0x1C; // dword, MB (2.7+)

/// Size sentinel: the slot is empty / no module installed.
const SIZE_EMPTY: u16 = 0;
/// Size sentinel: the real size is unknown.
const SIZE_UNKNOWN: u16 = 0xFFFF;
/// Size sentinel: the real size is in the Extended Size dword (DIMMs ≥ 32 GiB,
/// which overflow the 15-bit MB field).
const SIZE_USE_EXTENDED: u16 = 0x7FFF;
/// Size bit 15: 0 ⇒ value is in MB, 1 ⇒ value is in KB.
const SIZE_UNIT_KB_BIT: u16 = 0x8000;
/// SMBIOS "unknown" sentinel for the Speed word.
const SPEED_UNKNOWN: u16 = 0xFFFF;

const MIB_PER_GIB: u64 = 1024;

/// Collect one [`MemoryModule`] per populated DIMM. Empty slots and DIMMs whose
/// size cannot be determined are omitted, so every emitted entry carries a
/// controller-parseable capacity.
pub fn collect(structures: &[Structure]) -> Vec<MemoryModule> {
    structures
        .iter()
        .filter(|s| s.header_type == TYPE_MEMORY_DEVICE)
        .filter_map(decode)
        .collect()
}

/// Decode a populated DIMM; `None` for an empty slot or an indeterminate size.
fn decode(s: &Structure) -> Option<MemoryModule> {
    let capacity = capacity(s)?;
    Some(MemoryModule {
        id: cleaned(s.string(OFF_DEVICE_LOCATOR)),
        mem_type: memory_type(s.byte(OFF_MEMORY_TYPE)),
        capacity,
        speed: speed(s.word(OFF_SPEED)),
    })
}

/// The DIMM capacity as an IEC string, or `None` when the slot is empty or its
/// size is unknown (so the caller drops the entry rather than emit an
/// unparseable capacity).
fn capacity(s: &Structure) -> Option<String> {
    let size = s.word(OFF_SIZE)?;
    if size == SIZE_EMPTY || size == SIZE_UNKNOWN {
        return None;
    }
    let mib = if size == SIZE_USE_EXTENDED {
        // Extended Size is in MB; bit 31 is reserved (0).
        u64::from(s.dword(OFF_EXTENDED_SIZE)?)
    } else if size & SIZE_UNIT_KB_BIT != 0 {
        u64::from(size & !SIZE_UNIT_KB_BIT) / 1024 // KB → MiB (rare for DIMMs)
    } else {
        u64::from(size) // MB == MiB
    };
    Some(format_capacity(mib))
}

/// Largest whole IEC unit the controller accepts: `GiB` when an exact multiple,
/// else `MiB`.
fn format_capacity(mib: u64) -> String {
    if mib != 0 && mib % MIB_PER_GIB == 0 {
        format!("{}GiB", mib / MIB_PER_GIB)
    } else {
        format!("{mib}MiB")
    }
}

/// Map the Memory Type byte (DSP0134 §7.18.2) to a DRAM family string.
fn memory_type(code: Option<u8>) -> String {
    let name = match code {
        Some(0x12) => "DDR",
        Some(0x13) => "DDR2",
        Some(0x14) => "DDR2 FB-DIMM",
        Some(0x18) => "DDR3",
        Some(0x1A) => "DDR4",
        Some(0x1B) => "LPDDR",
        Some(0x1C) => "LPDDR2",
        Some(0x1D) => "LPDDR3",
        Some(0x1E) => "LPDDR4",
        Some(0x22) => "DDR5",
        Some(0x23) => "LPDDR5",
        _ => "Unknown",
    };
    name.to_string()
}

/// Render Speed (MT/s) as e.g. `"3200MHz"` (the golden fixture's convention).
/// `0`/absent and the SMBIOS "unknown" sentinel yield "".
fn speed(mts: Option<u16>) -> String {
    match mts {
        Some(0) | Some(SPEED_UNKNOWN) | None => String::new(),
        Some(v) => format!("{v}MHz"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smbios::{encode_structure, parse_table};

    /// Build a Type 17 structure spanning offsets 0x04..=0x1F (28 bytes) so the
    /// Extended Size dword at 0x1C is always present. `size_word` is the 0x0C
    /// Size field; `ext_size` the 0x1C Extended Size (used iff size_word is the
    /// 0x7FFF sentinel).
    fn dimm(
        handle: u16,
        locator: &str,
        mem_type: u8,
        size_word: u16,
        ext_size: u32,
        speed_mts: u16,
    ) -> Vec<u8> {
        let mut f = vec![0u8; 28]; // offsets 0x04..=0x1F
        let put_word = |f: &mut [u8], off: usize, v: u16| {
            let b = v.to_le_bytes();
            f[off - 4] = b[0];
            f[off - 3] = b[1];
        };
        put_word(&mut f, OFF_SIZE, size_word);
        f[OFF_DEVICE_LOCATOR - 4] = 1; // string #1
        f[OFF_MEMORY_TYPE - 4] = mem_type;
        put_word(&mut f, OFF_SPEED, speed_mts);
        let es = ext_size.to_le_bytes();
        f[OFF_EXTENDED_SIZE - 4..OFF_EXTENDED_SIZE].copy_from_slice(&es);
        encode_structure(TYPE_MEMORY_DEVICE, handle, &f, &[locator])
    }

    fn table(blobs: &[Vec<u8>]) -> Vec<Structure> {
        let mut raw = Vec::new();
        for b in blobs {
            raw.extend_from_slice(b);
        }
        raw.extend(encode_structure(127, 0x7f00, &[], &[]));
        parse_table(&raw).expect("valid table")
    }

    // 0x1A = DDR4. 32 GiB overflows the 15-bit MB Size field, so it uses the
    // 0x7FFF sentinel + Extended Size = 32768 MB — exactly real Dell/HPE firmware.
    fn golden_dimm(handle: u16, locator: &str) -> Vec<u8> {
        dimm(handle, locator, 0x1A, SIZE_USE_EXTENDED, 32768, 3200)
    }

    #[test]
    fn reproduces_the_golden_four_dimms() {
        let structures = table(&[
            golden_dimm(0x1100, "DIMM.Socket.A1"),
            golden_dimm(0x1101, "DIMM.Socket.A2"),
            golden_dimm(0x1102, "DIMM.Socket.B1"),
            golden_dimm(0x1103, "DIMM.Socket.B2"),
        ]);
        let mem = collect(&structures);
        let expect = |id: &str| MemoryModule {
            id: id.into(),
            mem_type: "DDR4".into(),
            capacity: "32GiB".into(),
            speed: "3200MHz".into(),
        };
        assert_eq!(
            mem,
            vec![
                expect("DIMM.Socket.A1"),
                expect("DIMM.Socket.A2"),
                expect("DIMM.Socket.B1"),
                expect("DIMM.Socket.B2"),
            ]
        );
    }

    #[test]
    fn empty_slot_is_skipped() {
        let structures = table(&[
            golden_dimm(0x1100, "DIMM.A1"),
            dimm(0x1101, "DIMM.A2", 0x1A, SIZE_EMPTY, 0, 0), // not installed
        ]);
        let mem = collect(&structures);
        assert_eq!(mem.len(), 1);
        assert_eq!(mem[0].id, "DIMM.A1");
    }

    #[test]
    fn unknown_size_is_skipped() {
        let structures = table(&[dimm(0x1100, "DIMM.A1", 0x1A, SIZE_UNKNOWN, 0, 3200)]);
        assert!(collect(&structures).is_empty());
    }

    #[test]
    fn direct_mb_size_under_the_extended_threshold() {
        // 16 GiB = 16384 MB fits the 15-bit field directly (no 0x7FFF sentinel).
        let structures = table(&[dimm(0x1100, "DIMM.A1", 0x18, 16384, 0, 2666)]);
        let mem = collect(&structures);
        assert_eq!(mem[0].capacity, "16GiB");
        assert_eq!(mem[0].mem_type, "DDR3");
        assert_eq!(mem[0].speed, "2666MHz");
    }

    #[test]
    fn non_power_of_two_capacity_falls_back_to_mib() {
        // 1536 MB is not a whole number of GiB.
        let structures = table(&[dimm(0x1100, "DIMM.A1", 0x1A, 1536, 0, 0)]);
        let mem = collect(&structures);
        assert_eq!(mem[0].capacity, "1536MiB");
        assert_eq!(mem[0].speed, ""); // speed 0 -> unknown
    }

    #[test]
    fn unknown_memory_type_is_labelled_unknown() {
        let structures = table(&[dimm(0x1100, "DIMM.A1", 0x99, 8192, 0, 3200)]);
        assert_eq!(collect(&structures)[0].mem_type, "Unknown");
    }

    #[test]
    fn ddr5_is_recognised() {
        let structures = table(&[dimm(
            0x1100,
            "DIMM.A1",
            0x22,
            SIZE_USE_EXTENDED,
            65536,
            4800,
        )]);
        let mem = collect(&structures);
        assert_eq!(mem[0].mem_type, "DDR5");
        assert_eq!(mem[0].capacity, "64GiB");
        assert_eq!(mem[0].speed, "4800MHz");
    }
}
