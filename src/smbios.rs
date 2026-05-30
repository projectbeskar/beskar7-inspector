//! A minimal, allocation-light parser for the raw SMBIOS *structure table*.
//!
//! The firmware exposes its DMI/SMBIOS tables to Linux at
//! `/sys/firmware/dmi/tables/DMI` — a flat blob of back-to-back *structures*.
//! This is the authoritative source for system identity (SMBIOS Type 1), per
//! socket processors (Type 4), and per-DIMM memory (Type 17), which the probe
//! collectors (subsequent PRs) turn into the inspection report's
//! `manufacturer`/`model`/`serialNumber`, `cpus[]`, and `memory[]` fields.
//!
//! This module is deliberately *semantics-free*: it splits the blob into
//! [`Structure`]s and exposes typed little-endian field accessors plus the
//! per-structure string set. Which byte offset means "manufacturer" — and how
//! to interpret it — lives with the collector that consumes it, next to where it
//! maps onto the report, because those offsets differ per structure type and per
//! SMBIOS version.
//!
//! ## Structure-table layout (DSP0134)
//!
//! Each structure is a 4-byte header — `type:u8`, `length:u8`, `handle:u16le` —
//! followed by `length - 4` bytes of *formatted* fields, then an *unformatted*
//! string set: NUL-terminated strings packed end to end and terminated by an
//! extra NUL (so the set ends in a double-NUL). A structure with no strings is
//! just `00 00`. Formatted fields reference strings by a 1-based index, where 0
//! means "not specified". `length` counts the header, so SMBIOS field offsets
//! (e.g. Type 1 Manufacturer at offset `0x04`) index straight into
//! [`Structure::data`].

use std::path::Path;

/// Canonical Linux sysfs path of the raw SMBIOS structure table.
pub const DMI_TABLE_PATH: &str = "/sys/firmware/dmi/tables/DMI";

/// SMBIOS structure type for the end-of-table marker (DSP0134 §7.45). Parsing
/// stops once this structure is consumed.
pub const TYPE_END_OF_TABLE: u8 = 127;

/// One decoded SMBIOS structure: its header, formatted area, and string set.
///
/// Field accessors are bounds-checked and return [`None`] for offsets past the
/// structure's `length` — a structure emitted by older firmware may simply not
/// carry a field defined by a later SMBIOS version, and the spec says to treat
/// that as absent rather than an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Structure {
    /// SMBIOS structure type (e.g. 1 = System, 4 = Processor, 17 = Memory Device).
    pub header_type: u8,
    /// The structure's handle (an opaque per-structure identifier).
    pub handle: u16,
    /// The formatted area, indexed by SMBIOS field offset from the structure
    /// start (so `data[0] == header_type`, `data[1] == length`, …).
    data: Vec<u8>,
    /// The string set, in order. Referenced from formatted fields by 1-based
    /// index; see [`Structure::string`].
    strings: Vec<String>,
}

impl Structure {
    /// The formatted-area byte at `offset`, or `None` if past `length`.
    pub fn byte(&self, offset: usize) -> Option<u8> {
        self.data.get(offset).copied()
    }

    /// A little-endian `u16` at `offset`, or `None` if it would read past `length`.
    pub fn word(&self, offset: usize) -> Option<u16> {
        let end = offset.checked_add(2)?;
        let bytes = self.data.get(offset..end)?;
        Some(u16::from_le_bytes(bytes.try_into().ok()?))
    }

    /// A little-endian `u32` at `offset`, or `None` if it would read past `length`.
    pub fn dword(&self, offset: usize) -> Option<u32> {
        let end = offset.checked_add(4)?;
        let bytes = self.data.get(offset..end)?;
        Some(u32::from_le_bytes(bytes.try_into().ok()?))
    }

    /// A little-endian `u64` at `offset`, or `None` if it would read past `length`.
    pub fn qword(&self, offset: usize) -> Option<u64> {
        let end = offset.checked_add(8)?;
        let bytes = self.data.get(offset..end)?;
        Some(u64::from_le_bytes(bytes.try_into().ok()?))
    }

    /// Resolve the string whose 1-based index is held in the formatted byte at
    /// `offset`. Returns `None` if the field is absent, names index 0 ("not
    /// specified"), or points past the string set.
    pub fn string(&self, offset: usize) -> Option<&str> {
        self.string_by_number(self.byte(offset)?)
    }

    /// Resolve a string by its 1-based SMBIOS string number directly. `0` ("not
    /// specified") and out-of-range numbers yield `None`.
    pub fn string_by_number(&self, number: u8) -> Option<&str> {
        if number == 0 {
            return None;
        }
        self.strings
            .get(usize::from(number - 1))
            .map(String::as_str)
    }

    /// The structure's full string set, in declaration order.
    pub fn strings(&self) -> &[String] {
        &self.strings
    }
}

/// Errors from parsing a raw SMBIOS structure table.
#[derive(Debug, thiserror::Error)]
pub enum SmbiosError {
    /// A structure ran past the end of the buffer — a malformed or truncated
    /// table. `offset` is where that structure began.
    #[error("SMBIOS structure at offset {offset} is truncated")]
    Truncated {
        /// Byte offset of the structure header that could not be fully read.
        offset: usize,
    },
    /// A structure declared a `length` smaller than its 4-byte header.
    #[error("SMBIOS structure at offset {offset} has invalid length {length}")]
    BadLength {
        /// Byte offset of the offending structure header.
        offset: usize,
        /// The invalid declared length.
        length: usize,
    },
    /// The sysfs table could not be read.
    #[error("reading {DMI_TABLE_PATH}")]
    Io(#[from] std::io::Error),
}

/// Read and parse the SMBIOS structure table from [`DMI_TABLE_PATH`].
pub fn from_sysfs() -> Result<Vec<Structure>, SmbiosError> {
    from_path(DMI_TABLE_PATH)
}

/// Read and parse the SMBIOS structure table from an arbitrary path (the sysfs
/// `DMI` blob, or a captured fixture).
pub fn from_path(path: impl AsRef<Path>) -> Result<Vec<Structure>, SmbiosError> {
    let raw = std::fs::read(path)?;
    parse_table(&raw)
}

/// Parse a raw SMBIOS structure-table blob into its [`Structure`]s.
///
/// Iterates until the end-of-table structure (type [`TYPE_END_OF_TABLE`]) is
/// consumed or the buffer is exhausted. Trailing bytes after the end-of-table
/// marker are ignored.
pub fn parse_table(raw: &[u8]) -> Result<Vec<Structure>, SmbiosError> {
    let mut structures = Vec::new();
    let mut pos = 0usize;

    // A structure needs at least its 4-byte header to begin.
    while pos + 4 <= raw.len() {
        let header_type = raw[pos];
        let length = raw[pos + 1] as usize;
        let handle = u16::from_le_bytes([raw[pos + 2], raw[pos + 3]]);

        if length < 4 {
            return Err(SmbiosError::BadLength {
                offset: pos,
                length,
            });
        }
        let formatted_end = pos
            .checked_add(length)
            .filter(|&end| end <= raw.len())
            .ok_or(SmbiosError::Truncated { offset: pos })?;
        let data = raw[pos..formatted_end].to_vec();

        let (strings, next) = parse_string_set(raw, formatted_end, pos)?;

        let is_end = header_type == TYPE_END_OF_TABLE;
        structures.push(Structure {
            header_type,
            handle,
            data,
            strings,
        });
        pos = next;

        if is_end {
            break;
        }
    }

    Ok(structures)
}

/// Parse the unformatted string set that begins at `start`, returning the
/// decoded strings and the offset of the next structure. `struct_offset` is the
/// owning structure's header offset, reported in [`SmbiosError::Truncated`].
fn parse_string_set(
    raw: &[u8],
    start: usize,
    struct_offset: usize,
) -> Result<(Vec<String>, usize), SmbiosError> {
    let truncated = || SmbiosError::Truncated {
        offset: struct_offset,
    };

    let mut p = start;
    // Every string set is terminated by at least a double-NUL; a set with no
    // strings is exactly `00 00`.
    if p + 2 > raw.len() {
        return Err(truncated());
    }
    if raw[p] == 0 && raw[p + 1] == 0 {
        return Ok((Vec::new(), p + 2));
    }

    let mut strings = Vec::new();
    loop {
        let str_start = p;
        while p < raw.len() && raw[p] != 0 {
            p += 1;
        }
        if p >= raw.len() {
            return Err(truncated());
        }
        strings.push(String::from_utf8_lossy(&raw[str_start..p]).into_owned());
        p += 1; // consume this string's NUL terminator

        match raw.get(p) {
            // A second NUL closes the set.
            Some(0) => return Ok((strings, p + 1)),
            // More strings follow.
            Some(_) => {}
            // Ran off the end before the closing NUL.
            None => return Err(truncated()),
        }
    }
}

/// Encode one SMBIOS structure: 4-byte header, `formatted` fields, then the
/// string set (`00 00` when empty, else each string NUL-terminated followed by
/// the closing NUL). Shared across the crate's unit tests — here and the probe
/// collectors — so every test builds fixtures the same, spec-correct way.
#[cfg(test)]
pub(crate) fn encode_structure(
    header_type: u8,
    handle: u16,
    formatted: &[u8],
    strings: &[&str],
) -> Vec<u8> {
    let length = 4 + formatted.len();
    let mut v = vec![
        header_type,
        length as u8,
        (handle & 0xff) as u8,
        (handle >> 8) as u8,
    ];
    v.extend_from_slice(formatted);
    if strings.is_empty() {
        v.extend_from_slice(&[0, 0]);
    } else {
        for s in strings {
            v.extend_from_slice(s.as_bytes());
            v.push(0);
        }
        v.push(0); // closing NUL of the double-NUL terminator
    }
    v
}

#[cfg(test)]
mod tests {
    use super::encode_structure as structure;
    use super::*;

    #[test]
    fn parses_single_structure_with_strings() {
        // Type 1 (System): manufacturer string# at offset 4, product at 5.
        let blob = structure(1, 0x0001, &[1, 2], &["Dell Inc.", "PowerEdge R650"]);
        let table = parse_table(&blob).expect("valid table");
        assert_eq!(table.len(), 1);

        let s = &table[0];
        assert_eq!(s.header_type, 1);
        assert_eq!(s.handle, 0x0001);
        assert_eq!(s.string(4), Some("Dell Inc."));
        assert_eq!(s.string(5), Some("PowerEdge R650"));
        assert_eq!(s.strings().len(), 2);
    }

    #[test]
    fn no_strings_yields_empty_set() {
        let blob = structure(127, 0, &[], &[]);
        let table = parse_table(&blob).expect("valid table");
        assert_eq!(table.len(), 1);
        assert!(table[0].strings().is_empty());
        assert_eq!(table[0].string(4), None);
    }

    #[test]
    fn string_index_zero_is_not_specified() {
        // Formatted byte 0 means "not specified".
        let blob = structure(1, 0, &[0], &["only-string"]);
        let table = parse_table(&blob).expect("valid table");
        assert_eq!(table[0].string(4), None);
        assert_eq!(table[0].string_by_number(0), None);
    }

    #[test]
    fn out_of_range_string_number_is_none() {
        let blob = structure(1, 0, &[3], &["one", "two"]); // index 3, only 2 strings
        let table = parse_table(&blob).expect("valid table");
        assert_eq!(table[0].string(4), None);
        assert_eq!(table[0].string_by_number(3), None);
    }

    #[test]
    fn integer_fields_are_little_endian() {
        let formatted = [
            0xAA, // byte at offset 4
            0x34, 0x12, // word at offset 5 -> 0x1234
            0x78, 0x56, 0x34, 0x12, // dword at offset 7 -> 0x12345678
            0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12, // qword at offset 11
        ];
        let blob = structure(4, 0, &formatted, &[]);
        let s = &parse_table(&blob).expect("valid")[0];
        assert_eq!(s.byte(4), Some(0xAA));
        assert_eq!(s.word(5), Some(0x1234));
        assert_eq!(s.dword(7), Some(0x1234_5678));
        assert_eq!(s.qword(11), Some(0x1234_5678_9ABC_DEF0));
    }

    #[test]
    fn fields_past_length_are_none() {
        let blob = structure(1, 0, &[1, 2], &["a", "b"]); // formatted ends at offset 6
        let s = &parse_table(&blob).expect("valid")[0];
        assert_eq!(s.byte(6), None);
        assert_eq!(s.word(5), None); // would read offset 5..7, past the area
        assert_eq!(s.dword(4), None);
        assert_eq!(s.qword(0), None);
    }

    #[test]
    fn parses_multiple_structures_and_stops_at_end_of_table() {
        let mut blob = Vec::new();
        blob.extend(structure(4, 0x0040, &[0x01], &["CPU0"])); // processor
        blob.extend(structure(17, 0x0110, &[0x01], &["DIMM_A1"])); // memory device
        blob.extend(structure(127, 0x7f00, &[], &[])); // end of table
                                                       // Anything after the end-of-table marker must be ignored.
        blob.extend(structure(1, 0xdead, &[1], &["should-not-parse"]));

        let table = parse_table(&blob).expect("valid table");
        let types: Vec<u8> = table.iter().map(|s| s.header_type).collect();
        assert_eq!(types, vec![4, 17, 127]);
        assert_eq!(table[0].string(4), Some("CPU0"));
        assert_eq!(table[1].string(4), Some("DIMM_A1"));
    }

    #[test]
    fn bad_length_is_rejected() {
        // length byte (offset 1) of 3 is smaller than the 4-byte header.
        let blob = [1u8, 3, 0, 0, 0, 0];
        match parse_table(&blob) {
            Err(SmbiosError::BadLength {
                offset: 0,
                length: 3,
            }) => {}
            other => panic!("expected BadLength, got {other:?}"),
        }
    }

    #[test]
    fn truncated_formatted_area_is_rejected() {
        // Header claims length 16 but the buffer is far shorter.
        let blob = [1u8, 16, 0, 0, 0xAA, 0xBB];
        assert!(matches!(
            parse_table(&blob),
            Err(SmbiosError::Truncated { offset: 0 })
        ));
    }

    #[test]
    fn truncated_string_set_is_rejected() {
        // Valid header + formatted area, but the string set never gets its
        // closing NUL.
        let blob = [1u8, 5, 0, 0, 1, b'n', b'o', b'-', b'e', b'n', b'd'];
        assert!(matches!(
            parse_table(&blob),
            Err(SmbiosError::Truncated { offset: 0 })
        ));
    }

    #[test]
    fn invalid_utf8_in_strings_is_replaced_not_panicked() {
        // 0xFF is not valid UTF-8; from_utf8_lossy must substitute U+FFFD.
        let mut blob = vec![1u8, 5, 0, 0, 1]; // header + 1 formatted byte (str# 1)
        blob.extend_from_slice(&[0xFF, 0x00, 0x00]); // string "\xFF", then terminator
        let table = parse_table(&blob).expect("lossy decode, not an error");
        assert_eq!(table[0].string(4), Some("\u{FFFD}"));
    }

    #[test]
    fn empty_blob_yields_no_structures() {
        assert!(parse_table(&[]).expect("valid").is_empty());
    }
}
