//! Library to parse ELF files.

use crate::{
    elf::{ElfHeader, ProgramHeader, ProgramHeaderTable},
    parse::Parse,
};

mod elf;
mod parse;

pub struct Elf<'a> {
    bytes: &'a [u8],
}

#[derive(Debug)]
pub enum Error {
    TruncatedInput {
        /// Required number of bytes for this value.
        needed: usize,
        /// Number of bytes supplied to the parser.
        available: usize,
    },
    UnsupportedElfType(u16),
    /// A program header type not currently recognized by the parser.
    UnsupportedProgramType(u32),
    TruncatedHeader,
    InvalidMagic,
    UnsupportedClass,
    UnsupportedByteOrder,
    InvalidField(&'static str),
}

pub fn parse(bytes: &[u8]) -> Result<Elf<'_>, Error> {
    let header = ElfHeader::parse(bytes).unwrap();
    let program_header_offset = header.e_phoff;
    let program_header_size = header.e_phentsize;
    let program_header_n = header.e_phnum;

    println!("Program header offset = {program_header_offset:#0x}");
    println!("Program header size   = {program_header_size}");
    println!("Program headers       = {program_header_n}");

    dbg!(core::mem::size_of::<ProgramHeader>());

    let program_header_table = ProgramHeaderTable::parse(
        &bytes[program_header_offset as usize..],
        program_header_n,
        program_header_size,
    )
    .unwrap();

    dbg!(program_header_table);

    dbg!(header.class());
    dbg!(header.endianess());
    dbg!(header.e_machine);

    Ok(Elf { bytes })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::ProgramType;

    /// A deterministic ELF64 little-endian entry, independent of a host compiler.
    fn program_header_bytes() -> [u8; 56] {
        let mut bytes = [0; 56];
        bytes[0..4].copy_from_slice(&1u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&5u32.to_le_bytes());
        bytes[8..16].copy_from_slice(&0x0000_0001_0000_1000u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&0xffff_ffff_8000_1000u64.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x0000_0002_8000_1000u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&0x123u64.to_le_bytes());
        bytes[40..48].copy_from_slice(&0x456u64.to_le_bytes());
        bytes[48..56].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes
    }

    #[test]
    fn program_types_use_elf_discriminants() {
        let cases = [
            (0, ProgramType::Unused),
            (1, ProgramType::Load),
            (2, ProgramType::Dynamic),
            (3, ProgramType::Interprete),
            (4, ProgramType::Note),
            (5, ProgramType::ShlibUnspecified),
            (6, ProgramType::ProgramHeader),
            (0x7000_0000, ProgramType::LoProc),
            (0x7fff_ffff, ProgramType::HiProc),
            (0x6474_e551, ProgramType::GnuStack),
        ];
        for (raw, expected) in cases {
            assert_eq!(ProgramType::try_from(raw).unwrap(), expected);
            assert_eq!(expected as u32, raw);
        }
    }

    #[test]
    fn unsupported_program_types_retain_the_raw_value() {
        for raw in [7, 8, 9, 0x6000_0000, 0x7000_0001, u32::MAX] {
            assert!(matches!(
                ProgramType::try_from(raw),
                Err(Error::UnsupportedProgramType(value)) if value == raw
            ));
            let mut bytes = program_header_bytes();
            bytes[..4].copy_from_slice(&raw.to_le_bytes());
            assert!(matches!(
                ProgramHeader::parse(&bytes),
                Err(Error::UnsupportedProgramType(value)) if value == raw
            ));
        }
    }

    #[test]
    fn parses_elf64_little_endian_program_header() {
        let bytes = program_header_bytes();
        // Start at an unaligned address and include bytes from a following entry.
        let mut input = vec![0xaa];
        input.extend_from_slice(&bytes);
        input.extend_from_slice(&[0xbb; 8]);
        let header = ProgramHeader::parse(&input[1..]).unwrap();
        assert_eq!(header.p_type, ProgramType::Load);
        assert_eq!(header.p_flags, 5);
        assert_eq!(header.p_offset, 0x0000_0001_0000_1000);
        assert_eq!(header.p_vaddr, 0xffff_ffff_8000_1000);
        assert_eq!(header.p_paddr, 0x0000_0002_8000_1000);
        assert_eq!(header.p_filesz, 0x123);
        assert_eq!(header.p_memsz, 0x456);
        assert_eq!(header.p_align, 0x1000);

        let header = ProgramHeader::parse(&[0; 56]).unwrap();
        assert_eq!(header.p_type, ProgramType::Unused);
        assert_eq!(header.p_flags, 0);
        assert_eq!(header.p_offset, 0);
        assert_eq!(header.p_vaddr, 0);
        assert_eq!(header.p_paddr, 0);
        assert_eq!(header.p_filesz, 0);
        assert_eq!(header.p_memsz, 0);
        assert_eq!(header.p_align, 0);
    }

    #[test]
    fn program_header_rejects_every_truncated_length() {
        let bytes = program_header_bytes();
        for len in 0..bytes.len() {
            assert!(matches!(
                ProgramHeader::parse(&bytes[..len]),
                Err(Error::TruncatedHeader)
            ));
        }
        assert!(ProgramHeader::parse(&bytes).is_ok());
    }

    #[test]
    fn program_header_permissions_follow_elf_flag_bits() {
        for flags in 0u32..8 {
            let mut bytes = program_header_bytes();
            // OS/processor-specific bits must be preserved without granting RWX.
            let raw_flags = flags | 0xf0f0_0000;
            bytes[4..8].copy_from_slice(&raw_flags.to_le_bytes());
            let header = ProgramHeader::parse(&bytes).unwrap();
            assert_eq!(header.p_flags, raw_flags);
            assert_eq!(header.is_executable(), flags & 1 != 0);
            assert_eq!(header.is_writable(), flags & 2 != 0);
            assert_eq!(header.is_readable(), flags & 4 != 0);
        }
    }
}
