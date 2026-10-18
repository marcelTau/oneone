use crate::{parse::Parse, Error};

mod constants {
    pub(crate) const MAGIC: &[u8; 4] = b"\x7fELF";
    pub(crate) const EI_CLASS: usize = 4;
    pub(crate) const EI_DATA: usize = 5;
    pub(crate) const EI_VERSION: usize = 6;
    pub(crate) const ELFCLASS64: u8 = 2;
    pub(crate) const ELFDATA2LSB: u8 = 1;
    pub(crate) const EV_CURRENT: u8 = 1;
    pub(crate) const ELF64_EHDR_SIZE: u16 = 64;
    pub(crate) const ELF64_PHDR_SIZE: u16 = 56;
    pub(crate) const ELF64_SHDR_SIZE: u16 = 64;
    pub(crate) const PN_XNUM: u16 = 0xffff;
    pub(crate) const SHN_UNDEF: u16 = 0;
    pub(crate) const SHN_LORESERVE: u16 = 0xff00;
    pub(crate) const SHN_XINDEX: u16 = 0xffff;
}

/// ELF object types currently relevant to this loader.
///
/// Only executable (`ET_EXEC`) objects are supported for now. Add other types
/// when needed; parsing their values currently returns [`ElfError::UnsupportedElfType`].
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
#[repr(u16)]
pub enum ElfType {
    Unknown = 0,
    Relocatable = 1,
    Executable = 2,
    SharedObject = 3,
    Core = 4,
}

impl Parse for ElfType {
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let value = u16::parse(bytes)?;
        if value == Self::Executable as u16 {
            Ok(Self::Executable)
        } else {
            Err(Error::UnsupportedElfType(value))
        }
    }
}

/// The ELF header is always at offset 0 of the file. It defines some metadata about the file and
/// the two most important concepts Program header table and Section header table which describe
/// the rest of the file.
#[derive(Debug)]
pub(crate) struct ElfHeader {
    /// Magic, class, byte order, version, OS ABI, ABI version, and padding.
    pub e_ident: [u8; 16],
    /// Supported object file type (currently only [`ElfType::EtExec`]).
    pub e_type: ElfType,
    /// Target machine (for example, 62 = x86-64, 243 = RISC-V).
    pub e_machine: u16,
    /// ELF format version.
    pub e_version: u32,
    /// Target virtual address of the entry point.
    pub e_entry: u64,
    /// File offset of the program header table.
    pub e_phoff: u64,
    /// File offset of the section header table.
    pub e_shoff: u64,
    /// Machine-specific flags.
    pub e_flags: u32,
    /// ELF header size in bytes.
    pub e_ehsize: u16,
    /// Program header entry size in bytes.
    pub e_phentsize: u16,
    /// Number of program header entries.
    pub e_phnum: u16,
    /// Section header entry size in bytes.
    pub e_shentsize: u16,
    /// Number of section header entries.
    pub e_shnum: u16,
    /// Section name string table index, or zero when absent.
    pub e_shstrndx: u16,
}

fn parse_field<T: Parse>(bytes: &[u8], offset: usize) -> Result<T, Error> {
    let tail = bytes.get(offset..).ok_or(Error::TruncatedHeader)?;
    T::parse(tail).map_err(|error| match error {
        Error::TruncatedInput { .. } => Error::TruncatedHeader,
        other => other,
    })
}

impl Parse for ElfHeader {
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        use constants::*;
        let e_ident: [u8; 16] = parse_field(bytes, 0)?;
        if &e_ident[..MAGIC.len()] != constants::MAGIC {
            return Err(Error::InvalidMagic);
        }
        if e_ident[EI_CLASS] != ELFCLASS64 {
            return Err(Error::UnsupportedClass);
        }
        if e_ident[EI_DATA] != ELFDATA2LSB {
            return Err(Error::UnsupportedByteOrder);
        }

        // These byte offsets are the ELF64 on-disk layout, not Rust field offsets.
        let header = Self {
            e_ident,
            e_type: parse_field(bytes, 16)?,
            e_machine: parse_field(bytes, 18)?,
            e_version: parse_field(bytes, 20)?,
            e_entry: parse_field(bytes, 24)?,
            e_phoff: parse_field(bytes, 32)?,
            e_shoff: parse_field(bytes, 40)?,
            e_flags: parse_field(bytes, 48)?,
            e_ehsize: parse_field(bytes, 52)?,
            e_phentsize: parse_field(bytes, 54)?,
            e_phnum: parse_field(bytes, 56)?,
            e_shentsize: parse_field(bytes, 58)?,
            e_shnum: parse_field(bytes, 60)?,
            e_shstrndx: parse_field(bytes, 62)?,
        };

        if header.e_ehsize != ELF64_EHDR_SIZE {
            return Err(Error::InvalidField("e_ehsize"));
        }

        Ok(header)
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum Architecture {
    Invalid,
    Class32,
    Class64,
}

impl From<u8> for Architecture {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Class32,
            2 => Self::Class64,
            _ => Self::Invalid,
        }
    }
}

#[derive(Debug)]
#[repr(u8)]
pub enum Endianess {
    Unknown,
    LittleEndian,
    BigEndian,
}

impl From<u8> for Endianess {
    fn from(value: u8) -> Self {
        match value {
            1 => Endianess::LittleEndian,
            2 => Endianess::BigEndian,
            _ => Endianess::Unknown,
        }
    }
}

impl ElfHeader {
    pub fn class(&self) -> Architecture {
        self.e_ident[constants::EI_CLASS].into()
    }

    pub fn endianess(&self) -> Endianess {
        self.e_ident[constants::EI_DATA].into()
    }
}

/// Program types recognized by the parser; recognition does not imply loading support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum ProgramType {
    Unused = 0,
    /// A loadable segment described by p_filesz and p_memsz.
    Load = 1,
    Dynamic = 2,
    Interprete = 3,
    Note = 4,
    ShlibUnspecified = 5,
    ProgramHeader = 6,

    IgnoredForNow,
    LoProc = 0x7000_0000,
    HiProc = 0x7fff_ffff,
    GnuStack = 0x6474_e551,

    /// Can be ignored when building for risc-v
    GnuProperties = 0x6474_e553,
}

impl TryFrom<u32> for ProgramType {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Unused),
            1 => Ok(Self::Load),
            2 => Ok(Self::Dynamic),
            3 => Ok(Self::Interprete),
            4 => Ok(Self::Note),
            5 => Ok(Self::ShlibUnspecified),
            6 => Ok(Self::ProgramHeader),
            v if v >= 0x6474_e551 => Ok(Self::IgnoredForNow),
            // 0x6474_e553 => Ok(Self::GnuProperties),
            // 0x7000_0000 => Ok(Self::LoProc),
            // 0x7fff_ffff => Ok(Self::HiProc),
            // 0x6474_e551 => Ok(Self::GnuStack),
            other => Err(Error::UnsupportedProgramType(other)),
        }
    }
}

/// An ELF64 little-endian program header, meaningful for executables and shared objects.
///
/// Parsing reads one 56-byte entry without allocation and accepts trailing bytes.
/// It rejects truncated entries and unsupported types, but does not validate the
/// referenced segment's file bounds, address ranges, or loading requirements.
#[derive(Debug)]
pub(crate) struct ProgramHeader {
    pub(crate) p_type: ProgramType,

    /// Contains a bitmask of RWX permissions.
    pub(crate) p_flags: u32,

    /// Offset from the beginning of the file to the first byte of the segment.
    pub(crate) p_offset: u64,

    /// Virtual address of the first byte of the segment.
    pub(crate) p_vaddr: u64,

    /// Must be 0 if physical addressing is not relevant.
    pub(crate) p_paddr: u64,

    /// Number of bytes in the elf-file image of the segment.
    pub(crate) p_filesz: u64,

    /// Number of bytes in the memory image of the segment starting at p_vaddr.
    pub(crate) p_memsz: u64,
    pub(crate) p_align: u64,
}

impl ProgramHeader {
    pub(crate) fn is_readable(&self) -> bool {
        self.p_flags & (1 << 2) != 0
    }

    pub(crate) fn is_writable(&self) -> bool {
        self.p_flags & (1 << 1) != 0
    }

    pub(crate) fn is_executable(&self) -> bool {
        self.p_flags & 1 != 0
    }
}

impl Parse for ProgramHeader {
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        // Require a complete ELF64 entry, independently of Rust's struct layout.
        let bytes = bytes
            .get(..usize::from(constants::ELF64_PHDR_SIZE))
            .ok_or(Error::TruncatedHeader)?;

        Ok(Self {
            p_type: u32::parse(bytes)?.try_into()?,
            p_flags: parse_field(bytes, 4)?,
            p_offset: parse_field(bytes, 8)?,
            p_vaddr: parse_field(bytes, 16)?,
            p_paddr: parse_field(bytes, 24)?,
            p_filesz: parse_field(bytes, 32)?,
            p_memsz: parse_field(bytes, 40)?,
            p_align: parse_field(bytes, 48)?,
        })
    }
}

#[derive(Debug)]
pub(crate) struct ProgramHeaderTable {
    table: Vec<ProgramHeader>,
}

impl ProgramHeaderTable {
    pub(crate) fn parse(bytes: &[u8], entries: u16, entry_size: u16) -> Result<Self, Error> {
        let mut table = Vec::new();

        for n in 0..entries {
            let start = (n * entry_size) as usize;
            let end = start + entry_size as usize;
            table.push(ProgramHeader::parse(&bytes[start..end])?);
        }

        Ok(Self { table })
    }
}
