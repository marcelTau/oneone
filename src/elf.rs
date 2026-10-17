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
    /// An executable object file (`ET_EXEC`).
    EtExec = 2,
}

impl Parse for ElfType {
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let value = u16::parse(bytes)?;
        if value == Self::EtExec as u16 {
            Ok(Self::EtExec)
        } else {
            Err(Error::UnsupportedElfType(value))
        }
    }
}

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

fn parse_header_field<T: Parse>(bytes: &[u8], offset: usize) -> Result<T, Error> {
    let tail = bytes.get(offset..).ok_or(Error::TruncatedHeader)?;
    T::parse(tail).map_err(|error| match error {
        Error::TruncatedInput { .. } => Error::TruncatedHeader,
        other => other,
    })
}

impl Parse for ElfHeader {
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        use constants::*;
        let e_ident: [u8; 16] = parse_header_field(bytes, 0)?;
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
            e_type: parse_header_field(bytes, 16)?,
            e_machine: parse_header_field(bytes, 18)?,
            e_version: parse_header_field(bytes, 20)?,
            e_entry: parse_header_field(bytes, 24)?,
            e_phoff: parse_header_field(bytes, 32)?,
            e_shoff: parse_header_field(bytes, 40)?,
            e_flags: parse_header_field(bytes, 48)?,
            e_ehsize: parse_header_field(bytes, 52)?,
            e_phentsize: parse_header_field(bytes, 54)?,
            e_phnum: parse_header_field(bytes, 56)?,
            e_shentsize: parse_header_field(bytes, 58)?,
            e_shnum: parse_header_field(bytes, 60)?,
            e_shstrndx: parse_header_field(bytes, 62)?,
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
