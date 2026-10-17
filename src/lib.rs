//! Library to parse ELF files.

use crate::{elf::ElfHeader, parse::Parse};

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
    TruncatedHeader,
    InvalidMagic,
    UnsupportedClass,
    UnsupportedByteOrder,
    InvalidField(&'static str),
}

pub fn parse(bytes: &[u8]) -> Result<Elf<'_>, Error> {
    let header = ElfHeader::parse(bytes).unwrap();

    dbg!(header.class());
    dbg!(header.endianess());

    todo!()
}
