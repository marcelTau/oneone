use crate::Error;

/// Parse an owned value from the beginning of a borrowed byte slice.
///
/// Parsing leaves the input unchanged. Fixed-size values accept trailing bytes
/// and return [`ElfError::TruncatedInput`] if their encoding is incomplete.
/// Integer implementations decode little-endian bytes independently of the host.
/// Larger types can also validate data referenced by their fields: [`ElfHeader`]
/// expects complete file bytes to check its declared header tables.
pub(crate) trait Parse: Sized {
    /// Decode and validate a value without allocation or file I/O.
    fn parse(bytes: &[u8]) -> Result<Self, Error>;
}

impl<const N: usize> Parse for [u8; N] {
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        bytes
            .get(..N)
            .and_then(|field| field.try_into().ok())
            .ok_or(Error::TruncatedInput {
                needed: N,
                available: bytes.len(),
            })
    }
}

impl Parse for u8 {
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        Ok(<[u8; 1]>::parse(bytes)?[0])
    }
}

impl Parse for u16 {
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_le_bytes(<[u8; 2]>::parse(bytes)?))
    }
}

impl Parse for u32 {
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_le_bytes(<[u8; 4]>::parse(bytes)?))
    }
}

impl Parse for u64 {
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_le_bytes(<[u8; 8]>::parse(bytes)?))
    }
}
