use oneone::parse;

fn main() -> Result<(), String> {
    let bytes =
        std::fs::read("test.bin").map_err(|error| format!("failed to read test.bin: {error}"))?;
    let _elf = parse(&bytes).map_err(|error| format!("failed to parse test.bin: {error:?}"))?;

    Ok(())
}
