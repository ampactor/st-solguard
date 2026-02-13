// Minimal safe Rust code — should produce zero scanner findings.

pub fn safe_add(a: u64, b: u64) -> Option<u64> {
    a.checked_add(b)
}

pub fn safe_sub(a: u64, b: u64) -> Option<u64> {
    a.checked_sub(b)
}

pub struct Config {
    pub name: String,
    pub version: u32,
}
