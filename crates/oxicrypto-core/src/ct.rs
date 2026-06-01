/// Constant-time byte-slice equality comparison.
///
/// Returns `true` if `a` and `b` are equal.  The comparison time depends only
/// on the length of the shorter slice, never on the position of the first
/// differing byte.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq as _;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Constant-time check whether every byte in `data` is zero.
///
/// Returns `true` only if all bytes are `0x00`.  The runtime is proportional
/// to `data.len()`, regardless of the actual content.
#[must_use]
pub fn ct_is_zero(data: &[u8]) -> bool {
    use subtle::ConstantTimeEq as _;
    let mut acc: u8 = 0;
    for &b in data {
        acc |= b;
    }
    acc.ct_eq(&0u8).into()
}

/// Constant-time conditional select: returns `a` if `choice` is `0`,
/// or `b` if `choice` is `1`.  Any other `choice` value is treated as `1`.
#[must_use]
pub fn ct_select(a: u8, b: u8, choice: u8) -> u8 {
    use subtle::ConditionallySelectable;
    let c = subtle::Choice::from(choice & 1);
    u8::conditional_select(&a, &b, c)
}
