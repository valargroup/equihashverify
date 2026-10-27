//! Test-only bridge to the pinned Common verifier. No production Rust dependency.
#![deny(unsafe_op_in_unsafe_fn)]

/// Returns 1 for valid, 0 for invalid, and -1 if the reference panics.
///
/// # Safety
/// Non-null pointers with accepted lengths must reference readable buffers for
/// the duration of the call. Null pointers and wrong lengths are rejected first.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_reference_verify(
    header: *const u8,
    header_len: usize,
    solution: *const u8,
    solution_len: usize,
) -> i32 {
    if header.is_null() || solution.is_null() || header_len != 140 || solution_len != 1344 {
        return 0;
    }
    std::panic::catch_unwind(|| {
        // SAFETY: lengths and null pointers were checked; readable storage is
        // supplied by the native differential test.
        let header = unsafe { std::slice::from_raw_parts(header, header_len) };
        let solution = unsafe { std::slice::from_raw_parts(solution, solution_len) };
        i32::from(equihash::is_valid_solution(200, 9, &header[..108], &header[108..], solution).is_ok())
    })
    .unwrap_or(-1)
}
