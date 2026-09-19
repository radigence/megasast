// rule: megasast/rust-slice-raw-parts
fn f(p: *mut u8) {
    Vec::from_raw_parts(p, 1, 1);
}
