// rule: megasast/rust-unsafe
fn f(p: *const u8) {
    unsafe {
        std::ptr::read(p);
    }
}
