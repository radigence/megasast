// rule: megasast/rust-transmute
fn f(raw: u32) {
    let value = std::mem::transmute(raw);
}
