// rule: megasast/rust-mem-zeroed
fn f() {
    let x: u8 = mem::zeroed();
}
