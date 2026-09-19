// rule: megasast/rust-from-utf8-unchecked
fn f(v: Vec<u8>) {
    String::from_utf8_unchecked(v);
}
