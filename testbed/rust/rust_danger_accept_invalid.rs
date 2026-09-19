// rule: megasast/rust-danger-accept-invalid
fn f() {
    Client::builder().danger_accept_invalid_certs(true);
}
