// rule: megasast/rust-command
use std::process::Command;

fn f() {
    let _ = Command::new("ls");
}
