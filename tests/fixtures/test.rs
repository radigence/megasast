use std::process::Command;

fn main() {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(user_input);
    let output = cmd.output().unwrap();
    let x = std::process::Command::new("ls");
    let raw = unsafe { std::ptr::read(ptr) };
    let value = std::mem::transmute(raw);
    println!("{:?} {:?}", output, value);
}
