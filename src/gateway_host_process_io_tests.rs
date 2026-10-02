use nix::{sys::signal::kill, unistd::Pid};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
fn child_that_never_reads_stdin_is_bounded_and_killed() {
    let root = temporary("blocked-input");
    let pid = root.join("pid");
    let command = shell(&format!("echo $$ > {}; sleep 30", pid.display()));
    let started = Instant::now();
    let result = crate::gateway_host_process_io::run(
        command,
        &vec![b'x'; 2_097_152],
        Duration::from_millis(150),
    );
    assert!(result.is_err());
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_group_gone(&pid);
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn grandchild_holding_output_pipe_is_killed_before_receive() {
    let root = temporary("grandchild");
    let pid = root.join("pid");
    let command = shell(&format!("sleep 30 & echo $! > {}; echo ok", pid.display()));
    let started = Instant::now();
    let output =
        crate::gateway_host_process_io::run(command, b"request", Duration::from_millis(500))
            .expect("bounded response");
    assert_eq!(output, b"ok\n");
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_process_gone(&pid);
    fs::remove_dir_all(root).expect("cleanup");
}

fn shell(script: &str) -> Command {
    let mut value = Command::new("/bin/sh");
    value
        .args(["-c", script])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    value
}

fn temporary(name: &str) -> std::path::PathBuf {
    let root =
        std::env::temp_dir().join(format!("crowsi-host-process-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).expect("directory");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("mode");
    root
}

fn assert_group_gone(path: &std::path::Path) {
    let pid = read_pid(path);
    for _ in 0..20 {
        if !group_has_live_member(pid) {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("process group remains: {pid}");
}

fn group_has_live_member(group: i32) -> bool {
    fs::read_dir("/proc")
        .expect("proc")
        .filter_map(Result::ok)
        .filter_map(|item| item.file_name().to_str()?.parse::<i32>().ok())
        .filter_map(|pid| fs::read_to_string(format!("/proc/{pid}/stat")).ok())
        .any(|stat| {
            let Some((_, fields)) = stat.rsplit_once(") ") else {
                return true;
            };
            let mut fields = fields.split_whitespace();
            let state = fields.next();
            let _parent = fields.next();
            let process_group = fields.next().and_then(|value| value.parse::<i32>().ok());
            process_group == Some(group) && state != Some("Z")
        })
}

fn assert_process_gone(path: &std::path::Path) {
    let pid = read_pid(path);
    for _ in 0..20 {
        if kill(Pid::from_raw(pid), None).is_err() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("process remains: {pid}");
}

fn read_pid(path: &std::path::Path) -> i32 {
    fs::read_to_string(path)
        .expect("pid")
        .trim()
        .parse()
        .expect("numeric pid")
}
