fn terminate_group(child: &mut Child) {
    kill_group(child, Signal::SIGTERM);
    let exited = child
        .wait_timeout(Duration::from_millis(100))
        .ok()
        .flatten()
        .is_some();
    if exited {
        kill_group(child, Signal::SIGKILL);
    } else {
        kill_group(child, Signal::SIGKILL);
        let _ = child.wait();
    }
}

fn kill_group(child: &Child, signal: Signal) {
    let group = Pid::from_raw(child.id().try_into().unwrap_or(i32::MAX));
    let _ = killpg(group, signal);
}
