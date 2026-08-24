// DIAGNOSTIC BINARY -- not part of the shipped product, not built into the
// `solarplex-guardian` binary (separate `src/bin/` entry, no shared code).
//
// STATUS as of the last live test on a real kernel: this reproduces the
// open bug. `notif_addfd`'s ioctl returns success (fd correctly installed
// in the tracee's fd table) but the tracee (confirmed via `/proc/<pid>/stack`)
// never leaves `seccomp_do_user_notification` -- it stays blocked forever.
// The same result was independently reproduced through the full
// notify.rs/io_uring event loop, so this file exists to bisect whether that
// event loop was the cause (it isn't -- this minimal, io_uring-free, plain
// blocking poll() harness hits the exact same symptom). Ruled out so far,
// via direct kernel-level testing on the same box: two-filter composition,
// Landlock, PID/net/IPC namespaces (individually and combined),
// exec-persistence, tokio threading in sandbox_entry, command complexity
// (reproduces with a bare `cat`, no shell chain), multi- vs single-syscall
// BPF filter (byte-identical to a known-working standalone C probe),
// AppArmor's bwrap/unpriv_bwrap profile (reproduces identically in complain
// mode), and IMA/EVM (no policy loaded on this kernel, inert). Root cause
// still open -- see project memory / session notes for the full writeup.
//
// Usage: notify_minimal_probe <bwrap-path> <guardian-binary-path> <target-file>

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;

#[repr(C)]
#[derive(Default)]
struct SeccompNotif {
    id: u64,
    pid: u32,
    flags: u32,
    nr: i32,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

#[repr(C)]
struct SeccompNotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

#[repr(C)]
struct SeccompNotifAddfd {
    id: u64,
    flags: u32,
    srcfd: u32,
    newfd: u32,
    newfd_flags: u32,
}

const SECCOMP_ADDFD_FLAG_SEND: u32 = 1 << 0;
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1 << 0;

const fn ioc(dir: u32, ty: u32, nr: u32, size: u32) -> u64 {
    ((dir as u64) << 30) | ((ty as u64) << 8) | (nr as u64) | ((size as u64) << 16)
}
const SECCOMP_IOCTL_NOTIF_ID_VALID: u64 = ioc(1, b'!' as u32, 2, 8);
const SECCOMP_IOCTL_NOTIF_ADDFD: u64 = ioc(1, b'!' as u32, 3, 24);

struct NotifSizes { recv: u64, send: u64 }
fn notif_ioctls() -> NotifSizes {
    #[repr(C)]
    struct Sizes { seccomp_notif: u16, seccomp_notif_resp: u16, seccomp_data: u16 }
    let mut sizes = Sizes { seccomp_notif: 0, seccomp_notif_resp: 0, seccomp_data: 0 };
    let rc = unsafe { libc::syscall(libc::SYS_seccomp, 3u32, 0u32, &mut sizes as *mut Sizes) };
    assert!(rc == 0, "SECCOMP_GET_NOTIF_SIZES failed");
    NotifSizes {
        recv: ioc(3, b'!' as u32, 0, sizes.seccomp_notif as u32),
        send: ioc(3, b'!' as u32, 1, sizes.seccomp_notif_resp as u32),
    }
}

fn notif_recv(fd: RawFd, ioctls: &NotifSizes) -> io::Result<SeccompNotif> {
    let mut req = SeccompNotif::default();
    let rc = unsafe { libc::ioctl(fd, ioctls.recv, &mut req as *mut SeccompNotif) };
    if rc < 0 { return Err(io::Error::last_os_error()); }
    Ok(req)
}
fn notif_id_valid(fd: RawFd, id: u64) -> io::Result<()> {
    let rc = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id as *const u64) };
    if rc < 0 { return Err(io::Error::last_os_error()); }
    Ok(())
}
fn notif_continue(fd: RawFd, id: u64, ioctls: &NotifSizes) -> io::Result<()> {
    let resp = SeccompNotifResp { id, val: 0, error: 0, flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE };
    let rc = unsafe { libc::ioctl(fd, ioctls.send, &resp as *const SeccompNotifResp) };
    if rc < 0 { return Err(io::Error::last_os_error()); }
    Ok(())
}
fn notif_addfd(fd: RawFd, id: u64, src_fd: RawFd) -> io::Result<i32> {
    let addfd = SeccompNotifAddfd { id, flags: SECCOMP_ADDFD_FLAG_SEND, srcfd: src_fd as u32, newfd: 0, newfd_flags: libc::O_CLOEXEC as u32 };
    let rc = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd as *const SeccompNotifAddfd) };
    if rc < 0 { return Err(io::Error::last_os_error()); }
    Ok(rc)
}

fn read_tracee_cstring(pid: u32, addr: u64) -> Option<String> {
    use std::os::unix::fs::FileExt;
    let f = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
    let mut buf = [0u8; 512];
    let n = f.read_at(&mut buf, addr).ok()?;
    let nul = buf[..n].iter().position(|&b| b == 0)?;
    String::from_utf8(buf[..nul].to_vec()).ok()
}

// Matches fd_passing.rs's SCM_RIGHTS recv, trimmed to just what's needed.
fn recv_fd(sock_fd: RawFd) -> io::Result<OwnedFd> {
    let mut iobuf = [0u8; 1];
    let mut iov = libc::iovec { iov_base: iobuf.as_mut_ptr() as *mut _, iov_len: 1 };
    let mut cbuf = [0u8; 64];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut _;
    msg.msg_controllen = cbuf.len();
    let rc = unsafe { libc::recvmsg(sock_fd, &mut msg, 0) };
    if rc < 0 { return Err(io::Error::last_os_error()); }
    if rc == 0 { return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed")); }
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        assert!(!cmsg.is_null(), "no cmsg");
        let data = libc::CMSG_DATA(cmsg) as *const i32;
        let fd = *data;
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let bwrap = &args[1];
    let guardian_bin = &args[2];
    let target_file = &args[3];

    let mut sv = [0i32; 2];
    unsafe { assert_eq!(libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()), 0); }
    let (parent_end, child_end) = (sv[0], sv[1]);

    let mut cmd = std::process::Command::new(bwrap);
    cmd.args([
        "--ro-bind", "/", "/",
        "--tmpfs", "/tmp",
        "--dev", "/dev",
        "--proc", "/proc",
        "--bind", target_file, target_file,
        "--unshare-net", "--unshare-pid", "--unshare-ipc",
        "--",
        guardian_bin, "sandbox-entry",
        "--no-network",
        "--file-effect", &format!("w:-:-:{target_file}"),
        "--",
        "cat", target_file,
    ]);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    unsafe {
        cmd.pre_exec(move || {
            libc::close(parent_end);
            if libc::dup2(child_end, 5) < 0 { return Err(io::Error::last_os_error()); }
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    unsafe { libc::close(child_end); }

    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id() as libc::pid_t, 0) } as RawFd;
    assert!(pidfd >= 0, "pidfd_open failed");

    eprintln!("MINIMAL-PROBE: waiting for notify_fd over fd-5 rendezvous...");
    let notify_fd_owned = recv_fd(parent_end)?;
    let notify_fd = notify_fd_owned.as_raw_fd();
    eprintln!("MINIMAL-PROBE: got notify_fd={notify_fd}, entering blocking poll loop");

    let ioctls = notif_ioctls();
    let mut stdout_pipe = child.stdout.take().unwrap();
    let mut stderr_pipe = child.stderr.take().unwrap();

    loop {
        let mut fds = [
            libc::pollfd { fd: pidfd, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: notify_fd, events: libc::POLLIN, revents: 0 },
        ];
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 5000) };
        if rc < 0 { return Err(io::Error::last_os_error().into()); }
        if rc == 0 {
            eprintln!("MINIMAL-PROBE: poll timeout, no activity in 5s -- treating as hang");
            break;
        }
        if fds[0].revents & libc::POLLIN != 0 {
            eprintln!("MINIMAL-PROBE: pidfd readable -- child exited, done");
            break;
        }
        if fds[1].revents & libc::POLLIN != 0 {
            let req = match notif_recv(notify_fd, &ioctls) {
                Ok(r) => r,
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
                Err(e) => return Err(e.into()),
            };
            if notif_id_valid(notify_fd, req.id).is_err() { continue; }
            let nr_openat = libc::SYS_openat;
            let is_openat = req.nr as i64 == nr_openat;
            let path = if is_openat { read_tracee_cstring(req.pid, req.args[1]) } else { None };
            let matches = path.as_deref().map(|p| p.ends_with(target_file.rsplit('/').next().unwrap())).unwrap_or(false);
            if matches {
                let real_path = target_file.clone();
                match std::fs::File::open(&real_path) {
                    Ok(file) => {
                        let r = notif_addfd(notify_fd, req.id, file.as_raw_fd());
                        eprintln!("MINIMAL-PROBE: ADDFD pid={} path={} result={:?}", req.pid, real_path, r);
                    }
                    Err(e) => {
                        eprintln!("MINIMAL-PROBE: open failed: {e}, CONTINUE instead");
                        let _ = notif_continue(notify_fd, req.id, &ioctls);
                    }
                }
            } else {
                let _ = notif_continue(notify_fd, req.id, &ioctls);
            }
        }
    }

    // Drain and print whatever we got.
    use std::io::Read;
    let mut out = String::new();
    let _ = stdout_pipe.read_to_string(&mut out);
    let mut err = String::new();
    let _ = stderr_pipe.read_to_string(&mut err);
    eprintln!("MINIMAL-PROBE: final stdout={out:?} stderr={err:?}");

    let _ = child.kill();
    let _ = child.wait();
    Ok(())
}
