//! `SCM_RIGHTS` fd passing over a `AF_UNIX` socket -- used for the fd-5
//! rendezvous between `sandbox_entry.rs` (installs the seccomp-notify
//! filter inside the sandboxed child, sends the resulting notify fd back)
//! and `executor.rs` (receives it in Guardian's own process, hands it to
//! `notify.rs`'s supervisor). Same marshaling shape as the standalone C
//! seccomp-notify test harness this design was validated against.

use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

pub fn send_fd(sock_fd: RawFd, fd: RawFd) -> io::Result<()> {
    let payload = [0u8; 1];
    let iov = libc::iovec { iov_base: payload.as_ptr() as *mut _, iov_len: 1 };

    let mut cbuf = [0u8; unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize }];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &iov as *const _ as *mut _;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut _;
    msg.msg_controllen = cbuf.len();

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::copy_nonoverlapping(&fd as *const RawFd as *const u8, libc::CMSG_DATA(cmsg), std::mem::size_of::<RawFd>());
    }

    let rc = unsafe { libc::sendmsg(sock_fd, &msg, 0) };
    if rc < 0 { return Err(io::Error::last_os_error()); }
    Ok(())
}

pub fn recv_fd(sock_fd: RawFd) -> io::Result<OwnedFd> {
    let mut payload = [0u8; 1];
    let iov = libc::iovec { iov_base: payload.as_mut_ptr() as *mut _, iov_len: 1 };

    let mut cbuf = [0u8; unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize }];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &iov as *const _ as *mut _;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut _;
    msg.msg_controllen = cbuf.len();

    let rc = unsafe { libc::recvmsg(sock_fd, &mut msg, 0) };
    if rc < 0 { return Err(io::Error::last_os_error()); }
    if rc == 0 {
        // A clean EOF (peer closed without ever sending) is not a syscall
        // error -- errno is not meaningfully set on a 0 return, so
        // last_os_error() here would report whatever stale value happens
        // to be sitting in thread-local errno from an unrelated earlier
        // call, not the real cause. Report it as what it actually is.
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "recv_fd: peer closed the socket without sending an fd",
        ));
    }

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "recv_fd: no control message received"));
    }
    let mut fd: RawFd = -1;
    unsafe {
        std::ptr::copy_nonoverlapping(libc::CMSG_DATA(cmsg), &mut fd as *mut RawFd as *mut u8, std::mem::size_of::<RawFd>());
    }
    if fd < 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "recv_fd: no fd in control message"));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
