//! Raw seccomp-notify FFI: struct layouts, ioctl request codes, and BPF
//! filter construction for the `SECCOMP_FILTER_FLAG_NEW_LISTENER` +
//! `SECCOMP_IOCTL_NOTIF_*` mechanism.
//!
//! Hand-rolled rather than built on a crate, and deliberately so: `libc`
//! wraps `seccomp(2)` but not the notify ioctls (they're too new/narrow a
//! surface for a general-purpose libc crate), and `seccompiler` (used
//! elsewhere in this module for the classic BASELINE_DENY/NETWORK_DENY/
//! SUBPROCESS_DENY filter) has no `SECCOMP_RET_USER_NOTIF` action and no way
//! to request `NEW_LISTENER` at all (confirmed against its own docs before
//! deciding to hand-roll this instead of guessing at an unfamiliar crate's
//! API for a security-critical filter). Every struct and constant here
//! mirrors the exact shapes already validated end-to-end on a real kernel by
//! the standalone C seccomp-notify test harness earlier this project
//! (broker holds a pidfd, validates NOTIF_ID_VALID, injects an fd via
//! NOTIF_ADDFD+SEND) — this is a direct Rust port of proven-working C, not a
//! fresh design.
//!
//! Two independently-installed filters are layered rather than merged into
//! one BPF program: the existing `seccompiler`-built classic filter
//! (unchanged, still handles BASELINE_DENY/NETWORK_DENY/SUBPROCESS_DENY via
//! plain `SECCOMP_RET_ERRNO`) and a small filter installed here with
//! `NEW_LISTENER`, covering only the pathname syscalls that need live
//! mediation. Seccomp filters compose: the kernel evaluates every attached
//! filter per syscall and the most-restrictive return value wins (per the
//! documented precedence order, `ERRNO` outranks `USER_NOTIF` outranks
//! `ALLOW`), so a syscall denied by the classic filter stays denied
//! regardless of what this filter says about it, and this filter only ever
//! needs to say "notify" for the syscalls it actually cares about and
//! "allow" for everything else.

use std::io;
use std::mem::size_of;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

// ── struct seccomp_data (what the BPF program reads) ──────────────────────

// Byte-offset layout of the kernel's `struct seccomp_data`, for the raw
// LD|ABS BPF instructions in `build_notify_filter_program` below (which
// read directly from that struct's wire layout) and for the test module's
// interpreter. Only `nr`/`arch` are ever read by the BPF program itself --
// this filter's own decision never inspects `args` (the actual pathname
// argument is read later, once, from `/proc/<pid>/mem` by `notify.rs`, not
// by the BPF program), so only those two fields' offsets are named here.
#[repr(C)]
#[allow(dead_code)] // constructed only under #[cfg(test)]; documents the C layout either way
struct SeccompData {
    nr: i32,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

// ── raw classic BPF program (used only to build the NEW_LISTENER filter --
// the classic deny filter itself is still built by seccompiler, unchanged) ─

#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;

const fn bpf_stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code: code | BPF_K,
        jt: 0,
        jf: 0,
        k,
    }
}
const fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter {
        code: code | BPF_K,
        jt,
        jf,
        k,
    }
}

const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

const SECCOMP_SET_MODE_FILTER: u32 = 1;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: u32 = 1 << 3;

/// Pure construction of the BPF instruction list -- factored out from
/// `install_notify_filter` specifically so the jump-offset logic can be
/// unit-tested without a live kernel (see the tests module). All syscall
/// numbers are assumed to already belong to this arch (caller resolves via
/// `libc::SYS_*`, itself arch-gated by the `libc` crate).
fn build_notify_filter_program(notify_syscalls: &[i64]) -> Vec<SockFilter> {
    let mut prog: Vec<SockFilter> = Vec::with_capacity(4 + notify_syscalls.len());

    // Arch check first, same as the working C probe: refuse to even
    // consider this filter's jump table under a different audit
    // architecture (e.g. a 32-bit compat syscall entry) rather than
    // silently mis-evaluating syscall numbers that mean something
    // different there.
    prog.push(bpf_stmt(BPF_LD | BPF_ABS | BPF_W, SECCOMP_DATA_ARCH_OFFSET));
    prog.push(bpf_jump(BPF_JMP | BPF_JEQ, AUDIT_ARCH_X86_64, 1, 0));
    prog.push(bpf_stmt(BPF_RET, SECCOMP_RET_KILL_PROCESS));

    // One JEQ per notify syscall, all sharing a single trailing RET
    // ALLOW / RET USER_NOTIF pair rather than one RET-pair per syscall (an
    // earlier draft of this function emitted a RET ALLOW right after each
    // JEQ with no RET USER_NOTIF anywhere -- a match would skip past that
    // RET ALLOW and land on either the *next* syscall's JEQ or the final
    // fallthrough, never on a notify return, so the filter would have
    // compiled and installed cleanly while silently notifying nothing at
    // all. Caught by tracing the jump offsets by hand before this ever
    // touched a real kernel.
    //
    // For syscall index i of n total: on match, jump forward far enough to
    // clear every remaining JEQ (n-1-i of them) plus the trailing RET
    // ALLOW, landing exactly on RET USER_NOTIF -- i.e. jt = n - i. On no
    // match (jf=0), fall through to the next syscall's JEQ. The last
    // syscall (i = n-1) reduces to jt=1, skipping just the one RET ALLOW
    // directly below it.
    let n = notify_syscalls.len();
    prog.push(bpf_stmt(BPF_LD | BPF_ABS | BPF_W, SECCOMP_DATA_NR_OFFSET));
    for (i, &nr) in notify_syscalls.iter().enumerate() {
        let jt = (n - i) as u8;
        prog.push(bpf_jump(BPF_JMP | BPF_JEQ, nr as u32, jt, 0));
    }
    prog.push(bpf_stmt(BPF_RET, SECCOMP_RET_ALLOW)); // nothing matched
    prog.push(bpf_stmt(BPF_RET, SECCOMP_RET_USER_NOTIF)); // landing spot for any match

    prog
}

/// Builds and installs a small `NEW_LISTENER` filter: the given syscall
/// numbers notify; everything else allows. Layered on top of the existing
/// classic deny filter, which stays authoritative for anything it denies
/// (see the module doc for why this composition is safe). Returns the
/// notify fd.
pub fn install_notify_filter(notify_syscalls: &[i64]) -> io::Result<OwnedFd> {
    let prog = build_notify_filter_program(notify_syscalls);
    let fprog = SockFprog {
        len: prog.len() as u16,
        filter: prog.as_ptr(),
    };

    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &fprog as *const SockFprog,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // rc is the notify fd on success (NEW_LISTENER's documented return value).
    Ok(unsafe { OwnedFd::from_raw_fd(rc as RawFd) })
}

// ── seccomp-notify ioctl structs (mirror <linux/seccomp.h> exactly) ───────

#[repr(C)]
#[derive(Default)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    nr: i32,
    arch: u32,
    instruction_pointer: u64,
    pub args: [u64; 6],
}

impl SeccompNotif {
    pub fn syscall_nr(&self) -> i64 {
        self.nr as i64
    }
}

#[repr(C)]
#[derive(Default)]
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

// ROOT CAUSE of the long-standing "ADDFD reports success but the tracee
// never wakes" bug: this was `1 << 0` (the value for
// SECCOMP_ADDFD_FLAG_SETFD -- "install at exactly this fd number") for
// most of this project's history. The real kernel value, confirmed
// directly against include/uapi/linux/seccomp.h, is `1 << 1`:
//   #define SECCOMP_ADDFD_FLAG_SETFD (1UL << 0) /* Specify remote fd */
//   #define SECCOMP_ADDFD_FLAG_SEND  (1UL << 1) /* Addfd and return it, atomically */
// With the wrong bit set and `newfd: 0` always passed (see notif_addfd
// below), every call was silently interpreted as "install at fd 0
// specifically" (matching the observed fd=0-every-time symptom exactly)
// and never atomically responded to the notification at all -- which is
// exactly why the tracee stayed parked in seccomp_do_user_notification
// forever. The standalone C probe that "proved this mechanism worked"
// happened to get the correct value anyway: its own fallback #define for
// this constant was *also* `1 << 0`, but sat inside an
// `#ifndef SECCOMP_IOCTL_NOTIF_ADDFD` guard, so on a kernel new enough to
// have this constant in its own <linux/seccomp.h>, that fallback was
// never compiled in -- the system header's correct value silently won.
// Rust has no equivalent "prefer the system's own definition" mechanism,
// so this hardcoded value was always what actually ran here.
pub const SECCOMP_ADDFD_FLAG_SEND: u32 = 1 << 1;
pub const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1 << 0;

const fn ioc(dir: u32, ty: u32, nr: u32, size: u32) -> u64 {
    ((dir as u64) << 30) | ((ty as u64) << 8) | (nr as u64) | ((size as u64) << 16)
}
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;
const SECCOMP_IOC_MAGIC: u32 = b'!' as u32;

// RECV/SEND ioctl numbers are NOT hardcoded from `size_of` here -- the
// kernel's `seccomp_notif`/`seccomp_notif_resp` structs are explicitly
// versioned and allowed to grow across kernel releases (that's the whole
// reason `SECCOMP_GET_NOTIF_SIZES` exists), so a compile-time guess at
// their size risks silently encoding the wrong ioctl request number on a
// kernel newer than whatever this was written against. Queried once, at
// first use, from the running kernel instead. ID_VALID's payload is a bare
// u64 (not a kernel-versioned struct) so it's stable and fine to compute
// directly. ADDFD has no query mechanism at all (`seccomp_notif_sizes` only
// ever gained three fields: notif/resp/data, never addfd) -- its layout
// here mirrors the exact struct already validated against a real running
// kernel by the standalone C test harness, the best available confidence
// short of a kernel-provided size query that doesn't exist for it.
const SECCOMP_IOCTL_NOTIF_ID_VALID: u64 =
    ioc(IOC_WRITE, SECCOMP_IOC_MAGIC, 2, size_of::<u64>() as u32);
const SECCOMP_IOCTL_NOTIF_ADDFD: u64 = ioc(
    IOC_WRITE,
    SECCOMP_IOC_MAGIC,
    3,
    size_of::<SeccompNotifAddfd>() as u32,
);

const SECCOMP_GET_NOTIF_SIZES: u32 = 3; // seccomp(2) operation (not SET_MODE_FILTER)

#[repr(C)]
#[derive(Default)]
struct SeccompNotifSizes {
    seccomp_notif: u16,
    seccomp_notif_resp: u16,
    seccomp_data: u16,
}

struct NotifIoctls {
    recv: u64,
    send: u64,
}

fn notif_ioctls() -> io::Result<&'static NotifIoctls> {
    static CELL: std::sync::OnceLock<io::Result<NotifIoctls>> = std::sync::OnceLock::new();
    CELL.get_or_init(|| {
        let mut sizes = SeccompNotifSizes::default();
        let rc = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_GET_NOTIF_SIZES,
                0u32,
                &mut sizes as *mut SeccompNotifSizes,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(NotifIoctls {
            recv: ioc(
                IOC_READ | IOC_WRITE,
                SECCOMP_IOC_MAGIC,
                0,
                sizes.seccomp_notif as u32,
            ),
            send: ioc(
                IOC_READ | IOC_WRITE,
                SECCOMP_IOC_MAGIC,
                1,
                sizes.seccomp_notif_resp as u32,
            ),
        })
    })
    .as_ref()
    .map_err(|e| io::Error::new(e.kind(), e.to_string()))
}

/// Blocks until a notification is available. Call only when the notify fd's
/// readiness has already been signalled (by the io_uring poll in
/// `notify.rs`) -- this itself does not poll.
pub fn notif_recv(notify_fd: RawFd) -> io::Result<SeccompNotif> {
    let ioctls = notif_ioctls()?;
    let mut req = SeccompNotif::default();
    let rc = unsafe { libc::ioctl(notify_fd, ioctls.recv, &mut req as *mut SeccompNotif) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(req)
}

/// Defends the documented PID-reuse race: confirms `id` is still live
/// before acting on anything derived from it (the pid, the resolved path).
/// A stale/invalid id means the tracee already went away and any decision
/// made from this notification would be meaningless (or, worse, could be
/// misattributed to a *different*, later process reusing the same pid).
pub fn notif_id_valid(notify_fd: RawFd, id: u64) -> io::Result<()> {
    let rc = unsafe { libc::ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id as *const u64) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Lets the real syscall proceed normally (Landlock, installed independently
/// and unchanged, is the actual enforcement boundary for whatever this
/// resolves to -- see the module doc).
pub fn notif_continue(notify_fd: RawFd, id: u64) -> io::Result<()> {
    let ioctls = notif_ioctls()?;
    let resp = SeccompNotifResp {
        id,
        val: 0,
        error: 0,
        flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    };
    let rc = unsafe { libc::ioctl(notify_fd, ioctls.send, &resp as *const SeccompNotifResp) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Denies the syscall outright with the given errno (used when a path
/// resolves to something that should never have been asked for at all --
/// distinct from the ordinary "not one of ours, let Landlock decide" case,
/// which uses `notif_continue` instead).
pub fn notif_deny(notify_fd: RawFd, id: u64, errno: i32) -> io::Result<()> {
    let ioctls = notif_ioctls()?;
    let resp = SeccompNotifResp {
        id,
        val: -1,
        error: errno,
        flags: 0,
    };
    let rc = unsafe { libc::ioctl(notify_fd, ioctls.send, &resp as *const SeccompNotifResp) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Injects `src_fd` into the tracee as the return value of the notified
/// syscall, atomically completing the notification in the same call
/// (`SECCOMP_ADDFD_FLAG_SEND`) -- the tracee's own `openat2` never runs at
/// all, so object identity is settled entirely on Guardian's side before
/// the tracee regains control. This is the TOCTOU-safe path; see the module
/// doc on why `CONTINUE` is deliberately not used for a granted effect.
pub fn notif_addfd(notify_fd: RawFd, id: u64, src_fd: RawFd) -> io::Result<i32> {
    let addfd = SeccompNotifAddfd {
        id,
        flags: SECCOMP_ADDFD_FLAG_SEND,
        srcfd: src_fd as u32,
        newfd: 0,
        newfd_flags: libc::O_CLOEXEC as u32,
    };
    let rc = unsafe {
        libc::ioctl(
            notify_fd,
            SECCOMP_IOCTL_NOTIF_ADDFD,
            &addfd as *const SeccompNotifAddfd,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(rc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_valid_and_addfd_ioctl_codes_match_kernel_uapi() {
        // Only these two are compile-time-computable at all (RECV/SEND are
        // queried at runtime instead -- see notif_ioctls's doc). Cross-
        // checked by hand against <linux/seccomp.h>'s _IOW/_IOWR expansion:
        // ID_VALID = _IOW('!', 2, __u64), ADDFD = _IOW('!', 3, struct
        // seccomp_notif_addfd). This test exists so a future struct-layout
        // change (which would silently change ADDFD's value via size_of)
        // fails loudly instead of producing a wrong ioctl request code.
        assert_eq!(SECCOMP_IOCTL_NOTIF_ID_VALID, 0x4008_2102);
        assert_eq!(SECCOMP_IOCTL_NOTIF_ADDFD, 0x4018_2103);
    }

    #[test]
    fn addfd_send_flag_is_not_setfd() {
        // Regression test for the actual root cause of the long-standing
        // "ADDFD reports success but the tracee never wakes" bug: this
        // constant was `1 << 0` (SETFD's value) for most of this project's
        // history, confirmed correct only by eye against a C probe whose
        // own matching fallback #define was never actually compiled in
        // (see this constant's doc comment for the full story). Cross-
        // checked directly against a fresh fetch of
        // include/uapi/linux/seccomp.h, not against local memory of an
        // earlier "confirmed" value.
        assert_eq!(
            SECCOMP_ADDFD_FLAG_SEND,
            1 << 1,
            "must NOT equal SETFD's value (1 << 0)"
        );
        assert_ne!(
            SECCOMP_ADDFD_FLAG_SEND,
            1 << 0,
            "1 << 0 is SECCOMP_ADDFD_FLAG_SETFD, not SEND"
        );
    }

    /// A minimal BPF interpreter covering exactly the instruction shapes
    /// `build_notify_filter_program` emits (LD|ABS|W, JMP|JEQ, RET) -- just
    /// enough to walk the real generated program and confirm the jump
    /// offsets actually land where the doc comment claims. This is the test
    /// that would have caught the "compiles, installs, notifies nothing"
    /// bug an earlier draft of this function had: that version passed a
    /// naive "does it have a RET USER_NOTIF instruction somewhere" check
    /// (it did -- just unreachable) but fails this one, since this actually
    /// traces control flow rather than just scanning for a return code.
    fn run(prog: &[SockFilter], data: &SeccompData) -> u32 {
        let mut pc = 0usize;
        let mut acc: u32 = 0;
        loop {
            let ins = &prog[pc];
            let class = ins.code & 0x07;
            match class {
                0x00 => {
                    // LD
                    let offset = ins.k;
                    acc = if offset == SECCOMP_DATA_ARCH_OFFSET {
                        data.arch
                    } else if offset == SECCOMP_DATA_NR_OFFSET {
                        data.nr as u32
                    } else {
                        panic!("unhandled LD offset {offset} at pc {pc}")
                    };
                    pc += 1;
                }
                0x05 => {
                    // JMP (only JEQ used here)
                    pc += 1 + if acc == ins.k {
                        ins.jt as usize
                    } else {
                        ins.jf as usize
                    };
                }
                0x06 => return ins.k, // RET
                other => panic!("unhandled BPF class {other} at pc {pc}"),
            }
        }
    }

    fn data_for(nr: i64) -> SeccompData {
        SeccompData {
            nr: nr as i32,
            arch: AUDIT_ARCH_X86_64,
            instruction_pointer: 0,
            args: [0; 6],
        }
    }

    #[test]
    fn every_listed_syscall_reaches_user_notif() {
        let syscalls = [
            257i64, /* openat */
            437,    /* openat2 */
            87,     /* unlink */
            263,    /* unlinkat */
        ];
        let prog = build_notify_filter_program(&syscalls);
        for &nr in &syscalls {
            assert_eq!(
                run(&prog, &data_for(nr)),
                SECCOMP_RET_USER_NOTIF,
                "syscall {nr} did not reach RET USER_NOTIF"
            );
        }
    }

    #[test]
    fn unlisted_syscall_falls_through_to_allow() {
        let syscalls = [257i64, 437, 87, 263];
        let prog = build_notify_filter_program(&syscalls);
        // 39 = SYS_getpid on x86_64 -- deliberately not in the notify list.
        assert_eq!(run(&prog, &data_for(39)), SECCOMP_RET_ALLOW);
    }

    #[test]
    fn wrong_arch_is_killed_regardless_of_syscall_list() {
        let prog = build_notify_filter_program(&[257]);
        let mut data = data_for(257);
        data.arch = 0xDEAD_BEEF; // not AUDIT_ARCH_X86_64
        assert_eq!(run(&prog, &data), SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn single_syscall_list_still_works() {
        // The degenerate n=1 case this was originally (incorrectly) written
        // to handle -- confirm the general formula still covers it.
        let prog = build_notify_filter_program(&[257]);
        assert_eq!(run(&prog, &data_for(257)), SECCOMP_RET_USER_NOTIF);
        assert_eq!(run(&prog, &data_for(39)), SECCOMP_RET_ALLOW);
    }
}
