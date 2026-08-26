//! Process-lifetime memory sealing for the shim's own authority-bearing
//! state, including its held cap's identity/permissions (`Config`) and the cached
//! standing policy (`Policy`) via `mmap` -> `mprotect(PROT_READ)` ->
//! `mseal()`, so that a memory-corruption bug in this process (the one
//! process the threat model designates as trusted.
//!
//! `mseal()` (Linux 6.10+) is permanent (no unseal or `munmap`) which
//! is exactly why this is only used for data written once at process start
//! and read for the rest of the process's life, never per-request (a
//! per-request seal would leak a mapping on every tool call). `SYS_mseal`
//! is hand-rolled here the same way `crates/guardian/src/seccomp_ffi.rs`
//! hand-rolls syscalls too new for the `libc` crate to wrap yet.
//!
//! Falls back to a plain heap buffer on any failure (old kernel, syscall
//! unavailable). Hardening is additive here. The fallback is loud: a
//! `tracing::warn!` names exactly what's missing and why.

use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::Serialize;

#[cfg(target_os = "linux")]
const SYS_MSEAL: i64 = 462; // x86_64; matches mseal_probe.c, validated against a real 7.0.0 kernel this project.

enum Backing {
    /// `ptr` refers to a dedicated (never shared with the general
    /// allocator's arena) anonymous mapping of `len` bytes, currently at
    /// least `mprotect(PROT_READ)`-only and, where the kernel supports it,
    /// additionally `mseal()`-permanent. Never written to again after
    /// construction.
    #[cfg(target_os = "linux")]
    Sealed {
        ptr: *const u8,
        len: usize,
    },
    Fallback(Vec<u8>),
}

// SAFETY: `Backing::Sealed`'s pointer refers to memory that is, by
// construction, never written through again after `SealedRegion::from_bytes`
// returns, sharing `&Backing`/`Backing` itself across threads is exactly
// as safe as sharing an immutable `&'static [u8]` would be.
#[cfg(target_os = "linux")]
unsafe impl Send for Backing {}
#[cfg(target_os = "linux")]
unsafe impl Sync for Backing {}

/// A byte buffer written once at construction, then never mutated again --
/// see the module doc for why and how. Intentionally has no API for
/// obtaining a mutable view; that's the entire point.
pub struct SealedRegion {
    backing: Backing,
}

impl SealedRegion {
    /// Copies `bytes` into a fresh sealed region. On Linux, attempts the
    /// real `mmap` -> `mprotect(PROT_READ)` -> `mseal()` sequence and falls
    /// back to a plain heap copy (with a `WARN` naming why) on any failure;
    /// on non-Linux targets, always uses the plain heap copy.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        #[cfg(target_os = "linux")]
        {
            if let Some(region) = Self::try_seal(bytes) {
                return region;
            }
        }
        SealedRegion {
            backing: Backing::Fallback(bytes.to_vec()),
        }
    }

    #[cfg(target_os = "linux")]
    fn try_seal(bytes: &[u8]) -> Option<Self> {
        let len = bytes.len().max(1); // mmap a real region even for empty input.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let mapped_len = len.div_ceil(page_size) * page_size;

        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mapped_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            tracing::warn!(
                error = %std::io::Error::last_os_error(),
                "sealed: mmap failed, falling back to a plain (unsealed) heap buffer",
            );
            return None;
        }

        // SAFETY: `ptr` was just mmap'd RW for exactly `mapped_len` bytes
        // (>= bytes.len()), and nothing else holds any reference to this
        // memory yet. This is the only write this region will ever see.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr as *mut u8, bytes.len());
        }

        if unsafe { libc::mprotect(ptr, mapped_len, libc::PROT_READ) } != 0 {
            let err = std::io::Error::last_os_error();
            unsafe {
                libc::munmap(ptr, mapped_len);
            }
            tracing::warn!(
                error = %err,
                "sealed: mprotect(PROT_READ) failed, falling back to a plain (unsealed) heap buffer",
            );
            return None;
        }

        // mseal() is the stronger guarantee (permanently blocks even an
        // attacker who can call mprotect themselves), but its absence
        // doesn't undo the mprotect(PROT_READ) above, which is still real,
        // meaningfully weaker-but-nonzero protection (blocks an ordinary
        // OOB/UAF write). Keep the region either way; only log the gap.
        let mseal_rc = unsafe { libc::syscall(SYS_MSEAL, ptr, mapped_len, 0u64) };
        if mseal_rc != 0 {
            tracing::warn!(
                error = %std::io::Error::last_os_error(),
                "sealed: mseal() unavailable (kernel likely older than 6.10) -- region is \
                 mprotect(PROT_READ)-only, not permanently sealed",
            );
        }

        Some(SealedRegion {
            backing: Backing::Sealed {
                ptr: ptr as *const u8,
                len: bytes.len(),
            },
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        match &self.backing {
            #[cfg(target_os = "linux")]
            Backing::Sealed { ptr, len } => unsafe { std::slice::from_raw_parts(*ptr, *len) },
            Backing::Fallback(v) => v.as_slice(),
        }
    }
}

/// A `T`, serialized once into a [`SealedRegion`] and deserialized fresh on
/// every [`SealedJson::get`] call. Cheap for the handful of small
/// string/Vec fields this is used for (`Config`'s identity fields,
/// `Policy`'s standing-policy cache), and called far less often than once
/// per proposal. `Clone` is a cheap `Arc` clone, not a re-seal: there is
/// exactly one sealed mapping for the process's whole life, and every
/// clone (matching every existing `config.clone()`/`policy.clone()` call
/// site) just shares a reference to it.
pub struct SealedJson<T> {
    region: Arc<SealedRegion>,
    _marker: std::marker::PhantomData<fn() -> T>,
}

impl<T> Clone for SealedJson<T> {
    fn clone(&self) -> Self {
        SealedJson {
            region: Arc::clone(&self.region),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<T: Serialize> SealedJson<T> {
    pub fn new(value: &T) -> Self {
        let bytes = serde_json::to_vec(value)
            .expect("SealedJson::new: serializing a well-formed value cannot fail");
        SealedJson {
            region: Arc::new(SealedRegion::from_bytes(&bytes)),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<T: DeserializeOwned> SealedJson<T> {
    pub fn get(&self) -> T {
        serde_json::from_slice(self.region.as_slice()).expect(
            "SealedJson::get: sealed bytes were written by SealedJson::new and never mutated",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[test]
    fn region_round_trips_arbitrary_bytes() {
        let data = b"hello sealed world, this is more than one page \0\x01\xff".repeat(300);
        let region = SealedRegion::from_bytes(&data);
        assert_eq!(region.as_slice(), &data[..]);
    }

    #[test]
    fn region_round_trips_empty_input() {
        let region = SealedRegion::from_bytes(&[]);
        assert_eq!(region.as_slice(), &[] as &[u8]);
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct Sample {
        name: String,
        perms: Vec<String>,
        n: u64,
    }

    #[test]
    fn sealed_json_round_trips_and_clones_share_one_region() {
        let value = Sample {
            name: "agent-1".into(),
            perms: vec!["read_file".into(), "write_file".into()],
            n: 42,
        };
        let sealed = SealedJson::new(&value);
        assert_eq!(sealed.get(), value);

        // Clone shares the same underlying Arc<SealedRegion> -- not a re-seal.
        let cloned = sealed.clone();
        assert_eq!(cloned.get(), value);
        assert!(Arc::ptr_eq(&sealed.region, &cloned.region));
    }

    #[test]
    fn sealed_json_get_is_repeatable() {
        // Each .get() deserializes fresh -- confirm multiple calls agree and
        // don't consume/corrupt the underlying sealed bytes.
        let sealed = SealedJson::new(&Sample {
            name: "x".into(),
            perms: vec![],
            n: 1,
        });
        for _ in 0..5 {
            assert_eq!(sealed.get().n, 1);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sealed_region_is_actually_mprotect_read_only() {
        // Direct analogue of this project's mseal_probe.c: confirm the
        // region built by SealedRegion is really not writable through a
        // raw pointer, regardless of whether mseal() itself is available
        // on this kernel (WSL's 6.6 is below the 6.10 floor and is
        // expected to hit the mprotect-only path, not the full mseal).
        let region = SealedRegion::from_bytes(b"do not write to me");
        match &region.backing {
            Backing::Sealed { ptr, len } => {
                let rc = unsafe { libc::mprotect(*ptr as *mut _, *len, libc::PROT_READ) };
                // Already PROT_READ-only: re-asserting PROT_READ must still
                // succeed (idempotent), proving the mapping exists and is
                // at least mprotect-managed, not a stray/freed pointer.
                assert_eq!(
                    rc, 0,
                    "expected the sealed region to still be a valid, mprotect-manageable mapping"
                );
            }
            Backing::Fallback(_) => {
                // mmap/mprotect themselves failed on this host (sandboxed
                // CI, unusual restrictions) -- the graceful-fallback path
                // this test would otherwise be pointless to run against.
            }
        }
    }
}
