//! Purpose-built sandbox rootfs — swaps `exec_sandboxed`'s `--ro-bind / /`
//! (the real host filesystem, read-only) for a minimal OCI-derived image.
//! Closes a real, if low-severity, information-disclosure surface: a
//! Ring-2 command couldn't write outside its declared `file_effects`, but
//! it could still *read* anything world-readable on the actual host —
//! `/etc/passwd`'s structure, installed package versions, hostname, and so
//! on. An OCI-derived image means the sandboxed command only ever sees a
//! minimal, purpose-built filesystem and never touches the host's own
//! namespace at all.
//!
//! Entirely opt-in — unset `SOLARPLEX_SANDBOX_ROOTFS_SRC` and none of this
//! runs; `exec_sandboxed` falls back to today's host-bind behavior. This is
//! a strict improvement over that default, not a security floor the way
//! landlock/seccomp are, so setup failure logs a `WARN` and degrades to the
//! existing behavior rather than refusing to execute.
//!
//! Build (unprivileged, `oci2rootfs`) and mount (privileged, loopback) both
//! happen once, lazily, on first use — not per exec, which would be far too
//! slow for a command-at-a-time sandbox.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const ENV_SRC:   &str = "SOLARPLEX_SANDBOX_ROOTFS_SRC";
const ENV_IMAGE: &str = "SOLARPLEX_SANDBOX_ROOTFS_IMAGE";
const ENV_MOUNT: &str = "SOLARPLEX_SANDBOX_ROOTFS_MOUNT";

const DEFAULT_IMAGE: &str = "/var/lib/solarplex/guardian/sandbox-rootfs.ext4";
const DEFAULT_MOUNT: &str = "/var/lib/solarplex/guardian/sandbox-rootfs";

/// The mounted rootfs path, if the feature is configured and setup
/// succeeded — `None` if unconfigured, or if the build/mount failed (the
/// warning was already logged the first time this ran). Cached for the
/// life of the process; the build+mount only ever happens once.
pub(crate) fn sandbox_rootfs() -> Option<&'static Path> {
    static ROOTFS: OnceLock<Option<PathBuf>> = OnceLock::new();
    ROOTFS.get_or_init(setup).as_deref()
}

fn setup() -> Option<PathBuf> {
    let src = std::env::var(ENV_SRC).ok()?;
    let image = PathBuf::from(std::env::var(ENV_IMAGE).unwrap_or_else(|_| DEFAULT_IMAGE.to_string()));
    let mount = PathBuf::from(std::env::var(ENV_MOUNT).unwrap_or_else(|_| DEFAULT_MOUNT.to_string()));

    if let Err(e) = build_image(&src, &image) {
        tracing::warn!(
            "guardian: sandbox rootfs build failed ({e}) — falling back to host filesystem \
             bind for --ro-bind / /. Check {ENV_SRC} points at a valid local OCI image \
             layout or docker overlay2 directory, or unset it to silence this warning."
        );
        return None;
    }
    if let Err(e) = mount_image(&image, &mount) {
        tracing::warn!(
            "guardian: sandbox rootfs mount failed ({e}) — falling back to host filesystem \
             bind for --ro-bind / /. Loopback mount needs CAP_SYS_ADMIN (or root); confirm \
             the guardian process actually holds it — the same privilege bwrap's own \
             namespace construction already assumes is not automatically the same thing."
        );
        return None;
    }
    tracing::info!(
        image = %image.display(), mount = %mount.display(),
        "guardian: sandbox rootfs ready — Ring-2 commands will see this image, not the host filesystem",
    );
    Some(mount)
}

/// Idempotent: an existing image file is reused as-is, matching the
/// `creates:`-guarded idempotency already used for the dm-verity image
/// build in `deploy/ansible/roles/solarplex_binary_integrity` — rebuilding
/// on every guardian restart would be needless and slow. Delete the image
/// file by hand to force a rebuild (e.g. after updating the source image).
fn build_image(src: &str, image: &Path) -> anyhow::Result<()> {
    if image.exists() {
        return Ok(());
    }
    if let Some(parent) = image.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // `autodetect` resolves OCI image layouts for linux/amd64 unconditionally
    // — on an aarch64 host with a multi-arch layout, use
    // `OciLayoutSource::open(src)?.platform(Platform::new("linux", "arm64"))`
    // directly instead. Not wired up here since this deployment doesn't run
    // on aarch64 hosts today; flagging so it isn't a silent wrong-arch pull
    // if that changes.
    let source = oci2rootfs::autodetect(src)?;
    oci2rootfs::Converter::new(image).convert(source)?;
    Ok(())
}

/// Idempotent via `/proc/mounts` rather than attempting the mount and
/// inspecting the error — a mount surviving from a previous guardian
/// process (crash, restart) should be reused, not treated as a failure.
fn mount_image(image: &Path, mount: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(mount)?;
    if already_mounted(mount)? {
        return Ok(());
    }
    let status = std::process::Command::new("mount")
        .args(["-o", "loop,ro"])
        .arg(image)
        .arg(mount)
        .status()?;
    if !status.success() {
        anyhow::bail!("mount exited with {status}");
    }
    Ok(())
}

fn already_mounted(mount: &Path) -> anyhow::Result<bool> {
    let mounts = std::fs::read_to_string("/proc/mounts")?;
    let target = mount.to_string_lossy();
    Ok(mounts.lines().any(|l| l.split_whitespace().nth(1) == Some(target.as_ref())))
}
