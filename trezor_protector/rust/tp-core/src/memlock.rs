//! Locking secret pages into physical RAM.
//!
//! Keys and other secrets are wiped on drop, but between allocation and
//! wipe the OS could page them out to the swap file or a hibernation image,
//! where they would survive on disk. `VirtualLock` (Windows) / `mlock`
//! (Unix) pin the page in RAM so that never happens. We go through the
//! `region` crate, which exposes a safe wrapper, so this crate keeps
//! `#![forbid(unsafe_code)]`.
//!
//! Limits (stated honestly): this does not stop a process that can already
//! read our address space (a debugger, a RAT with our privileges, a kernel
//! attacker). It closes the *swap-to-disk* and *hibernation* leak, which is
//! the part achievable from user space.

/// Records whether a secret's page was successfully pinned in RAM.
///
/// We intentionally do **not** hold `region`'s RAII unlock guard: two small
/// keys often share one 4 KiB page, and per-key unlock-on-drop then either
/// double-unlocks that page or (worse) unlocks it after the allocator has
/// freed the backing memory. Instead we lock once and let the page stay
/// pinned until the process exits — correct, simple, and cheap for the
/// handful of keys this tool holds. Secrets are still zeroized on drop.
pub struct Locked(bool);

/// Lock `len` bytes starting at `ptr` into RAM. Never fails hard: locking is
/// a hardening measure, not a correctness requirement, so a failure (e.g.
/// the per-process working-set quota was hit) just yields an unlocked
/// marker.
pub fn lock(ptr: *mut u8, len: usize) -> Locked {
    match region::lock(ptr, len) {
        Ok(guard) => {
            // Keep the page locked for the process lifetime.
            std::mem::forget(guard);
            Locked(true)
        }
        Err(_) => Locked(false),
    }
}

impl Locked {
    /// Whether the region is actually pinned in RAM.
    pub fn is_locked(&self) -> bool {
        self.0
    }
}
