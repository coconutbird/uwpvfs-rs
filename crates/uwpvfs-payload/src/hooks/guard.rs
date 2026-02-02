//! Reentrancy guard for hook functions
//!
//! Uses Windows TLS to detect when we're already inside a hook,
//! preventing infinite recursion when our hook code calls file system APIs.

/// Thread-local storage key for reentrancy detection
/// We use Windows TLS directly for reliability in hook contexts
#[cfg(target_os = "windows")]
mod tls {
    use std::sync::atomic::{AtomicU32, Ordering};
    use windows::Win32::System::Threading::{
        TLS_OUT_OF_INDEXES, TlsAlloc, TlsFree, TlsGetValue, TlsSetValue,
    };

    static TLS_INDEX: AtomicU32 = AtomicU32::new(TLS_OUT_OF_INDEXES);

    /// Initialize TLS slot (call once at startup)
    pub fn init() {
        let idx = unsafe { TlsAlloc() };
        if idx != TLS_OUT_OF_INDEXES {
            TLS_INDEX.store(idx, Ordering::SeqCst);
        }
    }

    /// Check if we're currently in a hook
    pub fn is_in_hook() -> bool {
        let idx = TLS_INDEX.load(Ordering::SeqCst);
        if idx == TLS_OUT_OF_INDEXES {
            return false;
        }
        let val = unsafe { TlsGetValue(idx) };
        !val.is_null()
    }

    /// Set the in-hook flag
    pub fn set_in_hook(value: bool) {
        let idx = TLS_INDEX.load(Ordering::SeqCst);
        if idx == TLS_OUT_OF_INDEXES {
            return;
        }
        let ptr = if value {
            std::ptr::dangling_mut()
        } else {
            std::ptr::null_mut()
        };
        unsafe {
            let _ = TlsSetValue(idx, Some(ptr));
        }
    }

    /// Cleanup TLS slot
    pub fn cleanup() {
        let idx = TLS_INDEX.swap(TLS_OUT_OF_INDEXES, Ordering::SeqCst);
        if idx != TLS_OUT_OF_INDEXES {
            unsafe {
                let _ = TlsFree(idx);
            }
        }
    }
}

/// RAII guard for reentrancy protection
pub struct ReentrancyGuard {
    _private: (),
}

impl ReentrancyGuard {
    /// Try to enter the hook. Returns Some(guard) if not already in a hook, None if reentrant.
    #[inline]
    pub fn try_enter() -> Option<Self> {
        if tls::is_in_hook() {
            None
        } else {
            tls::set_in_hook(true);
            Some(ReentrancyGuard { _private: () })
        }
    }
}

impl Drop for ReentrancyGuard {
    #[inline]
    fn drop(&mut self) {
        tls::set_in_hook(false);
    }
}

/// Initialize the reentrancy guard system (call once at DLL load)
pub fn init() {
    tls::init();
}

/// Cleanup the reentrancy guard system (call at DLL unload)
pub fn cleanup() {
    tls::cleanup();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guard_first_entry_succeeds() {
        init();
        let guard = ReentrancyGuard::try_enter();
        assert!(guard.is_some(), "First entry should succeed");
        drop(guard);
        cleanup();
    }

    #[test]
    fn test_guard_blocks_reentry() {
        init();
        let _guard1 = ReentrancyGuard::try_enter().expect("First entry should succeed");
        let guard2 = ReentrancyGuard::try_enter();
        assert!(guard2.is_none(), "Nested entry should be blocked");
        cleanup();
    }

    #[test]
    fn test_guard_raii_resets_on_drop() {
        init();
        {
            let _guard = ReentrancyGuard::try_enter().expect("First entry should succeed");
            // Guard is held here
        }
        // After drop, should be able to enter again
        let guard = ReentrancyGuard::try_enter();
        assert!(
            guard.is_some(),
            "Should be able to enter after guard is dropped"
        );
        cleanup();
    }

    #[test]
    fn test_guard_multiple_enter_exit_cycles() {
        init();
        for i in 0..5 {
            let guard = ReentrancyGuard::try_enter();
            assert!(guard.is_some(), "Entry {} should succeed", i);
            drop(guard);
        }
        cleanup();
    }

    #[test]
    fn test_guard_thread_local_isolation() {
        init();
        // Hold guard in main thread
        let _guard = ReentrancyGuard::try_enter().expect("Main thread entry should succeed");

        // Different thread should be able to enter independently
        let handle = std::thread::spawn(|| {
            // Note: TLS is per-thread, so this thread has its own slot value
            ReentrancyGuard::try_enter().is_some()
        });

        let other_thread_entered = handle.join().expect("Thread should not panic");
        assert!(
            other_thread_entered,
            "Other thread should be able to enter independently"
        );
        cleanup();
    }

    #[test]
    fn test_guard_deeply_nested_blocks() {
        init();
        let guard1 = ReentrancyGuard::try_enter();
        assert!(guard1.is_some());

        let guard2 = ReentrancyGuard::try_enter();
        assert!(guard2.is_none());

        let guard3 = ReentrancyGuard::try_enter();
        assert!(guard3.is_none());

        drop(guard1);

        // After dropping the first guard, should be able to enter again
        let guard4 = ReentrancyGuard::try_enter();
        assert!(guard4.is_some());
        cleanup();
    }
}
