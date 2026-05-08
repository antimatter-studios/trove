//! Idle-lock tracker. Drops vault state after a configurable period of no
//! client activity.
//!
//! ## Design
//!
//! A single tokio task is spawned at construction time and lives for the
//! lifetime of the daemon. It alternates between:
//!
//!   * **Idle** — no timer is running; the task waits on a `Notify` until
//!     `start_or_reset` fires.
//!   * **Running** — a timer is armed; the task sleeps until
//!     `last_activity + timeout`, then fires the lock callback. While
//!     sleeping it also listens on the same `Notify`; any of `bump`,
//!     `start_or_reset`, or `cancel` wakes it and recomputes the deadline.
//!
//! ## Activity bump cost
//!
//! `bump()` is the hot path: every SSH agent message and every GPG Assuan
//! command calls it. To stay cheap it does:
//!
//!   1. one `AtomicU64::store(Relaxed)` of an i64 monotonic-millis timestamp;
//!   2. one `Notify::notify_one()` (lock-free, just a CAS on an internal
//!      atomic counter).
//!
//! No allocation, no mutex, no syscall. The timer task absorbs the wakeup
//! cost — which is bounded by "wake at most once per bump batch" because
//! `notify_one` coalesces.
//!
//! ## Callback approach (vs. holding stores directly)
//!
//! Storage of secret material is owned by `main.rs`/`handler.rs`. The tracker
//! takes a `Box<dyn Fn() -> BoxFuture<()>>` lock callback, which `main.rs`
//! constructs to wipe the materialize store, drop the vault, and clear both
//! key stores. This keeps the tracker:
//!
//!   * unit-testable without `Vault` / `KeyStore` types;
//!   * decoupled from sdpm-core / ssh-key / gpg packet types;
//!   * trivially reusable if we ever need a second timer (e.g. screensaver).

#![forbid(unsafe_code)]

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::Instant;

/// A future returned by the idle-lock callback. Boxed so the callback type
/// is object-safe.
pub type LockFuture = Pin<Box<dyn Future<Output = ()> + Send>>;
pub type LockCallback = Box<dyn Fn() -> LockFuture + Send + Sync>;

/// Public observable state of the tracker — used by the `get-idle-timeout`
/// RPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleState {
    /// Timeout is configured to 0 — auto-lock disabled.
    Disabled,
    /// Timeout > 0 but no timer is running (vault not unlocked).
    NotRunning,
    /// Timer is running; this many seconds remain before fire.
    Running { remaining_secs: u64 },
}

/// State machine driven by `start_or_reset` / `bump` / `cancel`.
///
/// We keep all mutable state in atomics so `bump` never grabs a mutex. The
/// driver task does Acquire loads to observe the latest values.
struct Inner {
    /// Configured timeout in milliseconds. 0 means "disabled".
    timeout_ms: AtomicU64,
    /// Tokio Instant of last activity, encoded as milliseconds since the task
    /// started (i.e. since the tracker was constructed). Negative sentinel
    /// `-1` means "no timer running".
    last_activity_ms: AtomicI64,
    /// The instant the tracker was constructed. All other instants are
    /// expressed as (instant - epoch).as_millis() so they fit in i64.
    epoch: Instant,
    /// Wakes the driver task on any state change.
    wake: Notify,
}

impl Inner {
    fn now_ms(&self) -> i64 {
        // saturating_duration_since because Instant::elapsed isn't safe
        // against clock perturbations on some platforms.
        let d = Instant::now().saturating_duration_since(self.epoch);
        // u128 -> i64 saturating; we'll never overflow in practice
        // (3e8 years), but be defensive.
        i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
    }
}

/// Idle-lock tracker. Cheaply cloneable via `Arc`.
pub struct IdleTracker {
    inner: Arc<Inner>,
    /// Held only so the driver task is dropped when the tracker is dropped.
    _driver: tokio::task::JoinHandle<()>,
}

impl IdleTracker {
    /// Construct a tracker with `default_timeout` and spawn the driver task.
    /// `lock_cb` is invoked on the tokio runtime when the timer expires.
    pub fn new(default_timeout: Duration, lock_cb: LockCallback) -> Arc<Self> {
        let timeout_ms = u64::try_from(default_timeout.as_millis()).unwrap_or(u64::MAX);
        let inner = Arc::new(Inner {
            timeout_ms: AtomicU64::new(timeout_ms),
            last_activity_ms: AtomicI64::new(-1),
            epoch: Instant::now(),
            wake: Notify::new(),
        });
        let driver_inner = inner.clone();
        let driver = tokio::spawn(async move {
            run_driver(driver_inner, lock_cb).await;
        });
        Arc::new(IdleTracker {
            inner,
            _driver: driver,
        })
    }

    /// Note recent activity, resetting the remaining countdown. No-op if the
    /// timer isn't running (vault locked) or auto-lock is disabled.
    ///
    /// Cheap: one atomic store + one Notify CAS. No allocations, no mutex.
    #[inline]
    pub fn bump(&self) {
        // If timer isn't running, nothing to do. Avoid a wake if the timer
        // would have nothing useful to recompute.
        if self.inner.last_activity_ms.load(Ordering::Acquire) < 0 {
            return;
        }
        if self.inner.timeout_ms.load(Ordering::Acquire) == 0 {
            return;
        }
        let now = self.inner.now_ms();
        self.inner.last_activity_ms.store(now, Ordering::Release);
        self.inner.wake.notify_one();
    }

    /// Start the timer (called on `unlock`) or reconfigure it on a
    /// subsequent `unlock`. If `timeout` is zero, the timer stays disabled.
    pub fn start_or_reset(&self, timeout: Duration) {
        let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        self.inner.timeout_ms.store(timeout_ms, Ordering::Release);
        if timeout_ms == 0 {
            // Disabled — make sure any prior running state is cleared too.
            self.inner.last_activity_ms.store(-1, Ordering::Release);
        } else {
            let now = self.inner.now_ms();
            self.inner.last_activity_ms.store(now, Ordering::Release);
        }
        self.inner.wake.notify_one();
    }

    /// Cancel the timer (called on `lock` and `shutdown`).
    pub fn cancel(&self) {
        self.inner.last_activity_ms.store(-1, Ordering::Release);
        self.inner.wake.notify_one();
    }

    /// Update the timeout. The new value takes effect immediately: the
    /// driver wakes, recomputes the deadline against the existing
    /// `last_activity` timestamp, and may fire right away if the new
    /// timeout already elapsed. Setting to 0 disables auto-lock and cancels
    /// any running timer (matches the env-var semantics).
    pub fn set_timeout(&self, timeout: Duration) {
        let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        self.inner.timeout_ms.store(timeout_ms, Ordering::Release);
        if timeout_ms == 0 {
            self.inner.last_activity_ms.store(-1, Ordering::Release);
        }
        self.inner.wake.notify_one();
    }

    /// Snapshot the current configured timeout in seconds.
    pub fn current_timeout_secs(&self) -> u64 {
        self.inner.timeout_ms.load(Ordering::Acquire) / 1000
    }

    /// Snapshot the current public state.
    pub fn current_state(&self) -> IdleState {
        let timeout_ms = self.inner.timeout_ms.load(Ordering::Acquire);
        if timeout_ms == 0 {
            return IdleState::Disabled;
        }
        let last = self.inner.last_activity_ms.load(Ordering::Acquire);
        if last < 0 {
            return IdleState::NotRunning;
        }
        let now = self.inner.now_ms();
        let elapsed_ms = (now - last).max(0) as u64;
        let remaining_ms = timeout_ms.saturating_sub(elapsed_ms);
        IdleState::Running {
            remaining_secs: remaining_ms.div_ceil(1000),
        }
    }
}

async fn run_driver(inner: Arc<Inner>, lock_cb: LockCallback) {
    loop {
        // Snapshot
        let timeout_ms = inner.timeout_ms.load(Ordering::Acquire);
        let last = inner.last_activity_ms.load(Ordering::Acquire);
        if timeout_ms == 0 || last < 0 {
            // Disabled or not-running: park until something changes.
            inner.wake.notified().await;
            continue;
        }
        let deadline_ms = last.saturating_add(timeout_ms as i64);
        let now = inner.now_ms();
        let remaining_ms = (deadline_ms - now).max(0) as u64;

        if remaining_ms == 0 {
            // Already expired by the time we woke. Fire.
        } else {
            tokio::select! {
                _ = inner.wake.notified() => {
                    // State changed — restart the loop and recompute.
                    continue;
                }
                _ = tokio::time::sleep(Duration::from_millis(remaining_ms)) => {
                    // Sleep elapsed — re-check below in case of races.
                }
            }
        }

        // Re-validate before firing: another thread may have bumped or
        // cancelled while we were on the verge of waking, in which case
        // last_activity will have moved forward or last == -1.
        let timeout_ms_now = inner.timeout_ms.load(Ordering::Acquire);
        let last_now = inner.last_activity_ms.load(Ordering::Acquire);
        if timeout_ms_now == 0 || last_now < 0 {
            // Cancelled or disabled while we slept — bail.
            continue;
        }
        let now2 = inner.now_ms();
        let deadline_now = last_now.saturating_add(timeout_ms_now as i64);
        if now2 < deadline_now {
            // A bump moved the deadline. Loop.
            continue;
        }

        // Fire. We mark "not running" BEFORE invoking the callback so a
        // concurrent explicit `lock` won't double-wipe and so a fresh
        // `unlock` during the callback can re-arm cleanly.
        inner.last_activity_ms.store(-1, Ordering::Release);

        let timeout_secs = (timeout_ms_now / 1000).max(1);
        eprintln!("idle lock after {timeout_secs} seconds");

        // Run the callback. We drop and recreate it would be wrong (we don't
        // own it); just call it.
        lock_cb().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn count_callback() -> (Arc<AtomicU32>, LockCallback) {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_cb = counter.clone();
        let cb: LockCallback = Box::new(move || {
            let c = counter_cb.clone();
            Box::pin(async move {
                c.fetch_add(1, Ordering::SeqCst);
            }) as LockFuture
        });
        (counter, cb)
    }

    #[tokio::test(start_paused = true)]
    async fn timer_fires_after_timeout_with_no_activity() {
        let (count, cb) = count_callback();
        let t = IdleTracker::new(Duration::from_secs(2), cb);
        t.start_or_reset(Duration::from_secs(2));

        // Step past the deadline.
        tokio::time::sleep(Duration::from_millis(2100)).await;

        assert_eq!(count.load(Ordering::SeqCst), 1, "should fire once");
        assert!(matches!(t.current_state(), IdleState::NotRunning));
    }

    #[tokio::test(start_paused = true)]
    async fn bump_resets_countdown() {
        let (count, cb) = count_callback();
        let t = IdleTracker::new(Duration::from_secs(2), cb);
        t.start_or_reset(Duration::from_secs(2));

        // 3 bumps each separated by 1s — each resets the 2s clock.
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_secs(1)).await;
            t.bump();
        }
        // After bumps stop, vault should still be live for ~1.9s.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert_eq!(count.load(Ordering::SeqCst), 0, "shouldn't have fired yet");

        // Now wait past the new deadline.
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert_eq!(count.load(Ordering::SeqCst), 1, "should have fired once");
    }

    #[tokio::test(start_paused = true)]
    async fn cancel_suspends_timer() {
        let (count, cb) = count_callback();
        let t = IdleTracker::new(Duration::from_secs(2), cb);
        t.start_or_reset(Duration::from_secs(2));

        tokio::time::sleep(Duration::from_millis(500)).await;
        t.cancel();
        tokio::time::sleep(Duration::from_secs(5)).await;

        assert_eq!(count.load(Ordering::SeqCst), 0, "cancel must prevent fire");
        assert!(matches!(t.current_state(), IdleState::NotRunning));
    }

    #[tokio::test(start_paused = true)]
    async fn set_timeout_takes_effect_immediately() {
        // Behavior we picked: set_timeout takes effect immediately. If the new
        // timeout has already elapsed against last_activity, we fire on the
        // next driver wake.
        let (count, cb) = count_callback();
        let t = IdleTracker::new(Duration::from_secs(60), cb);
        t.start_or_reset(Duration::from_secs(60));

        tokio::time::sleep(Duration::from_secs(1)).await;
        // Reconfigure to a much shorter timeout that has already elapsed
        // relative to `last_activity` (1s elapsed > 100ms timeout).
        t.set_timeout(Duration::from_millis(100));
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "shorter timeout should fire"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_zero_disables() {
        let (count, cb) = count_callback();
        let t = IdleTracker::new(Duration::from_secs(0), cb);
        t.start_or_reset(Duration::from_secs(0));

        tokio::time::sleep(Duration::from_secs(10)).await;
        assert_eq!(count.load(Ordering::SeqCst), 0);
        assert!(matches!(t.current_state(), IdleState::Disabled));
    }

    #[tokio::test(start_paused = true)]
    async fn bump_is_noop_when_not_running() {
        let (count, cb) = count_callback();
        let t = IdleTracker::new(Duration::from_secs(2), cb);
        // No start_or_reset — bump should not arm anything.
        for _ in 0..100 {
            t.bump();
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert_eq!(count.load(Ordering::SeqCst), 0);
        assert!(matches!(t.current_state(), IdleState::NotRunning));
    }

    #[tokio::test(start_paused = true)]
    async fn current_state_running_reports_remaining() {
        let (_count, cb) = count_callback();
        let t = IdleTracker::new(Duration::from_secs(10), cb);
        t.start_or_reset(Duration::from_secs(10));
        tokio::time::sleep(Duration::from_secs(3)).await;
        match t.current_state() {
            IdleState::Running { remaining_secs } => {
                assert!(
                    (6..=10).contains(&remaining_secs),
                    "expected ~7s remaining; got {remaining_secs}"
                );
            }
            other => panic!("expected Running; got {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn second_unlock_resets_deadline() {
        let (count, cb) = count_callback();
        let t = IdleTracker::new(Duration::from_secs(2), cb);
        t.start_or_reset(Duration::from_secs(2));
        tokio::time::sleep(Duration::from_millis(1500)).await;
        // Re-unlock — full 2s again.
        t.start_or_reset(Duration::from_secs(2));
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert_eq!(
            count.load(Ordering::SeqCst),
            0,
            "second unlock should have reset"
        );
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}
