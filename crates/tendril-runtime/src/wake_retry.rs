//! The single wake-and-retry loop shared by the CLI, the C ABI, the Python and Node bindings,
//! and [`wake_and_dial_v2`](crate::v2_driver::wake_and_dial_v2).
//!
//! Exhausting the attempts returns the error of the final connect. Counting the connect that
//! precedes the wake hint, up to `1 + max(1, max_attempts)` connects can run.

use std::future::Future;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::driver::AttemptError;
use crate::v2_driver::WakeDialOptions;
use crate::wake::WakeOutcome;

/// Runs `connect` under the wake flow described by `wake`, with the system clock.
///
/// With `wake.pre_wake` the wake hint goes first, then up to `max(1, max_attempts)` connects run.
/// Otherwise one connect runs first: success returns `(value, None)` and an error that
/// `is_wakeable` rejects returns at once without a wake. A wakeable miss sends the wake hint
/// (bounded by `wake_timeout`, a timeout reports [`WakeOutcome::Skipped`]) and then runs up to
/// `max(1, max_attempts)` connects `retry_delay` apart, retrying only wakeable errors. The error
/// of the final connect is returned when the attempts run out.
pub async fn connect_with_wake<T, E, F, Fut>(
    wake: &WakeDialOptions,
    is_wakeable: impl Fn(&E) -> bool,
    connect: F,
) -> Result<(T, Option<WakeOutcome>), E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    connect_with_wake_at(wake, system_now_unix, is_wakeable, connect).await
}

/// [`connect_with_wake`] with the wake classifier of a policy connect,
/// [`AttemptError::is_wakeable_miss`].
pub async fn connect_with_wake_policy<T, F, Fut>(
    wake: &WakeDialOptions,
    connect: F,
) -> Result<(T, Option<WakeOutcome>), AttemptError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, AttemptError>>,
{
    connect_with_wake(wake, AttemptError::is_wakeable_miss, connect).await
}

/// [`connect_with_wake`] reading the wake tag time from `now_unix` when sending the wake hint.
/// `now_unix` runs at most once and never when no wake hint is sent.
pub(crate) async fn connect_with_wake_at<T, E, F, Fut>(
    wake: &WakeDialOptions,
    now_unix: impl FnOnce() -> u64,
    is_wakeable: impl Fn(&E) -> bool,
    mut connect: F,
) -> Result<(T, Option<WakeOutcome>), E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let outcome = if wake.pre_wake {
        notify(wake, now_unix()).await
    } else {
        match connect().await {
            Ok(value) => return Ok((value, None)),
            Err(err) if !is_wakeable(&err) => return Err(err),
            Err(_) => notify(wake, now_unix()).await,
        }
    };
    let attempts = wake.max_attempts.max(1);
    let mut attempt = 0;
    loop {
        attempt += 1;
        match connect().await {
            Ok(value) => return Ok((value, Some(outcome))),
            Err(err) if attempt >= attempts || !is_wakeable(&err) => return Err(err),
            Err(_) => tokio::time::sleep(wake.retry_delay).await,
        }
    }
}

/// Sends one best-effort wake hint, tagged for `now_unix`, bounded by `wake.wake_timeout`.
async fn notify(wake: &WakeDialOptions, now_unix: u64) -> WakeOutcome {
    let tag = wake.secret.derive_tag(now_unix);
    tokio::time::timeout(
        wake.wake_timeout,
        wake.provider
            .notify_best_effort(&wake.target, &tag, now_unix),
    )
    .await
    .unwrap_or(WakeOutcome::Skipped)
}

fn system_now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use async_trait::async_trait;

    use super::*;
    use crate::error::RuntimeError;
    use crate::wake::{WakeAdapterKind, WakeProvider, WakeSecret, WakeTag, WakeTarget};

    const SECRET: [u8; 32] = [7; 32];

    /// The error a fake connect fails with: its 1-based attempt index and whether it is wakeable.
    type Miss = (usize, bool);

    #[derive(Clone, Copy)]
    enum Reply {
        Outcome(WakeOutcome),
        Fail,
    }

    struct FakeWake {
        notifies: AtomicUsize,
        /// Connects that had run when each notify arrived.
        connects_at_notify: Mutex<Vec<usize>>,
        /// The `(tag, now)` of the last notify.
        last: Mutex<Option<(WakeTag, u64)>>,
        delay: Option<Duration>,
        reply: Reply,
        connects: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl WakeProvider for FakeWake {
        async fn notify(
            &self,
            _target: &WakeTarget,
            tag: &WakeTag,
            now_unix_secs: u64,
        ) -> Result<WakeOutcome, RuntimeError> {
            self.notifies.fetch_add(1, Ordering::SeqCst);
            *self.last.lock().unwrap() = Some((*tag, now_unix_secs));
            self.connects_at_notify
                .lock()
                .unwrap()
                .push(self.connects.load(Ordering::SeqCst));
            if let Some(delay) = self.delay {
                tokio::time::sleep(delay).await;
            }
            match self.reply {
                Reply::Outcome(outcome) => Ok(outcome),
                Reply::Fail => Err(RuntimeError::Closed),
            }
        }
    }

    struct Rig {
        provider: Arc<FakeWake>,
        connects: Arc<AtomicUsize>,
    }

    impl Rig {
        fn new() -> Self {
            Self::with(None, Reply::Outcome(WakeOutcome::Delivered))
        }

        fn with(delay: Option<Duration>, reply: Reply) -> Self {
            let connects = Arc::new(AtomicUsize::new(0));
            let provider = Arc::new(FakeWake {
                notifies: AtomicUsize::new(0),
                connects_at_notify: Mutex::new(Vec::new()),
                last: Mutex::new(None),
                delay,
                reply,
                connects: Arc::clone(&connects),
            });
            Self { provider, connects }
        }

        fn options(&self, pre_wake: bool, max_attempts: usize) -> WakeDialOptions {
            let target =
                WakeTarget::new(WakeAdapterKind::Webhook, "https://wake.example/hook").unwrap();
            WakeDialOptions::new(
                Arc::clone(&self.provider) as Arc<dyn WakeProvider>,
                target,
                WakeSecret::from_bytes(SECRET),
            )
            .with_pre_wake(pre_wake)
            .with_retry_delay(Duration::ZERO)
            .with_max_attempts(max_attempts)
            .with_wake_timeout(Duration::from_millis(50))
        }

        fn notifies(&self) -> usize {
            self.provider.notifies.load(Ordering::SeqCst)
        }

        fn connect_count(&self) -> usize {
            self.connects.load(Ordering::SeqCst)
        }

        fn at_notify(&self) -> Vec<usize> {
            self.provider.connects_at_notify.lock().unwrap().clone()
        }

        /// A connect whose `n`th run (1-based) returns `outcome(n)`.
        fn connect(
            &self,
            outcome: impl Fn(usize) -> Result<usize, Miss>,
        ) -> impl FnMut() -> std::future::Ready<Result<usize, Miss>> {
            let connects = Arc::clone(&self.connects);
            move || {
                let n = connects.fetch_add(1, Ordering::SeqCst) + 1;
                std::future::ready(outcome(n))
            }
        }

        /// Every connect fails; wakeable or not.
        fn failing(
            &self,
            wakeable: bool,
        ) -> impl FnMut() -> std::future::Ready<Result<usize, Miss>> {
            self.connect(move |n| Err((n, wakeable)))
        }

        /// Connects fail wakeable until the `at`th, which succeeds.
        fn succeeding_at(
            &self,
            at: usize,
        ) -> impl FnMut() -> std::future::Ready<Result<usize, Miss>> {
            self.connect(move |n| if n >= at { Ok(n) } else { Err((n, true)) })
        }
    }

    fn wakeable(err: &Miss) -> bool {
        err.1
    }

    #[tokio::test]
    async fn first_try_success_sends_no_wake_and_reads_no_clock() {
        let rig = Rig::new();
        let clock_reads = AtomicUsize::new(0);
        let res = connect_with_wake_at(
            &rig.options(false, 3),
            || {
                clock_reads.fetch_add(1, Ordering::SeqCst);
                0
            },
            wakeable,
            rig.succeeding_at(1),
        )
        .await;
        assert_eq!(res, Ok((1, None)));
        assert_eq!((rig.connect_count(), rig.notifies()), (1, 0));
        assert_eq!(clock_reads.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn permanent_error_ends_at_once_without_a_wake_or_clock_read() {
        let rig = Rig::new();
        let clock_reads = AtomicUsize::new(0);
        let res: Result<(usize, _), Miss> = connect_with_wake_at(
            &rig.options(false, 3),
            || {
                clock_reads.fetch_add(1, Ordering::SeqCst);
                0
            },
            wakeable,
            rig.failing(false),
        )
        .await;
        assert_eq!(res, Err((1, false)));
        assert_eq!((rig.connect_count(), rig.notifies()), (1, 0));
        assert_eq!(clock_reads.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn wakeable_miss_wakes_once_then_retries_to_success() {
        let rig = Rig::new();
        let res = connect_with_wake(&rig.options(false, 5), wakeable, rig.succeeding_at(3)).await;
        assert_eq!(res, Ok((3, Some(WakeOutcome::Delivered))));
        assert_eq!((rig.connect_count(), rig.notifies()), (3, 1));
        assert_eq!(rig.at_notify(), vec![1], "the wake follows the first miss");
    }

    #[tokio::test]
    async fn exhausting_attempts_returns_the_last_error_after_one_wake() {
        let rig = Rig::new();
        let res: Result<(usize, _), Miss> =
            connect_with_wake(&rig.options(false, 3), wakeable, rig.failing(true)).await;
        assert_eq!(
            res,
            Err((4, true)),
            "the first connect plus max_attempts retries"
        );
        assert_eq!((rig.connect_count(), rig.notifies()), (4, 1));

        let rig = Rig::new();
        let res: Result<(usize, _), Miss> =
            connect_with_wake(&rig.options(true, 3), wakeable, rig.failing(true)).await;
        assert_eq!(
            res,
            Err((3, true)),
            "max_attempts connects after the pre-wake"
        );
        assert_eq!((rig.connect_count(), rig.notifies()), (3, 1));
    }

    #[tokio::test]
    async fn zero_attempts_still_connects_once_after_the_wake() {
        let rig = Rig::new();
        let mut wake = rig.options(false, 1);
        wake.max_attempts = 0;
        let res: Result<(usize, _), Miss> =
            connect_with_wake(&wake, wakeable, rig.failing(true)).await;
        assert_eq!(res, Err((2, true)));
        assert_eq!((rig.connect_count(), rig.notifies()), (2, 1));
    }

    #[tokio::test]
    async fn pre_wake_notifies_before_the_first_connect() {
        let rig = Rig::new();
        let res = connect_with_wake(&rig.options(true, 3), wakeable, rig.succeeding_at(1)).await;
        assert_eq!(res, Ok((1, Some(WakeOutcome::Delivered))));
        assert_eq!((rig.connect_count(), rig.notifies()), (1, 1));
        assert_eq!(rig.at_notify(), vec![0], "the wake precedes every connect");
    }

    #[tokio::test]
    async fn pre_wake_stops_on_a_permanent_error() {
        let rig = Rig::new();
        let res: Result<(usize, _), Miss> =
            connect_with_wake(&rig.options(true, 3), wakeable, rig.failing(false)).await;
        assert_eq!(res, Err((1, false)));
        assert_eq!((rig.connect_count(), rig.notifies()), (1, 1));
    }

    #[tokio::test]
    async fn a_permanent_error_on_a_retry_stops_at_once() {
        let rig = Rig::new();
        let res: Result<(usize, _), Miss> = connect_with_wake(
            &rig.options(false, 5),
            wakeable,
            rig.connect(|n| Err((n, n == 1))),
        )
        .await;
        assert_eq!(res, Err((2, false)));
        assert_eq!((rig.connect_count(), rig.notifies()), (2, 1));
    }

    #[tokio::test]
    async fn a_slow_wake_provider_reports_skipped() {
        let rig = Rig::with(
            Some(Duration::from_secs(30)),
            Reply::Outcome(WakeOutcome::Delivered),
        );
        let res = connect_with_wake(&rig.options(false, 3), wakeable, rig.succeeding_at(2)).await;
        assert_eq!(res, Ok((2, Some(WakeOutcome::Skipped))));
        assert_eq!((rig.connect_count(), rig.notifies()), (2, 1));
    }

    #[tokio::test]
    async fn a_failed_or_undelivered_wake_still_retries() {
        let cases = [
            (Reply::Fail, WakeOutcome::Skipped),
            (
                Reply::Outcome(WakeOutcome::Coalesced),
                WakeOutcome::Coalesced,
            ),
            (Reply::Outcome(WakeOutcome::Noop), WakeOutcome::Noop),
        ];
        for (reply, want) in cases {
            for pre_wake in [false, true] {
                let rig = Rig::with(None, reply);
                let res =
                    connect_with_wake(&rig.options(pre_wake, 5), wakeable, rig.succeeding_at(3))
                        .await;
                assert_eq!(res, Ok((3, Some(want))), "pre_wake={pre_wake}");
                assert_eq!((rig.connect_count(), rig.notifies()), (3, 1));
            }
        }
    }

    #[tokio::test]
    async fn the_wake_tag_time_is_read_when_the_hint_is_sent() {
        let rig = Rig::new();
        let clock = AtomicU64::new(1_000);
        let connects = Arc::clone(&rig.connects);
        let advancing = || {
            let n = connects.fetch_add(1, Ordering::SeqCst) + 1;
            clock.fetch_add(1, Ordering::SeqCst);
            std::future::ready(if n >= 3 { Ok(n) } else { Err((n, true)) })
        };
        let clock_reads = AtomicUsize::new(0);
        let res = connect_with_wake_at(
            &rig.options(false, 5),
            || {
                clock_reads.fetch_add(1, Ordering::SeqCst);
                clock.load(Ordering::SeqCst)
            },
            wakeable,
            advancing,
        )
        .await;
        assert!(res.is_ok());
        assert_eq!(clock_reads.load(Ordering::SeqCst), 1);
        let (tag, now) = rig.provider.last.lock().unwrap().unwrap();
        assert_eq!(now, 1_001, "the clock after the first connect, not before");
        assert!(tag == WakeSecret::from_bytes(SECRET).derive_tag(now));
    }

    #[tokio::test(start_paused = true)]
    async fn retry_delay_separates_only_the_post_wake_retries() {
        let delay = Duration::from_secs(10);
        let run = |pre_wake: bool, max_attempts: usize, wakeable_errors: bool| async move {
            let rig = Rig::new();
            let mut wake = rig.options(pre_wake, max_attempts);
            wake.retry_delay = delay;
            let start = tokio::time::Instant::now();
            let res: Result<(usize, _), Miss> =
                connect_with_wake(&wake, wakeable, rig.failing(wakeable_errors)).await;
            assert!(res.is_err());
            (start.elapsed(), rig.connect_count())
        };
        // 4 connects (first plus 3 retries): 2 sleeps, none after the wake or the last failure.
        assert_eq!(run(false, 3, true).await, (delay * 2, 4));
        // 3 connects after the pre-wake: 2 sleeps.
        assert_eq!(run(true, 3, true).await, (delay * 2, 3));
        // One retry attempt allowed: no sleep at all.
        assert_eq!(run(false, 1, true).await, (Duration::ZERO, 2));
        // A permanent error never sleeps.
        assert_eq!(run(false, 3, false).await, (Duration::ZERO, 1));
        assert_eq!(run(true, 3, false).await, (Duration::ZERO, 1));
    }

    #[tokio::test]
    async fn the_policy_classifier_wakes_only_on_wakeable_misses() {
        let make = |error: RuntimeError, committed: bool| {
            let mut err = AttemptError::from(error);
            err.committed = committed;
            err
        };
        let error = |permanent: bool| {
            if permanent {
                RuntimeError::Protocol("no dialable stored routes".into())
            } else {
                RuntimeError::Closed
            }
        };
        // (permanent error, committed, connects run, wake hints sent)
        let cases = [
            (false, false, 4, 1),
            (false, true, 1, 0),
            (true, false, 1, 0),
        ];
        for (permanent, committed, want_connects, want_notifies) in cases {
            let rig = Rig::new();
            let connects = Arc::clone(&rig.connects);
            let res: Result<(usize, _), AttemptError> =
                connect_with_wake_policy(&rig.options(false, 3), || {
                    connects.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(Err(make(error(permanent), committed)))
                })
                .await;
            assert!(res.is_err());
            assert_eq!(
                (rig.connect_count(), rig.notifies()),
                (want_connects, want_notifies)
            );
        }
    }
}
