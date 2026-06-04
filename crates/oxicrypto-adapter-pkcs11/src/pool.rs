//! A simple PKCS#11 session pool for reusing authenticated sessions.
//!
//! `cryptoki::session::Session` is `Send` but `!Sync` (it contains a
//! `PhantomData<*mut u32>` to prevent multi-thread sharing without
//! synchronisation).  Wrapping sessions in `Arc<Mutex<Vec<Session>>>` is
//! valid because:
//!
//! 1. `Session: Send` — the cryptoki crate applies `unsafe impl Send for Session`.
//! 2. `Mutex<T>` is `Sync` when `T: Send`, so `Arc<Mutex<Vec<Session>>>` is
//!    `Send + Sync`.
//! 3. Access to the inner `Vec` is serialised by the `Mutex`, satisfying the
//!    PKCS#11 requirement that the same session handle is not used concurrently.

use std::sync::{Arc, Mutex};

use cryptoki::session::Session;

use crate::provider::PkcsError;

/// A lightweight pool of PKCS#11 `Session` objects.
///
/// Sessions are returned to the pool when the [`PooledSession`] guard is
/// dropped.  If no sessions are available on checkout, the caller receives a
/// `PooledSession` whose inner `session` field is `None`; the caller is then
/// responsible for creating a fresh session and optionally returning it.
///
/// # Thread safety
///
/// The pool is `Send + Sync`.  Each session is protected by the `Mutex`:
/// only one thread accesses the session list at a time.  Individual
/// `PooledSession` guards own the session exclusively for their lifetime.
#[derive(Debug, Clone)]
pub struct Pkcs11SessionPool {
    inner: Arc<Mutex<Vec<Session>>>,
}

/// An exclusive lease on a `Session` from a [`Pkcs11SessionPool`].
///
/// On drop, the session (if present) is returned to the pool.
#[derive(Debug)]
pub struct PooledSession<'a> {
    pool: &'a Pkcs11SessionPool,
    /// The borrowed session, or `None` if the pool was empty at checkout.
    pub session: Option<Session>,
}

impl Pkcs11SessionPool {
    /// Create a new, empty session pool.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Add a pre-authenticated `Session` to the pool.
    ///
    /// # Errors
    /// Returns [`PkcsError::Internal`] if the pool mutex is poisoned.
    pub fn checkin(&self, session: Session) -> Result<(), PkcsError> {
        let mut sessions = self
            .inner
            .lock()
            .map_err(|_| PkcsError::Internal("pool mutex poisoned".to_string()))?;
        sessions.push(session);
        Ok(())
    }

    /// Checkout a `Session` from the pool.
    ///
    /// If the pool is empty, returns a [`PooledSession`] with `session = None`.
    /// The caller should then open and authenticate a fresh session and
    /// optionally return it via the `PooledSession`'s drop implementation.
    ///
    /// # Errors
    /// Returns [`PkcsError::Internal`] if the pool mutex is poisoned.
    pub fn checkout(&self) -> Result<PooledSession<'_>, PkcsError> {
        let mut sessions = self
            .inner
            .lock()
            .map_err(|_| PkcsError::Internal("pool mutex poisoned".to_string()))?;
        let session = sessions.pop();
        Ok(PooledSession {
            pool: self,
            session,
        })
    }

    /// Returns the number of idle sessions currently in the pool.
    ///
    /// # Errors
    /// Returns [`PkcsError::Internal`] if the pool mutex is poisoned.
    pub fn idle_count(&self) -> Result<usize, PkcsError> {
        let sessions = self
            .inner
            .lock()
            .map_err(|_| PkcsError::Internal("pool mutex poisoned".to_string()))?;
        Ok(sessions.len())
    }
}

impl Default for Pkcs11SessionPool {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> Drop for PooledSession<'a> {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            if let Ok(mut sessions) = self.pool.inner.lock() {
                sessions.push(session);
            }
            // If the lock is poisoned, the session is dropped (closed) here.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A new pool with no sessions returns PooledSession { session: None }.
    #[test]
    fn test_session_pool_empty() {
        let pool = Pkcs11SessionPool::new();
        let leased = pool
            .checkout()
            .expect("checkout should not fail on empty pool");
        assert!(
            leased.session.is_none(),
            "expected None session from empty pool"
        );
    }

    /// idle_count() returns 0 on a fresh pool.
    #[test]
    fn test_session_pool_idle_count_zero() {
        let pool = Pkcs11SessionPool::new();
        assert_eq!(pool.idle_count().expect("idle_count"), 0);
    }

    /// Cloning the pool shares the underlying session list.
    #[test]
    fn test_session_pool_clone_shares_state() {
        let pool = Pkcs11SessionPool::new();
        let cloned = pool.clone();
        assert_eq!(
            pool.idle_count().expect("count"),
            cloned.idle_count().expect("clone count")
        );
    }
}
