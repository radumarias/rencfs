use std::error::Error;
use std::marker::PhantomData;
use std::string::ToString;
use std::sync::{Arc, Weak};
use std::time::Duration;

use async_trait::async_trait;
use retainer::Cache;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

const KEY: &str = "key";

#[async_trait]
pub trait ValueProvider<T, E: Error + Send + Sync + 'static>: Send + Sync + 'static {
    async fn provide(&self) -> Result<T, E>;
}

/// It keeps the value in memory while it's being used and while there are strong references to it.
///
/// After the specified `duration` it will remove it from internal cache and just keep it while there are strong references to it, after which it will be zeroized and dropped from memory.  
// Helps mitigate against [Cold boot attack](https://en.wikipedia.org/wiki/Cold_boot_attack) by expiring values from memory.
pub struct ExpireValue<
    T: Send + Sync + 'static,
    E: Error + Send + Sync + 'static,
    P: ValueProvider<T, E> + Send + Sync + 'static,
> {
    cache: Arc<Cache<String, Arc<T>>>,
    weak: RwLock<Option<Weak<T>>>,
    monitor: Option<JoinHandle<()>>,
    provider: P,
    duration: Duration,
    _marker: PhantomData<E>,
}

impl<
        T: Send + Sync + 'static,
        E: Error + Send + Sync + 'static,
        P: ValueProvider<T, E> + Send + Sync + 'static,
    > ExpireValue<T, E, P>
{
    pub fn new(provider: P, duration: Duration) -> Self {
        let mut s = Self {
            cache: Arc::new(Cache::new()),
            weak: RwLock::new(None),
            monitor: None,
            provider,
            duration,
            _marker: PhantomData {},
        };
        let clone = s.cache.clone();
        s.monitor = Some(tokio::spawn(async move {
            clone.monitor(4, 0.25, duration).await;
        }));

        s
    }

    pub async fn get(&self) -> Result<Arc<T>, E> {
        if let Some(value) = self.get_from_ref_or_cache().await {
            return Ok(value);
        }
        let value = self.provider.provide().await?;
        let v = Arc::new(value);
        self.cache
            .insert(KEY.to_string(), v.clone(), self.duration)
            .await;
        let mut weak = self.weak.write().await;
        *weak = Some(Arc::downgrade(&v));
        Ok(v)
    }

    async fn get_from_ref_or_cache(&self) -> Option<Arc<T>> {
        let lock = self.weak.read().await;
        if let Some(ref weak) = *lock {
            // try to take it from weak ref
            if let Some(ref v) = weak.upgrade() {
                return Some(v.clone());
            }
            // try to take it from cache
            if let Some(v) = self.cache.get(&KEY.to_string()).await {
                return Some(v.clone());
            }
        }
        None
    }

    pub async fn clear(&self) {
        self.cache.clear().await;
    }
}

impl<T: Send + Sync + 'static, E: Error + Send + Sync + 'static, P: ValueProvider<T, E>> Drop
    for ExpireValue<T, E, P>
{
    fn drop(&mut self) {
        if let Some(ref monitor) = self.monitor {
            monitor.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::time::Duration;

    use tokio::sync::Mutex;

    use super::*;

    struct TestProvider {
        called: Arc<Mutex<u8>>,
    }
    #[async_trait]
    impl ValueProvider<String, Infallible> for TestProvider {
        async fn provide(&self) -> Result<String, Infallible> {
            *self.called.lock().await += 1;
            Ok("test".to_string())
        }
    }

    #[tokio::test]
    async fn test_expire_value() {
        let called = Arc::new(Mutex::default());
        let provider = TestProvider {
            called: called.clone(),
        };

        let expire_value = ExpireValue::new(provider, Duration::from_secs(1));
        let v = expire_value.get().await.unwrap();
        // ensure out value is correct
        assert_eq!(*v, "test");
        // ensure the provider wa called
        assert_eq!(*called.lock().await, 1);

        // wait for cache to expire
        tokio::time::sleep(Duration::from_secs(2)).await;
        // ensure it's taken from Weak ref
        let _ = expire_value.get().await.unwrap();
        assert_eq!(*called.lock().await, 1);

        // drop ref so now provider should be called again
        drop(v);
        let _ = expire_value.get().await.unwrap();
        // ensure provider was called again
        assert_eq!(*called.lock().await, 2);

        // clear cache
        expire_value.clear().await;
        let _ = expire_value.get().await.unwrap();
        // ensure provider was called again
        assert_eq!(*called.lock().await, 3);
    }

    #[tokio::test]
    async fn test_basic_functionality() {
        let called = Arc::new(Mutex::new(0));
        let provider = TestProvider {
            called: called.clone(),
        };

        let expire_value = ExpireValue::new(provider, Duration::from_secs(1));

        // First call should call the provider
        let v1 = expire_value.get().await.unwrap();
        assert_eq!(*v1, "test");
        assert_eq!(*called.lock().await, 1);

        // Second immediate call should use cached value
        let v2 = expire_value.get().await.unwrap();
        assert_eq!(*v2, "test");
        assert_eq!(*called.lock().await, 1);

        // Wait for cache to expire
        tokio::time::sleep(Duration::from_secs(2)).await;

        // This call should still use the weak reference
        let v3 = expire_value.get().await.unwrap();
        assert_eq!(*v3, "test");
        assert_eq!(*called.lock().await, 1);

        // Drop all strong references
        drop(v1);
        drop(v2);
        drop(v3);

        // This call should call the provider again
        let v4 = expire_value.get().await.unwrap();
        assert_eq!(*v4, "test");
        assert_eq!(*called.lock().await, 2);
    }

    #[tokio::test]
    async fn test_clear_cache() {
        let called = Arc::new(Mutex::new(0));
        let provider = TestProvider {
            called: called.clone(),
        };

        let expire_value = ExpireValue::new(provider, Duration::from_secs(10));

        // First call
        let _ = expire_value.get().await.unwrap();
        assert_eq!(*called.lock().await, 1);

        // Clear cache
        expire_value.clear().await;

        // This should call the provider again
        let _ = expire_value.get().await.unwrap();
        assert_eq!(*called.lock().await, 2);
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        let called = Arc::new(Mutex::new(0));
        let provider = TestProvider {
            called: called.clone(),
        };

        let expire_value = Arc::new(ExpireValue::new(provider, Duration::from_secs(1)));

        let mut handles = vec![];
        for _ in 0..10 {
            let ev = expire_value.clone();
            handles.push(tokio::spawn(async move { ev.get().await.unwrap() }));
        }

        for handle in handles {
            let _ = handle.await.unwrap();
        }

        // Provider should only be called once despite concurrent access
        assert_eq!(*called.lock().await, 1);
    }

    #[tokio::test]
    async fn test_error_propagation() {
        struct ErrorProvider;

        #[async_trait]
        impl ValueProvider<String, std::io::Error> for ErrorProvider {
            async fn provide(&self) -> Result<String, std::io::Error> {
                Err(std::io::Error::new(std::io::ErrorKind::Other, "Test error"))
            }
        }

        let expire_value = ExpireValue::new(ErrorProvider, Duration::from_secs(1));

        let result = expire_value.get().await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::Other);
    }

    #[tokio::test]
    async fn test_very_long_expiration() {
        let called = Arc::new(Mutex::new(0));
        let provider = TestProvider {
            called: called.clone(),
        };

        let expire_value = ExpireValue::new(provider, Duration::from_secs(1000));

        // First call
        let v1 = expire_value.get().await.unwrap();
        assert_eq!(*v1, "test");
        assert_eq!(*called.lock().await, 1);

        // Wait for a reasonable amount of time (e.g., 5 seconds)
        tokio::time::sleep(Duration::from_secs(5)).await;

        // Second call should still use cached value due to very long expiration
        let v2 = expire_value.get().await.unwrap();
        assert_eq!(*v2, "test");
        assert_eq!(*called.lock().await, 1);
    }
    #[tokio::test]
    async fn test_rapid_consecutive_calls() {
        let called = Arc::new(Mutex::new(0));
        let provider = TestProvider {
            called: called.clone(),
        };

        let expire_value = Arc::new(ExpireValue::new(provider, Duration::from_secs(1)));

        let mut handles = vec![];
        for _ in 0..100 {
            let ev = expire_value.clone();
            handles.push(tokio::spawn(async move { ev.get().await.unwrap() }));
        }

        for handle in handles {
            let _ = handle.await.unwrap();
        }

        // Provider should only be called once despite rapid consecutive calls
        assert_eq!(*called.lock().await, 1);
    }

    #[tokio::test]
    async fn test_alternating_clear_and_get() {
        let called = Arc::new(Mutex::new(0));
        let provider = TestProvider {
            called: called.clone(),
        };
        let expire_value = ExpireValue::new(provider, Duration::from_secs(1));
        for _ in 0..10 {
            let _ = expire_value.get().await.unwrap();
            expire_value.clear().await;
        }

        // Provider should be called 10 times due to alternating clear and get
        assert_eq!(*called.lock().await, 10);
    }

    #[tokio::test]
    async fn test_expired_value_with_living_reference() {
        let called = Arc::new(Mutex::new(0));
        let provider = TestProvider {
            called: called.clone(),
        };
        let expire_value = ExpireValue::new(provider, Duration::from_millis(50));

        // Get the initial value
        let initial_value = expire_value.get().await.unwrap();
        assert_eq!(*called.lock().await, 1);

        // Wait for the value to expire
        tokio::time::sleep(Duration::from_secs(1)).await;

        // ensure it's taken from Weak ref
        let _ = expire_value.get().await.unwrap();
        assert_eq!(*called.lock().await, 1);

        // The initial value should still be valid and contain the original data
        assert_eq!(*initial_value, "test");
    }

    #[tokio::test]
    async fn test_drop_expire_value_with_living_reference() {
        let called = Arc::new(Mutex::new(0));
        let provider = TestProvider {
            called: called.clone(),
        };

        let expire_value = ExpireValue::new(provider, Duration::from_secs(1));

        // Get the initial value
        let value = expire_value.get().await.unwrap();
        assert_eq!(*called.lock().await, 1);

        // Drop the ExpireValue instance
        drop(expire_value);

        // The value should still be valid and contain the original data
        assert_eq!(*value, "test");
    }

    #[tokio::test]
    async fn test_multiple_clears_between_gets() {
        let called = Arc::new(Mutex::new(0));
        let provider = TestProvider {
            called: called.clone(),
        };

        let expire_value = ExpireValue::new(provider, Duration::from_secs(1));

        // Initial get
        let _ = expire_value.get().await.unwrap();
        assert_eq!(*called.lock().await, 1);

        // Multiple clears
        for _ in 0..5 {
            expire_value.clear().await;
        }

        // Get after multiple clears
        let _ = expire_value.get().await.unwrap();

        // Provider should only be called twice (once for initial, once after clears)
        assert_eq!(*called.lock().await, 2);
    }
}
