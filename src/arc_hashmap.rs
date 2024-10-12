use std::collections::HashMap;
use std::hash::Hash;
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

type Value<V> = (Arc<V>, Arc<AtomicUsize>);
pub struct ArcHashMap<K, V>
where
    K: Eq + Hash,
{
    map: RwLock<HashMap<K, Value<V>>>,
}

pub struct Holder<'a, K: Eq + Hash, V> {
    val: Arc<V>,
    rc: Arc<AtomicUsize>,
    map: &'a ArcHashMap<K, V>,
}

impl<K: Eq + Hash, V> Drop for Holder<'_, K, V> {
    fn drop(&mut self) {
        self.rc.fetch_sub(1, Ordering::SeqCst);
        // debug!(remaining = self.rc.load(Ordering::SeqCst), "Dropping guard");
        self.map.purge();
    }
}

impl<K: Eq + Hash, V> Deref for Holder<'_, K, V> {
    type Target = V;

    fn deref(&self) -> &Self::Target {
        &self.val
    }
}

impl<K: Eq + Hash, V> Default for ArcHashMap<K, V> {
    fn default() -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
        }
    }
}

impl<K: Eq + Hash, V> ArcHashMap<K, V> {
    pub fn insert(&self, key: K, value: V) -> Holder<K, V> {
        self.get_or_insert_with(key, || value)
    }

    #[allow(clippy::missing_panics_doc)]
    pub fn get(&self, key: &K) -> Option<Holder<K, V>> {
        self.get_internal(self.map.read().expect("cannot obtain lock").get(key))
    }

    fn get_internal(&self, v: Option<&Value<V>>) -> Option<Holder<K, V>> {
        if let Some((v, rc)) = v {
            rc.fetch_add(1, Ordering::SeqCst);
            return Some(Holder {
                val: v.clone(),
                rc: rc.clone(),
                map: self,
            });
        }
        None
    }

    #[allow(clippy::missing_panics_doc)]
    pub fn get_or_insert_with<F>(&self, key: K, f: F) -> Holder<K, V>
    where
        F: FnOnce() -> V,
    {
        let mut map = self.map.write().expect("cannot obtain lock");
        self.get_internal(Some(
            map.entry(key)
                .or_insert_with(|| (Arc::new(f()), Arc::new(AtomicUsize::new(0)))),
        ))
        .unwrap()
    }

    fn purge(&self) {
        let mut map = self.map.write().unwrap();
        map.retain(|_, v| v.1.load(Ordering::SeqCst) > 0);
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[allow(clippy::missing_panics_doc)]
    pub fn len(&self) -> usize {
        self.map.read().expect("cannot obtain lock").len()
    }
}

#[cfg(test)]
mod tests {
    use std::{thread, time::Duration};

    use super::*;

    #[test]
    fn test_arc_hashmap() {
        let m = ArcHashMap::default();
        {
            let v = m.insert(1, 2);
            assert_eq!(*v, 2);
            assert_eq!(m.len(), 1);
            m.insert(2, 3);
            assert_eq!(m.len(), 1);
            let v = m.get_or_insert_with(3, || 4);
            assert_eq!(*v, 4);
            assert_eq!(m.len(), 2);
        }
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn test_insert_and_get() {
        let map = ArcHashMap::default();

        let value = map.insert("key1", "value1");
        assert_eq!(*value, "value1");

        let retrieved = map.get(&"key1").unwrap();
        assert_eq!(*retrieved, "value1");
    }

    #[test]
    fn test_get_or_insert_with() {
        let map = ArcHashMap::default();
        let value = map.get_or_insert_with("key2", || "value2");
        assert_eq!(*value, "value2");

        let retrieved = map.get(&"key2").unwrap();
        assert_eq!(*retrieved, "value2");

        let existing = map.get_or_insert_with("key2", || "new value");
        assert_eq!(*existing, "value2");
    }

    #[test]
    fn test_holder_behavior() {
        let map = ArcHashMap::default();
        map.insert(1, "one");
        assert!(map.is_empty());
        let v = map.insert(1, "1");
        assert!(!map.is_empty());
        assert_eq!(map.len(), 1);
        assert_eq!(*v, "1");
    }

    #[test]
    fn test_len_and_is_emtpy() {
        let map = ArcHashMap::default();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);

        let _v = map.insert("key1", "value");
        assert!(!map.is_empty());
        assert_eq!(map.len(), 1);
        let _v1 = map.insert("key2", "value");
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_drop_behavior() {
        let map = ArcHashMap::default();
        {
            let _v1 = map.insert("key1", "value1");
            assert_eq!(map.len(), 1);
            {
                let _v2 = map.insert("key2", "value2");
                assert_eq!(map.len(), 2);
            }
            assert_eq!(map.len(), 1);
        }
        assert_eq!(map.len(), 0)
    }
    #[test]
    fn test_concurrent_access() {
        let map = Arc::new(ArcHashMap::default());
        let threads: Vec<_> = (0..10)
            .map(|i| {
                let map_clone = Arc::clone(&map);
                thread::spawn(move || {
                    let key = format!("key{}", i);
                    let value = format!("value{}", i);
                    let _v = map_clone.insert(key.clone(), value);
                    thread::sleep(Duration::from_millis(10));
                    let retrieved = map_clone.get(&key).unwrap();
                    assert_eq!(*retrieved, format!("value{}", i));
                })
            })
            .collect();

        for thread in threads {
            thread.join().unwrap();
        }
    }

    #[test]
    fn test_purge_behavior() {
        let map = ArcHashMap::default();
        {
            let _value1 = map.insert("key7", "value7");
            let _value2 = map.insert("key8", "value8");
            assert_eq!(map.len(), 2);
        }
        // After dropping both values, the map should be empty
        assert_eq!(map.len(), 0);

        // Insert a new value to ensure the map still works after purging
        let _value3 = map.insert("key9", "value9");
        assert_eq!(map.len(), 1);
    }

    // New tests and edge cases

    #[test]
    fn test_overwrite_existing_key() {
        let map = ArcHashMap::default();
        let value1 = map.insert("key", "value1");
        assert_eq!(*value1, "value1");

        let value2 = map.insert("key", "value2");
        assert_eq!(*value2, "value1"); // Should return the existing value

        let retrieved = map.get(&"key").unwrap();
        assert_eq!(*retrieved, "value1"); // Should still be the original value
    }

    #[test]
    fn test_get_nonexistent_key() {
        let map: ArcHashMap<&str, &str> = ArcHashMap::default();
        assert!(map.get(&"nonexistent").is_none());
    }

    #[test]
    fn test_multiple_references() {
        let map = ArcHashMap::default();
        let value1 = map.insert("key", "value");
        let value2 = map.get(&"key").unwrap();
        let value3 = map.get(&"key").unwrap();

        assert_eq!(*value1, "value");
        assert_eq!(*value2, "value");
        assert_eq!(*value3, "value");
        assert_eq!(map.len(), 1);

        drop(value1);
        assert_eq!(map.len(), 1);

        drop(value2);
        assert_eq!(map.len(), 1);

        drop(value3);
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn test_large_number_of_insertions() {
        let map: ArcHashMap<i32, String> = ArcHashMap::default();

        for i in 0..10000 {
            let value = map.get_or_insert_with(i, || i.to_string());
            assert_eq!(*value, i.to_string());
        }
    }

    #[test]
    fn test_concurrent_insert_and_drop() {
        let map = Arc::new(ArcHashMap::default());
        let threads: Vec<_> = (0..100)
            .map(|i| {
                let map_clone = Arc::clone(&map);
                thread::spawn(move || {
                    let key = i % 10; // Use only 10 keys to force contention
                    let _value = map_clone.insert(key, i);
                    thread::sleep(Duration::from_millis(1));
                    // The value is immediately dropped here
                })
            })
            .collect();

        for thread in threads {
            thread.join().unwrap();
        }

        // All values should have been dropped
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn test_zero_sized_values() {
        let map = ArcHashMap::default();
        let _v1 = map.insert("key1", ());
        let _v2 = map.insert("key2", ());

        assert_eq!(map.len(), 2);
        assert!(map.get(&"key1").is_some());
        assert!(map.get(&"key2").is_some());

        drop(_v1);
        assert_eq!(map.len(), 1);
    }
}
