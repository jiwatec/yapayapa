use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use uuid::Uuid;
use yapayapa_common::types::ServerFrame;

use crate::store::Store;

/// One live WebSocket connection. `conn_id` lets a disconnect handler avoid
/// tearing down a newer connection that replaced it.
pub struct OnlineConn {
    pub conn_id: Uuid,
    pub tx: mpsc::UnboundedSender<ServerFrame>,
}

pub struct AppState {
    pub store: Box<dyn Store>,
    pub online: Mutex<HashMap<Uuid, OnlineConn>>,
    pub max_attachment_bytes: u64,
    /// Max register/login attempts per IP per 5 minutes.
    pub auth_rate_max: usize,
    /// Sliding-window request counters for rate limiting, keyed per IP or per
    /// authenticated user.
    limiter: Mutex<HashMap<RateKey, Vec<Instant>>>,
}

/// Rate-limit bucket key. Each limit class gets its own variant so that
/// different limits (with different windows) never share a hit bucket —
/// e.g. heavy message sending must not consume the attachment-upload budget.
#[derive(Hash, PartialEq, Eq, Clone)]
pub enum RateKey {
    AuthIp(IpAddr),
    UserSend(Uuid),
    UserUpload(Uuid),
}

impl AppState {
    pub fn new(store: Box<dyn Store>, max_attachment_bytes: u64) -> Self {
        Self {
            store,
            online: Mutex::new(HashMap::new()),
            max_attachment_bytes,
            auth_rate_max: 20,
            limiter: Mutex::new(HashMap::new()),
        }
    }

    /// Loosen the per-IP auth rate limit (tests register many users).
    pub fn with_auth_rate(mut self, max: usize) -> Self {
        self.auth_rate_max = max;
        self
    }

    /// Returns true if the caller is within `max` events per `window`.
    pub fn rate_allow(&self, key: RateKey, max: usize, window: Duration) -> bool {
        let now = Instant::now();
        let mut g = self.limiter.lock().unwrap();
        let hits = g.entry(key).or_default();
        hits.retain(|t| now.duration_since(*t) < window);
        if hits.len() >= max {
            return false;
        }
        hits.push(now);
        true
    }

    pub fn send_if_online(&self, user_id: Uuid, frame: ServerFrame) -> bool {
        let g = self.online.lock().unwrap();
        match g.get(&user_id) {
            Some(conn) => conn.tx.send(frame).is_ok(),
            None => false,
        }
    }
}
