//! Tests specifically for tokens

use std::{
    io::Cursor,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
};

use assert_matches::assert_matches;

use crate::{
    ConnectionError, ConnectionId, DatagramEvent, Duration, Endpoint, EndpointConfig, Event,
    FourTuple, Instant, SystemTime, TimeSource, TokenStore, TransportErrorCode, VarInt,
    DEFAULT_SUPPORTED_VERSIONS,
    frame::{ConnectionClose, Crypto, FrameStruct},
    packet::{FixedLengthConnectionIdParser, Header, InitialHeader, PacketNumber, ProtectedHeader},
};

use super::util::{
    IncomingConnectionBehavior, Pair, client_config, server_config, subscribe, validate_incoming,
};

use bytes::{Bytes, BytesMut};
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test as test;

#[test]
fn oversized_cached_initial_token() {
    let _guard = subscribe();
    for mtu in [1200, 1500] {
        let limit = initial_token_limit(mtu, None);
        for token_len in [0, 64, limit - 1, limit, limit + 1, mtu as usize] {
            let mut config = client_config();
            Arc::get_mut(&mut config.transport)
                .unwrap()
                .initial_mtu(mtu);
            config
                .token_store
                .insert("localhost", vec![0; token_len].into());
            let mut endpoint = Endpoint::new(Arc::new(EndpointConfig::default()), None, true);
            let now = Instant::now();
            let (_, mut conn) = endpoint
                .connect(now, config, "[::1]:4433".parse().unwrap(), "localhost")
                .unwrap();
            let mut buf = Vec::new();
            let fits = token_len <= limit;
            assert_eq!(
                conn.poll_transmit(now, NonZeroUsize::MIN, &mut buf)
                    .is_some(),
                fits,
                "token {token_len}, MTU {mtu}",
            );
            if fits {
                assert!(buf.len() <= mtu as usize);
                assert!(conn.stats().frame_tx.crypto > 0);
            } else {
                assert!(buf.is_empty());
                assert_matches!(
                    conn.poll(),
                    Some(Event::ConnectionLost { reason: ConnectionError::TransportError(err) })
                    if err.code == TransportErrorCode::PROTOCOL_VIOLATION
                        && err.reason == "Initial token leaves insufficient packet space"
                );
                assert!(conn.is_drained());
                assert!(
                    conn.poll_transmit(now, NonZeroUsize::MIN, &mut buf)
                        .is_none()
                );
                assert!(buf.is_empty());
            }
        }
    }
}

#[test]
fn oversized_retry_token() {
    let _guard = subscribe();
    let retry_cid = ConnectionId::new(&[1; 20]);
    let limit = initial_token_limit(1200, Some(retry_cid));
    for token_len in [64, limit - 1, limit, limit + 1, 1200] {
        let address = "[::1]:4433".parse().unwrap();
        let mut endpoint = Endpoint::new(Arc::new(EndpointConfig::default()), None, true);
        let now = Instant::now();
        let (_, mut conn) = endpoint
            .connect(now, client_config(), address, "localhost")
            .unwrap();
        let mut buf = Vec::new();
        assert!(
            conn.poll_transmit(now, NonZeroUsize::MIN, &mut buf)
                .is_some()
        );
        let ProtectedHeader::Initial(initial) = ProtectedHeader::decode(
            &mut Cursor::new(&buf[..]),
            &FixedLengthConnectionIdParser::new(0),
            DEFAULT_SUPPORTED_VERSIONS,
            false,
        )
        .unwrap() else {
            panic!("expected an Initial packet");
        };
        let mut retry = Vec::new();
        Header::Retry {
            src_cid: retry_cid,
            dst_cid: initial.src_cid,
            version: initial.version,
        }
        .encode(&mut retry);
        retry.resize(retry.len() + token_len, 0);
        let tag = server_config()
            .crypto
            .retry_tag(initial.version, initial.dst_cid, &retry);
        retry.extend_from_slice(&tag);
        let Some(DatagramEvent::ConnectionEvent(_, event)) = endpoint.handle(
            now,
            FourTuple::new(address, None),
            None,
            BytesMut::from(&retry[..]),
            &mut buf,
        ) else {
            panic!("Retry must be routed to the client connection");
        };
        conn.handle_event(event);
        let now = now + Duration::from_secs(1);
        let crypto_before = conn.stats().frame_tx.crypto;
        buf.clear();
        assert_eq!(
            conn.poll_transmit(now, NonZeroUsize::MIN, &mut buf)
                .is_some(),
            token_len <= limit,
            "Retry token {token_len}",
        );
        if token_len <= limit {
            assert!(conn.stats().frame_tx.crypto > crypto_before);
            assert!(buf.len() <= 1200);
        } else {
            assert!(buf.is_empty());
            assert_matches!(
                conn.poll(),
                Some(Event::ConnectionLost { reason: ConnectionError::TransportError(err) })
                if err.code == TransportErrorCode::PROTOCOL_VIOLATION
            );
            assert!(conn.is_drained());
            assert!(
                conn.poll_transmit(now, NonZeroUsize::MIN, &mut buf)
                    .is_none()
            );
            assert!(buf.is_empty());
        }
    }
}

fn initial_token_limit(mtu: u16, retry_cid: Option<ConnectionId>) -> usize {
    let mut endpoint = Endpoint::new(Arc::new(EndpointConfig::default()), None, true);
    let now = Instant::now();
    let (_, mut conn) = endpoint
        .connect(
            now,
            client_config(),
            "[::1]:4433".parse().unwrap(),
            "localhost",
        )
        .unwrap();
    let mut buf = Vec::new();
    assert!(
        conn.poll_transmit(now, NonZeroUsize::MIN, &mut buf)
            .is_some()
    );
    let ProtectedHeader::Initial(initial) = ProtectedHeader::decode(
        &mut Cursor::new(&buf[..]),
        &FixedLengthConnectionIdParser::new(0),
        DEFAULT_SUPPORTED_VERSIONS,
        false,
    )
    .unwrap() else {
        panic!("expected an Initial packet");
    };
    let dst_cid = retry_cid.unwrap_or(initial.dst_cid);
    let keys = server_config()
        .crypto
        .initial_keys(initial.version, dst_cid)
        .unwrap();
    // Encode with a two-byte token length, as used by every boundary case below.
    let mut header = Vec::new();
    Header::Initial(InitialHeader {
        src_cid: initial.src_cid,
        dst_cid,
        token: vec![0; 64].into(),
        number: PacketNumber::new(0, 0),
        version: initial.version,
    })
    .encode(&mut header);
    let required = (Crypto::SIZE_BOUND + 1).max(ConnectionClose::SIZE_BOUND);
    let limit = mtu as usize - (header.len() - 64) - keys.packet.local.tag_len() - required;
    assert!((64..16384).contains(&limit));
    limit
}

#[test]
fn stateless_retry() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    pair.server.handle_incoming = Box::new(validate_incoming);
    let (client_ch, _server_ch) = pair.connect();
    pair.client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);
}

#[test]
fn retry_token_expired() {
    let _guard = subscribe();

    let fake_time = Arc::new(FakeTimeSource::new());
    let retry_token_lifetime = Duration::from_secs(1);

    let mut pair = Pair::default();
    pair.server.handle_incoming = Box::new(validate_incoming);

    let mut config = server_config();
    config
        .time_source(Arc::clone(&fake_time) as _)
        .retry_token_lifetime(retry_token_lifetime);
    pair.server.set_server_config(Some(Arc::new(config)));

    let client_ch = pair.begin_connect(client_config());
    pair.drive_client();
    pair.drive_server();
    pair.drive_client();

    // to expire retry token
    fake_time.advance(retry_token_lifetime + Duration::from_millis(1));

    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::ConnectionLost { reason: ConnectionError::ConnectionClosed(err) })
        if err.error_code == TransportErrorCode::INVALID_TOKEN
    );

    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);
}

#[test]
fn use_token() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let client_config = client_config();
    let (client_ch, _server_ch) = pair.connect_with(client_config.clone());
    pair.client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);

    pair.server.handle_incoming = Box::new(|incoming| {
        assert!(incoming.remote_address_validated());
        assert!(incoming.may_retry());
        IncomingConnectionBehavior::Accept
    });
    let (client_ch_2, _server_ch_2) = pair.connect_with(client_config);
    pair.client
        .connections
        .get_mut(&client_ch_2)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);
}

#[test]
fn retry_then_use_token() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let client_config = client_config();
    pair.server.handle_incoming = Box::new(validate_incoming);
    let (client_ch, _server_ch) = pair.connect_with(client_config.clone());
    pair.client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);

    pair.server.handle_incoming = Box::new(|incoming| {
        assert!(incoming.remote_address_validated());
        assert!(incoming.may_retry());
        IncomingConnectionBehavior::Accept
    });
    let (client_ch_2, _server_ch_2) = pair.connect_with(client_config);
    pair.client
        .connections
        .get_mut(&client_ch_2)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);
}

#[test]
fn use_token_then_retry() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let client_config = client_config();
    let (client_ch, _server_ch) = pair.connect_with(client_config.clone());
    pair.client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);

    pair.server.handle_incoming = Box::new({
        let mut i = 0;
        move |incoming| {
            if i == 0 {
                assert!(incoming.remote_address_validated());
                assert!(incoming.may_retry());
                i += 1;
                IncomingConnectionBehavior::Retry
            } else if i == 1 {
                assert!(incoming.remote_address_validated());
                assert!(!incoming.may_retry());
                i += 1;
                IncomingConnectionBehavior::Accept
            } else {
                panic!("too many handle_incoming iterations")
            }
        }
    });
    let (client_ch_2, _server_ch_2) = pair.connect_with(client_config);
    pair.client
        .connections
        .get_mut(&client_ch_2)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);
}

#[test]
fn use_same_token_twice() {
    #[derive(Default)]
    struct EvilTokenStore(Mutex<Bytes>);

    impl TokenStore for EvilTokenStore {
        fn insert(&self, _server_name: &str, token: Bytes) {
            let mut lock = self.0.lock().unwrap();
            if lock.is_empty() {
                *lock = token;
            }
        }

        fn take(&self, _server_name: &str) -> Option<Bytes> {
            let lock = self.0.lock().unwrap();
            if lock.is_empty() {
                None
            } else {
                Some(lock.clone())
            }
        }
    }

    let _guard = subscribe();
    let mut pair = Pair::default();
    let mut client_config = client_config();
    client_config.token_store(Arc::new(EvilTokenStore::default()));
    let (client_ch, _server_ch) = pair.connect_with(client_config.clone());
    pair.client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);

    pair.server.handle_incoming = Box::new(|incoming| {
        assert!(incoming.remote_address_validated());
        assert!(incoming.may_retry());
        IncomingConnectionBehavior::Accept
    });
    let (client_ch_2, _server_ch_2) = pair.connect_with(client_config.clone());
    pair.client
        .connections
        .get_mut(&client_ch_2)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);

    pair.server.handle_incoming = Box::new(|incoming| {
        assert!(!incoming.remote_address_validated());
        assert!(incoming.may_retry());
        IncomingConnectionBehavior::Accept
    });
    let (client_ch_3, _server_ch_3) = pair.connect_with(client_config);
    pair.client
        .connections
        .get_mut(&client_ch_3)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);
}

#[test]
fn use_token_expired() {
    let _guard = subscribe();
    let fake_time = Arc::new(FakeTimeSource::new());
    let lifetime = Duration::from_secs(10000);
    let mut server_config = server_config();
    server_config
        .time_source(Arc::clone(&fake_time) as _)
        .validation_token
        .lifetime(lifetime);
    let mut pair = Pair::new(Default::default(), server_config);
    let client_config = client_config();
    let (client_ch, _server_ch) = pair.connect_with(client_config.clone());
    pair.client
        .connections
        .get_mut(&client_ch)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);

    pair.server.handle_incoming = Box::new(|incoming| {
        assert!(incoming.remote_address_validated());
        assert!(incoming.may_retry());
        IncomingConnectionBehavior::Accept
    });
    let (client_ch_2, _server_ch_2) = pair.connect_with(client_config.clone());
    pair.client
        .connections
        .get_mut(&client_ch_2)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);

    fake_time.advance(lifetime + Duration::from_secs(1));

    pair.server.handle_incoming = Box::new(|incoming| {
        assert!(!incoming.remote_address_validated());
        assert!(incoming.may_retry());
        IncomingConnectionBehavior::Accept
    });
    let (client_ch_3, _server_ch_3) = pair.connect_with(client_config);
    pair.client
        .connections
        .get_mut(&client_ch_3)
        .unwrap()
        .close(pair.time, VarInt(42), Bytes::new());
    pair.drive();
    assert_eq!(pair.client.known_connections(), 0);
    assert_eq!(pair.client.known_cids(), 0);
    assert_eq!(pair.server.known_connections(), 0);
    assert_eq!(pair.server.known_cids(), 0);
}

pub(super) struct FakeTimeSource(Mutex<SystemTime>);

impl FakeTimeSource {
    pub(super) fn new() -> Self {
        Self(Mutex::new(SystemTime::now()))
    }

    pub(super) fn advance(&self, dur: Duration) {
        *self.0.lock().unwrap() += dur;
    }
}

impl TimeSource for FakeTimeSource {
    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap()
    }
}
