use std::num::NonZeroUsize;

use bytes::{Bytes, BytesMut};

use super::{AckFrequencyState, Connection, PacketBuilder, QlogRecvPacket, TransmitBuf};
use crate::{
    AckFrequencyConfig, ConnectionId, Duration, Event, FrameStats, Instant, PathId,
    SendDatagramError, Side, TransportConfig, TransportError, TransportErrorCode, VarInt,
    cid_queue::CidQueue,
    coding::Encodable,
    frame,
    packet::{self, Header, Packet, SpaceId},
    tests::security_connection,
    transport_parameters::TransportParameters,
};

const H: usize = core::mem::size_of::<frame::Datagram>();

fn connection(budget: usize) -> Connection {
    let mut config = TransportConfig::default();
    config.datagram_receive_buffer_size(Some(budget));
    config.datagram_send_buffer_size(budget);
    config.max_concurrent_multipath_paths(4);
    security_connection(config)
}

fn dispatch(conn: &mut Connection, payload: BytesMut) -> Result<(), TransportError> {
    let packet = Packet {
        header: Header::Short {
            spin: false,
            key_phase: false,
            dst_cid: ConnectionId::new(&[1; 8]),
            number: packet::PacketNumber::U8(0),
        },
        header_data: Bytes::new(),
        payload,
    };
    conn.process_payload(
        Instant::now(),
        conn.network_path(PathId::ZERO).unwrap(),
        PathId::ZERO,
        0,
        packet,
        &mut QlogRecvPacket::new(0),
    )
}

fn cid(
    conn: &mut Connection,
    path: Option<PathId>,
    sequence: u64,
    prior: u64,
) -> Result<(), TransportError> {
    let mut payload = BytesMut::new();
    frame::NewConnectionId {
        path_id: path,
        sequence,
        retire_prior_to: prior,
        id: ConnectionId::new(&sequence.to_be_bytes()),
        reset_token: [7; 16].into(),
    }
    .encode(&mut payload);
    dispatch(conn, payload)
}

fn receive(conn: &mut Connection, data: Bytes) -> Result<(), TransportError> {
    let mut payload = BytesMut::new();
    frame::Datagram { data }.encode(&mut payload);
    dispatch(conn, payload)
}

#[test]
fn security_retired_cid_frame_flood_is_bounded() {
    let mut conn = connection(4096);
    conn.spaces[SpaceId::Data].pending.retire_cids.clear();
    let prior = conn.remote_cids[&PathId::ZERO].active_seq() + 5;
    cid(&mut conn, None, prior, prior).unwrap();
    let cap = CidQueue::LEN * 10;
    while conn.spaces[SpaceId::Data].pending.retire_cids.len() < cap {
        cid(&mut conn, None, 0, 0).unwrap();
    }
    let before = conn.spaces[SpaceId::Data].pending.retire_cids.clone();
    let error = cid(&mut conn, None, 0, 0).unwrap_err();
    assert_eq!(error.code, TransportErrorCode::CONNECTION_ID_LIMIT_ERROR);
    assert_eq!(conn.spaces[SpaceId::Data].pending.retire_cids, before);
}

#[test]
fn security_empty_datagram_receive_frame_flood_is_bounded() {
    let mut conn = connection(2 * H);
    conn.events.clear();
    for _ in 0..100 {
        receive(&mut conn, Bytes::new()).unwrap();
    }
    assert_eq!(conn.datagrams.incoming.len(), 2);
    assert_eq!(
        conn.events
            .iter()
            .filter(|x| matches!(x, Event::DatagramReceived))
            .count(),
        1
    );
}

#[test]
fn security_empty_datagram_single_send_blocks() {
    let mut conn = connection(2 * H);
    conn.datagrams().send(Bytes::new(), false).unwrap();
    conn.datagrams().send(Bytes::new(), false).unwrap();
    assert!(
        matches!(conn.datagrams().send(Bytes::new(), false), Err(SendDatagramError::Blocked(x)) if x.is_empty())
    );
}

#[test]
fn security_empty_datagram_batch_send_has_exact_prefix() {
    let mut conn = connection(2 * H);
    assert_eq!(
        conn.datagrams()
            .send_many(&[Bytes::new(), Bytes::new(), Bytes::new()], false)
            .unwrap(),
        2
    );
}

#[test]
fn security_ack_delay_peer_minimum_roundtrip() {
    for max in [100u32, 200] {
        for configured in [
            None,
            Some(Duration::from_millis(1)),
            Some(Duration::from_millis(150)),
        ] {
            let params = TransportParameters {
                min_ack_delay: Some(100_000u32.into()),
                max_ack_delay: max.into(),
                ..TransportParameters::default()
            };
            let mut wire = Vec::new();
            params.write(&mut wire);
            let params = TransportParameters::read(Side::Server, &mut wire.as_slice()).unwrap();
            let config = AckFrequencyConfig {
                max_ack_delay: configured,
                ..AckFrequencyConfig::default()
            };
            let state = AckFrequencyState::new(Duration::from_millis(max.into()));
            assert_eq!(
                state.candidate_max_ack_delay(Duration::from_millis(5), &config, &params),
                Duration::from_millis(100)
            );
        }
    }
}

#[test]
fn security_cid_ordinary_and_multipath_share_admission_budget() {
    let mut conn = connection(4096);
    conn.spaces[SpaceId::Data].pending.retire_cids.clear();
    let active = conn.remote_cids[&PathId::ZERO].active_seq();
    // An ordinary range uses the final five available aggregate slots.
    for sequence in 0..45 {
        conn.spaces[SpaceId::Data]
            .pending
            .retire_cids
            .push((PathId(3), sequence));
    }
    cid(&mut conn, None, active + 5, active + 5).unwrap();
    assert_eq!(conn.spaces[SpaceId::Data].pending.retire_cids.len(), 50);
    let before = conn.spaces[SpaceId::Data].pending.retire_cids.clone();
    assert_eq!(
        cid(&mut conn, None, active + 6, active + 6)
            .unwrap_err()
            .code,
        TransportErrorCode::CONNECTION_ID_LIMIT_ERROR
    );
    assert_eq!(conn.spaces[SpaceId::Data].pending.retire_cids, before);

    let mut conn = connection(4096);
    conn.spaces[SpaceId::Data].pending.retire_cids.clear();
    conn.spaces[SpaceId::Data]
        .pending
        .retire_cids
        .extend((0..49).map(|seq| (PathId(3), seq)));
    let before = conn.spaces[SpaceId::Data].pending.retire_cids.clone();
    let active = conn.remote_cids[&PathId::ZERO].active_seq();
    assert_eq!(
        cid(&mut conn, None, active + 5, active + 5)
            .unwrap_err()
            .code,
        TransportErrorCode::CONNECTION_ID_LIMIT_ERROR
    );
    assert_eq!(conn.spaces[SpaceId::Data].pending.retire_cids, before);

    let mut conn = connection(4096);
    conn.spaces[SpaceId::Data].pending.retire_cids.clear();
    assert!(conn.is_multipath_negotiated());
    assert!(conn.local_max_path_id >= PathId(1));
    cid(&mut conn, Some(PathId(1)), 5, 5).unwrap();
    cid(&mut conn, None, active + 5, active + 5).unwrap();
    while conn.spaces[SpaceId::Data].pending.retire_cids.len() < 50 {
        cid(&mut conn, Some(PathId(1)), 0, 0).unwrap();
        if conn.spaces[SpaceId::Data].pending.retire_cids.len() < 50 {
            cid(&mut conn, None, 0, 0).unwrap();
        }
    }
    let before = conn.spaces[SpaceId::Data].pending.retire_cids.clone();
    assert!(before.iter().any(|&(p, _)| p == PathId(1)));
    assert!(before.iter().any(|&(p, _)| p == PathId::ZERO));
    assert_eq!(
        cid(&mut conn, Some(PathId(1)), 0, 0).unwrap_err().code,
        TransportErrorCode::CONNECTION_ID_LIMIT_ERROR
    );
    assert_eq!(conn.spaces[SpaceId::Data].pending.retire_cids, before);
}

#[test]
fn security_high_cid_sequence_retirement_is_bounded() {
    let mut conn = connection(4096);
    conn.spaces[SpaceId::Data].pending.retire_cids.clear();
    cid(
        &mut conn,
        None,
        VarInt::MAX.into_inner(),
        VarInt::MAX.into_inner(),
    )
    .unwrap();
    assert!(conn.spaces[SpaceId::Data].pending.retire_cids.len() <= CidQueue::LEN);
    while conn.spaces[SpaceId::Data].pending.retire_cids.len() < 50 {
        cid(&mut conn, None, VarInt::MAX.into_inner() - 1, 0).unwrap();
    }
    assert_eq!(
        cid(&mut conn, None, VarInt::MAX.into_inner() - 1, 0)
            .unwrap_err()
            .code,
        TransportErrorCode::CONNECTION_ID_LIMIT_ERROR
    );
    assert_eq!(conn.spaces[SpaceId::Data].pending.retire_cids.len(), 50);
}

#[test]
fn security_receive_metadata_refusal_preserves_queue() {
    let mut conn = connection(2 * H);
    receive(&mut conn, Bytes::from_static(b"a")).unwrap();
    conn.events.clear();
    let budget = 2 * H;
    let datagram = frame::Datagram {
        data: Bytes::from(vec![9; budget - <frame::Datagram as frame::FrameStruct>::SIZE_BOUND]),
    };
    let mut payload = BytesMut::new();
    datagram.encode(&mut payload);
    // Both peers use this budget, so the negotiated advertisement is the receive limit too.
    let advertised = conn
        .peer_params
        .max_datagram_frame_size
        .unwrap()
        .into_inner();
    assert_eq!(advertised, budget as u64);
    assert!(payload.len() as u64 <= advertised);
    assert!(datagram.data.len() + H > budget);
    dispatch(&mut conn, payload).unwrap();
    assert_eq!(conn.datagrams().recv(), Some(Bytes::from_static(b"a")));
    assert!(conn.datagrams().recv().is_none());
    assert!(conn.events.is_empty());
}

fn write_datagram(conn: &mut Connection, capacity: usize) -> Option<Bytes> {
    let mut bytes = Vec::new();
    {
        let mut transmit = TransmitBuf::new(&mut bytes, NonZeroUsize::MIN, capacity);
        transmit.start_new_datagram();
        let mut builder = PacketBuilder::simple_data_buf(&mut transmit);
        if !conn
            .datagrams
            .write(&mut builder, &mut FrameStats::default())
        {
            return None;
        }
    }
    let mut frames = frame::Iter::new(Bytes::from(bytes)).unwrap();
    let frame::Frame::Datagram(datagram) = frames.next().unwrap().unwrap() else {
        panic!("expected DATAGRAM")
    };
    assert!(frames.next().is_none());
    Some(datagram.data)
}

#[test]
fn security_datagram_budget_boundaries_and_empty_slices() {
    for budget in [0, H - 1, H, H + 1] {
        let mut conn = connection(budget);
        assert_eq!(conn.datagrams().send_many(&[], false).unwrap(), 0);
        assert_eq!(conn.datagrams().recv_many(&mut []), 0);
        let result = conn.datagrams().send(Bytes::new(), false);
        if budget < H {
            assert_eq!(result, Err(SendDatagramError::TooLarge));
        } else {
            result.unwrap();
            assert_eq!(conn.datagrams().send_buffer_space(), 0);
            assert!(matches!(
                conn.datagrams().send(Bytes::new(), false),
                Err(SendDatagramError::Blocked(_))
            ));
        }
        conn.datagrams.outgoing.assert_accounting(budget);
        if budget >= H {
            for _ in 0..20 {
                conn.datagrams().send(Bytes::new(), true).unwrap();
                conn.datagrams.outgoing.assert_accounting(budget);
                assert_eq!(conn.datagrams.outgoing.len(), 1);
            }
            assert_eq!(
                conn.datagrams()
                    .send_many(&[Bytes::new(), Bytes::new()], true)
                    .unwrap(),
                2
            );
            assert_eq!(conn.datagrams.outgoing.len(), 1);
            conn.datagrams.outgoing.assert_accounting(budget);
        } else {
            assert_eq!(
                conn.datagrams().send(Bytes::new(), true),
                Err(SendDatagramError::TooLarge)
            );
        }
        receive(&mut conn, Bytes::new()).unwrap();
        conn.datagrams.incoming.assert_accounting(budget);
        assert_eq!(conn.datagrams.incoming.len(), usize::from(budget >= H));
        assert_eq!(conn.datagrams().recv_many(&mut []), 0);
        let mut out = [Bytes::new(); 1];
        assert_eq!(
            conn.datagrams().recv_many(&mut out),
            usize::from(budget >= H)
        );
        conn.datagrams.incoming.assert_accounting(budget);
    }
    let items = [
        Bytes::from_static(b"a"),
        Bytes::new(),
        Bytes::from_static(b"bc"),
    ];
    let total = 3 * H + 3;
    for budget in [total - 1, total, total + 1] {
        let mut conn = connection(budget);
        assert_eq!(
            conn.datagrams().send_many(&items, false).unwrap(),
            if budget < total { 2 } else { 3 }
        );
        conn.datagrams.outgoing.assert_accounting(budget);
        for item in items.iter().take(if budget < total { 2 } else { 3 }) {
            assert_eq!(write_datagram(&mut conn, 1200), Some(item.clone()));
            conn.datagrams.outgoing.assert_accounting(budget);
        }
        assert!(write_datagram(&mut conn, 1200).is_none());
        for item in &items {
            receive(&mut conn, item.clone()).unwrap();
            conn.datagrams.incoming.assert_accounting(budget);
        }
        let retained = if budget < total {
            &items[1..]
        } else {
            &items[..]
        };
        conn.datagrams.incoming.assert_payloads(retained);
        for item in retained {
            assert_eq!(conn.datagrams().recv(), Some(item.clone()));
            conn.datagrams.incoming.assert_accounting(budget);
        }
    }
}

#[test]
fn security_datagram_eviction_retry_pruning_account_once() {
    let budget = 3 * H + 3;
    let mut conn = connection(budget);
    let mut expected = std::collections::VecDeque::<Bytes>::new();
    for n in 0..100 {
        let items = [Bytes::new(), Bytes::from(vec![n; (n % 3 + 1) as usize])];
        for item in &items {
            while expected.iter().map(|x| x.len() + H).sum::<usize>() + item.len() + H > budget {
                expected.pop_front().unwrap();
            }
            expected.push_back(item.clone());
        }
        if n % 2 == 0 {
            for item in &items {
                conn.datagrams().send(item.clone(), true).unwrap();
                conn.datagrams.outgoing.assert_accounting(budget);
            }
        } else {
            assert_eq!(
                conn.datagrams().send_many(&items, true).unwrap(),
                items.len()
            );
        }
        conn.datagrams.outgoing.assert_accounting(budget);
        conn.datagrams
            .outgoing
            .assert_payloads(&expected.iter().cloned().collect::<Vec<_>>());
    }
    assert!(write_datagram(&mut conn, 1).is_none());
    conn.datagrams.outgoing.assert_accounting(budget);
    conn.datagrams
        .outgoing
        .assert_payloads(&expected.iter().cloned().collect::<Vec<_>>());
    while let Some(item) = expected.pop_front() {
        assert_eq!(write_datagram(&mut conn, 1200), Some(item));
        conn.datagrams.outgoing.assert_accounting(budget);
    }
    assert!(write_datagram(&mut conn, 1200).is_none());

    conn.datagrams()
        .send_many(
            &[
                Bytes::new(),
                Bytes::from_static(b"a"),
                Bytes::from_static(b"bb"),
            ],
            true,
        )
        .unwrap();
    assert!(conn.datagrams.drop_oversized(2)); // Preserve the existing strict pruning boundary.
    conn.datagrams.outgoing.assert_accounting(budget);
    conn.datagrams
        .outgoing
        .assert_payloads(&[Bytes::new(), Bytes::from_static(b"a")]);
    assert_eq!(write_datagram(&mut conn, 1200), Some(Bytes::new()));
    assert_eq!(
        write_datagram(&mut conn, 1200),
        Some(Bytes::from_static(b"a"))
    );
    conn.datagrams.outgoing.assert_accounting(budget);
}

#[test]
fn security_datagram_atomic_size_rejection_preserves_existing_queue() {
    let mut conn = connection(2 * H);
    conn.datagrams()
        .send(Bytes::from_static(b"a"), false)
        .unwrap();
    for oversized in [
        Bytes::from(vec![1; H + 1]),
        Bytes::from(vec![1; conn.datagrams().max_size().unwrap() + 1]),
    ] {
        assert_eq!(
            conn.datagrams()
                .send_many(&[Bytes::new(), oversized.clone()], true),
            Err(SendDatagramError::TooLarge)
        );
        assert_eq!(
            conn.datagrams().send(oversized, true),
            Err(SendDatagramError::TooLarge)
        );
        assert!(!conn.datagrams.send_blocked);
        conn.datagrams.outgoing.assert_accounting(2 * H);
        conn.datagrams
            .outgoing
            .assert_payloads(&[Bytes::from_static(b"a")]);
    }
}

#[test]
fn security_datagram_mixed_receive_slow_reads_and_notifications() {
    let budget = 3 * H + 3;
    let mut conn = connection(budget);
    conn.events.clear();
    let mut expected = std::collections::VecDeque::<Bytes>::new();
    for n in 0..100u8 {
        let data = if n % 2 == 0 {
            Bytes::new()
        } else {
            Bytes::from(vec![n; 2])
        };
        while expected.iter().map(|x| x.len() + H).sum::<usize>() + data.len() + H > budget {
            expected.pop_front().unwrap();
        }
        expected.push_back(data.clone());
        receive(&mut conn, data).unwrap();
        conn.datagrams.incoming.assert_accounting(budget);
        if n % 3 == 0 {
            assert_eq!(conn.datagrams().recv(), expected.pop_front());
        }
        conn.datagrams.incoming.assert_accounting(budget);
        conn.datagrams
            .incoming
            .assert_payloads(&expected.iter().cloned().collect::<Vec<_>>());
    }
    // First insertion and the insertion after the first slow read emptied the queue.
    assert_eq!(
        conn.events
            .iter()
            .filter(|x| matches!(x, Event::DatagramReceived))
            .count(),
        2
    );
    let mut out = vec![Bytes::new(); expected.len()];
    assert_eq!(conn.datagrams().recv_many(&mut out), expected.len());
    assert_eq!(out, expected.into_iter().collect::<Vec<_>>());
    conn.datagrams.incoming.assert_accounting(budget);
    conn.events.clear();
    receive(&mut conn, Bytes::new()).unwrap();
    assert!(matches!(
        conn.events.pop_front(),
        Some(Event::DatagramReceived)
    ));
}

#[test]
fn security_datagram_packet_transmission_unblocks_and_allows_retry() {
    let mut conn = connection(H);
    conn.events.clear();
    conn.datagrams().send(Bytes::new(), false).unwrap();
    assert!(matches!(
        conn.datagrams().send(Bytes::new(), false),
        Err(SendDatagramError::Blocked(_))
    ));
    assert!(write_datagram(&mut conn, 1).is_none());
    assert!(conn.datagrams.send_blocked);
    assert!(conn.events.is_empty());
    let mut bytes = Vec::new();
    assert!(
        conn.poll_transmit(Instant::now(), NonZeroUsize::MIN, &mut bytes)
            .is_some()
    );
    assert!(!conn.datagrams.send_blocked);
    assert!(
        conn.events
            .iter()
            .any(|x| matches!(x, Event::DatagramsUnblocked))
    );
    conn.datagrams.outgoing.assert_accounting(H);
    conn.datagrams().send(Bytes::new(), false).unwrap();
    assert_eq!(
        conn.datagrams()
            .send_many(&[Bytes::new(), Bytes::new()], false)
            .unwrap(),
        0
    );
    assert!(conn.datagrams.send_blocked);
    assert!(
        conn.poll_transmit(Instant::now(), NonZeroUsize::MIN, &mut bytes)
            .is_some()
    );
    assert!(!conn.datagrams.send_blocked);
    assert_eq!(
        conn.datagrams()
            .send_many(&[Bytes::new(), Bytes::new()], false)
            .unwrap(),
        1
    );
    conn.datagrams.outgoing.assert_accounting(H);
}

#[test]
fn security_ack_delay_normal_automatic_limit_is_preserved() {
    let params = TransportParameters {
        min_ack_delay: Some(1_000u32.into()),
        ..TransportParameters::default()
    };
    let state = AckFrequencyState::new(Duration::from_millis(100));
    assert_eq!(
        state.candidate_max_ack_delay(
            Duration::from_millis(5),
            &crate::AckFrequencyConfig::default(),
            &params
        ),
        Duration::from_millis(25)
    );
    assert_eq!(
        state.candidate_max_ack_delay(
            Duration::from_millis(50),
            &crate::AckFrequencyConfig::default(),
            &params
        ),
        Duration::from_millis(50)
    );
}

#[test]
fn empty_range_insertion_sequence() {
    let mut ranges = crate::range_set::ArrayRangeSet::<2>::default();
    for range in [3..3, 6..10, 5..5, 2..7] {
        ranges.insert(range);
    }
    assert_eq!(ranges.iter().collect::<Vec<_>>(), vec![2..10]);
}

#[test]
fn security_unordered_empty_stream_followed_by_overlap_readback() {
    let mut conn = connection(4096);
    let id = crate::StreamId::new(Side::Server, crate::Dir::Uni, 0);
    for (offset, data) in [
        (3, Bytes::new()),
        (6, Bytes::from_static(b"ghij")),
        (5, Bytes::new()),
        (2, Bytes::from_static(b"cdefg")),
    ] {
        let mut payload = BytesMut::new();
        let meta = frame::StreamMeta {
            id,
            offsets: offset..offset + data.len() as u64,
            fin: false,
        };
        meta.encoder(true).encode(&mut payload);
        payload.extend_from_slice(&data);
        dispatch(&mut conn, payload).unwrap();
        if offset == 3 {
            // Switch the live receive stream to unordered mode before the overlapping frames.
            let mut stream = conn.recv_stream(id);
            let chunks = stream.read(false).unwrap();
            let _ = chunks.finalize();
        }
    }
    let mut stream = conn.recv_stream(id);
    let mut chunks = stream.read(false).unwrap();
    let mut output = std::collections::BTreeMap::new();
    loop {
        let chunk = match chunks.next(usize::MAX) {
            Ok(Some(chunk)) => chunk,
            Ok(None) | Err(crate::ReadError::Blocked) => break,
            Err(error) => panic!("unexpected stream read error: {error:?}"),
        };
        for (index, byte) in chunk.bytes.iter().enumerate() {
            assert!(output.insert(chunk.offset + index as u64, *byte).is_none());
        }
    }
    assert_eq!(
        output.into_iter().collect::<Vec<_>>(),
        (2..10).zip(b"cdefghij".iter().copied()).collect::<Vec<_>>()
    );
    let _ = chunks.finalize();
}

#[test]
fn security_pending_over_cap_refuses_new_frames_without_discarding_retransmissions() {
    let mut conn = connection(4096);
    conn.spaces[SpaceId::Data].pending.retire_cids.clear();
    let prior = conn.remote_cids[&PathId::ZERO].active_seq() + 5;
    cid(&mut conn, None, prior, prior).unwrap();
    // Local rotation/loss requeue may legitimately put this vector above peer-frame admission.
    conn.spaces[SpaceId::Data]
        .pending
        .retire_cids
        .extend((0..51).map(|seq| (PathId(1), seq)));
    let before = conn.spaces[SpaceId::Data].pending.retire_cids.clone();
    assert_eq!(
        cid(&mut conn, None, 0, 0).unwrap_err().code,
        TransportErrorCode::CONNECTION_ID_LIMIT_ERROR
    );
    assert_eq!(conn.spaces[SpaceId::Data].pending.retire_cids, before);
}
