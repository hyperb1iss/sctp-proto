use super::*;

const PAYLOAD_SIZE: u32 = 1062;

fn established() -> Association {
    let mut association = Association::new_common(
        Arc::new(TransportConfig::default()),
        PAYLOAD_SIZE,
        SocketAddr::from_str("127.0.0.1:5000").unwrap(),
        None,
        Side::Client,
        1,
        1,
    );
    association.state = AssociationState::Established;
    association.source_port = 5000;
    association.destination_port = 5000;
    association.peer_verification_tag = 1;
    association.rwnd = association.max_receive_buffer_size;
    association.ssthresh = association.rwnd;
    association.create_stream(1, false, PayloadProtocolIdentifier::Binary);
    association
}

fn write(association: &mut Association, bytes: &[u8]) {
    assert_eq!(
        association.stream(1).unwrap().write(bytes).unwrap(),
        bytes.len()
    );
}

fn outbound(association: &mut Association, now: Instant) -> Vec<Bytes> {
    association.gather_outbound(now).0
}

fn deliver(association: &mut Association, packets: &[Bytes], now: Instant) {
    for packet in packets {
        association
            .handle_inbound(Packet::unmarshal(packet).unwrap(), now)
            .unwrap();
    }
}

fn data_chunks(packets: &[Bytes]) -> Vec<ChunkPayloadData> {
    packets
        .iter()
        .flat_map(|packet| {
            Packet::unmarshal(packet)
                .unwrap()
                .chunks
                .iter()
                .filter_map(|chunk| chunk.as_any().downcast_ref::<ChunkPayloadData>().cloned())
                .collect::<Vec<_>>()
        })
        .collect()
}

fn read(association: &mut Association) -> Vec<u8> {
    let message = association.stream(1).unwrap().read().unwrap().unwrap();
    let mut bytes = vec![0; message.len()];
    assert_eq!(message.read(&mut bytes).unwrap(), bytes.len());
    bytes
}

#[test]
fn recovery_flight_progresses_without_delayed_ack_waits() {
    let mut sender = established();
    let mut receiver = established();
    let start = Instant::now();
    let first = vec![1; 449];
    write(&mut sender, &first);
    let lost = outbound(&mut sender, start);
    assert!(
        data_chunks(&lost)[0].immediate_sack,
        "the last DATA before the queue drains requests an immediate SACK"
    );
    assert!(sender.pending_queue.is_empty());

    let timeout = sender.poll_timeout().unwrap();
    sender.handle_timeout(timeout);
    assert_eq!(sender.cwnd, 1090);
    assert_eq!(sender.ssthresh, 4360);
    let retransmit = outbound(&mut sender, timeout);
    assert_eq!(data_chunks(&retransmit)[0].tsn, data_chunks(&lost)[0].tsn);
    assert_eq!(data_chunks(&retransmit)[0].user_data, first);
    assert!(sender.pending_queue.is_empty());

    // The next message arrives only after the restricted flight was emitted.
    let second = vec![2; 2 * PAYLOAD_SIZE as usize + 25];
    write(&mut sender, &second);
    let mut now = timeout + Duration::from_millis(1);
    deliver(&mut receiver, &retransmit, now);
    assert_eq!(read(&mut receiver), first);
    let ack = outbound(&mut receiver, now);
    assert!(
        !ack.is_empty(),
        "the first recovery packet must not wait 200ms for a SACK"
    );
    deliver(&mut sender, &ack, now);
    assert_eq!(sender.cwnd, 1539);

    let next = outbound(&mut sender, now);
    let chunks = data_chunks(&next);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].user_data.len(), PAYLOAD_SIZE as usize);
    assert_eq!(sender.inflight_queue.get_num_bytes(), PAYLOAD_SIZE as usize);
    assert!(sender.inflight_queue.get_num_bytes() <= sender.cwnd as usize);
    now += Duration::from_millis(1);
    deliver(&mut receiver, &next, now);
    assert!(receiver.stream(1).unwrap().read().unwrap().is_none());
    let ack = outbound(&mut receiver, now);
    assert!(
        !ack.is_empty(),
        "the next restricted fragment must also progress immediately"
    );
    deliver(&mut sender, &ack, now);
    assert_eq!(sender.cwnd, 2601);

    let final_flight = outbound(&mut sender, now);
    assert_eq!(data_chunks(&final_flight).len(), 2);
    assert!(sender.pending_queue.is_empty());
    assert!(sender.inflight_queue.get_num_bytes() <= sender.cwnd as usize);
    deliver(&mut receiver, &final_flight, now + Duration::from_millis(1));
    assert_eq!(read(&mut receiver), second);
    assert!(receiver.stream(1).unwrap().read().unwrap().is_none());
}

#[test]
fn unflagged_data_keeps_delayed_ack_timer() {
    let mut sender = established();
    let mut receiver = established();
    let now = Instant::now();
    write(&mut sender, &vec![3; 2 * PAYLOAD_SIZE as usize + 449]);
    let packets = outbound(&mut sender, now);
    let chunks = data_chunks(&packets);
    assert_eq!(chunks.len(), 3);
    assert!(!chunks[0].immediate_sack);
    assert!(!chunks[1].immediate_sack);
    assert!(chunks[2].immediate_sack);

    // A packet that leaves more queued DATA behind keeps the delayed ACK.
    let first = packets
        .iter()
        .find(|packet| data_chunks(core::slice::from_ref(*packet))[0].tsn == chunks[0].tsn)
        .unwrap();
    deliver(&mut receiver, core::slice::from_ref(first), now);
    assert!(outbound(&mut receiver, now).is_empty());
    let deadline = receiver.poll_timeout().unwrap();
    assert_eq!(deadline - now, Duration::from_millis(200));
    receiver.handle_timeout(deadline - Duration::from_millis(1));
    assert!(outbound(&mut receiver, deadline - Duration::from_millis(1)).is_empty());
    receiver.handle_timeout(deadline);
    assert!(!outbound(&mut receiver, deadline).is_empty());
}

#[test]
fn drained_single_packet_is_acknowledged_at_once() {
    let mut sender = established();
    let mut receiver = established();
    let now = Instant::now();
    write(&mut sender, &[3; 449]);
    let packets = outbound(&mut sender, now);
    assert!(data_chunks(&packets)[0].immediate_sack);
    deliver(&mut receiver, &packets, now);
    assert!(
        !outbound(&mut receiver, now).is_empty(),
        "the peer must not hold the only outstanding DATA for 200ms"
    );
}

#[test]
fn new_data_bursts_end_with_an_ack_request() {
    // A burst ends either because a full fragment no longer fits the window
    // or because the queue drained. Both request an immediate SACK.
    for (cwnd, rwnd) in [
        (1090, 10000),
        (10000, 1090),
        (449 + PAYLOAD_SIZE - 1, 10000),
        (10000, 449 + PAYLOAD_SIZE - 1),
        (449 + PAYLOAD_SIZE, 10000),
        (10000, 449 + PAYLOAD_SIZE),
        (10000, 10000),
    ] {
        let mut sender = established();
        sender.cwnd = cwnd;
        sender.rwnd = rwnd;
        write(&mut sender, &[4; 449]);
        let chunks = data_chunks(&outbound(&mut sender, Instant::now()));
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].immediate_sack, "cwnd={cwnd}, rwnd={rwnd}");
        assert_eq!(sender.cwnd, cwnd);
        assert_eq!(sender.rwnd, rwnd - 449);
        assert!(
            !sender
                .inflight_queue
                .get(chunks[0].tsn)
                .unwrap()
                .immediate_sack
        );
    }
}

#[test]
fn immediate_ack_does_not_expand_congestion_or_receiver_window() {
    for (cwnd, rwnd) in [(1090, 10000), (10000, 1090)] {
        let mut sender = established();
        sender.cwnd = cwnd;
        sender.rwnd = rwnd;
        write(&mut sender, &vec![5; 2 * PAYLOAD_SIZE as usize]);
        let now = Instant::now();
        let chunks = data_chunks(&outbound(&mut sender, now));
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].immediate_sack);
        assert_eq!(sender.inflight_queue.get_num_bytes(), PAYLOAD_SIZE as usize);
        assert!(!sender.pending_queue.is_empty());
        assert!(outbound(&mut sender, now).is_empty());
        assert_eq!(sender.cwnd, cwnd);
        assert_eq!(sender.rwnd, rwnd - PAYLOAD_SIZE);
    }
}

#[test]
fn zero_window_probe_still_sends_only_one_chunk() {
    let mut sender = established();
    sender.rwnd = 0;
    write(&mut sender, &vec![6; 2 * PAYLOAD_SIZE as usize]);
    let now = Instant::now();
    let probe = data_chunks(&outbound(&mut sender, now));
    assert_eq!(probe.len(), 1);
    assert!(probe[0].immediate_sack);
    assert_eq!(sender.rwnd, 0);
    assert!(outbound(&mut sender, now).is_empty());
    let timeout = sender.poll_timeout().unwrap();
    sender.handle_timeout(timeout);
    let retransmit = data_chunks(&outbound(&mut sender, timeout));
    assert_eq!(retransmit.len(), 1);
    assert_eq!(retransmit[0].tsn, probe[0].tsn);
    assert!(retransmit[0].immediate_sack);
    assert_eq!(sender.rwnd, 0);
    assert!(!sender.pending_queue.is_empty());
}

#[test]
fn only_last_chunk_of_restricted_flight_requests_ack() {
    for (cwnd, rwnd) in [(4360, 10000), (10000, 4360)] {
        let mut sender = established();
        sender.cwnd = cwnd;
        sender.rwnd = rwnd;
        write(&mut sender, &vec![7; 5 * PAYLOAD_SIZE as usize]);
        let chunks = data_chunks(&outbound(&mut sender, Instant::now()));
        assert_eq!(chunks.len(), 4);
        assert!(chunks[..3].iter().all(|chunk| !chunk.immediate_sack));
        assert!(chunks[3].immediate_sack);
        assert!(sender.inflight_queue.get_num_bytes() <= cwnd as usize);
        assert_eq!(sender.rwnd, rwnd - 4 * PAYLOAD_SIZE);
        assert!(!sender.pending_queue.is_empty());
    }
}

#[test]
fn retransmission_recomputes_ack_request_from_current_window() {
    let mut sender = established();
    sender.cwnd = 1090;
    write(&mut sender, &[8; 449]);
    let now = Instant::now();
    let original = data_chunks(&outbound(&mut sender, now));
    assert!(original[0].immediate_sack);

    // A later retransmission can have enough room for another full fragment.
    sender.cwnd = 10000;
    sender.rwnd = 10000;
    sender.inflight_queue.mark_all_to_retrasmit();
    let retransmit = data_chunks(&outbound(&mut sender, now));
    assert_eq!(retransmit.len(), 1);
    assert!(!retransmit[0].immediate_sack);
    assert_eq!(retransmit[0].tsn, original[0].tsn);
    assert_eq!(
        retransmit[0].stream_sequence_number,
        original[0].stream_sequence_number
    );
    assert_eq!(retransmit[0].user_data, original[0].user_data);
}

#[test]
fn retransmission_receiver_window_counts_selected_bytes_once() {
    for (rwnd, immediate) in [
        (1090, true),
        (449 + PAYLOAD_SIZE - 1, true),
        (449 + PAYLOAD_SIZE, false),
    ] {
        let mut sender = established();
        let now = Instant::now();
        write(&mut sender, &[9; 449]);
        outbound(&mut sender, now);
        sender.rwnd = rwnd;
        sender.inflight_queue.mark_all_to_retrasmit();
        let chunks = data_chunks(&outbound(&mut sender, now));
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].immediate_sack, immediate, "rwnd={rwnd}");
        assert_eq!(sender.rwnd, rwnd);
        assert_eq!(sender.inflight_queue.get_num_bytes(), 449);
    }
}
