use super::*;

fn established(initial_tsn: u32, receive_bytes: u32) -> Association {
    let mut association = Association::new_common(
        Arc::new(TransportConfig::default().with_max_receive_buffer_size(receive_bytes)),
        1062,
        SocketAddr::from_str("127.0.0.1:5000").unwrap(),
        None,
        Side::Client,
        1,
        initial_tsn,
    );
    association.state = AssociationState::Established;
    association.source_port = 5000;
    association.destination_port = 5000;
    association.peer_verification_tag = 1;
    association.peer_last_tsn = initial_tsn.wrapping_sub(1);
    association.rwnd = association.max_receive_buffer_size;
    association.ssthresh = association.rwnd;
    association.create_stream(1, false, PayloadProtocolIdentifier::Binary);
    association
}

fn send(sender: &mut Association, bytes: &[u8], now: Instant) -> Bytes {
    assert_eq!(sender.stream(1).unwrap().write(bytes).unwrap(), bytes.len());
    let packets = sender.gather_outbound(now).0;
    assert_eq!(packets.len(), 1);
    let packet = Packet::unmarshal(&packets[0]).unwrap();
    assert_eq!(packet.chunks.len(), 1);
    let mut data = packet.chunks[0]
        .as_any()
        .downcast_ref::<ChunkPayloadData>()
        .unwrap()
        .clone();
    // The sender requests an immediate SACK for the last DATA it has queued.
    // Clear the I-bit so these tests exercise the receiver's own rules.
    data.immediate_sack = false;
    let packet = sender
        .create_packet(vec![Box::new(data)])
        .marshal()
        .unwrap();
    assert!(
        !Packet::unmarshal(&packet).unwrap().chunks[0]
            .as_any()
            .downcast_ref::<ChunkPayloadData>()
            .unwrap()
            .immediate_sack,
        "the receiver must not rely on the I-bit"
    );
    packet
}

fn receive(receiver: &mut Association, packet: &Bytes, now: Instant) {
    receiver
        .handle_inbound(Packet::unmarshal(packet).unwrap(), now)
        .unwrap();
}

fn sack(receiver: &mut Association, now: Instant) -> ChunkSelectiveAck {
    let packets = receiver.gather_outbound(now).0;
    assert_eq!(packets.len(), 1, "expected a SACK without advancing time");
    assert!(packets[0].len() <= receiver.mtu as usize);
    assert!(packets[0].len() <= COMMON_HEADER_SIZE as usize + u16::MAX as usize);
    let packet = Packet::unmarshal(&packets[0]).unwrap();
    assert_eq!(packet.chunks.len(), 1);
    let ack = packet.chunks[0]
        .as_any()
        .downcast_ref::<ChunkSelectiveAck>()
        .unwrap();
    ChunkSelectiveAck {
        cumulative_tsn_ack: ack.cumulative_tsn_ack,
        advertised_receiver_window_credit: ack.advertised_receiver_window_credit,
        gap_ack_blocks: ack.gap_ack_blocks.clone(),
        duplicate_tsn: ack.duplicate_tsn.clone(),
    }
}

fn delayed_sack(receiver: &mut Association, now: Instant) -> ChunkSelectiveAck {
    assert!(receiver.gather_outbound(now).0.is_empty());
    let due = now + Duration::from_millis(200);
    receiver.handle_timeout(due);
    sack(receiver, due)
}

fn read(receiver: &mut Association) -> Option<Vec<u8>> {
    receiver.stream(1).unwrap().read().unwrap().map(|message| {
        let mut bytes = vec![0; message.len()];
        assert_eq!(message.read(&mut bytes).unwrap(), bytes.len());
        bytes
    })
}

#[test]
fn cumulative_duplicates_are_reported_immediately_and_drained() {
    let mut sender = established(10, 65536);
    let mut receiver = established(10, 65536);
    let now = Instant::now();
    let first = send(&mut sender, b"first", now);
    receive(&mut receiver, &first, now);
    assert_eq!(read(&mut receiver), Some(b"first".to_vec()));
    assert!(delayed_sack(&mut receiver, now).duplicate_tsn.is_empty());

    let duplicate_at = now + Duration::from_millis(210);
    receive(&mut receiver, &first, duplicate_at);
    let ack = sack(&mut receiver, duplicate_at);
    assert_eq!(ack.cumulative_tsn_ack, 10);
    assert_eq!(ack.duplicate_tsn, [10]);
    assert!(read(&mut receiver).is_none());

    let next_at = duplicate_at + Duration::from_millis(1);
    let second = send(&mut sender, b"second", next_at);
    receive(&mut receiver, &second, next_at);
    assert_eq!(read(&mut receiver), Some(b"second".to_vec()));
    let ack = delayed_sack(&mut receiver, next_at);
    assert_eq!(ack.cumulative_tsn_ack, 11);
    assert!(ack.duplicate_tsn.is_empty(), "reports drain after one SACK");
    assert!(read(&mut receiver).is_none());
}

#[test]
fn gap_duplicates_preserve_order_and_are_reported_once() {
    let mut sender = established(10, 65536);
    let mut receiver = established(10, 65536);
    let now = Instant::now();
    let first = send(&mut sender, b"first", now);
    let second = send(&mut sender, b"second", now);
    receive(&mut receiver, &second, now);
    let ack = sack(&mut receiver, now);
    assert_eq!(ack.cumulative_tsn_ack, 9);
    assert!(ack.duplicate_tsn.is_empty());
    assert_eq!(ack.gap_ack_blocks.len(), 1);
    assert_eq!(ack.gap_ack_blocks[0].start, 2);
    assert!(read(&mut receiver).is_none());
    let queued_bytes = receiver.payload_queue.get_num_bytes();

    receive(&mut receiver, &second, now);
    let ack = sack(&mut receiver, now);
    assert_eq!(ack.duplicate_tsn, [11]);
    assert_eq!(receiver.payload_queue.get_num_bytes(), queued_bytes);
    assert!(read(&mut receiver).is_none());

    receive(&mut receiver, &first, now);
    assert_eq!(read(&mut receiver), Some(b"first".to_vec()));
    assert_eq!(read(&mut receiver), Some(b"second".to_vec()));
    assert!(read(&mut receiver).is_none());
    // DATA that closes the last gap is acknowledged without delay.
    let ack = sack(&mut receiver, now);
    assert_eq!(ack.cumulative_tsn_ack, 11);
    assert!(ack.gap_ack_blocks.is_empty());
    assert!(ack.duplicate_tsn.is_empty());
}

#[test]
fn cumulative_duplicate_detection_handles_tsn_wrap() {
    let initial = u32::MAX - 1;
    let mut receiver = established(initial, 65536);
    let mut now = Instant::now();
    let mut packets = Vec::new();
    for index in 0..3 {
        let data = [index];
        let packet = Packet {
            common_header: CommonHeader {
                source_port: 5000,
                destination_port: 5000,
                verification_tag: 1,
            },
            chunks: vec![Box::new(ChunkPayloadData {
                beginning_fragment: true,
                ending_fragment: true,
                immediate_sack: false,
                tsn: initial.wrapping_add(index as u32),
                stream_identifier: 1,
                stream_sequence_number: index as u16,
                payload_type: PayloadProtocolIdentifier::Binary,
                user_data: Bytes::copy_from_slice(&data),
                ..Default::default()
            })],
        }
        .marshal()
        .unwrap();
        receive(&mut receiver, &packet, now);
        assert_eq!(read(&mut receiver), Some(data.to_vec()));
        assert!(delayed_sack(&mut receiver, now).duplicate_tsn.is_empty());
        packets.push(packet);
        now += Duration::from_millis(210);
    }
    assert_eq!(receiver.peer_last_tsn, 0);
    for (index, packet) in packets.iter().enumerate() {
        receive(&mut receiver, packet, now);
        let ack = sack(&mut receiver, now);
        assert_eq!(ack.cumulative_tsn_ack, 0);
        assert_eq!(ack.duplicate_tsn, [initial.wrapping_add(index as u32)]);
        assert!(read(&mut receiver).is_none());
    }
}

#[test]
fn duplicate_cancels_an_outstanding_delayed_ack() {
    let mut sender = established(10, 65536);
    let mut receiver = established(10, 65536);
    let now = Instant::now();
    let packet = send(&mut sender, b"first", now);
    receive(&mut receiver, &packet, now);
    assert!(receiver.gather_outbound(now).0.is_empty());
    assert_eq!(
        receiver.timers.get(Timer::Ack),
        Some(now + Duration::from_millis(200))
    );

    let duplicate_at = now + Duration::from_millis(1);
    receive(&mut receiver, &packet, duplicate_at);
    assert_eq!(sack(&mut receiver, duplicate_at).duplicate_tsn, [10]);
    assert_eq!(receiver.timers.get(Timer::Ack), None);
    receiver.handle_timeout(now + Duration::from_millis(200));
    assert!(
        receiver
            .gather_outbound(now + Duration::from_millis(200))
            .0
            .is_empty()
    );
    assert_eq!(read(&mut receiver), Some(b"first".to_vec()));
    assert!(read(&mut receiver).is_none());
}

#[test]
fn receive_window_rejection_is_not_a_duplicate() {
    let mut sender = established(10, 65536);
    let mut receiver = established(10, 4);
    let now = Instant::now();
    let first = send(&mut sender, b"full", now);
    let second = send(&mut sender, b"new", now);
    receive(&mut receiver, &first, now);
    assert_eq!(
        delayed_sack(&mut receiver, now).advertised_receiver_window_credit,
        0
    );

    for offset in [210, 420] {
        let at = now + Duration::from_millis(offset);
        receive(&mut receiver, &second, at);
        let ack = delayed_sack(&mut receiver, at);
        assert_eq!(ack.cumulative_tsn_ack, 10);
        assert!(
            ack.duplicate_tsn.is_empty(),
            "rejected DATA was never received"
        );
    }
    assert_eq!(read(&mut receiver), Some(b"full".to_vec()));
    assert!(read(&mut receiver).is_none());

    let retry_at = now + Duration::from_millis(630);
    receive(&mut receiver, &second, retry_at);
    assert_eq!(read(&mut receiver), Some(b"new".to_vec()));
    let ack = delayed_sack(&mut receiver, retry_at);
    assert_eq!(ack.cumulative_tsn_ack, 11);
    assert!(ack.duplicate_tsn.is_empty());
    assert!(read(&mut receiver).is_none());
}

#[test]
fn bundled_duplicates_report_every_tsn_without_redelivery() {
    let mut sender = established(10, 65536);
    let mut receiver = established(10, 65536);
    let now = Instant::now();
    let first = send(&mut sender, b"first", now);
    let second = send(&mut sender, b"second", now);
    let mut packet = Packet::unmarshal(&first).unwrap();
    packet
        .chunks
        .extend(Packet::unmarshal(&second).unwrap().chunks);
    let bundle = packet.marshal().unwrap();
    receive(&mut receiver, &bundle, now);
    let ack = delayed_sack(&mut receiver, now);
    assert_eq!(ack.cumulative_tsn_ack, 11);
    assert!(ack.duplicate_tsn.is_empty());
    assert_eq!(read(&mut receiver), Some(b"first".to_vec()));
    assert_eq!(read(&mut receiver), Some(b"second".to_vec()));

    let duplicate_at = now + Duration::from_millis(210);
    receive(&mut receiver, &bundle, duplicate_at);
    let ack = sack(&mut receiver, duplicate_at);
    assert_eq!(ack.cumulative_tsn_ack, 11);
    assert_eq!(ack.duplicate_tsn, [10, 11]);
    assert!(read(&mut receiver).is_none());
    assert!(receiver.gather_outbound(duplicate_at).0.is_empty());
}

#[test]
fn duplicate_metadata_is_bounded_without_queuing_payload() {
    let mut queue = PayloadQueue::new();
    for _ in 0..1000 {
        queue.record_duplicate(10, 3);
    }
    assert_eq!(queue.pop_duplicates(), [10, 10, 10]);
    assert!(queue.pop_duplicates().is_empty());
    assert_eq!(queue.get_num_bytes(), 0);
    assert!(queue.is_empty());
    queue.record_duplicate(11, 0);
    assert!(queue.pop_duplicates().is_empty());
}

#[test]
fn duplicate_bursts_fit_mtu_and_chunk_length_and_drain() {
    for mtu in [1090, 100_000] {
        let mut sender = established(10, 65536);
        let mut receiver = established(10, 65536);
        receiver.mtu = mtu;
        let now = Instant::now();
        let packet = send(&mut sender, b"first", now);
        receive(&mut receiver, &packet, now);
        assert_eq!(read(&mut receiver), Some(b"first".to_vec()));
        delayed_sack(&mut receiver, now);
        let capacity = ((mtu as usize - 12).min(u16::MAX as usize) - 16) / 4;
        let duplicate_at = now + Duration::from_millis(210);
        for _ in 0..capacity + 100 {
            receive(&mut receiver, &packet, duplicate_at);
        }
        let ack = sack(&mut receiver, duplicate_at);
        assert_eq!(ack.duplicate_tsn, vec![10; capacity]);
        assert_eq!(ack.advertised_receiver_window_credit, 65536);
        assert!(read(&mut receiver).is_none());

        let next_at = duplicate_at + Duration::from_millis(1);
        let second = send(&mut sender, b"second", next_at);
        receive(&mut receiver, &second, next_at);
        assert!(
            delayed_sack(&mut receiver, next_at)
                .duplicate_tsn
                .is_empty()
        );
        assert_eq!(read(&mut receiver), Some(b"second".to_vec()));
    }
}

#[test]
fn lowest_gap_blocks_take_priority_over_duplicate_reports() {
    let capacity = (1090 - 12 - 16) / 4;
    for gap_count in [2, capacity + 3] {
        let mut receiver = established(10, 65536);
        let now = Instant::now();
        let mut first_gap = None;
        for index in 0..gap_count {
            let packet = Packet {
                common_header: CommonHeader {
                    source_port: 5000,
                    destination_port: 5000,
                    verification_tag: 1,
                },
                chunks: vec![Box::new(ChunkPayloadData {
                    unordered: true,
                    beginning_fragment: true,
                    ending_fragment: true,
                    immediate_sack: false,
                    tsn: 11 + 2 * index as u32,
                    stream_identifier: 1,
                    payload_type: PayloadProtocolIdentifier::Binary,
                    user_data: Bytes::from_static(b"gap"),
                    ..Default::default()
                })],
            }
            .marshal()
            .unwrap();
            receive(&mut receiver, &packet, now);
            assert_eq!(read(&mut receiver), Some(b"gap".to_vec()));
            first_gap.get_or_insert(packet);
        }
        for _ in 0..capacity + 100 {
            receive(&mut receiver, first_gap.as_ref().unwrap(), now);
        }
        let ack = sack(&mut receiver, now);
        assert_eq!(ack.cumulative_tsn_ack, 9);
        let reported_gaps = gap_count.min(capacity);
        assert_eq!(ack.gap_ack_blocks.len(), reported_gaps);
        for (index, gap) in ack.gap_ack_blocks.iter().enumerate() {
            assert_eq!(gap.start, 2 + 2 * index as u16);
            assert_eq!(gap.end, gap.start);
        }
        assert_eq!(ack.duplicate_tsn, vec![11; capacity - reported_gaps]);
        assert!(read(&mut receiver).is_none());
        assert!(receiver.payload_queue.pop_duplicates().is_empty());
    }
}

#[test]
fn gap_closing_data_is_acknowledged_at_once() {
    let mut sender = established(10, 65536);
    let mut receiver = established(10, 65536);
    let now = Instant::now();
    let first = send(&mut sender, b"first", now);
    let second = send(&mut sender, b"second", now);
    let third = send(&mut sender, b"third", now);
    receive(&mut receiver, &second, now);
    assert_eq!(sack(&mut receiver, now).gap_ack_blocks.len(), 1);

    receive(&mut receiver, &first, now);
    let ack = sack(&mut receiver, now);
    assert_eq!(ack.cumulative_tsn_ack, 11);
    assert!(ack.gap_ack_blocks.is_empty());

    // In-order DATA after the gap closed returns to delayed acknowledgement.
    receive(&mut receiver, &third, now);
    let ack = delayed_sack(&mut receiver, now);
    assert_eq!(ack.cumulative_tsn_ack, 12);
    assert_eq!(read(&mut receiver), Some(b"first".to_vec()));
    assert_eq!(read(&mut receiver), Some(b"second".to_vec()));
    assert_eq!(read(&mut receiver), Some(b"third".to_vec()));
}
