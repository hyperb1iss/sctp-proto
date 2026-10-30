use crate::chunk::chunk_selective_ack::GapAckBlock;

use super::*;

fn endpoint() -> Association {
    let mut association = Association::new_common(
        Arc::new(TransportConfig::default().with_rto_min_ms(400)),
        1062,
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
    association.rto_mgr.set_new_rtt(10);
    association.create_stream(1, false, PayloadProtocolIdentifier::Binary);
    association
}

fn send(sender: &mut Association, messages: &[Vec<u8>], now: Instant) -> Vec<Bytes> {
    for message in messages {
        assert_eq!(
            sender.stream(1).unwrap().write(message).unwrap(),
            message.len()
        );
    }
    sender.gather_outbound(now).0
}

fn receive(receiver: &mut Association, packets: &[Bytes], now: Instant) {
    for packet in packets {
        receiver
            .handle_inbound(Packet::unmarshal(packet).unwrap(), now)
            .unwrap();
    }
}

fn data(packets: &[Bytes]) -> Vec<ChunkPayloadData> {
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

fn duplicates(packets: &[Bytes]) -> Vec<u32> {
    packets
        .iter()
        .flat_map(|packet| {
            Packet::unmarshal(packet)
                .unwrap()
                .chunks
                .iter()
                .filter_map(|chunk| chunk.as_any().downcast_ref::<ChunkSelectiveAck>())
                .flat_map(|sack| sack.duplicate_tsn.iter().copied())
                .collect::<Vec<_>>()
        })
        .collect()
}

fn acknowledge(receiver: &mut Association, packets: &[Bytes], now: &mut Instant) -> Vec<Bytes> {
    *now += Duration::from_millis(1);
    receive(receiver, packets, *now);
    let mut ack = receiver.gather_outbound(*now).0;
    if ack.is_empty() {
        *now = receiver
            .timers
            .get(Timer::Ack)
            .expect("DATA schedules an ACK");
        receiver.handle_timeout(*now);
        ack = receiver.gather_outbound(*now).0;
    }
    assert!(!ack.is_empty(), "receiver must emit a serialized ACK");
    ack
}

fn timeout(sender: &mut Association, now: &mut Instant) -> Vec<Bytes> {
    *now = sender.timers.get(Timer::T3RTX).unwrap();
    sender.handle_timeout(*now);
    let retransmit = sender.gather_outbound(*now).0;
    assert!(!data(&retransmit).is_empty());
    retransmit
}

fn assert_messages(receiver: &mut Association, messages: &[Vec<u8>]) {
    for expected in messages {
        let message = receiver
            .stream(1)
            .unwrap()
            .read()
            .unwrap()
            .expect("ordered message");
        let mut actual = vec![0; message.len()];
        assert_eq!(message.read(&mut actual).unwrap(), actual.len());
        assert_eq!(&actual, expected);
    }
    assert!(
        receiver.stream(1).unwrap().read().unwrap().is_none(),
        "duplicate DATA must not duplicate application delivery"
    );
}

#[test]
fn late_duplicate_after_original_ack_restores_only_threshold() {
    let mut sender = endpoint();
    let mut receiver = endpoint();
    let mut now = Instant::now();
    let messages = [vec![7; 449]];
    let original = send(&mut sender, &messages, now);
    let saved_threshold = sender.ssthresh;
    let retry = timeout(&mut sender, &mut now);
    assert!(sender.ssthresh < saved_threshold);
    let ack = acknowledge(&mut receiver, &original, &mut now);
    assert!(duplicates(&ack).is_empty());
    receive(&mut sender, &ack, now);
    assert!(sender.inflight_queue.is_empty());
    let before = (
        sender.cwnd,
        sender.rto_mgr.get_rto(),
        sender.rwnd,
        sender.timers.get(Timer::T3RTX),
    );
    let duplicate_ack = acknowledge(&mut receiver, &retry, &mut now);
    assert_eq!(duplicates(&duplicate_ack), vec![data(&original)[0].tsn]);
    receive(&mut sender, &duplicate_ack, now);
    assert_eq!(sender.ssthresh, saved_threshold);
    assert_eq!(
        (
            sender.cwnd,
            sender.rto_mgr.get_rto(),
            sender.rwnd,
            sender.timers.get(Timer::T3RTX)
        ),
        before
    );
    assert_messages(&mut receiver, &messages);
}

#[test]
fn true_loss_does_not_restore_threshold() {
    let mut sender = endpoint();
    let mut receiver = endpoint();
    let mut now = Instant::now();
    let messages = [vec![8; 449]];
    send(&mut sender, &messages, now);
    let retry = timeout(&mut sender, &mut now);
    let cut = sender.ssthresh;
    let ack = acknowledge(&mut receiver, &retry, &mut now);
    assert!(duplicates(&ack).is_empty());
    receive(&mut sender, &ack, now);
    assert_eq!(sender.ssthresh, cut);
    assert_messages(&mut receiver, &messages);
}

#[test]
fn first_duplicate_ack_cannot_also_prove_the_original_was_acknowledged() {
    let mut sender = endpoint();
    let mut receiver = endpoint();
    let mut now = Instant::now();
    let messages = [vec![9; 449]];
    let original = send(&mut sender, &messages, now);
    let retry = timeout(&mut sender, &mut now);
    let cut = sender.ssthresh;
    let lost_ack = acknowledge(&mut receiver, &original, &mut now);
    assert!(duplicates(&lost_ack).is_empty());
    let duplicate_ack = acknowledge(&mut receiver, &retry, &mut now);
    assert!(!duplicates(&duplicate_ack).is_empty());
    receive(&mut sender, &duplicate_ack, now);
    assert!(sender.inflight_queue.is_empty());
    assert_eq!(
        sender.ssthresh, cut,
        "reverse ACK loss must not authorize recovery"
    );
    assert_messages(&mut receiver, &messages);
}

#[test]
fn emitted_retransmission_proof_does_not_require_unsent_marked_chunks() {
    let mut sender = endpoint();
    let mut receiver = endpoint();
    let mut now = Instant::now();
    let messages = [vec![10; 1062], vec![11; 1062], vec![12; 1062]];
    let original = send(&mut sender, &messages, now);
    assert_eq!(data(&original).len(), 3);
    let saved_threshold = sender.ssthresh;
    let retry = timeout(&mut sender, &mut now);
    assert_eq!(
        data(&retry).len(),
        1,
        "T3 only emits the congestion-window-sized first batch"
    );
    let ack = acknowledge(&mut receiver, &original, &mut now);
    receive(&mut sender, &ack, now);
    assert!(sender.inflight_queue.is_empty());
    let duplicate_ack = acknowledge(&mut receiver, &retry, &mut now);
    assert_eq!(duplicates(&duplicate_ack).len(), 1);
    receive(&mut sender, &duplicate_ack, now);
    assert_eq!(
        sender.ssthresh, saved_threshold,
        "untransmitted retry marks are not loss evidence"
    );
    assert_messages(&mut receiver, &messages);
}

#[test]
fn original_endpoint_survives_multiple_retry_batches_and_new_data() {
    let mut sender = endpoint();
    let mut receiver = endpoint();
    let mut now = Instant::now();
    let messages = [vec![13; 1062], vec![14; 1062], vec![15; 1062]];
    let original = send(&mut sender, &messages, now);
    assert_eq!(original.len(), 3);
    let saved_threshold = sender.ssthresh;
    let mut retry = timeout(&mut sender, &mut now);
    let cut = sender.ssthresh;
    for (index, packet) in original.iter().enumerate() {
        assert_eq!(data(&retry).len(), 1);
        assert_eq!(
            data(&retry)[0].tsn,
            data(core::slice::from_ref(packet))[0].tsn
        );
        let ack = acknowledge(&mut receiver, core::slice::from_ref(packet), &mut now);
        receive(&mut sender, &ack, now);
        if index == 2 {
            let newer = send(&mut sender, &[vec![16; 449]], now);
            assert_eq!(data(&newer).len(), 1);
            assert!(!sender.inflight_queue.is_empty());
        }
        let duplicate_ack = acknowledge(&mut receiver, &retry, &mut now);
        let before = (sender.cwnd, sender.rto_mgr.get_rto());
        receive(&mut sender, &duplicate_ack, now);
        assert_eq!((sender.cwnd, sender.rto_mgr.get_rto()), before);
        assert_eq!(
            sender.ssthresh,
            if index == 2 { saved_threshold } else { cut }
        );
        if index < 2 {
            retry = sender.gather_outbound(now).0;
        }
    }
    assert_messages(&mut receiver, &messages);
}

#[test]
fn mixed_original_loss_and_duplicate_confirmation_does_not_restore() {
    let mut sender = endpoint();
    let mut receiver = endpoint();
    let mut now = Instant::now();
    let messages = [vec![17; 1062], vec![18; 1062]];
    let original = send(&mut sender, &messages, now);
    let first_retry = timeout(&mut sender, &mut now);
    let cut = sender.ssthresh;
    let first_ack = acknowledge(&mut receiver, &original[..1], &mut now);
    receive(&mut sender, &first_ack, now);
    let first_duplicate = acknowledge(&mut receiver, &first_retry, &mut now);
    receive(&mut sender, &first_duplicate, now);
    assert_eq!(sender.ssthresh, cut);
    let second_retry = sender.gather_outbound(now).0;
    assert_eq!(data(&second_retry)[0].tsn, data(&original)[1].tsn);
    let second_ack = acknowledge(&mut receiver, &second_retry, &mut now);
    assert!(duplicates(&second_ack).is_empty());
    receive(&mut sender, &second_ack, now);
    assert_eq!(sender.ssthresh, cut);
    assert_messages(&mut receiver, &messages);
}

#[test]
fn rejected_sacks_cannot_poison_later_valid_duplicate_proof() {
    for old in [true, false] {
        let mut sender = endpoint();
        let mut receiver = endpoint();
        let mut now = Instant::now();
        let original = send(&mut sender, &[vec![19; 449]], now);
        let saved_threshold = sender.ssthresh;
        let retry = timeout(&mut sender, &mut now);
        let ack = acknowledge(&mut receiver, &original, &mut now);
        receive(&mut sender, &ack, now);
        let cumulative = sender.cumulative_tsn_ack_point;
        let bad = receiver
            .create_packet(vec![Box::new(ChunkSelectiveAck {
                cumulative_tsn_ack: if old {
                    cumulative.wrapping_sub(1)
                } else {
                    cumulative
                },
                advertised_receiver_window_credit: receiver.rwnd,
                gap_ack_blocks: if old {
                    vec![]
                } else {
                    vec![GapAckBlock { start: 1, end: 1 }]
                },
                duplicate_tsn: vec![cumulative.wrapping_add(100)],
            })])
            .marshal()
            .unwrap();
        let result = sender.handle_inbound(Packet::unmarshal(&bad).unwrap(), now);
        assert_eq!(result.is_ok(), old);
        assert!(sender.ssthresh < saved_threshold);
        let duplicate_ack = acknowledge(&mut receiver, &retry, &mut now);
        receive(&mut sender, &duplicate_ack, now);
        assert_eq!(
            sender.ssthresh, saved_threshold,
            "old/invalid SACK must not disable a valid episode"
        );
    }
}

#[test]
fn local_reset_invalidates_pending_duplicate_recovery() {
    let mut sender = endpoint();
    let mut receiver = endpoint();
    let mut now = Instant::now();
    let original = send(&mut sender, &[vec![20; 449]], now);
    let retry = timeout(&mut sender, &mut now);
    let cut = sender.ssthresh;
    let ack = acknowledge(&mut receiver, &original, &mut now);
    receive(&mut sender, &ack, now);
    sender.send_reset_request(1).unwrap();
    let duplicate_ack = acknowledge(&mut receiver, &retry, &mut now);
    receive(&mut sender, &duplicate_ack, now);
    assert_eq!(sender.ssthresh, cut);
}

#[test]
fn second_timeout_cannot_rearm_recovery_for_the_same_original_flight() {
    let mut sender = endpoint();
    let mut receiver = endpoint();
    let mut now = Instant::now();
    let original = send(&mut sender, &[vec![21; 449]], now);
    let first_retry = timeout(&mut sender, &mut now);
    let second_retry = timeout(&mut sender, &mut now);
    assert_eq!(data(&first_retry)[0].tsn, data(&second_retry)[0].tsn);
    let cut = sender.ssthresh;
    let rto = sender.rto_mgr.get_rto();
    let ack = acknowledge(&mut receiver, &original, &mut now);
    receive(&mut sender, &ack, now);
    let duplicate_ack = acknowledge(&mut receiver, &second_retry, &mut now);
    receive(&mut sender, &duplicate_ack, now);
    assert_eq!(sender.ssthresh, cut);
    assert_eq!(sender.rto_mgr.get_rto(), rto);
    assert_eq!(sender.stats.get_num_t3timeouts(), 2);
}

#[test]
fn local_forward_tsn_disqualifies_recovery_before_or_with_final_proof() {
    for same_sack in [true, false] {
        let mut sender = endpoint();
        let mut receiver = endpoint();
        sender.use_forward_tsn = true;
        receiver.use_forward_tsn = true;
        let mut now = Instant::now();
        let original = send(&mut sender, &[vec![22; 449]], now);
        let retry = timeout(&mut sender, &mut now);
        let cut = sender.ssthresh;
        let original_ack = acknowledge(&mut receiver, &original, &mut now);
        receive(&mut sender, &original_ack, now);
        sender.create_stream(2, false, PayloadProtocolIdentifier::Binary);
        sender
            .stream(2)
            .unwrap()
            .set_reliability_params(false, ReliabilityType::Rexmit, 1)
            .unwrap();
        sender.stream(2).unwrap().write(&[23; 449]).unwrap();
        let abandoned = sender.gather_outbound(now).0;
        assert_eq!(data(&abandoned).len(), 1);
        let duplicate_ack = acknowledge(&mut receiver, &retry, &mut now);
        let forward = if same_sack {
            receive(&mut sender, &duplicate_ack, now);
            sender.gather_outbound(now).0
        } else {
            receive(&mut sender, &original_ack, now);
            let forward = sender.gather_outbound(now).0;
            receive(&mut sender, &duplicate_ack, now);
            forward
        };
        assert!(forward.iter().any(|packet| {
            Packet::unmarshal(packet)
                .unwrap()
                .chunks
                .iter()
                .any(|chunk| chunk.as_any().is::<ChunkForwardTsn>())
        }));
        assert_eq!(sender.ssthresh, cut);
        receive(&mut receiver, &forward, now);
    }
}

#[test]
fn invalid_sack_with_valid_prefix_does_not_commit_duplicate_evidence() {
    let mut sender = endpoint();
    let mut receiver = endpoint();
    let mut now = Instant::now();
    let original = send(&mut sender, &[vec![24; 449]], now);
    let saved_threshold = sender.ssthresh;
    let retry = timeout(&mut sender, &mut now);
    let ack = acknowledge(&mut receiver, &original, &mut now);
    receive(&mut sender, &ack, now);
    let prior = sender.cumulative_tsn_ack_point;
    let new = send(&mut sender, &[vec![25; 449]], now);
    let newer_tsn = data(&new)[0].tsn;
    let invalid = receiver
        .create_packet(vec![Box::new(ChunkSelectiveAck {
            cumulative_tsn_ack: newer_tsn,
            advertised_receiver_window_credit: receiver.rwnd,
            gap_ack_blocks: vec![GapAckBlock { start: 1, end: 1 }],
            duplicate_tsn: vec![prior],
        })])
        .marshal()
        .unwrap();
    assert!(
        sender
            .handle_inbound(Packet::unmarshal(&invalid).unwrap(), now)
            .is_err()
    );
    assert_eq!(sender.cumulative_tsn_ack_point, prior);
    assert!(sender.ssthresh < saved_threshold);
    // The rejected SACK must not consume the one allowed confirmation. A
    // later actual duplicate remains the first accepted proof for this flight.
    let duplicate_ack = acknowledge(&mut receiver, &retry, &mut now);
    receive(&mut sender, &duplicate_ack, now);
    assert_eq!(sender.ssthresh, saved_threshold);
}

#[test]
fn same_sack_fast_recovery_wins_over_final_duplicate_proof() {
    let mut sender = endpoint();
    let mut receiver = endpoint();
    let mut now = Instant::now();
    let original = send(&mut sender, &[vec![26; 449]], now);
    let saved_threshold = sender.ssthresh;
    let retry = timeout(&mut sender, &mut now);
    let ack = acknowledge(&mut receiver, &original, &mut now);
    receive(&mut sender, &ack, now);
    // Grow the current window with real, acknowledged DATA while the old
    // duplicate remains on the delayed path. No congestion state is injected.
    let warmup = vec![vec![27; 1062]; 6];
    let mut batch = send(&mut sender, &warmup, now);
    while !batch.is_empty() {
        let ack = acknowledge(&mut receiver, &batch, &mut now);
        receive(&mut sender, &ack, now);
        batch = sender.gather_outbound(now).0;
    }
    let next = send(&mut sender, &vec![vec![28; 1062]; 4], now);
    assert_eq!(data(&next).len(), 4);
    assert_eq!(next.len(), 4);
    for packet in &next[1..3] {
        let ack = acknowledge(&mut receiver, core::slice::from_ref(packet), &mut now);
        receive(&mut sender, &ack, now);
        assert!(!sender.in_fast_recovery);
    }
    now += Duration::from_millis(1);
    receive(&mut receiver, &next[3..], now);
    receive(&mut receiver, &retry, now);
    let final_ack = receiver.gather_outbound(now).0;
    assert_eq!(duplicates(&final_ack), vec![data(&original)[0].tsn]);
    receive(&mut sender, &final_ack, now);
    assert!(
        sender.in_fast_recovery,
        "third distinct missing report must trigger real fast recovery"
    );
    assert!(
        sender.ssthresh < saved_threshold,
        "competing loss prevents late threshold restoration"
    );
}
