use super::*;

fn established(minimum: u64) -> Association {
    let mut association =
        established_with_config(TransportConfig::default().with_rto_min_ms(minimum));
    association.rto_mgr.set_new_rtt(10);
    association
}

fn established_with_config(config: TransportConfig) -> Association {
    let mut association = Association::new_common(
        Arc::new(config),
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
    association.create_stream(1, false, PayloadProtocolIdentifier::Binary);
    association
}

fn send(association: &mut Association, bytes: &[u8], now: Instant) -> Vec<Bytes> {
    association.stream(1).unwrap().write(bytes).unwrap();
    association.gather_outbound(now).0
}

fn receive(association: &mut Association, packets: &[Bytes], now: Instant) {
    for packet in packets {
        association
            .handle_inbound(Packet::unmarshal(packet).unwrap(), now)
            .unwrap();
    }
}

fn read(association: &mut Association) -> Vec<u8> {
    let message = association.stream(1).unwrap().read().unwrap().unwrap();
    let mut result = vec![0; message.len()];
    message.read(&mut result).unwrap();
    result
}

#[test]
fn backoff_survives_drained_ack_until_a_fresh_rtt_sample() {
    for minimum in [400, 1000] {
        let mut sender = established(minimum);
        let mut receiver = established(minimum);
        let start = Instant::now();
        let first = vec![1; 449];
        let lost = send(&mut sender, &first, start);
        assert!(!lost.is_empty());
        let first_timeout = start + Duration::from_millis(minimum);
        sender.handle_timeout(first_timeout);
        let lost_retry = sender.gather_outbound(first_timeout).0;
        assert!(!lost_retry.is_empty());
        let second_timeout = first_timeout + Duration::from_millis(2 * minimum);
        assert_eq!(sender.timers.get(Timer::T3RTX), Some(second_timeout));
        sender.handle_timeout(second_timeout);
        let delivered_retry = sender.gather_outbound(second_timeout).0;
        assert_eq!(
            sender.timers.get(Timer::T3RTX),
            Some(second_timeout + Duration::from_millis(4 * minimum)),
            "each expiry doubles once, without applying a second timer multiplier"
        );

        let received_at = second_timeout + Duration::from_millis(5);
        receive(&mut receiver, &delivered_retry, received_at);
        assert_eq!(read(&mut receiver), first);
        let ack = receiver.gather_outbound(received_at).0;
        assert!(!ack.is_empty());
        let ack_at = received_at + Duration::from_millis(5);
        receive(&mut sender, &ack, ack_at);
        assert!(sender.inflight_queue.is_empty());
        assert_eq!(sender.timers.get(Timer::T3RTX), None);
        assert_eq!(sender.rto_mgr.srtt, 10, "Karn excludes the retransmission");
        assert_eq!(
            sender.rto_mgr.get_rto(),
            4 * minimum,
            "acknowledging retransmitted data must retain the backed-off path RTO"
        );

        let second = vec![2; 449];
        let next = send(&mut sender, &second, ack_at);
        assert_eq!(
            sender.timers.get(Timer::T3RTX),
            Some(ack_at + Duration::from_millis(4 * minimum))
        );
        // A clean 300ms RTT plus the receiver's 200ms delayed ACK now fits.
        let arrival = ack_at + Duration::from_millis(150);
        receive(&mut receiver, &next, arrival);
        assert_eq!(read(&mut receiver), second);
        let ack_due = arrival + Duration::from_millis(200);
        receiver.handle_timeout(ack_due);
        let ack = receiver.gather_outbound(ack_due).0;
        assert!(!ack.is_empty());
        receive(&mut sender, &ack, ack_due + Duration::from_millis(150));
        assert!(sender.inflight_queue.is_empty());
        assert_eq!(sender.stats.get_num_t3timeouts(), 2);
        assert!(
            sender.rto_mgr.srtt > 10,
            "fresh data measures the slower path"
        );
        assert!(sender.rto_mgr.get_rto() < 4 * minimum);
        assert!(receiver.stream(1).unwrap().read().unwrap().is_none());
    }
}

#[test]
fn cumulative_progress_restarts_t3_with_the_backed_off_rto() {
    let mut sender = established(400);
    let mut receiver = established(400);
    let start = Instant::now();
    let lost = send(&mut sender, &vec![3; 2124], start);
    assert_eq!(lost.len(), 2);
    let timeout = start + Duration::from_millis(400);
    sender.handle_timeout(timeout);
    let retransmit = sender.gather_outbound(timeout).0;
    assert_eq!(
        retransmit.len(),
        1,
        "the recovery window holds one fragment"
    );
    let arrival = timeout + Duration::from_millis(5);
    receive(&mut receiver, &retransmit, arrival);
    assert!(receiver.stream(1).unwrap().read().unwrap().is_none());
    let ack = receiver.gather_outbound(arrival).0;
    assert!(!ack.is_empty());
    let ack_at = arrival + Duration::from_millis(5);
    receive(&mut sender, &ack, ack_at);
    assert!(!sender.inflight_queue.is_empty());
    assert_eq!(sender.rto_mgr.get_rto(), 800);
    assert_eq!(
        sender.timers.get(Timer::T3RTX),
        Some(ack_at + Duration::from_millis(800))
    );
}

#[test]
fn t3_backoff_respects_the_configured_maximum() {
    let mut sender = established_with_config(TransportConfig::default().with_rto_max_ms(2500));
    sender.rto_mgr.set_new_rtt(10);
    let mut now = Instant::now();
    send(&mut sender, &[4; 449], now);
    for expected in [2000, 2500, 2500, 2500] {
        now = sender.timers.get(Timer::T3RTX).unwrap();
        sender.handle_timeout(now);
        sender.gather_outbound(now);
        assert_eq!(sender.rto_mgr.get_rto(), expected);
        assert_eq!(
            sender.timers.get(Timer::T3RTX),
            Some(now + Duration::from_millis(expected))
        );
    }
}

#[test]
fn first_data_timer_clamps_initial_rto_to_the_configured_maximum() {
    let mut sender = established_with_config(TransportConfig::default().with_rto_max_ms(1000));
    assert_eq!(sender.rto_mgr.get_rto(), 3000);
    let now = Instant::now();
    send(&mut sender, &[5; 449], now);
    assert_eq!(
        sender.timers.get(Timer::T3RTX),
        Some(now + Duration::from_millis(1000))
    );
}

#[test]
fn non_data_timers_keep_their_existing_exponential_backoff() {
    for timer in [
        Timer::T1Init,
        Timer::T1Cookie,
        Timer::T2Shutdown,
        Timer::Reconfig,
    ] {
        let mut timers = TimerTable::default();
        let mut now = Instant::now();
        timers.start(timer, now, 100);
        for interval in [200, 400, 800] {
            now = timers.get(timer).unwrap();
            assert!(timers.is_expired(timer, now).0);
            timers.start(timer, now, 100);
            assert_eq!(
                timers.get(timer),
                Some(now + Duration::from_millis(interval))
            );
        }
    }
}
