use super::*;

const PAYLOAD_SIZE: u32 = 1062;
const ONE_WAY: Duration = Duration::from_millis(10);
const SRTT: Duration = Duration::from_millis(20);

fn established() -> Association {
    let config = TransportConfig::default()
        .with_rto_initial_ms(500)
        .with_rto_min_ms(400);
    let mut association = Association::new_common(
        Arc::new(config),
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

fn data_chunks(packet: &Bytes) -> Vec<ChunkPayloadData> {
    Packet::unmarshal(packet)
        .unwrap()
        .chunks
        .iter()
        .filter_map(|chunk| chunk.as_any().downcast_ref::<ChunkPayloadData>().cloned())
        .collect()
}

fn sacks(packet: &Bytes) -> Vec<ChunkSelectiveAck> {
    Packet::unmarshal(packet)
        .unwrap()
        .chunks
        .iter()
        .filter_map(|chunk| {
            chunk
                .as_any()
                .downcast_ref::<ChunkSelectiveAck>()
                .map(|sack| ChunkSelectiveAck {
                    cumulative_tsn_ack: sack.cumulative_tsn_ack,
                    advertised_receiver_window_credit: sack.advertised_receiver_window_credit,
                    gap_ack_blocks: sack.gap_ack_blocks.clone(),
                    duplicate_tsn: sack.duplicate_tsn.clone(),
                })
        })
        .collect()
}

struct Transmission {
    at: Instant,
    chunk: ChunkPayloadData,
}

/// Two associations joined by a virtual link stepped in 1 ms ticks.
/// Peer 0 sends DATA to peer 1 unless a test sends both ways.
struct Pair {
    peers: [Association; 2],
    now: Instant,
    one_way: Duration,
    /// Serialization gap between consecutive packets from peer 0.
    spacing: Duration,
    last_arrival: Option<Instant>,
    network: Vec<(Instant, usize, Bytes)>,
    /// Drop the next transmission carrying each listed TSN from peer 0.
    drop_tsns: Vec<u32>,
    /// Extra delay for the next transmission carrying each listed TSN.
    delay_tsns: Vec<(u32, Duration)>,
    /// Drop this many SACK-bearing packets from peer 1.
    drop_sacks: usize,
    sent: [Vec<Transmission>; 2],
    sack_log: Vec<(Instant, ChunkSelectiveAck)>,
    received: [Vec<(Instant, Vec<u8>)>; 2],
}

impl Pair {
    fn new() -> Self {
        Pair {
            peers: [established(), established()],
            now: Instant::now(),
            one_way: ONE_WAY,
            spacing: Duration::ZERO,
            last_arrival: None,
            network: vec![],
            drop_tsns: vec![],
            delay_tsns: vec![],
            drop_sacks: 0,
            sent: [vec![], vec![]],
            sack_log: vec![],
            received: [vec![], vec![]],
        }
    }

    /// Lossless exchanges give peer 0 a 20 ms SRTT, then clear the logs.
    fn warmed_up() -> Self {
        let mut pair = Pair::new();
        for index in 0..5u8 {
            pair.write(0, &[index; 100]);
            pair.run(50);
        }
        assert_eq!(pair.peers[0].rto_mgr.srtt, SRTT.as_millis() as u64);
        assert_eq!(pair.received[1].len(), 5);
        pair.sent = [vec![], vec![]];
        pair.sack_log.clear();
        pair.received = [vec![], vec![]];
        pair
    }

    fn write(&mut self, from: usize, bytes: &[u8]) {
        let written = self.peers[from].stream(1).unwrap().write(bytes).unwrap();
        assert_eq!(written, bytes.len());
        self.flush();
    }

    fn flush(&mut self) {
        for from in 0..2 {
            for packet in self.peers[from].gather_outbound(self.now).0 {
                self.route(from, packet);
            }
        }
    }

    fn route(&mut self, from: usize, packet: Bytes) {
        let data = data_chunks(&packet);
        for chunk in &data {
            self.sent[from].push(Transmission {
                at: self.now,
                chunk: chunk.clone(),
            });
        }
        let mut arrival = self.now + self.one_way;
        if from == 0 {
            if let Some(last) = self.last_arrival {
                arrival = arrival.max(last + self.spacing);
            }
            self.last_arrival = Some(arrival);
            if let Some(index) = self
                .drop_tsns
                .iter()
                .position(|tsn| data.iter().any(|chunk| chunk.tsn == *tsn))
            {
                self.drop_tsns.remove(index);
                return;
            }
            if let Some(index) = self
                .delay_tsns
                .iter()
                .position(|(tsn, _)| data.iter().any(|chunk| chunk.tsn == *tsn))
            {
                arrival += self.delay_tsns.remove(index).1;
            }
        } else {
            let acks = sacks(&packet);
            if !acks.is_empty() && self.drop_sacks > 0 {
                self.drop_sacks -= 1;
                return;
            }
        }
        self.network.push((arrival, 1 - from, packet));
    }

    fn tick(&mut self) {
        self.now += Duration::from_millis(1);
        let mut index = 0;
        while index < self.network.len() {
            if self.network[index].0 <= self.now {
                let (_, to, packet) = self.network.remove(index);
                if to == 0 {
                    for sack in sacks(&packet) {
                        self.sack_log.push((self.now, sack));
                    }
                }
                self.peers[to]
                    .handle_inbound(Packet::unmarshal(&packet).unwrap(), self.now)
                    .unwrap();
            } else {
                index += 1;
            }
        }
        for peer in &mut self.peers {
            peer.handle_timeout(self.now);
        }
        self.flush();
        for to in 0..2 {
            while let Some(message) = self.peers[to].stream(1).unwrap().read().unwrap() {
                let mut bytes = vec![0; message.len()];
                assert_eq!(message.read(&mut bytes).unwrap(), bytes.len());
                self.received[to].push((self.now, bytes));
            }
        }
    }

    fn run(&mut self, millis: u64) {
        for _ in 0..millis {
            self.tick();
        }
    }

    fn transmissions_of(&self, tsn: u32) -> Vec<&Transmission> {
        self.sent[0]
            .iter()
            .filter(|transmission| transmission.chunk.tsn == tsn)
            .collect()
    }

    fn next_tsn(&self) -> u32 {
        self.peers[0].my_next_tsn
    }

    fn stats(&self) -> AssociationStats {
        self.peers[0].stats()
    }
}

#[test]
fn probe_recovers_a_lost_single_chunk_after_two_srtt() {
    let mut pair = Pair::warmed_up();
    let rto = pair.peers[0].rto_mgr.get_rto();
    let cwnd = pair.peers[0].cwnd;
    let ssthresh = pair.peers[0].ssthresh;
    let tsn = pair.next_tsn();
    pair.drop_tsns.push(tsn);
    let start = pair.now;
    let message = vec![7; 300];
    pair.write(0, &message);
    assert_eq!(
        pair.peers[0].timers.get(Timer::Probe),
        Some(start + 2 * SRTT)
    );

    pair.run(2 * SRTT.as_millis() as u64 - 1);
    assert_eq!(pair.transmissions_of(tsn).len(), 1);
    pair.run(1);
    let attempts = pair.transmissions_of(tsn);
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[1].at - attempts[0].at, 2 * SRTT);
    assert!(
        attempts[1].chunk.immediate_sack,
        "the probe requests a SACK"
    );

    // The probe itself leaves congestion control and the RTO alone.
    assert_eq!(pair.peers[0].cwnd, cwnd);
    assert_eq!(pair.peers[0].ssthresh, ssthresh);
    assert_eq!(pair.peers[0].rto_mgr.get_rto(), rto);

    pair.run(ONE_WAY.as_millis() as u64);
    assert_eq!(pair.received[1], [(start + 2 * SRTT + ONE_WAY, message)]);
    pair.run(ONE_WAY.as_millis() as u64);
    assert!(pair.peers[0].inflight_queue.is_empty());

    // An acknowledgement without a duplicate report proves a repaired loss:
    // the window halves to its fast retransmit floor instead of 1 MTU.
    let mtu = pair.peers[0].mtu;
    assert_eq!(pair.peers[0].ssthresh, (cwnd / 2).max(4 * mtu));
    assert_eq!(pair.peers[0].cwnd, pair.peers[0].ssthresh);
    assert!(pair.peers[0].cwnd > mtu);
    assert_eq!(pair.peers[0].rto_mgr.get_rto(), rto);
    let mut stats = pair.stats();
    assert_eq!(stats.get_num_loss_probes(), 1);
    assert_eq!(stats.get_num_t3timeouts(), 0);
    assert_eq!(pair.peers[0].timers.get(Timer::Probe), None);
    assert_eq!(pair.peers[0].timers.get(Timer::T3RTX), None);
}

#[test]
fn probe_restarts_on_progress_and_recovers_a_lost_final_fragment() {
    let mut pair = Pair::warmed_up();
    let first = pair.next_tsn();
    let last = first + 2;
    pair.drop_tsns.push(last);
    let start = pair.now;
    let message = vec![8; 2 * PAYLOAD_SIZE as usize + 100];
    pair.write(0, &message);
    let initial = pair.sent[0]
        .iter()
        .map(|t| (t.chunk.tsn, t.chunk.immediate_sack))
        .collect::<Vec<_>>();
    assert_eq!(
        initial,
        [(first, false), (first + 1, false), (last, true)],
        "only the DATA that drains the queue requests an immediate SACK"
    );

    // The first two fragments are acknowledged one RTT later. That progress
    // restarts the probe timer, so the probe follows two SRTT after it.
    pair.run(SRTT.as_millis() as u64);
    assert_eq!(pair.peers[0].cumulative_tsn_ack_point, first + 1);
    let progress = pair.now;
    assert_eq!(
        pair.peers[0].timers.get(Timer::Probe),
        Some(progress + 2 * SRTT)
    );
    pair.run(2 * SRTT.as_millis() as u64);
    let attempts = pair.transmissions_of(last);
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[1].at, progress + 2 * SRTT);
    assert!(attempts[1].chunk.immediate_sack);

    pair.run(ONE_WAY.as_millis() as u64);
    assert_eq!(pair.received[1], [(progress + 2 * SRTT + ONE_WAY, message)]);
    assert_eq!(pair.received[1][0].0 - start, 4 * SRTT - ONE_WAY);
    pair.run(1000);
    let mut stats = pair.stats();
    assert_eq!(stats.get_num_t3timeouts(), 0);
    assert_eq!(stats.get_num_loss_probes(), 1);
    assert_eq!(stats.get_num_fast_retrans(), 0);
    assert_eq!(pair.received[1].len(), 1);
}

#[test]
fn spurious_probe_after_a_lost_sack_keeps_the_window() {
    let mut pair = Pair::warmed_up();
    let cwnd = pair.peers[0].cwnd;
    let ssthresh = pair.peers[0].ssthresh;
    let tsn = pair.next_tsn();
    pair.drop_sacks = 1;
    let start = pair.now;
    pair.write(0, &[9; 200]);
    pair.run(2 * SRTT.as_millis() as u64 + SRTT.as_millis() as u64);

    let attempts = pair.transmissions_of(tsn);
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[1].at - start, 2 * SRTT);
    let duplicate_reports = pair
        .sack_log
        .iter()
        .filter(|(_, sack)| sack.duplicate_tsn.contains(&tsn))
        .count();
    assert_eq!(duplicate_reports, 1, "the peer reports the probe duplicate");
    assert!(pair.peers[0].inflight_queue.is_empty());
    assert_eq!(pair.peers[0].cwnd, cwnd);
    assert_eq!(pair.peers[0].ssthresh, ssthresh);
    assert!(
        matches!(pair.peers[0].spurious_recovery, SpuriousRecovery::Idle),
        "an explained duplicate must not disable spurious timeout detection"
    );
    assert_eq!(pair.received[1].len(), 1, "delivered exactly once");
}

#[test]
fn lost_probe_falls_back_to_t3_without_a_second_probe() {
    let mut pair = Pair::warmed_up();
    let tsn = pair.next_tsn();
    pair.drop_tsns.extend([tsn, tsn]);
    let start = pair.now;
    pair.write(0, &[10; 200]);
    let rto = pair.peers[0].rto_mgr.get_rto();
    pair.run(rto + 2 * ONE_WAY.as_millis() as u64);

    let attempts = pair.transmissions_of(tsn);
    assert_eq!(attempts.len(), 3);
    assert_eq!(attempts[1].at - start, 2 * SRTT);
    assert_eq!(
        attempts[2].at - start,
        Duration::from_millis(rto),
        "the probe must not postpone T3-rtx"
    );
    let mut stats = pair.stats();
    assert_eq!(stats.get_num_loss_probes(), 1);
    assert_eq!(stats.get_num_t3timeouts(), 1);
    assert_eq!(pair.received[1].len(), 1);
    assert_eq!(pair.peers[0].cwnd, pair.peers[0].mtu, "T3 still collapses");
}

#[test]
fn probe_waits_for_an_rtt_sample_and_yields_to_an_earlier_t3() {
    let mut fresh = Pair::new();
    fresh.write(0, &[11; 100]);
    assert!(!fresh.peers[0].rto_mgr.measured);
    assert_eq!(fresh.peers[0].timers.get(Timer::Probe), None);

    let mut slow = Pair::warmed_up();
    slow.peers[0].rto_mgr.srtt = 250;
    slow.write(0, &[12; 100]);
    assert_eq!(
        slow.peers[0].timers.get(Timer::Probe),
        None,
        "a 500 ms probe would follow the 400 ms T3-rtx"
    );
    assert!(slow.peers[0].timers.get(Timer::T3RTX).is_some());

    let mut fast = Pair::warmed_up();
    fast.peers[0].rto_mgr.srtt = 0;
    fast.write(0, &[13; 100]);
    assert_eq!(
        fast.peers[0].timers.get(Timer::Probe),
        Some(fast.now + loss_recovery::PTO_MIN)
    );
}

#[test]
fn new_data_replaces_a_probe_that_has_not_left() {
    let mut pair = Pair::warmed_up();
    let lost = pair.next_tsn();
    pair.drop_tsns.push(lost);
    let start = pair.now;
    pair.write(0, &[19; 100]);
    let probe_at = start + 2 * SRTT;
    pair.run(2 * SRTT.as_millis() as u64 - 1);

    // The timer expires, then the application queues more before polling.
    pair.now = probe_at;
    pair.peers[0].handle_timeout(probe_at);
    assert_eq!(pair.peers[0].will_send_probe, Some(lost));
    pair.write(0, &[20; 100]);
    let tail = lost + 1;
    assert_eq!(pair.transmissions_of(lost).len(), 1);
    assert_eq!(pair.transmissions_of(tail).len(), 1);
    assert_eq!(pair.peers[0].will_send_probe, None);
    assert_eq!(
        pair.peers[0].timers.get(Timer::Probe),
        Some(probe_at + 2 * SRTT),
        "the new tail restarts the probe timer"
    );

    // The new tail is acknowledged with a gap, and RACK repairs the hole.
    pair.run(SRTT.as_millis() as u64 + 1);
    assert_eq!(pair.transmissions_of(lost).len(), 2);
    pair.run(1000);
    assert_eq!(pair.received[1].len(), 2);
    let mut stats = pair.stats();
    assert_eq!(stats.get_num_loss_probes(), 0);
    assert_eq!(stats.get_num_early_retrans(), 1);
    assert_eq!(stats.get_num_t3timeouts(), 0);
}

#[test]
fn early_retransmit_recovers_a_hole_with_two_later_chunks() {
    let mut pair = Pair::warmed_up();
    let mtu = pair.peers[0].mtu;
    let cwnd = pair.peers[0].cwnd;
    let first = pair.next_tsn();
    pair.drop_tsns.push(first);
    let start = pair.now;
    let message = vec![14; 2 * PAYLOAD_SIZE as usize + 100];
    pair.write(0, &message);

    // The SACK reporting the hole returns one RTT later. The reordering
    // window, a quarter SRTT, must pass before the hole counts as lost.
    pair.run(SRTT.as_millis() as u64);
    assert_eq!(pair.sack_log.last().unwrap().1.gap_ack_blocks.len(), 1);
    let reo_wnd = SRTT / 4;
    assert_eq!(
        pair.peers[0].timers.get(Timer::Rack),
        Some(start + SRTT + reo_wnd)
    );
    assert_eq!(pair.peers[0].timers.get(Timer::Probe), None);
    pair.run(reo_wnd.as_millis() as u64 - 1);
    assert_eq!(pair.transmissions_of(first).len(), 1);
    pair.run(1);
    let attempts = pair.transmissions_of(first);
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[1].at - start, SRTT + reo_wnd);
    assert!(
        attempts[1].chunk.immediate_sack,
        "the repair requests a SACK"
    );

    pair.run(ONE_WAY.as_millis() as u64);
    assert_eq!(
        pair.received[1],
        [(start + SRTT + reo_wnd + ONE_WAY, message)]
    );
    pair.run(ONE_WAY.as_millis() as u64);
    assert!(pair.peers[0].inflight_queue.is_empty());
    assert!(!pair.peers[0].in_fast_recovery);
    assert_eq!(pair.peers[0].ssthresh, (cwnd / 2).max(4 * mtu));
    let mut stats = pair.stats();
    assert_eq!(stats.get_num_early_retrans(), 1);
    assert_eq!(stats.get_num_fast_retrans(), 1);
    assert_eq!(stats.get_num_t3timeouts(), 0);
    assert_eq!(stats.get_num_loss_probes(), 0);
}

#[test]
fn early_retransmit_waits_out_reordering() {
    let mut pair = Pair::warmed_up();
    let first = pair.next_tsn();
    let late = SRTT / 4 - Duration::from_millis(2);
    pair.delay_tsns.push((first, late));
    let message = vec![15; 2 * PAYLOAD_SIZE as usize + 100];
    pair.write(0, &message);
    pair.run(1000);

    assert_eq!(pair.transmissions_of(first).len(), 1);
    assert_eq!(pair.received[1].len(), 1);
    let mut stats = pair.stats();
    assert_eq!(stats.get_num_early_retrans(), 0);
    assert_eq!(stats.get_num_fast_retrans(), 0);
    assert_eq!(stats.get_num_loss_probes(), 0);
    assert_eq!(stats.get_num_t3timeouts(), 0);
    assert_eq!(pair.peers[0].timers.get(Timer::Rack), None);
}

#[test]
fn early_retransmit_leaves_larger_flights_to_the_three_miss_rule() {
    let mut pair = Pair::warmed_up();
    pair.peers[0].cwnd = 10 * pair.peers[0].mtu;
    // Each later chunk draws its own SACK, as on a slow link. SACKs spaced
    // wider than the reordering window let the hole's window close before
    // the third SACK, so only the later-chunk guard keeps RACK out.
    pair.spacing = SRTT / 4 + Duration::from_millis(1);
    let first = pair.next_tsn();
    pair.drop_tsns.push(first);
    let start = pair.now;
    pair.write(0, &vec![16; 4 * PAYLOAD_SIZE as usize + 100]);
    pair.run(1000);

    let attempts = pair.transmissions_of(first);
    assert_eq!(attempts.len(), 2);
    let third_sack = pair.sack_log[2].0;
    assert!(third_sack - start > SRTT + SRTT / 4);
    assert_eq!(attempts[1].at, third_sack, "three-miss fast retransmit");
    assert_eq!(pair.received[1].len(), 1);
    let mut stats = pair.stats();
    assert_eq!(stats.get_num_early_retrans(), 0);
    assert_eq!(stats.get_num_fast_retrans(), 1);
    assert_eq!(stats.get_num_t3timeouts(), 0);
}

#[test]
fn early_retransmit_waits_while_more_data_is_queued() {
    let mut pair = Pair::warmed_up();
    // Two fragments fit the window; the third stays queued.
    pair.peers[0].cwnd = 2 * PAYLOAD_SIZE;
    let first = pair.next_tsn();
    pair.drop_tsns.push(first);
    let start = pair.now;
    pair.write(0, &vec![17; 2 * PAYLOAD_SIZE as usize + 100]);
    assert!(!pair.peers[0].pending_queue.is_empty());

    // The hole is reported while the third fragment is still queued. More
    // SACKs will follow it, so RACK must not judge the hole yet.
    pair.run(SRTT.as_millis() as u64 - 1);
    assert!(!pair.peers[0].pending_queue.is_empty());
    pair.run(1);
    assert_eq!(pair.sack_log.len(), 1);
    assert_eq!(pair.transmissions_of(first + 2).len(), 1, "queue drained");
    assert_eq!(pair.peers[0].timers.get(Timer::Rack), None);
    assert_eq!(pair.stats().get_num_early_retrans(), 0);
    assert_eq!(pair.peers[0].cwnd, 2 * PAYLOAD_SIZE);

    // The last fragment's SACK arrives after the hole's window has passed.
    pair.run(SRTT.as_millis() as u64 - 1);
    assert_eq!(pair.transmissions_of(first).len(), 1);
    pair.run(1);
    let attempts = pair.transmissions_of(first);
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[1].at - start, 2 * SRTT);
    assert_eq!(pair.stats().get_num_early_retrans(), 1);
    pair.run(1000);
    assert_eq!(pair.received[1].len(), 1);
    assert_eq!(pair.stats().get_num_t3timeouts(), 0);
}

#[test]
fn probe_and_rack_recover_a_flight_whose_chunks_were_all_lost() {
    let mut pair = Pair::warmed_up();
    let first = pair.next_tsn();
    pair.drop_tsns.extend([first, first + 1]);
    let start = pair.now;
    let message = vec![18; PAYLOAD_SIZE as usize + 100];
    pair.write(0, &message);

    // The probe resends the tail; its SACK reveals the hole, and RACK uses
    // the probe's own delivery to declare the earlier chunk lost.
    pair.run(2 * SRTT.as_millis() as u64);
    assert_eq!(pair.transmissions_of(first + 1).len(), 2);
    pair.run(SRTT.as_millis() as u64 + 1);
    let attempts = pair.transmissions_of(first);
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[1].at - start, 3 * SRTT);
    pair.run(ONE_WAY.as_millis() as u64);
    assert_eq!(pair.received[1], [(start + 3 * SRTT + ONE_WAY, message)]);
    pair.run(1000);
    let mut stats = pair.stats();
    assert_eq!(stats.get_num_t3timeouts(), 0);
    assert_eq!(stats.get_num_loss_probes(), 1);
    assert_eq!(stats.get_num_early_retrans(), 1);
}

#[test]
fn clean_paths_never_retransmit() {
    for one_way in [0, 1, 10, 75] {
        let mut pair = Pair::new();
        pair.one_way = Duration::from_millis(one_way);
        let mut expected = [vec![], vec![]];
        for index in 0..200usize {
            let from = index % 2;
            let size = [1, 300, PAYLOAD_SIZE as usize, 3 * PAYLOAD_SIZE as usize + 7][index % 4];
            let message = vec![index as u8; size];
            pair.write(from, &message);
            expected[1 - from].push(message);
            // Alternate between back-to-back messages and idle gaps.
            pair.run(if index % 3 == 0 { 0 } else { 2 * one_way + 5 });
        }
        pair.run(2000);
        for (to, expected) in expected.iter().enumerate() {
            let received = pair.received[to]
                .iter()
                .map(|(_, bytes)| bytes.clone())
                .collect::<Vec<_>>();
            assert_eq!(&received, expected, "one_way={one_way}ms peer={to}");
        }
        for peer in &mut pair.peers {
            let mut stats = peer.stats();
            assert_eq!(stats.get_num_loss_probes(), 0, "one_way={one_way}ms");
            assert_eq!(stats.get_num_early_retrans(), 0, "one_way={one_way}ms");
            assert_eq!(stats.get_num_fast_retrans(), 0, "one_way={one_way}ms");
            assert_eq!(stats.get_num_t3timeouts(), 0, "one_way={one_way}ms");
        }
    }
}
