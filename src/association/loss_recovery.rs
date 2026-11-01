//! Tail loss probing and RACK early retransmission for small flights.
//!
//! A small message leaves too few later chunks for the three-miss fast
//! retransmit rule, so a lost tail otherwise waits for T3-rtx. Both
//! mechanisms adapt RFC 8985 to SCTP:
//!
//! - A tail loss probe retransmits the last outstanding chunk with the I-bit
//!   set after the flight stays unacknowledged for one probe timeout. The
//!   probe leaves cwnd and the RTO untouched. If no duplicate report for the
//!   probed chunk arrives within the probe's lead over the original once it
//!   is acknowledged, the probe repaired a loss and the ordinary fast
//!   retransmit window reduction follows (section 7.4).
//! - RACK early retransmission declares a chunk lost once a chunk sent after
//!   it has been delivered and a reordering window has passed (section 6).
//!   It only judges a hole the three-miss rule can no longer reach: every
//!   further miss indication needs a SACK that newly acknowledges a later
//!   chunk, so the hole's misses plus its unacknowledged later chunks must
//!   stay below three, with nothing else queued.

use super::*;

/// Lower bound on the probe timeout.
///
/// Twice the smoothed RTT is zero on paths whose millisecond samples
/// truncate to zero, and leaves no margin for timer granularity or the
/// peer's SACK scheduling. 10 ms is the floor from the original TLP
/// specification (draft-dukkipati-tcpm-tcp-loss-probe-01, section 2.1).
pub(super) const PTO_MIN: Duration = Duration::from_millis(10);

/// Lower bound on the RACK reordering window, the RTT sample granularity.
const REO_WND_MIN: Duration = Duration::from_millis(1);

/// Miss indications that trigger fast retransmit (RFC 9260 section 7.2.4).
const FAST_RETRANSMIT_THRESHOLD: usize = 3;

/// Recent TSNs whose duplicate reports our own retransmissions explain.
const EXPLAINED_HISTORY: usize = 16;

/// Delivery outcome of one DATA chunk, reported once it is acknowledged and
/// its losses are known. Enable with
/// [`TransportConfig::with_data_delivery_reports`](crate::TransportConfig::with_data_delivery_reports)
/// and drain with [`Association::poll_data_delivery`].
///
/// Congestion controllers outside SCTP can treat each transmission as a
/// packet: `lost_transmissions` of them did not reach the peer and the last
/// one did. The first lost transmission left at `first_sent`; later lost
/// retransmissions left between `first_sent` and `last_sent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataDelivery {
    /// When the chunk was first transmitted.
    pub first_sent: Instant,
    /// When the chunk was last transmitted.
    pub last_sent: Instant,
    /// When the acknowledgement arrived.
    pub acked_at: Instant,
    /// User data bytes carried by the chunk.
    pub bytes: usize,
    /// Transmissions that did not reach the peer. Every retransmission
    /// counts as one loss, except one proven unnecessary by a duplicate
    /// report. A tail loss probe's report waits for that evidence, so it can
    /// follow reports of chunks acknowledged later.
    pub lost_transmissions: u32,
}

/// A sent tail loss probe whose outcome is not yet known (RFC 8985 7.4).
#[derive(Debug)]
pub(super) struct ProbeEpisode {
    tsn: u32,
    /// Time between the probed chunk's original transmission and the probe.
    lead: Duration,
    /// Set once the probed chunk is acknowledged without a duplicate report,
    /// holding its delivery report until the evidence window closes.
    awaiting: Option<Option<DataDelivery>>,
    /// Fast recovery began during the episode and already reduced the
    /// window for this loss.
    window_reduced: bool,
}

/// RFC 8985 section 6 state, restricted to unambiguous deliveries.
#[derive(Debug, Default)]
pub(super) struct Rack {
    /// Transmission time and TSN of the most recently sent delivered chunk.
    xmit: Option<(Instant, u32)>,
    /// Round trip measured on that delivery.
    rtt: Duration,
    /// Smallest round trip measured on a chunk sent once.
    min_rtt: Option<Duration>,
}

/// A chunk acknowledged for the first time by the SACK being processed.
pub(super) struct Delivered {
    pub(super) tsn: u32,
    pub(super) nsent: u32,
    pub(super) bytes: usize,
    pub(super) since: Option<Instant>,
    pub(super) last_sent: Option<Instant>,
    pub(super) abandoned: bool,
}

impl Delivered {
    pub(super) fn of(c: &ChunkPayloadData, bytes: usize) -> Self {
        Delivered {
            tsn: c.tsn,
            nsent: c.nsent,
            bytes,
            since: c.since,
            last_sent: c.last_sent,
            abandoned: c.abandoned(),
        }
    }
}

/// Whether transmission `a` left after transmission `b` (RFC 8985 section 6.2).
fn sent_after(a: (Instant, u32), b: (Instant, u32)) -> bool {
    a.0 > b.0 || (a.0 == b.0 && sna32gt(a.1, b.1))
}

impl Association {
    /// Next delivery report, in the order outcomes became known. Always
    /// `None` unless
    /// [`TransportConfig::with_data_delivery_reports`](crate::TransportConfig::with_data_delivery_reports)
    /// enabled them.
    pub fn poll_data_delivery(&mut self) -> Option<DataDelivery> {
        self.delivery_reports.as_mut()?.pop_front()
    }

    /// Account for a chunk acknowledged for the first time.
    pub(super) fn on_chunk_delivered(&mut self, d: Delivered, duplicates: &[u32], now: Instant) {
        self.rack_on_delivery(&d, now);

        let duplicated = duplicates.contains(&d.tsn);
        let report = self.delivery_report(&d, duplicated, now);
        let margin = self.rack_reo_wnd() + PTO_MIN;
        if let Some(episode) = &mut self.loss_probe {
            if episode.tsn == d.tsn && episode.awaiting.is_none() {
                if d.abandoned || duplicated {
                    // The duplicate proves the original also arrived.
                    self.loss_probe = None;
                } else {
                    // Either the probe repaired a loss, or the original's SACK
                    // arrived first after a delay increase. The probe's
                    // duplicate then follows by about the time that separated
                    // the two transmissions (RFC 8985 section 7.4).
                    episode.awaiting = Some(report);
                    let deadline = now + episode.lead + margin;
                    self.timers.set(Timer::Probe, Some(deadline));
                    return;
                }
            }
        }
        self.push_delivery_report(report);
    }

    fn delivery_report(
        &self,
        d: &Delivered,
        duplicated: bool,
        now: Instant,
    ) -> Option<DataDelivery> {
        if d.abandoned || self.delivery_reports.is_none() {
            return None;
        }
        let retransmissions = d.nsent.saturating_sub(1);
        let proven_unnecessary = u32::from(duplicated && retransmissions > 0);
        Some(DataDelivery {
            first_sent: d.since?,
            last_sent: d.last_sent?,
            acked_at: now,
            bytes: d.bytes,
            lost_transmissions: retransmissions - proven_unnecessary,
        })
    }

    fn push_delivery_report(&mut self, report: Option<DataDelivery>) {
        if let (Some(reports), Some(report)) = (self.delivery_reports.as_mut(), report) {
            reports.push_back(report);
        }
    }

    /// A duplicate report for an acknowledged probe proves it unnecessary.
    pub(super) fn observe_probe_duplicate(&mut self, duplicates: &[u32], now: Instant) {
        let proven = self
            .loss_probe
            .as_ref()
            .is_some_and(|episode| episode.awaiting.is_some() && duplicates.contains(&episode.tsn));
        if !proven {
            return;
        }
        if let Some(ProbeEpisode {
            awaiting: Some(report),
            ..
        }) = self.loss_probe.take()
        {
            self.timers.stop(Timer::Probe);
            self.push_delivery_report(report.map(|report| DataDelivery {
                lost_transmissions: report.lost_transmissions.saturating_sub(1),
                ..report
            }));
            self.arm_loss_probe(now);
        }
    }

    /// No duplicate followed the probe: it repaired a lost tail. RFC 8985
    /// section 7.4.2 then reduces the window as fast retransmit would.
    fn confirm_probe_repaired_loss(&mut self, now: Instant) {
        let judged = self
            .loss_probe
            .as_ref()
            .is_some_and(|episode| episode.awaiting.is_some());
        if !judged {
            return;
        }
        let Some(ProbeEpisode {
            awaiting: Some(report),
            window_reduced,
            ..
        }) = self.loss_probe.take()
        else {
            return;
        };
        self.push_delivery_report(report);
        if !self.in_fast_recovery && !window_reduced {
            self.ssthresh = core::cmp::max(self.cwnd / 2, 4 * self.mtu);
            self.cwnd = self.ssthresh;
            self.partial_bytes_acked = 0;
            trace!(
                "[{}] updated cwnd={} ssthresh={} (TLP)",
                self.side, self.cwnd, self.ssthresh
            );
        }
        self.arm_loss_probe(now);
    }

    /// RFC 8985 section 6.2 steps 1 and 2: track the latest sent delivery.
    fn rack_on_delivery(&mut self, d: &Delivered, now: Instant) {
        if d.abandoned {
            return;
        }
        let Some(sent) = d.last_sent else {
            return;
        };
        let rtt = now.saturating_duration_since(sent);
        if d.nsent == 1 {
            self.rack.min_rtt = Some(self.rack.min_rtt.map_or(rtt, |m| m.min(rtt)));
        } else if self.rack.min_rtt.is_none_or(|min_rtt| rtt < min_rtt) {
            // Too fast to acknowledge the retransmission: likely the original.
            return;
        }
        if self
            .rack
            .xmit
            .is_none_or(|latest| sent_after((sent, d.tsn), latest))
        {
            self.rack.xmit = Some((sent, d.tsn));
            self.rack.rtt = rtt;
        }
    }

    /// Reordering window. RFC 8985 uses a quarter of the minimum RTT; a
    /// quarter of the smoothed RTT is never smaller, so it waits longer.
    fn rack_reo_wnd(&self) -> Duration {
        Duration::from_micros(self.rto_mgr.srtt.saturating_mul(250)).max(REO_WND_MIN)
    }

    /// RACK early retransmission for small flights. Marks chunks whose
    /// reordering window has passed for fast retransmission, and returns when
    /// the earliest remaining candidate's window closes.
    fn rack_detect_loss(&mut self, now: Instant) -> Option<Instant> {
        if self.in_fast_recovery || !self.pending_queue.is_empty() {
            return None;
        }
        let latest = self.rack.xmit?;
        let window = self.rack.rtt + self.rack_reo_wnd();

        let mut lost = vec![];
        let mut next_check: Option<Instant> = None;
        // Walk from the highest TSN down, counting unacknowledged later chunks.
        let mut unacked_later = 0;
        for &tsn in self.inflight_queue.sorted.iter().rev() {
            let Some(c) = self.inflight_queue.get(tsn) else {
                continue;
            };
            let later = unacked_later;
            if !c.acked {
                unacked_later += 1;
            }
            if c.acked || c.abandoned() || c.retransmit || c.nsent != 1 {
                continue;
            }
            // The three-miss rule can still fire for this hole.
            if c.miss_indicator as usize + later >= FAST_RETRANSMIT_THRESHOLD {
                continue;
            }
            let Some(sent) = c.last_sent else {
                continue;
            };
            if !sent_after(latest, (sent, tsn)) {
                continue;
            }
            let due = sent + window;
            if now >= due {
                lost.push(tsn);
            } else {
                next_check = Some(next_check.map_or(due, |at| at.min(due)));
            }
        }

        if lost.is_empty() {
            return next_check;
        }

        for tsn in lost {
            if let Some(c) = self.inflight_queue.get_mut(tsn) {
                c.miss_indicator = 3;
                self.stats.inc_early_retrans();
                self.explain_duplicate(tsn);
                trace!("[{}] RACK early retransmit: tsn={}", self.side, tsn);
            }
        }
        // RFC 9260 section 7.2.4 rule 2: one reduction per recovery, exiting
        // once the highest outstanding TSN is acknowledged.
        self.on_fast_recovery_entered();
        self.in_fast_recovery = true;
        self.fast_recover_exit_point = self.my_next_tsn.wrapping_sub(1);
        self.ssthresh = core::cmp::max(self.cwnd / 2, 4 * self.mtu);
        self.cwnd = self.ssthresh;
        self.partial_bytes_acked = 0;
        self.will_retransmit_fast = true;
        trace!(
            "[{}] updated cwnd={} ssthresh={} (RACK)",
            self.side, self.cwnd, self.ssthresh
        );
        None
    }

    /// Fast recovery reduces the window once for the losses it repairs, which
    /// includes any loss an open probe episode would otherwise report.
    pub(super) fn on_fast_recovery_entered(&mut self) {
        if let Some(episode) = &mut self.loss_probe {
            episode.window_reduced = true;
        }
    }

    /// Re-evaluate RACK and keep its timer on the next window expiry.
    pub(super) fn rack_rearm(&mut self, now: Instant) {
        match self.rack_detect_loss(now) {
            Some(at) => self.timers.set(Timer::Rack, Some(at)),
            None => self.timers.stop(Timer::Rack),
        }
    }

    pub(super) fn on_rack_timeout(&mut self, now: Instant) {
        self.rack_rearm(now);
        self.awake_write_loop();
    }

    /// Probe timeout (RFC 8985 section 7.2), once an RTT sample exists.
    fn probe_timeout(&self) -> Option<Duration> {
        self.rto_mgr
            .measured
            .then(|| Duration::from_millis(self.rto_mgr.srtt.saturating_mul(2)).max(PTO_MIN))
    }

    /// The last outstanding TSN when the flight is a quiet tail a probe may
    /// repair: nothing queued, no reported holes, no retransmission pending.
    /// Fast recovery qualifies once its repairs are acknowledged, since a
    /// lost tail past the repaired hole draws no SACK to report it.
    fn tail_probe_candidate(&self) -> Option<u32> {
        if !matches!(
            self.state,
            AssociationState::Established
                | AssociationState::ShutdownPending
                | AssociationState::ShutdownReceived
        ) || self.loss_probe.is_some()
            || self.will_send_probe.is_some()
            || !self.pending_queue.is_empty()
        {
            return None;
        }
        let last = *self.inflight_queue.sorted.last()?;
        for tsn in &self.inflight_queue.sorted {
            let c = self.inflight_queue.get(*tsn)?;
            let fast_retransmit_pending = c.miss_indicator >= FAST_RETRANSMIT_THRESHOLD as u32;
            if c.acked || c.retransmit || c.nsent != 1 || fast_retransmit_pending {
                return None;
            }
        }
        let c = self.inflight_queue.get(last)?;
        (!c.abandoned()).then_some(last)
    }

    /// Restart the probe timer from now after new data leaves or the
    /// cumulative ACK advances, or stop it when the flight does not qualify.
    /// Either event also replaces a probe chosen but not yet sent: new data
    /// probes the path itself, and progress shows the tail is not quiet.
    pub(super) fn arm_loss_probe(&mut self, now: Instant) {
        // RFC 8985 section 7.3 allows one probe until its outcome is known.
        if self.loss_probe.is_some() {
            return;
        }
        self.will_send_probe = None;
        self.timers.stop(Timer::Probe);
        if self.tail_probe_candidate().is_none() {
            return;
        }
        let Some(pto) = self.probe_timeout() else {
            return;
        };
        let at = now + pto;
        // T3-rtx already repairs a tail whose timer expires first.
        if self.timers.get(Timer::T3RTX).is_some_and(|t3| t3 <= at) {
            return;
        }
        self.timers.set(Timer::Probe, Some(at));
    }

    /// Stop a running probe timer when the flight no longer qualifies,
    /// without restarting it on acknowledgements that carry no progress.
    pub(super) fn cancel_loss_probe_if_ineligible(&mut self) {
        if self.loss_probe.is_none()
            && self.timers.get(Timer::Probe).is_some()
            && self.tail_probe_candidate().is_none()
        {
            self.timers.stop(Timer::Probe);
        }
    }

    pub(super) fn on_probe_timeout(&mut self, now: Instant) {
        if self.loss_probe.is_some() {
            self.confirm_probe_repaired_loss(now);
            return;
        }
        if let Some(tsn) = self.tail_probe_candidate() {
            self.will_send_probe = Some(tsn);
            self.awake_write_loop();
        }
    }

    /// T3-rtx retransmits the whole flight, which supersedes both mechanisms.
    /// A probed chunk already acknowledged keeps its report as a loss.
    pub(super) fn reset_loss_recovery_on_t3(&mut self) {
        self.timers.stop(Timer::Probe);
        self.timers.stop(Timer::Rack);
        self.will_send_probe = None;
        if let Some(ProbeEpisode {
            awaiting: Some(report),
            ..
        }) = self.loss_probe.take()
        {
            self.push_delivery_report(report);
        }
    }

    /// Expect one duplicate report for a TSN we are about to resend early.
    fn explain_duplicate(&mut self, tsn: u32) {
        if self.explained_duplicates.len() == EXPLAINED_HISTORY {
            self.explained_duplicates.pop_front();
        }
        self.explained_duplicates.push_back(tsn);
    }

    /// Duplicate reports not explained by a probe or RACK retransmission.
    /// Spurious timeout detection cannot attribute the rest and stops.
    pub(super) fn unexplained_duplicates(&mut self, duplicates: &[u32]) -> Vec<u32> {
        duplicates
            .iter()
            .copied()
            .filter(|tsn| {
                if let Some(index) = self.explained_duplicates.iter().position(|t| t == tsn) {
                    self.explained_duplicates.remove(index);
                    false
                } else {
                    true
                }
            })
            .collect()
    }

    pub(super) fn gather_outbound_probe_packets(
        &mut self,
        mut raw_packets: Vec<Bytes>,
        now: Instant,
    ) -> Vec<Bytes> {
        let Some(tsn) = self.will_send_probe.take() else {
            return raw_packets;
        };
        if self.tail_probe_candidate() != Some(tsn) {
            return raw_packets;
        }
        let Some(c) = self.inflight_queue.get_mut(tsn) else {
            return raw_packets;
        };
        let lead = c
            .last_sent
            .map_or(Duration::ZERO, |sent| now.saturating_duration_since(sent));
        c.nsent += 1;
        c.last_sent = Some(now);
        Association::check_partial_reliability_status(
            c,
            now,
            self.use_forward_tsn,
            self.side,
            &self.streams,
        );
        let mut probe = c.clone();
        probe.immediate_sack = true;
        trace!("[{}] tail loss probe: tsn={}", self.side, tsn);

        // A probe competes with T3 recovery for the duplicate evidence that
        // spurious timeout detection relies on.
        self.spurious_recovery.invalidate();
        self.loss_probe = Some(ProbeEpisode {
            tsn,
            lead,
            awaiting: None,
            // A tail lost within fast recovery belongs to its one reduction.
            window_reduced: self.in_fast_recovery,
        });
        self.explain_duplicate(tsn);
        self.stats.inc_loss_probes();
        self.timers
            .restart_if_stale(Timer::T3RTX, now, self.rto_mgr.get_rto());

        if let Ok(raw) = self.create_packet(vec![Box::new(probe)]).marshal() {
            raw_packets.push(raw);
        } else {
            warn!("[{}] failed to serialize a tail loss probe", self.side);
        }
        raw_packets
    }
}
