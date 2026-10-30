//! Conservative late timeout detection based on RFC 3708 duplicate TSNs.
//!
//! A successful detection only permits revalidating the previous slow-start
//! threshold. It never restores a congestion window or changes retransmission
//! timers. Requiring an earlier cumulative ACK deliberately rejects ambiguous
//! evidence, including lost acknowledgements and gap-only acknowledgements.

use crate::util::{sna32gte, sna32lte};
use rustc_hash::FxHashMap;

#[cfg(test)]
#[path = "spurious_recovery_test.rs"]
mod tests;

#[derive(Debug, Default)]
pub(super) enum SpuriousRecovery {
    #[default]
    Idle,
    Tracking(Episode),
    Ineligible {
        end: u32,
    },
    Disabled,
}

#[derive(Debug)]
pub(super) struct Episode {
    first: u32,
    end: u32,
    threshold: u32,
    chunk_count: usize,
    retransmitted: FxHashMap<u32, bool>,
}

impl SpuriousRecovery {
    pub(super) fn timeout(
        &mut self,
        first: u32,
        end: u32,
        threshold: u32,
        chunk_count: usize,
        eligible: bool,
    ) {
        match self {
            Self::Idle if eligible && chunk_count > 0 => {
                *self = Self::Tracking(Episode {
                    first,
                    end,
                    threshold,
                    chunk_count,
                    retransmitted: FxHashMap::default(),
                });
            }
            Self::Tracking(_) => self.invalidate(),
            _ => {}
        }
    }

    pub(super) fn invalidate(&mut self) {
        if let Self::Tracking(episode) = self {
            *self = Self::Ineligible { end: episode.end };
        }
    }

    pub(super) fn disable(&mut self) {
        *self = Self::Disabled;
    }

    pub(super) fn retransmit(&mut self, tsn: u32, transmissions: u32) {
        let Self::Tracking(episode) = self else {
            return;
        };
        if transmissions != 2
            || !sna32gte(tsn, episode.first)
            || !sna32lte(tsn, episode.end)
            || episode.retransmitted.contains_key(&tsn)
            || episode.retransmitted.len() >= episode.chunk_count
        {
            self.invalidate();
            return;
        }
        episode.retransmitted.insert(tsn, false);
    }

    /// Called only after the entire SACK has passed ordinary processing.
    pub(super) fn sack(
        &mut self,
        previous_cumulative: u32,
        cumulative: u32,
        duplicates: &[u32],
        disqualified: bool,
    ) -> Option<u32> {
        let mut ambiguous = false;
        for tsn in duplicates {
            let Self::Tracking(episode) = self else {
                // Without retained history this report cannot be distinguished
                // from network duplication. Ordinary congestion control remains.
                self.disable();
                return None;
            };
            let Some(confirmed) = episode.retransmitted.get_mut(tsn) else {
                self.disable();
                return None;
            };
            if *confirmed || !sna32lte(*tsn, previous_cumulative) {
                ambiguous = true;
            }
            *confirmed = true;
        }
        if disqualified || ambiguous {
            self.invalidate();
        }
        match self {
            Self::Tracking(episode)
                if sna32gte(cumulative, episode.end) && episode.retransmitted.is_empty() =>
            {
                *self = Self::Idle;
                None
            }
            Self::Tracking(episode)
                if sna32gte(cumulative, episode.end)
                    && !episode.retransmitted.is_empty()
                    && episode.retransmitted.values().all(|confirmed| *confirmed) =>
            {
                let threshold = episode.threshold;
                *self = Self::Idle;
                Some(threshold)
            }
            Self::Ineligible { end } if sna32gte(cumulative, *end) => {
                *self = Self::Idle;
                None
            }
            _ => None,
        }
    }
}
