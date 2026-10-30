use super::*;

fn episode() -> SpuriousRecovery {
    let mut recovery = SpuriousRecovery::default();
    recovery.timeout(10, 12, 100_000, 3, true);
    recovery
}

#[test]
fn original_flight_must_retire_before_threshold_can_be_revalidated() {
    let mut recovery = episode();
    recovery.retransmit(10, 2);
    assert_eq!(recovery.sack(9, 10, &[], false), None);
    assert_eq!(recovery.sack(10, 10, &[10], false), None);
    // A later retransmission batch still belongs to the frozen flight.
    recovery.retransmit(12, 2);
    assert_eq!(recovery.sack(10, 12, &[], false), None);
    assert_eq!(recovery.sack(12, 12, &[12], false), Some(100_000));
    assert_eq!(recovery.sack(12, 13, &[], false), None);
}

#[test]
fn true_loss_and_mixed_loss_never_restore_without_complete_proof() {
    for duplicated in [vec![], vec![10]] {
        let mut recovery = episode();
        recovery.retransmit(10, 2);
        recovery.retransmit(11, 2);
        assert_eq!(recovery.sack(9, 12, &[], false), None);
        assert_eq!(recovery.sack(12, 12, &duplicated, false), None);
    }
}

#[test]
fn duplicate_that_first_acknowledges_original_data_cannot_undo_ack_loss() {
    let mut recovery = episode();
    recovery.retransmit(10, 2);
    assert_eq!(recovery.sack(9, 12, &[10], false), None);
    assert!(matches!(recovery, SpuriousRecovery::Idle));
    assert_eq!(recovery.sack(12, 12, &[10], false), None);
    assert!(matches!(recovery, SpuriousRecovery::Disabled));
}

#[test]
fn second_timeout_cannot_rearm_until_original_flight_drains() {
    let mut recovery = episode();
    recovery.retransmit(10, 2);
    recovery.timeout(10, 14, 4_000, 5, true);
    recovery.timeout(11, 14, 4_000, 4, true);
    assert!(matches!(recovery, SpuriousRecovery::Ineligible { end: 12 }));
    assert_eq!(recovery.sack(9, 11, &[], false), None);
    assert_eq!(recovery.sack(11, 12, &[], false), None);
    recovery.timeout(13, 14, 4_000, 2, true);
    assert!(matches!(recovery, SpuriousRecovery::Tracking(_)));
}

#[test]
fn ambiguous_transmissions_and_competing_congestion_invalidate_proof() {
    for transmissions in [1, 3] {
        let mut recovery = episode();
        recovery.retransmit(10, transmissions);
        assert!(matches!(recovery, SpuriousRecovery::Ineligible { .. }));
    }
    let mut recovery = episode();
    recovery.retransmit(10, 2);
    recovery.retransmit(10, 2);
    assert!(matches!(recovery, SpuriousRecovery::Ineligible { .. }));
    let mut recovery = episode();
    recovery.retransmit(10, 2);
    assert_eq!(recovery.sack(9, 12, &[], false), None);
    assert_eq!(recovery.sack(12, 12, &[10], true), None);
}

#[test]
fn entire_duplicate_list_must_be_valid_before_any_restoration() {
    for duplicates in [vec![10, 99], vec![10, 10], vec![10, 10, 99]] {
        let unknown = duplicates.contains(&99);
        let mut recovery = episode();
        recovery.retransmit(10, 2);
        recovery.sack(9, 12, &[], false);
        assert_eq!(recovery.sack(12, 12, &duplicates, false), None);
        if unknown {
            assert!(matches!(recovery, SpuriousRecovery::Disabled));
        }
    }
}

#[test]
fn unclassified_reports_disable_recovery_without_retaining_unbounded_history() {
    let mut recovery = SpuriousRecovery::default();
    assert_eq!(recovery.sack(12, 12, &[10], false), None);
    recovery.timeout(13, 14, 100_000, 2, true);
    assert!(matches!(recovery, SpuriousRecovery::Disabled));
}

#[test]
fn empty_or_unretransmitted_flight_cannot_restore() {
    let mut recovery = episode();
    assert_eq!(recovery.sack(9, 12, &[], false), None);
    let mut recovery = SpuriousRecovery::default();
    recovery.timeout(10, 9, 100_000, 0, true);
    assert!(matches!(recovery, SpuriousRecovery::Idle));
}

#[test]
fn frozen_endpoint_and_duplicate_comparisons_cross_tsn_wrap() {
    let mut recovery = SpuriousRecovery::default();
    recovery.timeout(u32::MAX, 1, 100_000, 3, true);
    recovery.retransmit(u32::MAX, 2);
    recovery.retransmit(0, 2);
    assert_eq!(recovery.sack(u32::MAX - 1, 0, &[], false), None);
    assert_eq!(recovery.sack(0, 0, &[u32::MAX, 0], false), None);
    assert_eq!(recovery.sack(0, 1, &[], false), Some(100_000));
}

#[test]
fn retransmissions_outside_frozen_flight_or_beyond_its_size_abort() {
    for tsn in [9, 13] {
        let mut recovery = episode();
        recovery.retransmit(tsn, 2);
        assert!(matches!(recovery, SpuriousRecovery::Ineligible { .. }));
    }
    let mut recovery = SpuriousRecovery::default();
    recovery.timeout(10, 12, 100_000, 1, true);
    recovery.retransmit(10, 2);
    recovery.retransmit(11, 2);
    assert!(matches!(recovery, SpuriousRecovery::Ineligible { .. }));
}
