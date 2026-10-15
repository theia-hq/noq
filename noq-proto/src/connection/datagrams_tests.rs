use bytes::Bytes;

use super::DatagramQueue;

#[test]
fn charge_overflow_is_refused_without_inconsistent_queue_state() {
    let queue = DatagramQueue::default();
    assert!(!DatagramQueue::item_fits(usize::MAX, usize::MAX));
    assert!(!queue.has_space(usize::MAX, usize::MAX));
}

impl DatagramQueue {
    pub(in crate::connection) fn assert_accounting(&self, budget: usize) {
        let payload: usize = self.queue.iter().map(|x| x.data.len()).sum();
        assert_eq!(self.payload_total, payload);
        assert_eq!(
            self.memory_usage(),
            Some(payload + self.queue.len() * Self::OVERHEAD)
        );
        assert!(self.memory_usage().unwrap() <= budget);
    }

    pub(in crate::connection) fn assert_payloads(&self, expected: &[Bytes]) {
        assert_eq!(
            self.queue.iter().map(|x| &x.data).collect::<Vec<_>>(),
            expected.iter().collect::<Vec<_>>()
        );
    }
}
