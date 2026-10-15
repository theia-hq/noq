use std::collections::VecDeque;

use bytes::Bytes;
use thiserror::Error;
use tracing::{debug, trace};

use super::Connection;
use crate::{
    FrameStats, TransportError,
    connection::PacketBuilder,
    frame::{Datagram, FrameStruct},
};

/// API to control datagram traffic
pub struct Datagrams<'a> {
    pub(super) conn: &'a mut Connection,
}

impl Datagrams<'_> {
    /// Queue an unreliable, unordered datagram for immediate transmission
    ///
    /// If `drop` is true, previously queued datagrams which are still unsent may be discarded to
    /// make space for this datagram, in order of oldest to newest. If `drop` is false, and there
    /// isn't enough space due to previously queued datagrams, this function will return
    /// `SendDatagramError::Blocked`. `Event::DatagramsUnblocked` will be emitted once datagrams
    /// have been sent.
    ///
    /// Returns `Err` iff a `len`-byte datagram cannot currently be sent.
    pub fn send(&mut self, data: Bytes, drop: bool) -> Result<(), SendDatagramError> {
        if self.conn.config.datagram_receive_buffer_size.is_none() {
            return Err(SendDatagramError::Disabled);
        }
        let max = self
            .max_size()
            .ok_or(SendDatagramError::UnsupportedByPeer)?;
        let send_buffer_size = self.conn.config.datagram_send_buffer_size;
        if data.len() > max || !DatagramQueue::item_fits(data.len(), send_buffer_size) {
            return Err(SendDatagramError::TooLarge);
        }
        if drop {
            self.conn
                .datagrams
                .make_space_for(data.len(), send_buffer_size);
        } else if !self
            .conn
            .datagrams
            .has_send_buffer_space(data.len(), send_buffer_size)
        {
            self.conn.datagrams.send_blocked = true;
            return Err(SendDatagramError::Blocked(data));
        }
        self.conn.datagrams.outgoing.push_back(Datagram { data });
        Ok(())
    }

    /// Queue many unreliable, unordered datagrams for transmission in a single call.
    ///
    /// This is the batch analogue of [`Self::send`], avoiding repeated connection checks.
    ///
    /// The batch is rejected atomically with the [`TooLarge`] error if any datagram
    /// in the batch is too large.
    ///
    /// `drop` selects the backpressure behaviour, matching [`Self::send`]:
    ///
    /// - `drop = true` drops the oldest queued datagrams to make room, so every element is queued
    ///   and `Ok(datagrams.len())` is returned.
    /// - `drop = false` queues elements until the send buffer is full, then stops and returns
    ///   `Ok(n)` for the `n` elements queued. The remaining elements are the caller's to retry once
    ///   space frees up.
    ///
    /// Returns `Err` if datagrams are unsupported by the peer or disabled locally.
    ///
    /// [`TooLarge`]: SendDatagramError::TooLarge
    pub fn send_many(
        &mut self,
        datagrams: &[Bytes],
        drop: bool,
    ) -> Result<usize, SendDatagramError> {
        if self.conn.config.datagram_receive_buffer_size.is_none() {
            return Err(SendDatagramError::Disabled);
        }
        let max = self
            .max_size()
            .ok_or(SendDatagramError::UnsupportedByPeer)?;
        let send_buffer_size = self.conn.config.datagram_send_buffer_size;
        if datagrams
            .iter()
            .any(|data| data.len() > max || !DatagramQueue::item_fits(data.len(), send_buffer_size))
        {
            return Err(SendDatagramError::TooLarge);
        }

        let mut queued = 0usize;
        for data in datagrams {
            if drop {
                self.conn
                    .datagrams
                    .make_space_for(data.len(), send_buffer_size);
            } else if !self
                .conn
                .datagrams
                .has_send_buffer_space(data.len(), send_buffer_size)
            {
                self.conn.datagrams.send_blocked = true;
                break;
            }
            self.conn
                .datagrams
                .outgoing
                .push_back(Datagram { data: data.clone() });
            queued += 1;
        }

        Ok(queued)
    }

    /// Compute the maximum size of datagrams that may be passed to `send_datagram`
    ///
    /// Returns `None` if datagrams are unsupported by the peer or disabled locally.
    ///
    /// This may change over the lifetime of a connection according to variation in the path MTU
    /// estimate. The peer can also enforce an arbitrarily small fixed limit, but if the peer's
    /// limit is large this is guaranteed to be a little over a kilobyte at minimum.
    ///
    /// Not necessarily the maximum size of received datagrams.
    ///
    /// When multipath is enabled, this is calculated using the smallest MTU across all
    /// available paths.
    pub fn max_size(&self) -> Option<usize> {
        // We use the conservative overhead bound for any packet number, reducing the budget by at
        // most 3 bytes, so that PN size fluctuations don't cause users sending maximum-size
        // datagrams to suffer avoidable packet loss.
        let max_size = self.conn.current_mtu() as usize
            - self.conn.predict_1rtt_overhead_no_pn()
            - Datagram::SIZE_BOUND;
        let limit = self
            .conn
            .peer_params
            .max_datagram_frame_size?
            .into_inner()
            .saturating_sub(Datagram::SIZE_BOUND as u64);
        Some(limit.min(max_size as u64) as usize)
    }

    /// Receive an unreliable, unordered datagram
    pub fn recv(&mut self) -> Option<Bytes> {
        self.conn.datagrams.recv()
    }

    /// Drain up to `out.len()` buffered datagrams into `out`, in arrival order.
    ///
    /// This is the batch analogue of [`Self::recv`]: a single call takes many
    /// datagrams at once. `out` is filled from the front and overwritten in place;
    /// pass a slice of empty `Bytes` sized to the batch you want. Returns the number
    /// of datagrams written, which may be less than `out.len()` if fewer are buffered
    /// (0 if none). Any remaining datagrams stay queued for the next call.
    pub fn recv_many(&mut self, out: &mut [Bytes]) -> usize {
        self.conn.datagrams.recv_many(out)
    }

    /// Payload bytes available for one additional datagram, after reserving its queue record
    ///
    /// When greater than zero, [`send`](Self::send)ing a datagram of at most this size
    /// does not require dropping older datagrams. A return value of zero does not
    /// indicate whether an empty datagram fits.
    pub fn send_buffer_space(&self) -> usize {
        self.conn
            .config
            .datagram_send_buffer_size
            .saturating_sub(
                self.conn
                    .datagrams
                    .outgoing
                    .memory_usage()
                    .unwrap_or(usize::MAX),
            )
            .saturating_sub(DatagramQueue::OVERHEAD)
    }
}

#[derive(Default)]
pub(super) struct DatagramState {
    pub(super) incoming: DatagramQueue,
    pub(super) outgoing: DatagramQueue,
    pub(super) send_blocked: bool,
}

impl DatagramState {
    pub(super) fn received(
        &mut self,
        datagram: Datagram,
        window: &Option<usize>,
    ) -> Result<bool, TransportError> {
        let window = match window {
            None => {
                return Err(TransportError::PROTOCOL_VIOLATION(
                    "unexpected DATAGRAM frame",
                ));
            }
            Some(x) => *x,
        };

        if datagram.data.len() > window {
            return Err(TransportError::PROTOCOL_VIOLATION("oversized datagram"));
        }

        // A wire-valid payload may still exceed the local budget once its record is charged.
        if !DatagramQueue::item_fits(datagram.data.len(), window) {
            return Ok(false);
        }
        let was_empty = self.incoming.is_empty();
        while !self.incoming.has_space(datagram.data.len(), window) {
            debug!("dropping stale datagram");
            self.incoming.pop_front();
        }
        self.incoming.push_back(datagram);
        Ok(was_empty)
    }

    fn make_space_for(&mut self, datagram_len: usize, send_buffer_size: usize) {
        while !self.has_send_buffer_space(datagram_len, send_buffer_size) {
            let Some(prev) = self.outgoing.pop_front() else {
                break;
            };
            trace!(len = prev.data.len(), "dropping outgoing datagram");
        }
    }

    fn has_send_buffer_space(&self, datagram_len: usize, send_buffer_size: usize) -> bool {
        self.outgoing.has_space(datagram_len, send_buffer_size)
    }

    /// Discard outgoing datagrams with a payload larger than `max_payload` bytes
    ///
    /// Returns whether any datagrams were dropped.
    ///
    /// Used to ensure that reductions in MTU don't get us stuck in a state where we have a datagram
    /// queued but can't send it.
    pub(super) fn drop_oversized(&mut self, max_payload: usize) -> bool {
        let mut dropped_any = false;
        self.outgoing.retain(|datagram| {
            let result = datagram.data.len() < max_payload;
            if !result {
                trace!(
                    "dropping {} byte datagram violating {} byte limit",
                    datagram.data.len(),
                    max_payload
                );
                dropped_any = true;
            }
            result
        });
        dropped_any
    }

    /// Attempt to write a datagram frame into `buf`, consuming it from `self.outgoing`
    ///
    /// Returns whether a frame was written. At most `max_size` bytes will be written, including
    /// framing.
    pub(super) fn write<'a, 'b>(
        &mut self,
        buf: &mut PacketBuilder<'a, 'b>,
        stat: &mut FrameStats,
    ) -> bool {
        let Some(datagram) = self.outgoing.front() else {
            return false;
        };

        if buf.frame_space_remaining() < datagram.size(true) {
            // Leave the head and its accounting untouched until a packet can accommodate it.
            return false;
        }

        let Some(datagram) = self.outgoing.pop_front() else {
            return false;
        };
        buf.write_frame(datagram, stat);
        true
    }

    pub(super) fn recv(&mut self) -> Option<Bytes> {
        Some(self.incoming.pop_front()?.data)
    }

    /// Drain up to `out.len()` buffered datagrams into `out`, in arrival order.
    ///
    /// Returns the number of datagrams written into `out` (which may be less than
    /// `out.len()` if fewer are buffered). Remaining datagrams stay queued.
    pub(super) fn recv_many(&mut self, out: &mut [Bytes]) -> usize {
        let mut received = 0;
        for slot in out {
            let Some(datagram) = self.incoming.pop_front() else {
                break;
            };
            *slot = datagram.data;
            received += 1;
        }
        received
    }
}

/// Owns payload accounting for every queue mutation. Each initialized record also consumes
/// `size_of::<Datagram>()` bytes, including when its payload is empty.
#[derive(Default)]
pub(super) struct DatagramQueue {
    queue: VecDeque<Datagram>,
    payload_total: usize,
}

impl DatagramQueue {
    const OVERHEAD: usize = {
        let size = core::mem::size_of::<Datagram>();
        assert!(size > 0);
        size
    };

    fn item_fits(payload_len: usize, budget: usize) -> bool {
        payload_len
            .checked_add(Self::OVERHEAD)
            .is_some_and(|charge| charge <= budget)
    }

    fn memory_usage(&self) -> Option<usize> {
        self.queue
            .len()
            .checked_mul(Self::OVERHEAD)?
            .checked_add(self.payload_total)
    }

    fn has_space(&self, payload_len: usize, budget: usize) -> bool {
        let Some(remaining) = self
            .memory_usage()
            .and_then(|usage| budget.checked_sub(usage))
        else {
            return false;
        };
        Self::item_fits(payload_len, remaining)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub(super) fn front(&self) -> Option<&Datagram> {
        self.queue.front()
    }

    fn push_back(&mut self, datagram: Datagram) {
        // Admission proved payload plus initialized records fits in a usize-sized budget.
        self.payload_total += datagram.data.len();
        self.queue.push_back(datagram);
    }

    fn pop_front(&mut self) -> Option<Datagram> {
        let datagram = self.queue.pop_front()?;
        self.payload_total -= datagram.data.len();
        Some(datagram)
    }

    fn retain(&mut self, mut keep: impl FnMut(&Datagram) -> bool) {
        self.queue.retain(|datagram| {
            if keep(datagram) {
                true
            } else {
                self.payload_total -= datagram.data.len();
                false
            }
        });
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.queue.len()
    }
}

#[cfg(test)]
#[path = "datagrams_tests.rs"]
mod datagrams_tests;

/// Errors that can arise when sending a datagram
#[derive(Debug, Error, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SendDatagramError {
    /// The peer does not support receiving datagram frames
    #[error("datagrams not supported by peer")]
    UnsupportedByPeer,
    /// Datagram support is disabled locally
    #[error("datagram support disabled")]
    Disabled,
    /// The datagram is larger than the connection can currently accommodate
    ///
    /// Indicates that the path MTU minus overhead or the limit advertised by the peer has been
    /// exceeded.
    #[error("datagram too large")]
    TooLarge,
    /// Send would block
    #[error("datagram send blocked")]
    Blocked(Bytes),
}
