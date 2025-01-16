use crate::time::Instant;

use super::RttEstimator;

pub(super) mod no_control;

pub(super) mod cubic;

#[allow(unused_variables)]
pub(super) trait Controller {
    /// Returns the number of bytes that can be sent.
    fn window(&self) -> usize;

    /// Set the remote window size.
    fn set_remote_window(&mut self, remote_window: usize) {}

    fn on_ack(&mut self, now: Instant, len: usize, rtt: &RttEstimator) {}

    fn on_retransmit(&mut self, now: Instant) {}

    fn on_duplicate_ack(&mut self, now: Instant) {}

    fn pre_transmit(&mut self, now: Instant) {}

    fn post_transmit(&mut self, now: Instant, len: usize) {}

    /// Set the maximum segment size.
    fn set_mss(&mut self, mss: usize) {}
}

#[derive(Debug)]

pub(super) enum AnyController {
    None(no_control::NoControl),
    Cubic(cubic::Cubic),
}

impl AnyController {
    /// Create a new congestion controller.
    /// `AnyController::new()` selects the best congestion controller based on the features.
    ///
    /// - If `socket-tcp-cubic` feature is enabled, it will use `Cubic`.
    /// - If `socket-tcp-reno` feature is enabled, it will use `Reno`.
    /// - If both `socket-tcp-cubic` and `socket-tcp-reno` features are enabled, it will use `Cubic`.
    ///    - `Cubic` is more efficient regarding throughput.
    ///    - `Reno` is more conservative and is suitable for low-power devices.
    /// - If no congestion controller is available, it will use `NoControl`.
    ///
    /// Users can also select a congestion controller manually by [`super::Socket::set_congestion_control()`]
    /// method at run-time.
    #[allow(unreachable_code)]
    #[inline]
    pub fn new() -> Self {
        return AnyController::Cubic(cubic::Cubic::new());
    }

    #[inline]
    pub fn inner_mut(&mut self) -> &mut dyn Controller {
        match self {
            AnyController::None(n) => n,
            AnyController::Cubic(c) => c,
        }
    }

    #[inline]
    pub fn inner(&self) -> &dyn Controller {
        match self {
            AnyController::None(n) => n,
            AnyController::Cubic(c) => c,
        }
    }
}
