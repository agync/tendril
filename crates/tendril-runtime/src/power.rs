//! Power profile configuration for mobile and low-duty-cycle runtimes.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tendril_core::policy::PathPolicyConfig;
use tendril_core::v2::ScheduleJitterPolicy;

use crate::providers::STANDBY_POOL_SIZE;

/// Clock-skew overlap window kept on either side of a Wire v2 epoch boundary under
/// [`PowerProfile::LowPower`].
pub const LOW_POWER_EPOCH_OVERLAP_SECS: u64 = 120;

/// Fallback `GroupBook` watcher interval for host listeners when store notifications might miss
/// external process writes.
pub const HOST_BOOK_WATCH_FALLBACK: Duration = Duration::from_secs(5);

/// Default idle timeout for tearing down an unused P2P endpoint under [`PowerProfile::LowPower`].
pub const LOW_POWER_P2P_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Power and standby profile for Tendril runtime listeners, dialers, and background tasks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PowerProfile {
    /// Desktop/server profile with multi-socket relay standby pools and 3-epoch v2 mailboxes.
    #[default]
    Standard,
    /// Mobile/extension profile that eliminates standby pools, collapses v2 mailboxes to 1
    /// active epoch mid-hour, coalesces keepalives, and lowers dial concurrency.
    LowPower,
}

impl PowerProfile {
    /// Selects [`Self::LowPower`] on mobile Apple/Android targets and [`Self::Standard`] elsewhere.
    #[must_use]
    pub const fn platform_default() -> Self {
        #[cfg(any(
            target_os = "ios",
            target_os = "android",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "visionos",
        ))]
        {
            Self::LowPower
        }
        #[cfg(not(any(
            target_os = "ios",
            target_os = "android",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "visionos",
        )))]
        {
            Self::Standard
        }
    }

    /// Returns the path planner policy for this power profile.
    #[must_use]
    pub fn path_policy(self) -> PathPolicyConfig {
        match self {
            Self::Standard => PathPolicyConfig::default(),
            Self::LowPower => PathPolicyConfig::low_power(),
        }
    }

    /// Returns the Wire v2 keepalive/rekey jitter policy for this power profile.
    #[must_use]
    pub fn v2_jitter(self) -> ScheduleJitterPolicy {
        match self {
            Self::Standard => ScheduleJitterPolicy::default(),
            Self::LowPower => ScheduleJitterPolicy::low_power(),
        }
    }

    /// Returns the number of standby accept sockets per relay listener.
    #[must_use]
    pub const fn standby_pool_size(self) -> usize {
        match self {
            Self::Standard => STANDBY_POOL_SIZE,
            Self::LowPower => 0,
        }
    }

    /// Returns the Wire v2 epoch boundary skew overlap window in seconds (`None` keeps all
    /// three epochs `{e-1, e, e+1}` permanently).
    #[must_use]
    pub const fn v2_epoch_overlap_margin_secs(self) -> Option<u64> {
        match self {
            Self::Standard => None,
            Self::LowPower => Some(LOW_POWER_EPOCH_OVERLAP_SECS),
        }
    }

    /// Returns the default UPnP/PCP/NAT-PMP port-mapping setting for direct/P2P listeners.
    #[must_use]
    pub const fn p2p_port_mapping_default(self) -> bool {
        match self {
            Self::Standard => true,
            Self::LowPower => false,
        }
    }

    /// Returns the idle timeout after which an unused hint P2P endpoint is closed.
    #[must_use]
    pub const fn p2p_idle_timeout(self) -> Option<Duration> {
        match self {
            Self::Standard => None,
            Self::LowPower => Some(LOW_POWER_P2P_IDLE_TIMEOUT),
        }
    }

    /// Returns the fallback `GroupPool` watcher interval (`None` = pure notify-driven `0 Hz` idle).
    #[must_use]
    pub const fn group_watch_fallback_interval(self, listening: bool) -> Option<Duration> {
        match self {
            Self::LowPower if !listening => None,
            Self::Standard | Self::LowPower => Some(HOST_BOOK_WATCH_FALLBACK),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn power_profile_defaults_and_tunings() {
        assert_eq!(PowerProfile::default(), PowerProfile::Standard);
        assert_eq!(PowerProfile::Standard.standby_pool_size(), 2);
        assert_eq!(PowerProfile::LowPower.standby_pool_size(), 0);
        assert_eq!(PowerProfile::Standard.v2_epoch_overlap_margin_secs(), None);
        assert_eq!(
            PowerProfile::LowPower.v2_epoch_overlap_margin_secs(),
            Some(120)
        );
        assert!(PowerProfile::Standard.p2p_port_mapping_default());
        assert!(!PowerProfile::LowPower.p2p_port_mapping_default());
        assert_eq!(PowerProfile::Standard.p2p_idle_timeout(), None);
        assert_eq!(
            PowerProfile::LowPower.p2p_idle_timeout(),
            Some(Duration::from_secs(60))
        );
        assert_eq!(
            PowerProfile::LowPower.group_watch_fallback_interval(false),
            None
        );
        assert_eq!(
            PowerProfile::LowPower.group_watch_fallback_interval(true),
            Some(Duration::from_secs(5))
        );
    }
}
