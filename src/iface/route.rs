use heapless::Vec;

use crate::config::IFACE_MAX_ROUTE_COUNT;
use crate::time::Instant;
use crate::wire::{IpAddress, IpCidr};

use crate::wire::{Ipv4Address, Ipv4Cidr};

use crate::wire::{Ipv6Address, Ipv6Cidr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]

pub struct RouteTableFull;

impl core::fmt::Display for RouteTableFull {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Route table full")
    }
}

impl core::error::Error for RouteTableFull {}

/// A prefix of addresses that should be routed via a router
#[derive(Debug, Clone, Copy)]

pub struct Route {
    pub cidr: IpCidr,
    pub via_router: IpAddress,
    /// `None` means "forever".
    pub preferred_until: Option<Instant>,
    /// `None` means "forever".
    pub expires_at: Option<Instant>,
}


const IPV4_DEFAULT: IpCidr = IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::new(0, 0, 0, 0), 0));

const IPV6_DEFAULT: IpCidr =
    IpCidr::Ipv6(Ipv6Cidr::new(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 0), 0));

impl Route {
    /// Returns a route to 0.0.0.0/0 via the `gateway`, with no expiry.
    
    pub fn new_ipv4_gateway(gateway: Ipv4Address) -> Route {
        Route {
            cidr: IPV4_DEFAULT,
            via_router: gateway.into(),
            preferred_until: None,
            expires_at: None,
        }
    }

    /// Returns a route to ::/0 via the `gateway`, with no expiry.
    
    pub fn new_ipv6_gateway(gateway: Ipv6Address) -> Route {
        Route {
            cidr: IPV6_DEFAULT,
            via_router: gateway.into(),
            preferred_until: None,
            expires_at: None,
        }
    }
}

/// A routing table.
#[derive(Debug)]
pub struct Routes {
    storage: Vec<Route, IFACE_MAX_ROUTE_COUNT>,
}

impl Routes {
    /// Creates a new empty routing table.
    pub fn new() -> Self {
        Self {
            storage: Vec::new(),
        }
    }

    /// Update the routes of this node.
    pub fn update<F: FnOnce(&mut Vec<Route, IFACE_MAX_ROUTE_COUNT>)>(&mut self, f: F) {
        f(&mut self.storage);
    }

    /// Add a default ipv4 gateway (ie. "ip route add 0.0.0.0/0 via `gateway`").
    ///
    /// On success, returns the previous default route, if any.
    
    pub fn add_default_ipv4_route(
        &mut self,
        gateway: Ipv4Address,
    ) -> Result<Option<Route>, RouteTableFull> {
        let old = self.remove_default_ipv4_route();
        self.storage
            .push(Route::new_ipv4_gateway(gateway))
            .map_err(|_| RouteTableFull)?;
        Ok(old)
    }

    /// Add a default ipv6 gateway (ie. "ip -6 route add ::/0 via `gateway`").
    ///
    /// On success, returns the previous default route, if any.
    
    pub fn add_default_ipv6_route(
        &mut self,
        gateway: Ipv6Address,
    ) -> Result<Option<Route>, RouteTableFull> {
        let old = self.remove_default_ipv6_route();
        self.storage
            .push(Route::new_ipv6_gateway(gateway))
            .map_err(|_| RouteTableFull)?;
        Ok(old)
    }

    /// Remove the default ipv4 gateway
    ///
    /// On success, returns the previous default route, if any.
    
    pub fn remove_default_ipv4_route(&mut self) -> Option<Route> {
        if let Some((i, _)) = self
            .storage
            .iter()
            .enumerate()
            .find(|(_, r)| r.cidr == IPV4_DEFAULT)
        {
            Some(self.storage.remove(i))
        } else {
            None
        }
    }

    /// Remove the default ipv6 gateway
    ///
    /// On success, returns the previous default route, if any.
    
    pub fn remove_default_ipv6_route(&mut self) -> Option<Route> {
        if let Some((i, _)) = self
            .storage
            .iter()
            .enumerate()
            .find(|(_, r)| r.cidr == IPV6_DEFAULT)
        {
            Some(self.storage.remove(i))
        } else {
            None
        }
    }

    pub(crate) fn lookup(&self, addr: &IpAddress, timestamp: Instant) -> Option<IpAddress> {
        assert!(addr.is_unicast());

        self.storage
            .iter()
            // Keep only matching routes
            .filter(|route| {
                if let Some(expires_at) = route.expires_at {
                    if timestamp > expires_at {
                        return false;
                    }
                }
                route.cidr.contains_addr(addr)
            })
            // pick the most specific one (highest prefix_len)
            .max_by_key(|route| route.cidr.prefix_len())
            .map(|route| route.via_router)
    }
}
