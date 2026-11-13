//! Logical declaration and physical DNS choice are independent facts. Aliases
//! use distinct real SO_REUSEPORT sockets; no address or pointer is fabricated.
use std::{net::SocketAddr,sync::Arc};
use crate::http_config::{ListenIdentity,ListenerFamily};
#[derive(Clone,Debug,Eq,PartialEq,Ord,PartialOrd,Hash)]
pub(super) struct ListenerKey {pub(super) address:SocketAddr,pub(super) identity:Arc<ListenIdentity>}
impl ListenerKey {
 /// Requested mode only; never a claim about an existing socket.
 pub(super) fn requested_v6(&self)->bool {self.identity.family==ListenerFamily::V6}

 pub(super) fn numeric(address:SocketAddr)->Self {Self{address,identity:Arc::new(ListenIdentity{host:Arc::from(address.ip().to_string()),family:ListenerFamily::Any,port:address.port()})}}
 pub(super) fn with_port(&self,port:u16)->Self{let mut address=self.address;address.set_port(port);Self{address,identity:Arc::new(ListenIdentity{host:self.identity.host.clone(),family:self.identity.family,port})}}
}
impl std::ops::Deref for ListenerKey {type Target=SocketAddr;fn deref(&self)->&SocketAddr{&self.address}}
