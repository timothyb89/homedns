use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;

use color_eyre::Result;
use futures::prelude::*;
use futures_util::future;
use tracing::warn;
use trust_dns_resolver::IntoName;
use trust_dns_resolver::proto::rr::{RData, RecordSet};
use trust_dns_server::authority::{AuthLookup, Authority, LookupError, LookupRecords, MessageRequest, UpdateResult, ZoneType};
use trust_dns_server::client::op::{LowerQuery, ResponseCode};
use trust_dns_server::client::rr::dnssec::SupportedAlgorithms;
use trust_dns_server::client::rr::{Label, LowerName, RecordType};

use super::qnap::*;

pub struct QnapAuthority {
    origin: LowerName,
    zone_type: ZoneType,
    allow_axfr: bool,
    scanner: QnapScanner,
  }

impl QnapAuthority {
  pub fn new(origin: impl Into<LowerName>, zone_type: ZoneType, allow_axfr: bool, scanner: QnapScanner) -> Self {
    QnapAuthority {
      origin: origin.into(),
      zone_type,
      allow_axfr,
      scanner,
    }
  }
}

impl Authority for QnapAuthority {
  type Lookup = AuthLookup;

  type LookupFuture = Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>>;

  fn zone_type(&self) -> ZoneType {
    self.zone_type
  }

  fn is_axfr_allowed(&self) -> bool {
    self.allow_axfr
  }

  fn update(&mut self, _update: &MessageRequest) -> UpdateResult<bool> {
    Err(ResponseCode::NotImp)
  }

  fn origin(&self) -> &LowerName {
    &self.origin
  }

  fn lookup(
    &self,
    name: &LowerName,
    rtype: RecordType,
    is_secure: bool,
    supported_algorithms: SupportedAlgorithms,
  ) -> std::pin::Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
    let name = name.clone();
    let scanner = self.scanner.clone();

    async move {
      let name = match name.into_name() {
        Ok(name) => name,
        Err(e) => {
          warn!("invalid name: {}", e);
          return Err(LookupError::from(ResponseCode::FormErr));
        }
      };

      if name.num_labels() != 2 {
        return Err(LookupError::from(ResponseCode::Refused));
      }

      let label = match name.iter().next().map(Label::from_raw_bytes) {
        Some(Ok(label)) => label,
        _ => {
          return Err(LookupError::from(ResponseCode::FormErr));
        }
      };

      let entries = scanner.read_entries().await;
      let label = label.to_utf8().to_lowercase();
      let hosts = entries
        .keys()
        .filter(|d| d.hostname.to_lowercase() == label)
        .filter_map(|d| match d.ip {
          IpAddr::V4(a) => Some(a),
          _ => None
        })
        .collect::<Vec<_>>();
      if hosts.is_empty() {
        return Err(LookupError::from(ResponseCode::NXDomain))
      };

      match rtype {
        RecordType::A => {
          let mut rs = RecordSet::with_ttl(name.clone(), RecordType::A, 300);
            for ip in hosts {
              rs.add_rdata(RData::A(ip));
            }

            let lookup = LookupRecords::new(is_secure, supported_algorithms, Arc::new(rs));
            Ok(AuthLookup::answers(lookup, None))
        },

        // NOTE: Qnap firmware doesn't not currently support IPv6 (sigh).
        _ => Err(LookupError::NameExists)
      }
    }.boxed()
  }

  fn search(
    &self,
    query: &LowerQuery,
    is_secure: bool,
    supported_algorithms: SupportedAlgorithms,
  ) -> std::pin::Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
    Box::pin(self.lookup(query.name(), query.query_type(), is_secure, supported_algorithms))
  }

  fn get_nsec_records(
    &self,
    _name: &LowerName,
    _is_secure: bool,
    _supported_algorithms: SupportedAlgorithms,
  ) -> std::pin::Pin<Box<dyn Future<Output = Result<Self::Lookup, LookupError>> + Send>> {
    Box::pin(future::ok(AuthLookup::default()))
  }
}
