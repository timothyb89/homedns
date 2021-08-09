use std::collections::{BTreeMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use async_dnssd::{BrowseResult, ResolvedHostFlags, ScopedSocketAddr, StreamTimeoutExt};
use color_eyre::Result;
use color_eyre::eyre::{Context, eyre};
use futures::prelude::*;
use futures_util::future;
use lazy_static::lazy_static;
use regex::Regex;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use trust_dns_resolver::IntoName;
use trust_dns_resolver::proto::rr::{RData, RecordSet};
use trust_dns_server::authority::{AuthLookup, Authority, LookupError, LookupRecords, MessageRequest, UpdateResult, ZoneType};
use trust_dns_server::client::op::{LowerQuery, ResponseCode};
use trust_dns_server::client::rr::dnssec::SupportedAlgorithms;
use trust_dns_server::client::rr::{Label, LowerName, RecordType};

const TIMEOUT_ADDRESS: Duration = Duration::from_secs(1);
const TIMEOUT_RESOLVE: Duration = Duration::from_secs(3);
const TIMEOUT_BROWSE_SINGLE: Duration = Duration::from_secs(5);
const TIMEOUT_BROWSE: Duration = Duration::from_secs(10);


#[derive(Debug)]
struct ResolvedService {
  service: BrowseResult,
  hosts: Vec<ScopedSocketAddr>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ServicePair {
  name: String,
  address: ScopedSocketAddr
}

type ServiceMap = BTreeMap<String, HashSet<ScopedSocketAddr>>;

async fn resolve(service: BrowseResult) -> Result<ResolvedService> {
  let mut hosts = vec![];

  let mut resolve = Box::pin(service.resolve().timeout(TIMEOUT_RESOLVE));
  while let Some(resolved) = resolve.next().await {
    let resolved = match resolved {
      Ok(resolved) => resolved,
      Err(e) => {
        debug!("could not resolve service {:?}: {}", service, e);
        continue;
      }
    };

    let mut resolve_hosts = Box::pin(resolved
        .resolve_socket_address()
        .timeout(TIMEOUT_ADDRESS));
    while let Some(host) = resolve_hosts.next().await {
      let host = host.with_context(|| format!("resolving host for {:?}", service))?;

      if host.flags.intersects(ResolvedHostFlags::ADD) {
        hosts.push(host.address)
      }
    }
  }

  Ok(ResolvedService {
    service, hosts
  })
}

async fn browse_single(name: String) -> (String, Vec<Result<ResolvedService>>) {
  let mut browse = Box::pin(async_dnssd::browse(&name)
    .timeout(TIMEOUT_BROWSE_SINGLE));

  let mut futures = vec![];
  while let Some(service) = browse.next().await {
    match service {
      Ok(service) => futures.push(resolve(service).boxed()),
      Err(e) => futures.push(future::ready(Err(eyre!(e))).boxed())
    }
  }

  (name, future::join_all(futures).await)
}

fn sanitize_name(s: &str) -> String {
  lazy_static! {
    static ref RE_WHITESPACE: Regex = Regex::new(r"\s+").unwrap();
    static ref RE_OTHER: Regex = Regex::new(r"[^\w-]+").unwrap();
  }

  let s = RE_WHITESPACE.replace_all(s, "-");
  let s = RE_OTHER.replace_all(&s, "");
  s.to_lowercase()
}

fn merge_services(pairs: &mut ServiceMap, service: &ResolvedService) {
  let name = sanitize_name(&service.service.service_name);
  let values = pairs.entry(name).or_default();
  values.extend(service.hosts.iter().cloned())
}

pub async fn browse_all() -> Result<BTreeMap<String, HashSet<ScopedSocketAddr>>> {
  let mut all = Box::pin(async_dnssd::browse("_services._dns-sd._udp").timeout(TIMEOUT_BROWSE));

  let mut services = HashSet::new();
  let mut futures = vec![];
  while let Some(Ok(service)) = all.next().await {
    let added = service.flags.contains(async_dnssd::BrowsedFlags::ADD);
    if !added {
      continue;
    }

    let name = format!("{}.{}", service.service_name, service.reg_type);
    if services.contains(&name) {
      debug!("skipping duplicate: {}", name);
    } else {
      services.insert(name.clone());
      futures.push(tokio::spawn(browse_single(name.clone())));
    }
  }

  let mut service_map = BTreeMap::new();
  for fut in future::join_all(futures).await {
    let (_kind, services) = fut?;
    for service in services {
      let service = match service {
        Ok(service) => service,
        Err(_e) => continue
      };

      merge_services(&mut service_map, &service);
    }
  }

  // for (name, addresses) in &service_map {
  //   println!("  {}:", name);

  //   for addr in addresses {
  //     println!("    {}", addr)
  //   }
  // }

  Ok(service_map)
}

async fn scan_continuous(services: Arc<Mutex<BTreeMap<String, HashSet<ScopedSocketAddr>>>>) {
  let mut interval = tokio::time::interval(Duration::from_secs(30));
  loop {
    interval.tick().await;

    match browse_all().await {
      Ok(refreshed_services) => {
        let mut s = services.lock().await;
        *s = refreshed_services;
        info!("refreshed services: {} known", s.len());
      },
      Err(e) => {
        warn!("could not refresh services: {}", e);
      }
    }
  }
}

pub struct DNSSDAuthority {
  origin: LowerName,
  zone_type: ZoneType,
  allow_axfr: bool,
  services: Arc<Mutex<BTreeMap<String, HashSet<ScopedSocketAddr>>>>
}

impl DNSSDAuthority {
  pub fn new(origin: impl Into<LowerName>, zone_type: ZoneType, allow_axfr: bool) -> Self {
    let services = Arc::new(Mutex::new(BTreeMap::new()));

    let services_scan = Arc::clone(&services);
    tokio::spawn(async move {
      scan_continuous(services_scan).await;
    });

    DNSSDAuthority {
      origin: origin.into(),
      zone_type,
      allow_axfr,
      services,
    }
  }
}

impl Authority for DNSSDAuthority {
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
    let services = Arc::clone(&self.services);

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

      let label = label.to_utf8();
      let services = services.lock().await;

      let service = match services.get(&label) {
        Some(service) => service,
        None => return Err(LookupError::from(ResponseCode::NXDomain))
      };

      match rtype {
        RecordType::A => {
          let addrs = service
            .iter()
            .filter_map(|addr| match addr {
              ScopedSocketAddr::V4 { address, .. } => Some(address),
              _ => None
            })
            .collect::<Vec<_>>();

          if addrs.is_empty() {
            Err(LookupError::NameExists)
          } else {
            let mut rs = RecordSet::with_ttl(name.clone(), RecordType::A, 300);
            for r in addrs {
              rs.add_rdata(RData::A(*r));
            }

            let lookup = LookupRecords::new(is_secure, supported_algorithms, Arc::new(rs));
            Ok(AuthLookup::answers(lookup, None))
          }
        },
        RecordType::AAAA => {
          let addrs = service
            .iter()
            .filter_map(|addr| match addr {
              ScopedSocketAddr::V6 { address, .. } => Some(address),
              _ => None
            })
            .collect::<Vec<_>>();

          if addrs.is_empty() {
            Err(LookupError::NameExists)
          } else {
            let mut rs = RecordSet::with_ttl(name.clone(), RecordType::AAAA, 300);
            for r in addrs {
              rs.add_rdata(RData::AAAA(*r));
            }

            let lookup = LookupRecords::new(is_secure, supported_algorithms, Arc::new(rs));
            Ok(AuthLookup::answers(lookup, None))
          }
        },
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
