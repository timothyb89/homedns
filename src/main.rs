use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use color_eyre::Result;
use color_eyre::eyre::{Context, eyre};

use reqwest::Url;
use serde_json::json;
use structopt::{clap::AppSettings, StructOpt};
use tide::{Body, Request};
use tokio::net::UdpSocket;
use tracing::{error, info};
use trust_dns_server::ServerFuture;
use trust_dns_server::authority::{AuthorityObject, Catalog, ZoneType};
use trust_dns_server::resolver::Name;
use trust_dns_server::resolver::config::{CLOUDFLARE_IPS, NameServerConfigGroup};
use trust_dns_server::store::forwarder::{ForwardAuthority, ForwardConfig};

mod util;
mod dnssd_authority;
mod qnap;
mod qnap_authority;

use dnssd_authority::DNSSDAuthority;
use qnap_authority::QnapAuthority;

use crate::qnap::QnapScanner;

#[derive(StructOpt, Debug)]
#[structopt(global_settings(&[AppSettings::ColoredHelp]))]
pub struct Options {
  /// The listen address for the DNS server.
  #[structopt(long, short, default_value = "0.0.0.0:5053")]
  dns_listen: SocketAddr,

  /// If set, additionally runs a web server to serve status info.
  #[structopt(long, short, env = "HOMEDNS_WEB_LISTEN")]
  web_listen: Option<SocketAddr>,

  /// If set along with a username and password, continuously scans a Qnap
  /// administrative API for client devices.
  #[structopt(long, env = "HOMEDNS_QNAP_URL")]
  qnap_url: Option<Url>,

  /// The Qnap username.
  #[structopt(long, env = "HOMEDNS_QNAP_USERNAME")]
  qnap_username: Option<String>,

  /// The Qnap password.
  #[structopt(long, env = "HOMEDNS_QNAP_PASSWORD")]
  qnap_password: Option<String>,
}

async fn build_qnap_zone(name: impl Into<Name>, scanner: QnapScanner) -> Box<dyn AuthorityObject> {
  let zone = QnapAuthority::new(name.into(), ZoneType::Primary, true, scanner);

  Box::new(Arc::new(RwLock::new(zone)))
}

async fn build_dnssd_zone(name: impl Into<Name>) -> Box<dyn AuthorityObject> {
  let zone = DNSSDAuthority::new(name.into(), ZoneType::Primary, true);

  Box::new(Arc::new(RwLock::new(zone)))
}

async fn build_forwarder(name: impl Into<Name>) -> Result<Box<dyn AuthorityObject>> {
  let forward_config = ForwardConfig {
    name_servers: NameServerConfigGroup::from_ips_tls(
      CLOUDFLARE_IPS,
      853,
      "cloudflare-dns.com".into(),
      true
    ),
    options: None,
  };

  let forwarder = ForwardAuthority::try_from_config(
    name.into(), ZoneType::Forward, &forward_config
  ).await.map_err(|e| eyre!("error initializing forwarder: {}", e))?;

  Ok(Box::new(Arc::new(RwLock::new(forwarder))))
}

#[derive(Clone)]
struct State {
  qnap_scanner: Option<QnapScanner>
}

async fn run_web(web_listen: SocketAddr, qnap_scanner: Option<QnapScanner>) -> Result<()> {
  let mut app = tide::with_state(State {
    qnap_scanner
  });

  app.at("/").get(|_req: Request<State>| async move {
    Ok(Body::from_string("hello world".to_string()))
  });

  app.at("/qnap").get(|req: Request<State>| async move {
    if let Some(scanner) = &req.state().qnap_scanner {
      let entries = scanner
        .read_entries()
        .await;

      let devices = entries
        .keys()
        .collect::<Vec<_>>();

      Ok(Body::from_json(&devices)?)
    } else {
      Ok(Body::from_json(&json!([]))?)
    }
  });

  Ok(app.listen(web_listen).await?)
}

#[tokio::main]
async fn main() -> Result<()> {
  util::install_tracing();
  color_eyre::install()?;

  let opts = Options::from_args();

  let mut catalog = Catalog::new();

  let qnap_scanner = match (opts.qnap_url, opts.qnap_username.as_deref(), opts.qnap_password.as_deref()) {
    (Some(url), Some(username), Some(password)) => {
      let mut client = qnap::QnapClient::new(url, username, password);
      client.login(true).await.context("logging in")?;

      let scanner = QnapScanner::from_client(client);

      // .lan resolver
      let lan = Name::from_ascii("lan.").context("building .lan zone")?;
      catalog.upsert(lan.clone().into(), build_qnap_zone(lan, scanner.clone()).await);

      Some(scanner)
    },
    _ => {
      info!("no qnap config available, .lan will not be enabled");
      None
    }
  };

  // .lan resolver
  let mdns = Name::from_ascii("mdns.").context("building .mdns zone")?;
  catalog.upsert(mdns.clone().into(), build_dnssd_zone(mdns).await);

  // fallback resolver
  let root = Name::from_ascii(".").context("building root name")?;
  catalog.upsert(root.clone().into(), build_forwarder(root).await?);

  let socket = UdpSocket::bind(opts.dns_listen).await.context("binding socket")?;
  let mut server = ServerFuture::new(catalog);
  server.register_socket(socket);

  if let Some(web_listen) = &opts.web_listen {
    let web_fut = run_web(*web_listen, qnap_scanner);

    info!("starting dns @ {} and web @ {}", opts.dns_listen, web_listen);

    tokio::select! {
      r = server.block_until_done() => {
        error!("dns server died, exiting: {:?}", r);
        r?;
      }
      r = web_fut => {
        error!("web server died, exiting: {:?}", r);
        r?;
      }
    };
  } else {
    server.block_until_done().await?;
  }

  Ok(())
}
