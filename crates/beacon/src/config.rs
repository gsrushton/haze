use clap::{self, value_t};

#[derive(Debug, failure::Fail)]
pub enum ArgParseError {
    #[fail(display = "Invalid port.")]
    InvalidPort(#[fail(cause)] clap::Error),
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Node {
    pub nodes: Option<Vec<haze_core::PublicKey>>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct Interface {
    address: Option<String>,
    port: Option<u16>,
    ssl_cert: Option<std::path::PathBuf>,
    ssl_key: Option<std::path::PathBuf>,
}

impl Interface {
    pub fn address(&self) -> &str {
        &self.address.as_deref().unwrap_or("0.0.0.0")
    }

    pub fn port(&self) -> u16 {
        self.port.unwrap_or(haze_core::DEFAULT_PORT)
    }

    pub fn ssl_cert(&self) -> &std::path::Path {
        &self
            .ssl_cert
            .as_deref()
            .unwrap_or(std::path::Path::new("/etc/haze/beacon.crt"))
    }

    pub fn ssl_key(&self) -> &std::path::Path {
        &self
            .ssl_key
            .as_deref()
            .unwrap_or(std::path::Path::new("/etc/haze/beacon.key"))
    }

    pub fn populate(self, args: &clap::ArgMatches) -> Result<Interface, ArgParseError> {
        Ok(Self {
            address: self
                .address
                .or_else(|| args.value_of("address").map(|addr| addr.to_string())),
            ssl_cert: self
                .ssl_cert
                .or_else(|| args.value_of("ssl-cert").map(std::path::PathBuf::from)),
            ssl_key: self
                .ssl_key
                .or_else(|| args.value_of("ssl-key").map(std::path::PathBuf::from)),
            port: if args.is_present("port") {
                Some(value_t!(args, "port", u16).map_err(|err| ArgParseError::InvalidPort(err))?)
            } else {
                None
            },
        })
    }
}

impl Default for Interface {
    fn default() -> Self {
        Self {
            address: None,
            port: None,
            ssl_cert: None,
            ssl_key: None,
        }
    }
}

pub struct Nodes<'a>(Option<std::slice::Iter<'a, haze_core::PublicKey>>);

impl<'a> Nodes<'a> {
    pub fn new(nodes: Option<std::slice::Iter<'a, haze_core::PublicKey>>) -> Self {
        Self(nodes)
    }
}

impl<'a> Iterator for Nodes<'a> {
    type Item = &'a haze_core::PublicKey;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.0 {
            Some(nodes) => nodes.next(),
            None => None,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Config {
    interface: Option<Interface>,
    nodes: std::collections::HashMap<haze_core::PublicKey, Option<Node>>,
}

impl Config {
    pub fn interface(&self) -> std::borrow::Cow<Interface> {
        match &self.interface {
            Some(interface) => std::borrow::Cow::Borrowed(interface),
            None => std::borrow::Cow::Owned(Interface::default()),
        }
    }

    pub fn nodes(&self, public_key: &haze_core::PublicKey) -> Nodes {
        Nodes::new(
            self.nodes
                .get(public_key)
                .and_then(|opt_node| opt_node.as_ref())
                .and_then(|node| node.nodes.as_ref())
                .map(|nodes| nodes.iter()),
        )
    }

    pub fn populate(self, args: &clap::ArgMatches) -> Result<Config, ArgParseError> {
        Ok(Self {
            interface: Some(
                self.interface
                    .unwrap_or_else(|| Interface::default())
                    .populate(args)?,
            ),
            nodes: self.nodes,
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interface: None,
            nodes: std::collections::HashMap::new(),
        }
    }
}
