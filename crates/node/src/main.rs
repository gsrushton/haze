use clap::{self, value_t};
use log::{debug, info};

#[derive(Debug, failure::Fail)]
enum Error {
    #[fail(display = "Failed to open config file '{}'.", 0)]
    FailedToOpenConfigFile(String, #[fail(cause)] std::io::Error),
    #[fail(display = "Failed to create config file '{}'.", 0)]
    FailedToCreateConfigFile(String, #[fail(cause)] std::io::Error),
    #[fail(display = "Invalid config file '{}'.", 0)]
    InvalidConfigFile(String, #[fail(cause)] serde_yaml::Error),
    #[fail(display = "Failed to write config file '{}'.", 0)]
    FailedToWriteConfigFile(#[fail(cause)] serde_yaml::Error),
    #[fail(display = "Failed to open SSL root cert '{}'.", 0)]
    FailedToOpenSslRootCert(String, #[fail(cause)] std::io::Error),
    #[fail(display = "Invalid SSL root cert '{}'.", 0)]
    InvalidSslRootCert(String),
    #[fail(display = "Invalid beacon host name - not a valid DNS name '{}'.", 0)]
    InvalidBeaconHostName(
        String,
        #[fail(cause)] tokio_rustls::webpki::InvalidDNSNameError,
    ),
    #[fail(display = "Invalid beacon port.")]
    InvalidBeaconPort(#[fail(cause)] clap::Error),
    #[fail(display = "Invalid beacon address.")]
    InvalidBeaconAddress(#[fail(cause)] std::io::Error),
    #[fail(display = "Failed to connect to the beacon.")]
    FailedToConnectToBeacon(#[fail(cause)] std::io::Error),
    #[fail(display = "Beacon SSL handshake failed.")]
    BeaconSslHandshakeFailed(#[fail(cause)] std::io::Error),
    #[fail(display = "Error communicating with the beacon.")]
    BeaconComError(#[fail(cause)] haze_core::ComError),
    #[fail(display = "The current system time is invalid.")]
    InvalidSystemTime(#[fail(cause)] std::time::SystemTimeError),
    #[fail(display = "The beacon server did not send a hello message.")]
    NoBeaconHello,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct Config {
    private_key: haze_core::PublicKey,
}

impl Config {
    pub fn private_key(&self) -> x25519_dalek::StaticSecret {
        x25519_dalek::StaticSecret::from(*self.private_key.as_bytes())
    }
}

impl Default for Config {
    fn default() -> Self {
        let static_key = x25519_dalek::StaticSecret::new(&mut rand::rngs::OsRng);
        Self {
            private_key: haze_core::PublicKey::from(static_key.to_bytes()),
        }
    }
}

async fn run() -> Result<(), Error> {
    let args = clap::App::new("haze-node")
        .version("0.1")
        .author("G. Rushton <gsrushton@gmail.com>")
        .about("Private control end-point for a haze network.")
        .arg(
            clap::Arg::with_name("beacon-host-name")
                .required(true)
                .help("Host name of the beacon server to connect to."),
        )
        .arg(
            clap::Arg::with_name("beacon-port")
                .short("p")
                .long("beacon-port")
                .takes_value(true)
                .default_value("18000")
                .help("Port on the beacon server to connect to."),
        )
        .arg(
            clap::Arg::with_name("config")
                .long("config")
                .takes_value(true)
                .default_value("/etc/haze/node.yaml")
                .help("Configuration file."),
        )
        .arg(
            clap::Arg::with_name("ssl-root")
                .long("ssl-root")
                .takes_value(true)
                .help("SSL root certificate path."),
        )
        .get_matches();

    let config_path = args.value_of("config").unwrap();
    let config = match std::fs::File::open(config_path) {
        Ok(file) => serde_yaml::from_reader(std::io::BufReader::new(file))
            .map_err(|err| Error::InvalidConfigFile(config_path.to_string(), err))?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            info!("Generating default config file: '{}'", config_path);

            let config = Config::default();

            serde_yaml::to_writer(
                std::io::BufWriter::new(std::fs::File::create(config_path).map_err(|err| {
                    Error::FailedToCreateConfigFile(config_path.to_string(), err)
                })?),
                &config,
            )
            .map_err(|err| Error::FailedToWriteConfigFile(err))?;

            config
        }
        Err(err) => {
            return Err(Error::FailedToOpenConfigFile(config_path.to_string(), err));
        }
    };

    let mut tls_config = tokio_rustls::rustls::ClientConfig::new();

    if args.is_present("ssl-root") {
        let ssl_root = args.value_of("ssl-root").unwrap();
        tls_config
            .root_store
            .add_pem_file(&mut std::io::BufReader::new(
                std::fs::File::open(ssl_root)
                    .map_err(|err| Error::FailedToOpenSslRootCert(ssl_root.to_string(), err))?,
            ))
            .map_err(|_| Error::InvalidSslRootCert(ssl_root.to_string()))?;
    } else {
        tls_config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    }

    let beacon_host_name = args.value_of("beacon-host-name").unwrap();

    let domain = tokio_rustls::webpki::DNSNameRef::try_from_ascii_str(beacon_host_name)
        .map_err(|err| Error::InvalidBeaconHostName(beacon_host_name.to_string(), err))?;

    let beacon_addr = {
        use std::net::ToSocketAddrs;
        (
            beacon_host_name,
            value_t!(args, "beacon-port", u16).map_err(|err| Error::InvalidBeaconPort(err))?,
        )
            .to_socket_addrs()
            .map_err(|err| Error::InvalidBeaconAddress(err))?
            .next()
            .unwrap()
    };

    debug!("Connecting to beacon {}.", beacon_addr);

    let node_private_key = config.private_key();
    let node_public_key = x25519_dalek::PublicKey::from(&node_private_key);

    let stream = tokio::net::TcpStream::connect(beacon_addr)
        .await
        .map_err(|err| Error::FailedToConnectToBeacon(err))?;

    debug!("Connected to beacon {}.", beacon_addr);

    let stream = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_config))
        .connect(domain, stream)
        .await
        .map_err(|err| Error::BeaconSslHandshakeFailed(err))?;

    debug!("SSL handshake completed.");

    let (rd, mut wr) = tokio::io::split(stream);

    let mut receiver = haze_core::Receiver::new(rd);

    if let haze_core::BeaconMsg::Hello(beacon_public_key, nonce) = receiver
        .recv::<haze_core::BeaconMsg>()
        .await
        .map_err(|err| Error::BeaconComError(err))?
    {
        use std::time::SystemTime;

        debug!("Received beacon hello {:?} {:?}.", beacon_public_key, nonce);

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|err| Error::InvalidSystemTime(err))?;

        haze_core::send(
            &mut wr,
            haze_core::NodeMsg::Hello(
                haze_core::PublicKey::from(*node_public_key.as_bytes()),
                now,
                haze_core::Signature::new(
                    node_private_key
                        .diffie_hellman(&x25519_dalek::PublicKey::from(
                            *beacon_public_key.as_bytes(),
                        ))
                        .as_bytes(),
                    &nonce,
                    now,
                ),
            ),
        )
        .await
        .map_err(|err| Error::BeaconComError(err))?;
    } else {
        return Err(Error::NoBeaconHello);
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env("HAZE_LOG").init();

    if let Err(err) = run().await {
        let mut stderr = std::io::stderr();
        for cause in failure::Fail::iter_chain(&err) {
            use std::io::Write;
            let _ = writeln!(&mut stderr, "{}", cause);
        }
        std::process::exit(1);
    }
}
