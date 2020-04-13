#![recursion_limit = "512"]

use futures::select;
use log::debug;

mod config;

mod node {
    #[derive(Debug, failure::Fail)]
    pub enum Error {
        #[fail(display = "TLS handshake failed.")]
        TlsHandshakeFailed(#[fail(cause)] std::io::Error),
        #[fail(display = "Communication error")]
        ComError(#[fail(cause)] haze_core::ComError),
        #[fail(display = "Invalid system time configuration")]
        TimeError(#[fail(cause)] std::time::SystemTimeError),
        #[fail(display = "Invalid operation")]
        InvalidOperation,
    }

    impl From<haze_core::ComError> for Error {
        fn from(err: haze_core::ComError) -> Self {
            Self::ComError(err)
        }
    }

    impl From<std::time::SystemTimeError> for Error {
        fn from(err: std::time::SystemTimeError) -> Self {
            Self::TimeError(err)
        }
    }

    type AuthTx = tokio::sync::oneshot::Sender<haze_core::PublicKey>;

    mod states {
        use crate::node::{AuthTx, Error, State};
        use log::debug;

        pub struct AwaitingHello {
            secret_key: x25519_dalek::EphemeralSecret,
            nonce: haze_core::Nonce,
            auth_tx: AuthTx,
        }

        impl AwaitingHello {
            pub async fn new<W>(wr: &mut W, auth_tx: AuthTx) -> Result<Self, Error>
            where
                W: tokio::io::AsyncWrite + std::marker::Unpin,
            {
                let secret_key = x25519_dalek::EphemeralSecret::new(&mut rand::rngs::OsRng);
                let nonce = haze_core::Nonce::new(&mut rand::rngs::OsRng);

                haze_core::send(
                    wr,
                    haze_core::BeaconMsg::Hello(
                        haze_core::PublicKey::from(
                            *x25519_dalek::PublicKey::from(&secret_key).as_bytes(),
                        ),
                        nonce.clone(),
                    ),
                )
                .await?;

                Ok(Self {
                    secret_key,
                    nonce,
                    auth_tx,
                })
            }

            pub async fn verify_node_hello<W>(
                self,
                wr: &mut W,
                node_public_key: &haze_core::PublicKey,
                time: &std::time::Duration,
                signature: &haze_core::Signature,
            ) -> Result<State, Error>
            where
                W: tokio::io::AsyncWrite + std::marker::Unpin,
            {
                use std::time::SystemTime;

                debug!(
                    "Verifying node hello {:?} {:?} {:?}.",
                    node_public_key, time, signature
                );

                let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
                if *time > now + haze_core::TIME_THRESHOLD {
                    return Dismissed::new(wr, haze_core::GoodByeReason::TooEarly).await;
                }
                if now > *time + haze_core::TIME_THRESHOLD {
                    return Dismissed::new(wr, haze_core::GoodByeReason::TooLate).await;
                }

                let expected_signature = haze_core::Signature::new(
                    &self
                        .secret_key
                        .diffie_hellman(&x25519_dalek::PublicKey::from(*node_public_key.as_bytes()))
                        .as_bytes(),
                    &self.nonce,
                    *time,
                );

                if expected_signature != *signature {
                    return Dismissed::new(wr, haze_core::GoodByeReason::BadSignature).await;
                }

                self.auth_tx.send(*node_public_key).unwrap();

                Ok(Established {}.into())
            }
        }

        pub struct Established;

        pub struct Dismissed;

        impl Dismissed {
            pub async fn new<W>(
                wr: &mut W,
                reason: haze_core::GoodByeReason,
            ) -> Result<State, Error>
            where
                W: tokio::io::AsyncWrite + std::marker::Unpin,
            {
                haze_core::send(wr, haze_core::BeaconMsg::GoodBye(reason)).await?;

                Ok(Self {}.into())
            }
        }
    }

    pub enum State {
        AwaitingHello(states::AwaitingHello),
        Established(states::Established),
        Dismissed(states::Dismissed),
    }

    impl State {
        pub async fn new<W>(wr: &mut W, auth_tx: AuthTx) -> Result<State, Error>
        where
            W: tokio::io::AsyncWrite + std::marker::Unpin,
        {
            Ok(Self::AwaitingHello(
                states::AwaitingHello::new(wr, auth_tx).await?,
            ))
        }
    }

    impl From<states::Established> for State {
        fn from(s: states::Established) -> Self {
            Self::Established(s)
        }
    }

    impl From<states::Dismissed> for State {
        fn from(s: states::Dismissed) -> Self {
            Self::Dismissed(s)
        }
    }

    async fn process_node_msg<W>(
        state: &mut Option<State>,
        wr: &mut W,
        msg: haze_core::NodeMsg,
    ) -> Result<(), Error>
    where
        W: tokio::io::AsyncWrite + std::marker::Unpin,
    {
        *state = Some(match (state.take(), msg) {
            (
                Some(State::AwaitingHello(awaiting_hello)),
                haze_core::NodeMsg::Hello(node_public_key, time, signature),
            ) => {
                awaiting_hello
                    .verify_node_hello(wr, &node_public_key, &time, &signature)
                    .await
            }
            _ => Err(Error::InvalidOperation),
        }?);
        Ok(())
    }

    pub async fn cake(
        tcp_stream: tokio::net::TcpStream,
        tls_config: std::sync::Arc<tokio_rustls::rustls::ServerConfig>,
        auth_tx: AuthTx,
    ) -> Result<(), Error> {
        let tls_stream = tokio_rustls::TlsAcceptor::from(tls_config)
            .accept(tcp_stream)
            .await
            .map_err(|err| Error::TlsHandshakeFailed(err))?;

        let (rd, mut wr) = tokio::io::split(tls_stream);

        let mut receiver = haze_core::Receiver::new(rd);

        let mut state = Some(State::new(&mut wr, auth_tx).await?);

        //let (tx, rx) = tokio::sync::mpsc::channel(8);

        loop {
            match receiver.recv::<haze_core::NodeMsg>().await {
                Ok(msg) => process_node_msg(&mut state, &mut wr, msg).await?,
                Err(haze_core::ComError::EndOfStream) => {
                    break Ok(());
                }
                Err(err) => {
                    break Err(err.into());
                }
            }
        }
    }
}

mod utils {
    use core::pin::Pin;
    use futures::{
        stream::{FusedStream, FuturesUnordered},
        task::{Context, Poll},
        Future, Stream,
    };

    pub struct Cake<Fut> {
        container: FuturesUnordered<Fut>,
    }

    impl<Fut: Future> Cake<Fut> {
        pub fn new() -> Self {
            Self {
                container: FuturesUnordered::new(),
            }
        }

        pub fn push(&mut self, f: Fut) {
            self.container.push(f)
        }
    }

    impl<Fut: Future> Stream for Cake<Fut> {
        type Item = Fut::Output;

        fn poll_next(mut self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Option<Self::Item>> {
            if self.container.len() == 0 {
                Poll::Pending
            } else {
                use futures::stream::StreamExt;
                self.container.poll_next_unpin(ctx)
            }
        }
    }

    impl<Fut: Future> FusedStream for Cake<Fut> {
        fn is_terminated(&self) -> bool {
            false
        }
    }
}

#[derive(Debug, failure::Fail)]
enum Error {
    #[fail(display = "Failed to parse arguments.")]
    ArgParseFailed(#[fail(cause)] config::ArgParseError),
    #[fail(display = "Failed to open config file '{}'.", 0)]
    FailedToOpenConfigFile(String, #[fail(cause)] std::io::Error),
    #[fail(display = "Invalid config file '{}'.", 0)]
    InvalidConfigFile(String, #[fail(cause)] serde_yaml::Error),
    #[fail(display = "Invalid address '{}'.", 0)]
    InvalidAddress(String, #[fail(cause)] std::net::AddrParseError),
    #[fail(display = "Failed to open SSL cert '{:?}'.", 0)]
    FailedToOpenSslCert(std::path::PathBuf, #[fail(cause)] std::io::Error),
    #[fail(display = "Invalid SSL cert '{:?}'.", 0)]
    InvalidSslCert(std::path::PathBuf),
    #[fail(display = "Failed to open SSL key '{:?}'.", 0)]
    FailedToOpenSslKey(std::path::PathBuf, #[fail(cause)] std::io::Error),
    #[fail(display = "Invalid SSL key '{:?}'.", 0)]
    InvalidSslKey(std::path::PathBuf),
    #[fail(display = "Invalid SSl config.")]
    InvalidSslConfig(#[fail(cause)] tokio_rustls::rustls::TLSError),
    #[fail(display = "Failed to bind listen socket to address '{}'.", 0)]
    FailedToBindListenSocket(std::net::SocketAddr, #[fail(cause)] std::io::Error),
    #[fail(display = "Failed to accept incoming connections.")]
    AcceptFailed(#[fail(cause)] std::io::Error),
}

async fn run() -> Result<(), Error> {
    let args = clap::App::new("haze-beacon")
        .version("0.1")
        .author("G. Rushton <gsrushton@gmail.com>")
        .about("Public control end-point for a haze network.")
        .arg(
            clap::Arg::with_name("address")
                .short("a")
                .long("address")
                .takes_value(true)
                .default_value("0.0.0.0")
                .help("Local address on which to listen for incoming connections."),
        )
        .arg(
            clap::Arg::with_name("port")
                .short("p")
                .long("port")
                .takes_value(true)
                .default_value("18000")
                .help("Local port on which to listen for incoming connections."),
        )
        .arg(
            clap::Arg::with_name("config")
                .long("config")
                .takes_value(true)
                .default_value("/etc/haze/beacon.yaml")
                .help("Configuration file."),
        )
        .arg(
            clap::Arg::with_name("ssl-cert")
                .long("ssl-cert")
                .takes_value(true)
                .default_value("/etc/haze/beacon.crt")
                .help("SSL certificate path."),
        )
        .arg(
            clap::Arg::with_name("ssl-key")
                .long("ssl-key")
                .takes_value(true)
                .default_value("/etc/haze/beacon.key")
                .help("SSL private key path."),
        )
        .get_matches();

    let config_path = args.value_of("config").unwrap();
    let config = match std::fs::File::open(config_path) {
        Ok(file) => serde_yaml::from_reader(std::io::BufReader::new(file))
            .map_err(|err| Error::InvalidConfigFile(config_path.to_string(), err))?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => config::Config::default(),
        Err(err) => {
            return Err(Error::FailedToOpenConfigFile(config_path.to_string(), err));
        }
    }
    .populate(&args)
    .map_err(|err| Error::ArgParseFailed(err))?;

    let interface_config = config.interface();

    let ip_address = interface_config.address();

    let socket_addr = std::net::SocketAddr::new(
        ip_address
            .parse()
            .map_err(|err| Error::InvalidAddress(ip_address.to_owned(), err))?,
        interface_config.port(),
    );

    let mut tls_config =
        tokio_rustls::rustls::ServerConfig::new(tokio_rustls::rustls::NoClientAuth::new());

    let ssl_cert_path = interface_config.ssl_cert();
    let ssl_key_path = interface_config.ssl_key();

    tls_config
        .set_single_cert(
            tokio_rustls::rustls::internal::pemfile::certs(&mut std::io::BufReader::new(
                std::fs::File::open(&ssl_cert_path)
                    .map_err(|err| Error::FailedToOpenSslCert(ssl_cert_path.to_owned(), err))?,
            ))
            .map_err(|_| Error::InvalidSslCert(ssl_cert_path.to_owned()))?,
            tokio_rustls::rustls::internal::pemfile::rsa_private_keys(
                &mut std::io::BufReader::new(
                    std::fs::File::open(&ssl_key_path)
                        .map_err(|err| Error::FailedToOpenSslKey(ssl_key_path.to_owned(), err))?,
                ),
            )
            .map_err(|_| Error::InvalidSslKey(ssl_key_path.to_owned()))?
            .remove(0),
        )
        .map_err(|err| Error::InvalidSslConfig(err))?;

    let tls_config = std::sync::Arc::new(tls_config);

    let mut auths = utils::Cake::new();
    let mut disconnects = utils::Cake::new();

    let mut tcp_listener = tokio::net::TcpListener::bind(socket_addr)
        .await
        .map_err(|err| Error::FailedToBindListenSocket(socket_addr, err))?;
    debug!("Listening on {}", socket_addr);

    let mut tcp_incoming = {
        use futures::stream::StreamExt;
        tcp_listener.incoming().fuse()
    };

    loop {
        use futures::stream::StreamExt;

        select! {
            accept_res = tcp_incoming.next() => {
                let tcp_stream = accept_res.unwrap().map_err(|err| Error::AcceptFailed(err))?;

                match tcp_stream.peer_addr() {
                    Ok(addr) => debug!("Node connected {}", addr),
                    Err(err) => debug!("Node connected")
                };

                let (auth_tx, auth_rx) = tokio::sync::oneshot::channel();
                let (disconnect_tx, disconnect_rx) = tokio::sync::oneshot::channel();

                let tls_config = tls_config.clone();
                tokio::spawn(async move {
                    if let Err(err) = node::cake(tcp_stream, tls_config, auth_tx).await {
                        debug!("Client error: {}", err);
                    }

                    disconnect_tx.send(()).unwrap();
                });

                auths.push(async move { auth_rx.await.map(|public_key| (public_key, disconnect_rx)) });
            },
            auth_res = auths.next() => match auth_res.unwrap() {
                Ok((public_key, disconnect_rx)) => {
                    debug!("Node authenticated {:?}", public_key);

                    for node in config.nodes(&public_key) {

                    }

                    disconnects.push(async move { disconnect_rx.await.map(|_| public_key) });
                },
                Err(err) => {
                    debug!("Unauthed node disconnected.");
                }
            },
            disconnect_res = disconnects.next() => {
                let public_key = disconnect_res.unwrap().unwrap();

                debug!("Node disconnected {:?}", public_key);
            }
        }
    }
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
