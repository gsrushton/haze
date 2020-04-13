pub const DEFAULT_PORT: u16 = 18000u16;

pub const TIME_THRESHOLD: std::time::Duration = std::time::Duration::from_secs(2);

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Block([u8; 32]);

impl Block {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for Block {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", base64::encode(self.0))
    }
}

impl serde::Serialize for Block {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&base64::encode(self.0))
    }
}

impl<'de> serde::Deserialize<'de> for Block {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = [u8; 32];

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "32 base64 encoded bytes")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let bytes = base64::decode(&s)
                    .map_err(|_| E::invalid_value(serde::de::Unexpected::Str(s), &self))?;
                if bytes.len() == 32 {
                    let mut block = [0u8; 32];
                    block.copy_from_slice(&bytes[0..32]);
                    Ok(block)
                } else {
                    Err(E::invalid_value(serde::de::Unexpected::Str(s), &self))
                }
            }
        }

        Ok(Self(deserializer.deserialize_str(Visitor)?))
    }
}

pub type PublicKey = Block;

pub const NONCE_LENGTH: usize = 32;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct Nonce([u8; NONCE_LENGTH]);

impl Nonce {
    pub fn new<R>(r: &mut R) -> Self
    where
        R: rand::RngCore,
    {
        let mut nonce = [0u8; NONCE_LENGTH];
        r.fill_bytes(&mut nonce);
        Self(nonce)
    }

    pub fn as_bytes(&self) -> &[u8; NONCE_LENGTH] {
        &self.0
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Signature(Block);

impl Signature {
    pub fn new(shared_key: &[u8; 32], nonce: &Nonce, time: std::time::Duration) -> Self {
        use hmac::Mac;
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_varkey(shared_key).unwrap();
        mac.input(nonce.as_bytes());
        mac.input(&time.as_nanos().to_le_bytes());
        let bytes: [u8; 32] = mac.result().code().into();
        Self(bytes.into())
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub enum GoodByeReason {
    Shutdown,
    Unrecognised,
    TooEarly,
    TooLate,
    BadSignature,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub enum BeaconMsg {
    Hello(PublicKey, Nonce),
    Welcome,
    GoodBye(GoodByeReason),
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub enum NodeMsg {
    Hello(PublicKey, std::time::Duration, Signature),
}

type PayloadLength = u32;

const MAX_PAYLOAD_LENGTH: PayloadLength = 4096;

#[derive(Debug, failure::Fail)]
pub enum ComError {
    #[fail(display = "IO error")]
    IoError(#[fail(cause)] std::io::Error),
    #[fail(display = "Serialisation/deserialisation error")]
    SerdeError(#[fail(cause)] bincode::Error),
    #[fail(display = "Payload too large")]
    PayloadTooLarge,
}

impl From<std::io::Error> for ComError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

impl From<bincode::Error> for ComError {
    fn from(err: bincode::Error) -> Self {
        Self::SerdeError(err)
    }
}

async fn write<S>(stream: &mut S, bytes: &[u8]) -> Result<(), std::io::Error>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let mut write_count = 0usize;
    while write_count < bytes.len() {
        write_count += stream.write(&bytes[write_count..]).await?;
    }
    Ok(())
}

pub async fn send<S, T>(stream: &mut S, v: T) -> Result<(), ComError>
where
    S: tokio::io::AsyncWrite + Unpin,
    T: serde::Serialize,
{
    use std::convert::TryFrom;
    let payload_length = PayloadLength::try_from(bincode::serialized_size(&v)?)
        .map_err(|_| ComError::PayloadTooLarge)?;
    write(stream, &payload_length.to_be_bytes()).await?;
    write(stream, &bincode::serialize(&v)?).await?;
    Ok(())
}

pub struct Receiver<S> {
    rd: S,
    bytes: [u8; MAX_PAYLOAD_LENGTH as usize],
    byte_count: usize,
}

impl<S> Receiver<S>
where
    S: tokio::io::AsyncRead + Unpin,
{
    pub fn new(rd: S) -> Self {
        Self {
            rd,
            bytes: [0u8; MAX_PAYLOAD_LENGTH as usize],
            byte_count: 0,
        }
    }

    async fn read<T, F>(&mut self, length: usize, f: F) -> Option<Result<T, ComError>>
    where
        S: tokio::io::AsyncRead + Unpin,
        F: FnOnce(&[u8]) -> Result<T, ComError>,
    {
        use tokio::io::AsyncReadExt;
        while self.byte_count < length {
            match self.rd.read(&mut self.bytes[self.byte_count..]).await {
                Ok(byte_count) if byte_count == 0 => return None,
                Ok(byte_count) => self.byte_count += byte_count,
                Err(err) => return Some(Err(err.into())),
            }
        }
        let v = f(&self.bytes[0..self.byte_count]);
        self.bytes.copy_within(length..self.byte_count, 0);
        self.byte_count -= length;
        Some(v)
    }

    pub async fn recv<T>(&mut self) -> Option<Result<T, ComError>>
    where
        for<'a> T: serde::Deserialize<'a>,
    {
        let payload_length: PayloadLength = match self
            .read(std::mem::size_of::<PayloadLength>(), |bytes| {
                use std::convert::TryInto;
                Ok(PayloadLength::from_be_bytes(
                    bytes[0..4].try_into().unwrap(),
                ))
            })
            .await
        {
            Some(result) => match result {
                Ok(payload_length) => payload_length,
                Err(err) => return Some(Err(err)),
            },
            None => return None,
        };

        if payload_length <= MAX_PAYLOAD_LENGTH {
            self.read(payload_length as usize, |bytes| {
                Ok(bincode::deserialize(bytes)?)
            })
            .await
        } else {
            Some(Err(ComError::PayloadTooLarge))
        }
    }
}

mod packet_stream {
    use core::pin::Pin;
    use futures::task::{Context, Poll};

    pub struct PacketStream<S, T> {
        recv: crate::Receiver<S>,
        terminated: bool,
        marker: std::marker::PhantomData<T>,
    }

    impl<S, T> PacketStream<S, T>
    where
        S: tokio::io::AsyncRead + Unpin,
    {
        pub fn new(rd: S) -> Self {
            Self {
                recv: crate::Receiver::new(rd),
                terminated: false,
                marker: std::marker::PhantomData,
            }
        }
    }

    impl<S, T> futures::stream::Stream for PacketStream<S, T>
    where
        for<'a> T: serde::Deserialize<'a>,
    {
        type Item = Result<T, crate::ComError>;

        fn poll_next(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Option<Self::Item>> {
            if self.terminated {
                Poll::Ready(None)
            } else {
                //self.
            }
        }
    }

    impl<S, T> futures::stream::FusedStream for PacketStream<S, T>
    where
        for<'a> T: serde::Deserialize<'a>,
    {
        fn is_terminated(&self) -> bool {
            self.terminated
        }
    }
}

pub use packet_stream::PacketStream;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
