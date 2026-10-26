//! Shadowsocks TCP and UDP server: the 2022 edition (SIP022) and the AEAD
//! methods of 2017 (SIP004). The client names the destination in its first
//! request or in each datagram, so a rule with this inbound has no targets
//! and connects where it is asked.
use crate::transport::BoxStream;
use anyhow::{Context as _, Result, anyhow, bail, ensure};
use base64::Engine as _;
use chacha20poly1305::{AeadInOut, KeyInit as _, XChaCha20Poly1305};
use rand::RngCore;
use ring::aead::{
    AES_128_GCM, AES_256_GCM, Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashSet, VecDeque},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    time::{Instant, timeout, timeout_at},
};

const TAG: usize = 16;
/// SIP022: request and response timestamps may differ from ours by this much.
const MAX_CLOCK_SKEW_SECS: u64 = 30;
/// SIP022: salts are remembered this long, twice the accepted clock skew.
const SALT_MEMORY: Duration = Duration::from_secs(60);
const MAX_PADDING: usize = 900;
/// A rejected connection is drained, not closed, for at most this long.
const DRAIN: Duration = Duration::from_secs(60);
/// SIP022: a UDP association is kept at least this long after its last
/// packet, so its packets cannot start a new one before their timestamps
/// expire.
pub const ASSOCIATION_MEMORY: Duration = Duration::from_secs(60);
/// SIP022 UDP: session ID and packet ID.
const SESSION_HEADER: usize = 16;
const XNONCE: usize = 24;
/// How many of the newest packet IDs an association remembers; a packet
/// reordered further back is refused.
const REPLAY_WINDOW: u64 = 2048;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Method {
    #[serde(rename = "2022-blake3-aes-128-gcm")]
    Blake3Aes128Gcm,
    #[serde(rename = "2022-blake3-aes-256-gcm")]
    Blake3Aes256Gcm,
    #[serde(rename = "2022-blake3-chacha20-poly1305")]
    Blake3Chacha20Poly1305,
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[serde(rename = "chacha20-ietf-poly1305")]
    Chacha20IetfPoly1305,
}
impl Method {
    fn edition_2022(self) -> bool {
        matches!(
            self,
            Self::Blake3Aes128Gcm | Self::Blake3Aes256Gcm | Self::Blake3Chacha20Poly1305
        )
    }
    /// Key and salt length.
    fn key_len(self) -> usize {
        match self {
            Self::Blake3Aes128Gcm | Self::Aes128Gcm => 16,
            _ => 32,
        }
    }
    fn algorithm(self) -> &'static ring::aead::Algorithm {
        match self {
            Self::Blake3Aes128Gcm | Self::Aes128Gcm => &AES_128_GCM,
            Self::Blake3Aes256Gcm | Self::Aes256Gcm => &AES_256_GCM,
            Self::Blake3Chacha20Poly1305 | Self::Chacha20IetfPoly1305 => &CHACHA20_POLY1305,
        }
    }
    fn max_chunk(self) -> usize {
        if self.edition_2022() { 0xFFFF } else { 0x3FFF }
    }
    /// Stable identity of the wire method, used to scope replay state.
    fn id(self) -> u8 {
        match self {
            Self::Blake3Aes128Gcm => 1,
            Self::Blake3Aes256Gcm => 2,
            Self::Blake3Chacha20Poly1305 => 3,
            Self::Aes128Gcm => 4,
            Self::Aes256Gcm => 5,
            Self::Chacha20IetfPoly1305 => 6,
        }
    }
}

/// Replay state is scoped to the cryptographic identity, not to one rule
/// revision: a rename, rate change or other edit that keeps the key and
/// method must not make captured requests acceptable again.
pub(crate) fn replay_key(config: &ServerConfig) -> Result<Vec<u8>> {
    let mut key = vec![config.method.id()];
    key.extend(config.key()?);
    Ok(key)
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub method: Method,
    /// 2022 methods: the base64 key of the method's length. Older methods: a
    /// password, stretched into a key as every client does.
    pub password: String,
    /// Loopback, private, link-local and other non-public destinations are
    /// refused unless this is set, so key holders cannot reach services
    /// that only the node itself should see.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_private_destinations: bool,
}
impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("method", &self.method)
            .field(
                "allow_private_destinations",
                &self.allow_private_destinations,
            )
            .finish_non_exhaustive()
    }
}
impl ServerConfig {
    fn key(&self) -> Result<Vec<u8>> {
        let len = self.method.key_len();
        if self.method.edition_2022() {
            let key = base64::engine::general_purpose::STANDARD
                .decode(self.password.trim())
                .ok()
                .filter(|key| key.len() == len)
                .with_context(|| {
                    format!("a {:?} key must be {len} bytes in base64", self.method)
                })?;
            return Ok(key);
        }
        ensure!(
            !self.password.is_empty()
                && self.password.len() <= 256
                && !self.password.chars().any(char::is_control),
            "a Shadowsocks password must be 1..256 bytes without control characters"
        );
        // OpenSSL EVP_BytesToKey with MD5 and one round, as in every client.
        use md5::{Digest, Md5};
        let (mut key, mut block) = (Vec::with_capacity(len + 16), Vec::new());
        while key.len() < len {
            block = Md5::new()
                .chain_update(&block)
                .chain_update(self.password.as_bytes())
                .finalize()
                .to_vec();
            key.extend_from_slice(&block);
        }
        key.truncate(len);
        Ok(key)
    }
}

pub fn validate_rule(rule: &crate::model::Rule) -> Result<()> {
    let Some(config) = &rule.inbound_shadowsocks else {
        return Ok(());
    };
    config.key()?;
    ensure!(
        rule.inbound_tls.is_none()
            && rule.inbound_websocket.is_none()
            && rule.inbound_multipath.is_none()
            && rule.outbound_multipath.is_none(),
        "a Shadowsocks server cannot be combined with inbound TLS, WebSocket or line combining"
    );
    ensure!(
        rule.health_check.is_none(),
        "a Shadowsocks server has no targets to health check"
    );
    Ok(())
}

/// Where the client asked to go, in SOCKS5 address form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Destination {
    Ip(SocketAddr),
    Domain(String, u16),
}
impl std::fmt::Display for Destination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(address) => address.fmt(f),
            Self::Domain(name, port) => write!(f, "{name}:{port}"),
        }
    }
}
/// Parses a SOCKS5 address and port; `None` while incomplete.
fn parse_address(data: &[u8]) -> Result<Option<(Destination, usize)>> {
    let Some(&kind) = data.first() else {
        return Ok(None);
    };
    let (host_end, host) = match kind {
        1 => (5, None),
        4 => (17, None),
        3 => {
            let Some(&len) = data.get(1) else {
                return Ok(None);
            };
            ensure!(len > 0, "empty destination name");
            (2 + usize::from(len), Some(2..2 + usize::from(len)))
        }
        _ => bail!("unknown destination address type"),
    };
    if data.len() < host_end + 2 {
        return Ok(None);
    }
    let port = u16::from_be_bytes([data[host_end], data[host_end + 1]]);
    ensure!(port != 0, "destination port 0");
    let destination = match host {
        None if kind == 1 => {
            let ip: [u8; 4] = data[1..5].try_into().unwrap();
            Destination::Ip(SocketAddr::new(Ipv4Addr::from(ip).into(), port))
        }
        None => {
            let ip: [u8; 16] = data[1..17].try_into().unwrap();
            Destination::Ip(SocketAddr::new(Ipv6Addr::from(ip).into(), port))
        }
        Some(range) => {
            let name = std::str::from_utf8(&data[range])
                .ok()
                .filter(|name| {
                    name.bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"-._".contains(&c))
                })
                .context("invalid destination name")?;
            Destination::Domain(name.to_ascii_lowercase(), port)
        }
    };
    Ok(Some((destination, host_end + 2)))
}

/// Whether a destination address is on the public Internet.
pub fn public(ip: IpAddr) -> bool {
    match crate::model::canonical_ip(ip) {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_multicast()
                || ip.is_documentation()
                || a == 0
                || a >= 240
                || (a == 100 && (64..128).contains(&b))
                || (a == 192 && b == 0 && c == 0)
                || (a == 198 && (18..20).contains(&b)))
        }
        IpAddr::V6(ip) => {
            let first = ip.segments()[0];
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80
                || (first == 0x2001 && ip.segments()[1] == 0x0db8)
                // NAT64 and IPv4-compatible forms can reach IPv4 private space.
                || ip.segments()[..6] == [0x64, 0xff9b, 0, 0, 0, 0]
                || ip.segments()[..6] == [0; 6])
        }
    }
}

struct Cipher {
    key: LessSafeKey,
    counter: u128,
}
impl Cipher {
    fn new(method: Method, key: &[u8], salt: &[u8]) -> Self {
        let mut subkey = vec![0; method.key_len()];
        if method.edition_2022() {
            let mut hasher = blake3::Hasher::new_derive_key("shadowsocks 2022 session subkey");
            hasher.update(key).update(salt);
            hasher.finalize_xof().fill(&mut subkey);
        } else {
            struct Len(usize);
            impl ring::hkdf::KeyType for Len {
                fn len(&self) -> usize {
                    self.0
                }
            }
            ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt)
                .extract(key)
                .expand(&[b"ss-subkey"], Len(subkey.len()))
                .and_then(|okm| okm.fill(&mut subkey))
                .expect("subkey length matches the method");
        }
        Self {
            key: LessSafeKey::new(
                UnboundKey::new(method.algorithm(), &subkey).expect("key length"),
            ),
            counter: 0,
        }
    }
    fn nonce(&mut self) -> Nonce {
        let mut nonce = [0; NONCE_LEN];
        nonce.copy_from_slice(&self.counter.to_le_bytes()[..NONCE_LEN]);
        self.counter += 1;
        Nonce::assume_unique_for_key(nonce)
    }
    /// Appends `plain`, encrypted and tagged, to `out`.
    fn seal(&mut self, out: &mut Vec<u8>, plain: &[u8]) {
        let start = out.len();
        out.extend_from_slice(plain);
        self.seal_from(out, start);
    }
    /// Encrypts `out[start..]` in place and appends its tag.
    fn seal_from(&mut self, out: &mut Vec<u8>, start: usize) {
        let nonce = self.nonce();
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, Aad::empty(), &mut out[start..])
            .expect("chunk within AEAD limits");
        out.extend_from_slice(tag.as_ref());
    }
    fn open<'a>(&mut self, data: &'a mut [u8]) -> io::Result<&'a mut [u8]> {
        let nonce = self.nonce();
        self.key
            .open_in_place(nonce, Aad::empty(), data)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Shadowsocks chunk failed authentication",
                )
            })
    }
}

/// Salts seen in the last [`SALT_MEMORY`]; a repeat is a replayed request.
#[derive(Default)]
pub(crate) struct Salts {
    seen: HashSet<Vec<u8>>,
    order: VecDeque<(Instant, Vec<u8>)>,
}
impl Salts {
    fn insert(&mut self, salt: &[u8], now: Instant) -> bool {
        while let Some((at, old)) = self.order.front() {
            if now.duration_since(*at) < SALT_MEMORY {
                break;
            }
            self.seen.remove(old);
            self.order.pop_front();
        }
        if !self.seen.insert(salt.to_vec()) {
            return false;
        }
        self.order.push_back((now, salt.to_vec()));
        true
    }
}

/// TCP request salts shared by every runtime that uses the same key and
/// method. The engine keeps one cache per cryptographic identity while a
/// rule uses it, so replacing a rule does not forget replayed requests.
pub(crate) type SaltCache = Arc<Mutex<Salts>>;

pub struct Server {
    method: Method,
    key: Vec<u8>,
    allow_private: bool,
    salts: SaltCache,
    udp: UdpKeys,
}
impl Server {
    pub fn new(config: &ServerConfig) -> Result<Self> {
        Self::with_salts(config, Arc::new(Mutex::new(Salts::default())))
    }
    pub(crate) fn with_salts(config: &ServerConfig, salts: SaltCache) -> Result<Self> {
        let key = config.key()?;
        let udp = match config.method {
            Method::Blake3Aes128Gcm | Method::Blake3Aes256Gcm => {
                UdpKeys::Block(HeaderBlock::new(&key))
            }
            Method::Blake3Chacha20Poly1305 => UdpKeys::XChaCha(Box::new(
                XChaCha20Poly1305::new_from_slice(&key).expect("32-byte key"),
            )),
            _ => UdpKeys::Salted,
        };
        Ok(Self {
            method: config.method,
            key,
            allow_private: config.allow_private_destinations,
            salts,
            udp,
        })
    }
    pub fn permits(&self, ip: IpAddr) -> bool {
        self.allow_private || public(ip)
    }
    /// Reads the request by `deadline`. A request that is late, malformed,
    /// forged or replayed is drained until the client closes, without
    /// replying, so a probe cannot learn how many bytes were read.
    pub async fn accept(
        &self,
        stream: BoxStream,
        deadline: Instant,
    ) -> Result<(Destination, Session)> {
        let mut session = Session::new(self.method, &self.key, stream);
        let error = match timeout_at(deadline, self.request(&mut session, unix_now())).await {
            Ok(Ok(destination)) => return Ok((destination, session)),
            Ok(Err(error)) => error,
            Err(_) => anyhow::anyhow!("Shadowsocks request timed out"),
        };
        drain(session.inner).await;
        Err(error)
    }
    async fn request(&self, session: &mut Session, now: u64) -> Result<Destination> {
        let mut salt = vec![0; self.method.key_len()];
        if !self.method.edition_2022() {
            session.inner.read_exact(&mut salt).await?;
            session.decrypt = Some(Cipher::new(self.method, &self.key, &salt));
            let mut head = Vec::new();
            let (destination, used) = loop {
                if let Some(parsed) = parse_address(&head)? {
                    break parsed;
                }
                let mut buffer = [0; 512];
                let n = session.read(&mut buffer).await?;
                ensure!(n > 0, "Shadowsocks request ended before its address");
                head.extend_from_slice(&buffer[..n]);
            };
            ensure!(
                self.salts.lock().unwrap().insert(&salt, Instant::now()),
                "replayed Shadowsocks request"
            );
            // Read before the rest of the current chunk, so returned first.
            session.pending = head.split_off(used);
            return Ok(destination);
        }
        // Salt and fixed header arrive in one write from the client.
        let mut head = vec![0; salt.len() + 11 + TAG];
        session.inner.read_exact(&mut head).await?;
        let (salt, fixed) = head.split_at_mut(salt.len());
        let mut cipher = Cipher::new(self.method, &self.key, salt);
        let fixed = cipher.open(fixed)?;
        ensure!(fixed[0] == 0, "not a Shadowsocks request header");
        let timestamp = u64::from_be_bytes(fixed[1..9].try_into().unwrap());
        ensure!(
            timestamp.abs_diff(now) <= MAX_CLOCK_SKEW_SECS,
            "Shadowsocks request time differs from ours by more than 30 s"
        );
        let length = usize::from(u16::from_be_bytes([fixed[9], fixed[10]]));
        let mut variable = vec![0; length + TAG];
        session.inner.read_exact(&mut variable).await?;
        let variable = cipher.open(&mut variable)?;
        let (destination, used) =
            parse_address(variable)?.context("incomplete Shadowsocks request header")?;
        let rest = &variable[used..];
        ensure!(rest.len() >= 2, "incomplete Shadowsocks request header");
        let padding = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
        ensure!(
            padding <= MAX_PADDING && rest.len() >= 2 + padding,
            "invalid Shadowsocks padding"
        );
        let payload = rest[2 + padding..].to_vec();
        ensure!(
            !payload.is_empty() || padding > 0,
            "Shadowsocks request has neither payload nor padding"
        );
        ensure!(
            self.salts.lock().unwrap().insert(salt, Instant::now()),
            "replayed Shadowsocks request"
        );
        session.request_salt = salt.to_vec();
        session.decrypt = Some(cipher);
        session.pending = payload;
        Ok(destination)
    }

    /// Authenticates and decrypts one client datagram in place. The caller
    /// checks a 2022 packet ID against its association's [`ReplayWindow`].
    pub fn open_datagram<'a>(&self, packet: &'a mut [u8], now: u64) -> Result<Datagram<'a>> {
        let (session, body) = match &self.udp {
            UdpKeys::Salted => {
                let salt_len = self.method.key_len();
                ensure!(packet.len() >= salt_len + TAG, "short Shadowsocks datagram");
                let (salt, body) = packet.split_at_mut(salt_len);
                let plain = Cipher::new(self.method, &self.key, salt).open(body)?;
                let (destination, used) =
                    parse_address(plain)?.context("incomplete Shadowsocks datagram address")?;
                return Ok(Datagram {
                    session: None,
                    packet_id: 0,
                    destination,
                    payload: &plain[used..],
                });
            }
            UdpKeys::Block(block) => {
                ensure!(
                    packet.len() >= SESSION_HEADER + TAG,
                    "short Shadowsocks datagram"
                );
                let (header, body) = packet.split_at_mut(SESSION_HEADER);
                block.decrypt(header);
                let key = Cipher::new(self.method, &self.key, &header[..8]).key;
                let nonce = Nonce::try_assume_unique_for_key(&header[4..]).expect("12 bytes");
                let body = key
                    .open_in_place(nonce, Aad::empty(), body)
                    .map_err(|_| anyhow!("Shadowsocks datagram failed authentication"))?;
                (&*header, &*body)
            }
            UdpKeys::XChaCha(cipher) => {
                ensure!(
                    packet.len() >= XNONCE + SESSION_HEADER + TAG,
                    "short Shadowsocks datagram"
                );
                let (nonce, rest) = packet.split_at_mut(XNONCE);
                let (body, tag) = rest.split_at_mut(rest.len() - TAG);
                cipher
                    .decrypt_inout_detached(
                        (&*nonce).try_into().expect("24 bytes"),
                        &[],
                        (&mut *body).into(),
                        (&*tag).try_into().expect("16 bytes"),
                    )
                    .map_err(|_| anyhow!("Shadowsocks datagram failed authentication"))?;
                body.split_at(SESSION_HEADER)
            }
        };
        ensure!(
            body.len() >= 11 && body[0] == 0,
            "not a Shadowsocks client datagram"
        );
        let timestamp = u64::from_be_bytes(body[1..9].try_into().unwrap());
        ensure!(
            timestamp.abs_diff(now) <= MAX_CLOCK_SKEW_SECS,
            "Shadowsocks datagram time differs from ours by more than 30 s"
        );
        let padding = usize::from(u16::from_be_bytes([body[9], body[10]]));
        let rest = body
            .get(11 + padding..)
            .context("invalid Shadowsocks padding")?;
        let (destination, used) =
            parse_address(rest)?.context("incomplete Shadowsocks datagram header")?;
        Ok(Datagram {
            session: Some(u64::from_be_bytes(session[..8].try_into().unwrap())),
            packet_id: u64::from_be_bytes(session[8..].try_into().unwrap()),
            destination,
            payload: &rest[used..],
        })
    }

    /// The server half of a new association with `client_session`.
    pub fn replies(&self, client_session: Option<u64>) -> Replies {
        let server_session = rand::random::<u64>();
        Replies {
            client_session: client_session.unwrap_or_default(),
            server_session,
            next_packet: 0,
            key: matches!(self.udp, UdpKeys::Block(_))
                .then(|| Cipher::new(self.method, &self.key, &server_session.to_be_bytes()).key),
        }
    }

    /// Appends a datagram carrying `payload` from `source` to `out`.
    pub fn seal_reply(
        &self,
        replies: &mut Replies,
        source: SocketAddr,
        payload: &[u8],
        out: &mut Vec<u8>,
    ) {
        let start = out.len();
        if let UdpKeys::Salted = self.udp {
            let mut salt = vec![0; self.method.key_len()];
            rand::thread_rng().fill_bytes(&mut salt);
            out.extend_from_slice(&salt);
            let body = out.len();
            write_address(out, source);
            out.extend_from_slice(payload);
            Cipher::new(self.method, &self.key, &salt).seal_from(out, body);
            return;
        }
        if let UdpKeys::XChaCha(_) = self.udp {
            out.resize(start + XNONCE, 0);
            rand::thread_rng().fill_bytes(&mut out[start..]);
        }
        let header = out.len();
        out.extend_from_slice(&replies.server_session.to_be_bytes());
        out.extend_from_slice(&replies.next_packet.to_be_bytes());
        replies.next_packet += 1;
        out.push(1);
        out.extend_from_slice(&unix_now().to_be_bytes());
        out.extend_from_slice(&replies.client_session.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        write_address(out, source);
        out.extend_from_slice(payload);
        match &self.udp {
            UdpKeys::Block(block) => {
                let key = replies.key.as_ref().expect("AES association key");
                let nonce = Nonce::try_assume_unique_for_key(&out[header + 4..header + 16])
                    .expect("12 bytes");
                let tag = key
                    .seal_in_place_separate_tag(
                        nonce,
                        Aad::empty(),
                        &mut out[header + SESSION_HEADER..],
                    )
                    .expect("datagram within AEAD limits");
                out.extend_from_slice(tag.as_ref());
                block.encrypt(&mut out[header..header + SESSION_HEADER]);
            }
            UdpKeys::XChaCha(cipher) => {
                let (nonce, body) = out[start..].split_at_mut(XNONCE);
                let tag = cipher
                    .encrypt_inout_detached(
                        (&*nonce).try_into().expect("24 bytes"),
                        &[],
                        body.into(),
                    )
                    .expect("datagram within AEAD limits");
                out.extend_from_slice(&tag);
            }
            UdpKeys::Salted => unreachable!(),
        }
    }
}

/// How datagrams are protected, which differs by method.
enum UdpKeys {
    /// 2022 AES: the session and packet IDs are one AES block under the key;
    /// the body is sealed with the session's subkey.
    Block(HeaderBlock),
    /// 2022 ChaCha20: XChaCha20-Poly1305 under the key itself, random nonces.
    XChaCha(Box<XChaCha20Poly1305>),
    /// Older methods: every datagram has its own salt and subkey.
    Salted,
}
enum HeaderBlock {
    Aes128(Box<aes::Aes128>),
    Aes256(Box<aes::Aes256>),
}
impl HeaderBlock {
    fn new(key: &[u8]) -> Self {
        use aes::cipher::KeyInit;
        match key.len() {
            16 => Self::Aes128(Box::new(
                aes::Aes128::new_from_slice(key).expect("16-byte key"),
            )),
            _ => Self::Aes256(Box::new(
                aes::Aes256::new_from_slice(key).expect("32-byte key"),
            )),
        }
    }
    fn encrypt(&self, block: &mut [u8]) {
        use aes::cipher::BlockCipherEncrypt;
        let block = <&mut aes::Block>::try_from(block).expect("one AES block");
        match self {
            Self::Aes128(cipher) => cipher.encrypt_block(block),
            Self::Aes256(cipher) => cipher.encrypt_block(block),
        }
    }
    fn decrypt(&self, block: &mut [u8]) {
        use aes::cipher::BlockCipherDecrypt;
        let block = <&mut aes::Block>::try_from(block).expect("one AES block");
        match self {
            Self::Aes128(cipher) => cipher.decrypt_block(block),
            Self::Aes256(cipher) => cipher.decrypt_block(block),
        }
    }
}

fn write_address(out: &mut Vec<u8>, address: SocketAddr) {
    match crate::model::canonical_address(address) {
        SocketAddr::V4(address) => {
            out.push(1);
            out.extend_from_slice(&address.ip().octets());
        }
        SocketAddr::V6(address) => {
            out.push(4);
            out.extend_from_slice(&address.ip().octets());
        }
    }
    out.extend_from_slice(&address.port().to_be_bytes());
}

/// One authenticated client datagram.
#[derive(Debug)]
pub struct Datagram<'a> {
    /// 2022 methods: the client session, which its association follows when
    /// the client's address changes. Older methods have none and go by
    /// address.
    pub session: Option<u64>,
    pub packet_id: u64,
    pub destination: Destination,
    pub payload: &'a [u8],
}

/// The server half of one UDP association: its own session ID and packet
/// counter, under which replies are sealed.
pub struct Replies {
    client_session: u64,
    server_session: u64,
    next_packet: u64,
    /// 2022 AES: the server session's subkey.
    key: Option<LessSafeKey>,
}

/// Packet IDs seen on one 2022 association (SIP022 §3.2.4): an ID seen
/// before, or too far behind the newest to be remembered, is a replay.
pub struct ReplayWindow {
    /// One past the newest accepted ID.
    next: u64,
    seen: [u64; REPLAY_WINDOW as usize / 64],
}
impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            next: 0,
            seen: [0; REPLAY_WINDOW as usize / 64],
        }
    }
}
impl ReplayWindow {
    /// Records `id`; false if it is a replay.
    pub fn accept(&mut self, id: u64) -> bool {
        let bit = |id: u64| ((id % REPLAY_WINDOW / 64) as usize, 1u64 << (id % 64));
        if id >= self.next {
            if id == u64::MAX {
                return false;
            }
            if id - self.next >= REPLAY_WINDOW {
                self.seen = [0; REPLAY_WINDOW as usize / 64];
            } else {
                // Slots the window slides over held IDs now out of range.
                for slot in self.next..=id {
                    let (word, mask) = bit(slot);
                    self.seen[word] &= !mask;
                }
            }
            self.next = id + 1;
        } else if self.next - id > REPLAY_WINDOW {
            return false;
        }
        let (word, mask) = bit(id);
        let fresh = self.seen[word] & mask == 0;
        self.seen[word] |= mask;
        fresh
    }
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Sends FIN and reads until the peer closes, so a rejected request looks the
/// same however many bytes it had.
async fn drain(mut stream: BoxStream) {
    let _ = timeout(DRAIN, async {
        let _ = stream.shutdown().await;
        let mut buffer = [0; 4096];
        while matches!(stream.read(&mut buffer).await, Ok(1..)) {}
    })
    .await;
}

/// An accepted Shadowsocks connection: reads return the client's payload and
/// writes are encrypted into the response stream.
pub struct Session {
    inner: BoxStream,
    method: Method,
    key: Vec<u8>,
    request_salt: Vec<u8>,
    /// Payload that arrived with the request, returned first.
    pending: Vec<u8>,
    pending_at: usize,
    decrypt: Option<Cipher>,
    /// The chunk being read; after decryption, `plain` is its unread payload.
    chunk: Vec<u8>,
    filled: usize,
    /// The next chunk is a payload of this length; `None` for a length chunk.
    payload: Option<usize>,
    plain: std::ops::Range<usize>,
    encrypt: Option<Cipher>,
    /// Ciphertext not yet written.
    out: Vec<u8>,
    written: usize,
}
impl Session {
    fn new(method: Method, key: &[u8], inner: BoxStream) -> Self {
        Self {
            inner,
            method,
            key: key.to_vec(),
            request_salt: Vec::new(),
            pending: Vec::new(),
            pending_at: 0,
            decrypt: None,
            chunk: Vec::new(),
            filled: 0,
            payload: None,
            plain: 0..0,
            encrypt: None,
            out: Vec::new(),
            written: 0,
        }
    }
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.out.len() {
            match ready!(Pin::new(&mut self.inner).poll_write(cx, &self.out[self.written..]))? {
                0 => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                n => self.written += n,
            }
        }
        self.out.clear();
        self.written = 0;
        Poll::Ready(Ok(()))
    }
}
impl AsyncRead for Session {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.pending_at < this.pending.len() {
                let n = buf.remaining().min(this.pending.len() - this.pending_at);
                buf.put_slice(&this.pending[this.pending_at..][..n]);
                this.pending_at += n;
                if this.pending_at == this.pending.len() {
                    (this.pending, this.pending_at) = (Vec::new(), 0);
                }
                return Poll::Ready(Ok(()));
            }
            if !this.plain.is_empty() {
                let n = buf.remaining().min(this.plain.len());
                buf.put_slice(&this.chunk[this.plain.start..][..n]);
                this.plain.start += n;
                return Poll::Ready(Ok(()));
            }
            let need = this.payload.unwrap_or(2) + TAG;
            if this.chunk.len() < need {
                this.chunk.resize(need, 0);
            }
            while this.filled < need {
                let mut read = ReadBuf::new(&mut this.chunk[this.filled..need]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
                let n = read.filled().len();
                if n == 0 {
                    // EOF is clean only between chunks.
                    if this.filled == 0 && this.payload.is_none() {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                this.filled += n;
            }
            this.filled = 0;
            let decrypt = this.decrypt.as_mut().expect("request read");
            let plain = decrypt.open(&mut this.chunk[..need])?;
            match this.payload.take() {
                None => {
                    let length = usize::from(u16::from_be_bytes([plain[0], plain[1]]));
                    if length > this.method.max_chunk() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Shadowsocks chunk too long",
                        )));
                    }
                    this.payload = Some(length);
                }
                Some(length) => this.plain = 0..length,
            }
        }
    }
}
impl AsyncWrite for Session {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(this.method.max_chunk());
        let length = (n as u16).to_be_bytes();
        match &mut this.encrypt {
            Some(cipher) => cipher.seal(&mut this.out, &length),
            None => {
                // The salt and header go out with the first payload.
                let mut salt = vec![0; this.method.key_len()];
                rand::thread_rng().fill_bytes(&mut salt);
                let mut cipher = Cipher::new(this.method, &this.key, &salt);
                this.out.extend_from_slice(&salt);
                if this.method.edition_2022() {
                    let mut header = vec![1];
                    header.extend_from_slice(&unix_now().to_be_bytes());
                    header.extend_from_slice(&this.request_salt);
                    header.extend_from_slice(&length);
                    cipher.seal(&mut this.out, &header);
                } else {
                    cipher.seal(&mut this.out, &length);
                }
                this.encrypt = Some(cipher);
            }
        }
        let cipher = this.encrypt.as_mut().unwrap();
        cipher.seal(&mut this.out, &buf[..n]);
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }
    fn server(method: Method, password: &str) -> Server {
        Server::new(&ServerConfig {
            method,
            password: password.into(),
            allow_private_destinations: false,
        })
        .unwrap()
    }
    async fn read(server: &Server, bytes: &[u8], now: u64) -> Result<(Destination, Vec<u8>)> {
        let mut session = Session::new(
            server.method,
            &server.key,
            Box::new(Cursor::new(bytes.to_vec())),
        );
        let destination = server.request(&mut session, now).await?;
        let mut payload = Vec::new();
        session.read_to_end(&mut payload).await?;
        Ok((destination, payload))
    }

    // Captured from shadowsocks-rust 1.25.0 sslocal, sending "hello".
    const KEY_0_TO_15: &str = "AAECAwQFBgcICQoLDA0ODw==";
    const SENT_2022: u64 = 1793023562;
    const REQUEST_2022: &str = "6bba1a4d748de319307f0ca0841582ce68c2c34a8aab54729913c7cba7492ce69590dad033176ac0b87f415317521f9f148043a99e3886561ab31b175bb7049efaa53e3ff3ebcbf796ac3233410c0ac54a";
    const REQUEST_CHACHA: &str = "02a569fdd116d99d7d1e1105c275618bcafbe91052601ae94bdc58e2984e25dcbcca5d001316703d45ffb9275448e671f6c7ed6ad0d6397ad14bd9ca65fcffbe8b71b0a474aa7a5f49c647775713";

    #[tokio::test]
    async fn requests_from_the_official_client_are_read_once_and_only_while_fresh() {
        let request = hex(REQUEST_2022);
        let ss2022 = server(Method::Blake3Aes128Gcm, KEY_0_TO_15);
        assert_eq!(
            read(&ss2022, &request, SENT_2022 + 30).await.unwrap(),
            (
                Destination::Domain("example.com".into(), 443),
                b"hello".to_vec()
            )
        );
        let replay = read(&ss2022, &request, SENT_2022 + 30).await.unwrap_err();
        assert!(replay.to_string().contains("replayed"), "{replay}");
        // Only the clock differs: one second past the allowed skew either way.
        for now in [SENT_2022 + 31, SENT_2022 - 31] {
            let fresh = server(Method::Blake3Aes128Gcm, KEY_0_TO_15);
            assert!(read(&fresh, &request, now).await.is_err());
        }
        let mut forged = request.clone();
        forged[20] ^= 1;
        let fresh = server(Method::Blake3Aes128Gcm, KEY_0_TO_15);
        assert!(read(&fresh, &forged, SENT_2022).await.is_err());

        let request = hex(REQUEST_CHACHA);
        let classic = server(Method::Chacha20IetfPoly1305, "relay test");
        assert_eq!(
            read(&classic, &request, 0).await.unwrap(),
            (
                Destination::Ip("192.0.2.7:8080".parse().unwrap()),
                b"hello".to_vec()
            )
        );
        assert!(read(&classic, &request, 0).await.is_err());
        let other = server(Method::Chacha20IetfPoly1305, "relay test2");
        assert!(read(&other, &request, 0).await.is_err());
    }

    // Captured from shadowsocks-rust 1.25.0 sslocal (SOCKS5 UDP), "hello".
    const KEY_0_TO_31: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    const SENT_DATAGRAMS: u64 = 1793028773;
    const DATAGRAM_AES: &str = "d3e50382ca103857bdaf9c543e0b2dde4897f1da68507434abf0c189401fc9d5a95e52f65f26bdefe12af55400c07f1f24e36c0b511d6f930d9ee75c5d73f3";
    const DATAGRAM_XCHACHA: &str = "740c637ac34d8748323addf8e71349fd889194126ec464c2f8f17c9c417da21a624004a45c1e473dfeeb17294734e456d4fe7ef0e6bda593e17abe3492cdd5bc8d1c90b2f90ac31d800dcd07cb99ef7bbebaabd16e1119";
    const DATAGRAM_CHACHA: &str = "0c24d7bb852abd327e269338f7b1c7e741fef004928ddc9432da95eda6aed4e15036a54c5a130aab1e04fd00de6e23b82ace27a41a4c0485ffb323a9";

    #[test]
    fn datagrams_from_the_official_client_open_only_with_the_key_and_while_fresh() {
        for (method, key, packet) in [
            (Method::Blake3Aes128Gcm, KEY_0_TO_15, DATAGRAM_AES),
            (
                Method::Blake3Chacha20Poly1305,
                KEY_0_TO_31,
                DATAGRAM_XCHACHA,
            ),
        ] {
            let ss = server(method, key);
            let mut bytes = hex(packet);
            let datagram = ss.open_datagram(&mut bytes, SENT_DATAGRAMS + 30).unwrap();
            assert!(datagram.session.is_some(), "{method:?}");
            assert_eq!(datagram.packet_id, 1);
            assert_eq!(
                datagram.destination,
                Destination::Domain("example.com".into(), 443)
            );
            assert_eq!(datagram.payload, b"hello");
            for now in [SENT_DATAGRAMS + 31, SENT_DATAGRAMS - 31] {
                assert!(ss.open_datagram(&mut hex(packet), now).is_err());
            }
            let mut forged = hex(packet);
            forged[30] ^= 1;
            assert!(ss.open_datagram(&mut forged, SENT_DATAGRAMS).is_err());
        }
        let other = server(
            Method::Blake3Aes128Gcm,
            &base64::engine::general_purpose::STANDARD.encode([1; 16]),
        );
        assert!(
            other
                .open_datagram(&mut hex(DATAGRAM_AES), SENT_DATAGRAMS)
                .is_err()
        );

        let classic = server(Method::Chacha20IetfPoly1305, "relay test");
        let mut bytes = hex(DATAGRAM_CHACHA);
        let datagram = classic.open_datagram(&mut bytes, 0).unwrap();
        assert_eq!(datagram.session, None);
        assert_eq!(
            datagram.destination,
            Destination::Ip("192.0.2.7:8080".parse().unwrap())
        );
        assert_eq!(datagram.payload, b"hello");
        let other = server(Method::Chacha20IetfPoly1305, "relay test2");
        assert!(other.open_datagram(&mut hex(DATAGRAM_CHACHA), 0).is_err());
    }

    #[test]
    fn a_packet_id_is_accepted_once_and_only_within_the_window() {
        let mut window = ReplayWindow::default();
        assert!(window.accept(0));
        assert!(!window.accept(0));
        // 2048 shares a slot with 0; sliding onto it must not read 0's mark.
        assert!(window.accept(REPLAY_WINDOW));
        assert!(!window.accept(0), "0 is now behind the window");
        assert!(window.accept(1), "1 is the oldest ID still inside");
        assert!(!window.accept(1));
        assert!(window.accept(REPLAY_WINDOW - 1), "reordered, not yet seen");
        // A jump past the whole window forgets everything before it.
        assert!(window.accept(10 * REPLAY_WINDOW));
        assert!(!window.accept(9 * REPLAY_WINDOW));
        assert!(window.accept(9 * REPLAY_WINDOW + 1));
        assert!(!window.accept(u64::MAX));
    }

    #[tokio::test]
    async fn a_rejected_request_gets_no_reply_until_the_client_closes() {
        let ss = server(
            Method::Blake3Aes256Gcm,
            &base64::engine::general_purpose::STANDARD.encode([7; 32]),
        );
        let (mut client, inner) = tokio::io::duplex(4096);
        client.write_all(&[0x55; 200]).await.unwrap();
        let accept = tokio::spawn(async move {
            ss.accept(Box::new(inner), Instant::now() + Duration::from_secs(5))
                .await
                .map(|_| ())
        });
        let mut reply = Vec::new();
        // FIN, no bytes; the server keeps reading what the client sends.
        tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert!(reply.is_empty());
        client.write_all(&[0x55; 100]).await.unwrap();
        assert!(!accept.is_finished());
        drop(client);
        assert!(
            tokio::time::timeout(Duration::from_secs(2), accept)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
    }

    #[test]
    fn only_public_destinations_are_reachable_by_default() {
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700::1111", "100.128.0.1"] {
            assert!(public(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "255.255.255.255",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "fd00::1",
            "fe80::1",
            "64:ff9b::a00:1",
            "::a00:1",
        ] {
            assert!(!public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn a_server_rule_has_no_targets_and_its_key_stays_out_of_logs() {
        let rule = |extra: &str| -> Result<crate::model::Rule> {
            let text = format!(
                r#"{{"id":"ss","tenant_id":"t","owner_id":"o","name":"ss","listen":"0.0.0.0:8388",
                "protocol":"tcp","inbound_shadowsocks":{{"method":"2022-blake3-aes-256-gcm",
                "password":"{}"}},"quota_bytes":null,"expires_at_ms":null,
                "rate_bytes_per_sec":null,"meter_epoch":"e",{extra}}}"#,
                base64::engine::general_purpose::STANDARD.encode([9; 32])
            );
            let rule: crate::model::Rule = serde_json::from_str(&text)?;
            rule.validate()?;
            Ok(rule)
        };
        let valid = rule(r#""targets":[]"#).unwrap();
        assert!(!format!("{valid:?}").contains("CQkJ"));
        assert!(rule(r#""targets":[{"address":"192.0.2.1:80"}]"#).is_err());
        let short = ServerConfig {
            method: Method::Blake3Aes256Gcm,
            password: base64::engine::general_purpose::STANDARD.encode([9; 16]),
            allow_private_destinations: false,
        };
        assert!(Server::new(&short).is_err());
    }
}
