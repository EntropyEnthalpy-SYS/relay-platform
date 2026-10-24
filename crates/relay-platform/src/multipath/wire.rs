use super::{CHUNK_BYTES, Counters};
use anyhow::{Result, ensure};
use std::{
    io,
    sync::{Arc, atomic::Ordering},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(super) const HEADER: usize = 16;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Frame {
    Data { sequence: u64, bytes: Arc<[u8]> },
    Fin(u64),
    Ack(u64, [u8; 32]),
}
impl Frame {
    pub fn sequence(&self) -> u64 {
        match self {
            Self::Data { sequence, .. } | Self::Fin(sequence) | Self::Ack(sequence, _) => *sequence,
        }
    }
    pub fn payload(&self) -> &[u8] {
        match self {
            Self::Data { bytes, .. } => bytes,
            _ => &[],
        }
    }
    pub async fn read<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let mut header = [0; HEADER];
        reader.read_exact(&mut header).await?;
        ensure!(
            header[1..4] == [0; 3],
            "multipath frame reserved bits are nonzero"
        );
        let sequence = u64::from_be_bytes(header[4..12].try_into().unwrap());
        let length = u32::from_be_bytes(header[12..16].try_into().unwrap()) as usize;
        match header[0] {
            1 => {
                ensure!(
                    (1..=CHUNK_BYTES).contains(&length),
                    "multipath data frame length out of range"
                );
                let mut bytes = vec![0; length];
                reader.read_exact(&mut bytes).await?;
                Ok(Self::Data {
                    sequence,
                    bytes: bytes.into(),
                })
            }
            2 => {
                ensure!(length == 0, "multipath FIN has payload");
                Ok(Self::Fin(sequence))
            }
            3 => {
                ensure!(
                    matches!(length, 0 | 32),
                    "invalid multipath acknowledgement bitmap length"
                );
                let mut received = [0; 32];
                if length != 0 {
                    reader.read_exact(&mut received).await?;
                }
                Ok(Self::Ack(sequence, received))
            }
            _ => anyhow::bail!("unknown multipath frame type"),
        }
    }
    pub fn header(&self) -> [u8; HEADER] {
        let mut header = [0; HEADER];
        header[0] = match self {
            Self::Data { .. } => 1,
            Self::Fin(_) => 2,
            Self::Ack(_, _) => 3,
        };
        header[4..12].copy_from_slice(&self.sequence().to_be_bytes());
        let length = if matches!(self, Self::Ack(_, _)) {
            32
        } else {
            self.payload().len() as u32
        };
        header[12..].copy_from_slice(&length.to_be_bytes());
        header
    }
}
#[derive(Clone, Copy)]
pub(super) enum CopyKind {
    Primary,
    Replica,
    Retransmission,
}
pub(super) struct Job {
    pub frame: Arc<Frame>,
    pub kind: CopyKind,
}
pub(super) async fn write<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &Frame,
    kind: CopyKind,
    slot: usize,
    stats: &Counters,
) -> io::Result<()> {
    let mut control = [0u8; HEADER + 32];
    control[..HEADER].copy_from_slice(&frame.header());
    let size = if let Frame::Ack(_, received) = frame {
        control[HEADER..].copy_from_slice(received);
        HEADER + 32
    } else {
        HEADER
    };
    let mut remaining = &control[..size];
    while !remaining.is_empty() {
        let n = writer.write(remaining).await?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        stats
            .framing_sent_bytes
            .fetch_add(n as u64, Ordering::Relaxed);
        remaining = &remaining[n..];
    }
    let mut remaining = frame.payload();
    while !remaining.is_empty() {
        let n = writer.write(remaining).await?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        stats
            .sent_payload_bytes
            .fetch_add(n as u64, Ordering::Relaxed);
        stats.path_sent_payload_bytes[slot].fetch_add(n as u64, Ordering::Relaxed);
        match kind {
            CopyKind::Primary => {}
            CopyKind::Replica => {
                stats
                    .replicated_payload_bytes
                    .fetch_add(n as u64, Ordering::Relaxed);
            }
            CopyKind::Retransmission => {
                stats
                    .retransmitted_payload_bytes
                    .fetch_add(n as u64, Ordering::Relaxed);
            }
        }
        remaining = &remaining[n..];
    }
    writer.flush().await
}
