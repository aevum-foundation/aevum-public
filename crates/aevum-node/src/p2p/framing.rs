use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::time::{timeout, Duration};
use bytes::Buf;

pub const IO_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024; // 10 MB

/// Читает length-prefixed сообщение с таймаутом
/// Формат: [4 байта длина: u32 big-endian] [payload]
pub async fn read_message(reader: &mut OwnedReadHalf) -> Result<Vec<u8>, FramingError> {
    // Читаем длину с таймаутом
    let mut len_buf = [0u8; 4];
    timeout(IO_TIMEOUT, reader.read_exact(&mut len_buf))
        .await
        .map_err(|_| FramingError::Timeout)?
        .map_err(|e| FramingError::Io(e))?;

    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_MESSAGE_SIZE {
        return Err(FramingError::MessageTooLarge(len));
    }

    // Читаем payload с таймаутом
    let mut payload = vec![0u8; len];
    timeout(IO_TIMEOUT, reader.read_exact(&mut payload))
        .await
        .map_err(|_| FramingError::Timeout)?
        .map_err(|e| FramingError::Io(e))?;

    Ok(payload)
}

/// Отправляет length-prefixed сообщение с таймаутом
pub async fn write_message(writer: &mut OwnedWriteHalf, payload: &[u8]) -> Result<(), FramingError> {
    if payload.len() > MAX_MESSAGE_SIZE {
        return Err(FramingError::MessageTooLarge(payload.len()));
    }

    let len = (payload.len() as u32).to_be_bytes();
    let mut packet = Vec::with_capacity(4 + payload.len());
    packet.extend_from_slice(&len);
    packet.extend_from_slice(payload);

    timeout(IO_TIMEOUT, writer.write_all(&packet))
        .await
        .map_err(|_| FramingError::Timeout)?
        .map_err(|e| FramingError::Io(e))?;

    Ok(())
}

#[derive(Debug)]
pub enum FramingError {
    Timeout,
    Io(std::io::Error),
    MessageTooLarge(usize),
}

impl std::fmt::Display for FramingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FramingError::Timeout => write!(f, "IO timeout"),
            FramingError::Io(e) => write!(f, "IO error: {}", e),
            FramingError::MessageTooLarge(s) => write!(f, "Message too large: {} bytes", s),
        }
    }
}

impl std::error::Error for FramingError {}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn test_read_write_message() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut reader, mut writer) = stream.into_split();
            
            let msg = read_message(&mut reader).await.unwrap();
            assert_eq!(msg, b"Hello, ATP!");
            
            write_message(&mut writer, b"ACK").await.unwrap();
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let (mut reader, mut writer) = stream.into_split();
        
        write_message(&mut writer, b"Hello, ATP!").await.unwrap();
        let response = read_message(&mut reader).await.unwrap();
        assert_eq!(response, b"ACK");
        
        server_handle.await.unwrap();
    }
}
