//! Streaming file encryption — TPENC2 format.
//!
//! ```text
//! magic  "TPENC2"                                    6 bytes
//! file_id                                            16 random bytes
//! name_len  u32 BE | name_blob (AES-GCM)             encrypted original filename
//! repeat:
//!   chunk_len u32 BE | chunk_blob (AES-GCM)          1 MiB plaintext per chunk
//! ```
//!
//! Security properties v1 (the Python format) did not have:
//!  * **Streaming.** Files are processed in 1 MiB chunks, so multi-GB files
//!    no longer need to fit in RAM.
//!  * **Per-file keys.** Each file gets its own HKDF-derived key (random
//!    16-byte `file_id` as salt), so GCM nonce collisions across a large
//!    corpus are a non-issue and one leaked file key exposes only that file.
//!  * **Reorder/truncation protection.** Every chunk's AAD contains its
//!    index, and the final chunk is marked "last" — swapping, dropping or
//!    cutting chunks fails authentication.
//!  * **Path-traversal-safe restore.** The embedded original filename is
//!    reduced to its basename before use, so a malicious archive cannot
//!    write outside the target directory.
//!
//! Legacy TPENC1 files (whole-file blob, raw master key) can still be
//! decrypted for migration.

use std::fs;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::crypto::{self, SecretKey};
use crate::error::{Error, Result};

const MAGIC_V2: &[u8] = b"TPENC2";
const MAGIC_V1: &[u8] = b"TPENC1";
pub const ENCRYPTED_EXT: &str = "tpenc";

const CHUNK_SIZE: usize = 1024 * 1024;
/// HKDF context for the file-encryption root key.
const FILES_KEY_CONTEXT: &str = "files-v2";

const AAD_NAME: &[u8] = b"TPENC2.name";

fn chunk_aad(index: u64, last: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(20);
    aad.extend_from_slice(if last { b"TPENC2.last." } else { b"TPENC2.chunk" });
    aad.extend_from_slice(&index.to_be_bytes());
    aad
}

/// Derive the per-file key: master → files root (HKDF) → file key
/// (HKDF salted with the random file_id stored in the header).
fn file_key(master: &SecretKey, file_id: &[u8; 16]) -> SecretKey {
    let root = master.derive(FILES_KEY_CONTEXT);
    let hk = Hkdf::<Sha256>::new(Some(file_id), root.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"file", &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    SecretKey::new(okm)
}

/// Strip any directory components from an embedded filename.
fn safe_basename(name: &str) -> String {
    let base = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .trim()
        .to_string();
    if base.is_empty() || base == "." || base == ".." {
        "restored.bin".to_string()
    } else {
        base
    }
}

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

pub fn encrypt_file(master: &SecretKey, src: &Path, dst: Option<&Path>) -> Result<PathBuf> {
    let dst: PathBuf = match dst {
        Some(p) => p.to_path_buf(),
        None => {
            let mut name = src
                .file_name()
                .ok_or_else(|| Error::InvalidInput("source has no file name".into()))?
                .to_os_string();
            name.push(format!(".{ENCRYPTED_EXT}"));
            src.with_file_name(name)
        }
    };

    let mut file_id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut file_id);
    let key = file_key(master, &file_id);

    let src_name = src
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());

    let reader = fs::File::open(src)?;
    let total = reader.metadata()?.len();
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(fs::File::create(&dst)?);

    writer.write_all(MAGIC_V2)?;
    writer.write_all(&file_id)?;

    let name_blob = crypto::encrypt(&key, src_name.as_bytes(), AAD_NAME)?;
    writer.write_all(&(name_blob.len() as u32).to_be_bytes())?;
    writer.write_all(&name_blob)?;

    let mut buf = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    let mut index: u64 = 0;
    let mut written: u64 = 0;
    loop {
        let n = read_full(&mut reader, &mut buf)?;
        written += n as u64;
        let last = written >= total || n < CHUNK_SIZE;
        let blob = crypto::encrypt(&key, &buf[..n], &chunk_aad(index, last))?;
        writer.write_all(&(blob.len() as u32).to_be_bytes())?;
        writer.write_all(&blob)?;
        index += 1;
        if last {
            break;
        }
    }
    writer.flush()?;
    Ok(dst)
}

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------

/// Decrypt to disk. Returns (output path, embedded original name).
pub fn decrypt_file(
    master: &SecretKey,
    src: &Path,
    dst: Option<&Path>,
) -> Result<(PathBuf, String)> {
    let mut reader = BufReader::new(fs::File::open(src)?);
    let mut magic = [0u8; 6];
    reader.read_exact(&mut magic)?;

    if magic == MAGIC_V1 {
        return decrypt_v1(master, src, dst);
    }
    if magic != MAGIC_V2 {
        return Err(Error::InvalidInput(
            "not a TrezorProtector encrypted file (bad magic)".into(),
        ));
    }

    let mut file_id = [0u8; 16];
    reader.read_exact(&mut file_id)?;
    let key = file_key(master, &file_id);

    let name_blob = read_len_prefixed(&mut reader)?;
    let name_bytes = crypto::decrypt(&key, &name_blob, AAD_NAME)
        .map_err(|_| Error::Crypto("cannot decrypt file header: wrong key or corrupt file".into()))?;
    let original_name = safe_basename(&String::from_utf8_lossy(&name_bytes));

    let dst: PathBuf = match dst {
        Some(p) => p.to_path_buf(),
        None => src
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(&original_name),
    };

    let mut writer = BufWriter::new(fs::File::create(&dst)?);
    stream_chunks(&key, &mut reader, |plain| {
        writer.write_all(plain).map_err(Error::Io)
    })?;
    writer.flush()?;
    Ok((dst, original_name))
}

/// Decrypt fully into memory (for `tp file view`). Returns (bytes, name).
pub fn read_encrypted(master: &SecretKey, src: &Path) -> Result<(Zeroizing<Vec<u8>>, String)> {
    let mut reader = BufReader::new(fs::File::open(src)?);
    let mut magic = [0u8; 6];
    reader.read_exact(&mut magic)?;

    if magic == MAGIC_V1 {
        let (plain, name) = decrypt_v1_bytes(master, src)?;
        return Ok((plain, name));
    }
    if magic != MAGIC_V2 {
        return Err(Error::InvalidInput(
            "not a TrezorProtector encrypted file (bad magic)".into(),
        ));
    }

    let mut file_id = [0u8; 16];
    reader.read_exact(&mut file_id)?;
    let key = file_key(master, &file_id);

    let name_blob = read_len_prefixed(&mut reader)?;
    let name_bytes = crypto::decrypt(&key, &name_blob, AAD_NAME)
        .map_err(|_| Error::Crypto("cannot decrypt file header: wrong key or corrupt file".into()))?;
    let original_name = safe_basename(&String::from_utf8_lossy(&name_bytes));

    let mut out = Zeroizing::new(Vec::new());
    stream_chunks(&key, &mut reader, |plain| {
        out.extend_from_slice(plain);
        Ok(())
    })?;
    Ok((out, original_name))
}

fn stream_chunks<R: Read>(
    key: &SecretKey,
    reader: &mut R,
    mut sink: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    let mut index: u64 = 0;
    loop {
        let blob = match try_read_len_prefixed(reader)? {
            Some(b) => b,
            None => {
                // Stream ended without a chunk marked "last" → truncated.
                return Err(Error::Crypto(
                    "encrypted file is truncated (missing final chunk)".into(),
                ));
            }
        };
        // Try as a middle chunk first, then as the final chunk.
        if let Ok(plain) = crypto::decrypt(key, &blob, &chunk_aad(index, false)) {
            sink(&plain)?;
            index += 1;
            continue;
        }
        let plain = crypto::decrypt(key, &blob, &chunk_aad(index, true)).map_err(|_| {
            Error::Crypto(format!(
                "chunk {index} failed authentication: wrong key, corruption, or tampering"
            ))
        })?;
        sink(&plain)?;
        // Final chunk: anything after it is trailing garbage.
        if try_read_len_prefixed(reader)?.is_some() {
            return Err(Error::Crypto(
                "data found after the final chunk — file has been tampered with".into(),
            ));
        }
        return Ok(());
    }
}

// ---------------------------------------------------------------------------
// Legacy TPENC1 (Python) support
// ---------------------------------------------------------------------------

fn decrypt_v1_bytes(master: &SecretKey, src: &Path) -> Result<(Zeroizing<Vec<u8>>, String)> {
    let raw = fs::read(src)?;
    let blob = &raw[MAGIC_V1.len()..];
    // v1 used the raw master key with no AAD.
    let payload = crypto::decrypt(master, blob, b"")
        .map_err(|_| Error::Crypto("cannot decrypt legacy file: wrong key or corrupt".into()))?;
    if payload.len() < 2 {
        return Err(Error::Crypto("legacy payload too short".into()));
    }
    let name_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    if payload.len() < 2 + name_len {
        return Err(Error::Crypto("legacy payload corrupt".into()));
    }
    let name = safe_basename(&String::from_utf8_lossy(&payload[2..2 + name_len]));
    let plain = Zeroizing::new(payload[2 + name_len..].to_vec());
    Ok((plain, name))
}

fn decrypt_v1(
    master: &SecretKey,
    src: &Path,
    dst: Option<&Path>,
) -> Result<(PathBuf, String)> {
    let (plain, name) = decrypt_v1_bytes(master, src)?;
    let dst: PathBuf = match dst {
        Some(p) => p.to_path_buf(),
        None => src.parent().unwrap_or_else(|| Path::new(".")).join(&name),
    };
    fs::write(&dst, &plain)?;
    Ok((dst, name))
}

// ---------------------------------------------------------------------------
// Steganographic dropper (hidden payload appended to a carrier file)
// ---------------------------------------------------------------------------
//
// A "container" is an ordinary file (PDF, JPEG, ZIP, PNG …) with an encrypted
// payload appended after its normal content plus a small trailer. Because
// those formats stop parsing at their own end marker and ignore trailing
// bytes, double-clicking the container opens the carrier normally in its
// default app. Only TrezorProtector — with the device — reveals the hidden
// file.
//
// Layout:
//   [ carrier bytes ][ hidden blob ][ u64 BE hidden_len ][ 8-byte magic ]
// hidden blob = file_id(16) || AES-256-GCM( u16 name_len | name | secret )
//
// Honesty: this is *hiding*, not cryptographic deniability. Someone who
// knows this tool can spot the trailer magic and tell a payload exists (they
// still can't read it without the device). For strong deniability, don't
// rely on obscurity.

const STEG_MAGIC: &[u8; 8] = b"TPSTEG01";
const AAD_STEG: &[u8] = b"TPENC2.steg";

/// Append `secret` to `carrier`, producing `output` (a working carrier file
/// that also carries the hidden, encrypted secret).
pub fn embed_hidden(
    master: &SecretKey,
    carrier: &Path,
    secret: &Path,
    output: &Path,
) -> Result<()> {
    let carrier_bytes = fs::read(carrier)?;
    let secret_bytes = Zeroizing::new(fs::read(secret)?);
    let secret_name = secret
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "secret.bin".into());

    let mut file_id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut file_id);
    let key = file_key(master, &file_id);

    let name = secret_name.as_bytes();
    if name.len() > u16::MAX as usize {
        return Err(Error::InvalidInput("secret filename too long".into()));
    }
    let mut payload = Zeroizing::new(Vec::with_capacity(2 + name.len() + secret_bytes.len()));
    payload.extend_from_slice(&(name.len() as u16).to_be_bytes());
    payload.extend_from_slice(name);
    payload.extend_from_slice(&secret_bytes);
    let blob = crypto::encrypt(&key, &payload, AAD_STEG)?;

    let mut hidden = Vec::with_capacity(16 + blob.len());
    hidden.extend_from_slice(&file_id);
    hidden.extend_from_slice(&blob);

    let mut out = carrier_bytes;
    out.extend_from_slice(&hidden);
    out.extend_from_slice(&(hidden.len() as u64).to_be_bytes());
    out.extend_from_slice(STEG_MAGIC);
    fs::write(output, out)?;
    Ok(())
}

/// Whether a file has a TrezorProtector hidden payload appended.
pub fn has_hidden(container: &Path) -> bool {
    let mut file = match fs::File::open(container) {
        Ok(f) => f,
        Err(_) => return false,
    };
    use std::io::{Seek, SeekFrom};
    if file.seek(SeekFrom::End(-8)).is_err() {
        return false;
    }
    let mut magic = [0u8; 8];
    file.read_exact(&mut magic).is_ok() && &magic == STEG_MAGIC
}

/// Extract the hidden secret from a container. Returns
/// (carrier_bytes, secret_name, secret_bytes).
pub fn extract_hidden(
    master: &SecretKey,
    container: &Path,
) -> Result<(Vec<u8>, String, Zeroizing<Vec<u8>>)> {
    let raw = fs::read(container)?;
    if raw.len() < 16 || &raw[raw.len() - 8..] != STEG_MAGIC {
        return Err(Error::InvalidInput(
            "no hidden TrezorProtector payload in this file".into(),
        ));
    }
    let len_pos = raw.len() - 16;
    let hidden_len = u64::from_be_bytes(raw[len_pos..raw.len() - 8].try_into().unwrap()) as usize;
    if hidden_len < 16 || hidden_len > len_pos {
        return Err(Error::Crypto("corrupt hidden-payload trailer".into()));
    }
    let hidden_start = len_pos - hidden_len;
    let hidden = &raw[hidden_start..len_pos];
    let carrier = raw[..hidden_start].to_vec();

    let file_id: [u8; 16] = hidden[..16].try_into().unwrap();
    let key = file_key(master, &file_id);
    let payload = crypto::decrypt(&key, &hidden[16..], AAD_STEG)
        .map_err(|_| Error::Crypto("wrong device or corrupt hidden payload".into()))?;
    if payload.len() < 2 {
        return Err(Error::Crypto("corrupt hidden payload".into()));
    }
    let name_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    if payload.len() < 2 + name_len {
        return Err(Error::Crypto("corrupt hidden payload".into()));
    }
    let name = safe_basename(&String::from_utf8_lossy(&payload[2..2 + name_len]));
    let secret = Zeroizing::new(payload[2 + name_len..].to_vec());
    Ok((carrier, name, secret))
}

// ---------------------------------------------------------------------------
// Secure delete
// ---------------------------------------------------------------------------

/// Overwrite a file with random data, then zeros, then remove it.
///
/// Note: on SSDs and copy-on-write filesystems the physical blocks may
/// survive due to wear-levelling — full-disk encryption is the only real
/// guarantee. This still raises the bar considerably on plain HDD/NTFS.
pub fn shred(path: &Path, passes: u32) -> Result<()> {
    let len = fs::metadata(path)?.len();
    {
        let mut fh = fs::OpenOptions::new().write(true).open(path)?;
        let mut buf = vec![0u8; 64 * 1024];
        for pass in 0..passes.max(1) + 1 {
            use std::io::{Seek, SeekFrom};
            fh.seek(SeekFrom::Start(0))?;
            let zero_pass = pass == passes.max(1); // final pass writes zeros
            let mut remaining = len;
            while remaining > 0 {
                let n = remaining.min(buf.len() as u64) as usize;
                if zero_pass {
                    buf[..n].fill(0);
                } else {
                    rand::rngs::OsRng.fill_bytes(&mut buf[..n]);
                }
                fh.write_all(&buf[..n])?;
                remaining -= n as u64;
            }
            fh.sync_all()?;
        }
    }
    fs::remove_file(path)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// IO helpers
// ---------------------------------------------------------------------------

fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = reader.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

fn read_len_prefixed<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    try_read_len_prefixed(reader)?
        .ok_or_else(|| Error::Crypto("unexpected end of encrypted file".into()))
}

fn try_read_len_prefixed<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    let mut len_bytes = [0u8; 4];
    match reader.read_exact(&mut len_bytes) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > CHUNK_SIZE + 1024 {
        return Err(Error::Crypto("implausible chunk length — corrupt file".into()));
    }
    let mut blob = vec![0u8; len];
    reader.read_exact(&mut blob)?;
    Ok(Some(blob))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("tpfiles-test-{}", crate::util::new_id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn roundtrip_small() {
        let dir = tmpdir();
        let src = dir.join("hello.txt");
        fs::write(&src, b"hello world").unwrap();
        let master = SecretKey::generate();

        let enc = encrypt_file(&master, &src, None).unwrap();
        assert!(enc.to_string_lossy().ends_with(".tpenc"));
        fs::remove_file(&src).unwrap();

        let (out, name) = decrypt_file(&master, &enc, None).unwrap();
        assert_eq!(name, "hello.txt");
        assert_eq!(fs::read(out).unwrap(), b"hello world");
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn roundtrip_multi_chunk() {
        let dir = tmpdir();
        let src = dir.join("big.bin");
        let data: Vec<u8> = (0..(2 * CHUNK_SIZE + 12345)).map(|i| (i % 251) as u8).collect();
        fs::write(&src, &data).unwrap();
        let master = SecretKey::generate();

        let enc = encrypt_file(&master, &src, None).unwrap();
        let (plain, _) = read_encrypted(&master, &enc).unwrap();
        assert_eq!(&plain[..], &data[..]);
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn truncation_detected() {
        let dir = tmpdir();
        let src = dir.join("doc.txt");
        let data: Vec<u8> = (0..(CHUNK_SIZE + 5000)).map(|i| (i % 13) as u8).collect();
        fs::write(&src, &data).unwrap();
        let master = SecretKey::generate();
        let enc = encrypt_file(&master, &src, None).unwrap();

        // Cut off the final chunk.
        let raw = fs::read(&enc).unwrap();
        let cut = dir.join("cut.tpenc");
        fs::write(&cut, &raw[..raw.len() - 100]).unwrap();
        assert!(read_encrypted(&master, &cut).is_err());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn wrong_key_rejected() {
        let dir = tmpdir();
        let src = dir.join("f.txt");
        fs::write(&src, b"secret").unwrap();
        let enc = encrypt_file(&SecretKey::generate(), &src, None).unwrap();
        assert!(read_encrypted(&SecretKey::generate(), &enc).is_err());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn traversal_names_sanitized() {
        assert_eq!(safe_basename("../../etc/passwd"), "passwd");
        assert_eq!(safe_basename("..\\..\\evil.exe"), "evil.exe");
        assert_eq!(safe_basename(".."), "restored.bin");
        assert_eq!(safe_basename(""), "restored.bin");
    }

    #[test]
    fn stego_roundtrip_and_carrier_intact() {
        let dir = tmpdir();
        let carrier = dir.join("photo.jpg");
        let carrier_data = b"\xff\xd8\xff\xe0 pretend JPEG bytes \xff\xd9".to_vec();
        fs::write(&carrier, &carrier_data).unwrap();
        let secret = dir.join("plan.txt");
        fs::write(&secret, b"the hidden plan").unwrap();

        let master = SecretKey::generate();
        let container = dir.join("out.jpg");
        embed_hidden(&master, &carrier, &secret, &container).unwrap();

        // Container still starts with the carrier bytes (opens as a JPEG).
        let container_bytes = fs::read(&container).unwrap();
        assert!(container_bytes.starts_with(&carrier_data));
        assert!(has_hidden(&container));
        assert!(!has_hidden(&carrier));

        let (recovered_carrier, name, secret_bytes) =
            extract_hidden(&master, &container).unwrap();
        assert_eq!(recovered_carrier, carrier_data);
        assert_eq!(name, "plan.txt");
        assert_eq!(&secret_bytes[..], b"the hidden plan");

        // Wrong device can't extract.
        assert!(extract_hidden(&SecretKey::generate(), &container).is_err());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn shred_removes_file() {
        let dir = tmpdir();
        let f = dir.join("gone.txt");
        fs::write(&f, b"sensitive").unwrap();
        shred(&f, 2).unwrap();
        assert!(!f.exists());
        fs::remove_dir_all(dir).ok();
    }
}
