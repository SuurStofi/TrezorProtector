//! Trezor device access via the official `trezor-client` crate.
//!
//! The vault master key is wrapped with the device's CipherKeyValue
//! operation on the SLIP-0016 path m/10016'/0'. The key string and flags
//! are identical to the Python v1 implementation, so a vault created there
//! unwraps with the same physical device here.
//!
//! Every wrap/unwrap requires an explicit button confirmation on the device
//! (`ask_on_encrypt` / `ask_on_decrypt` are both set), so malware that grabs
//! the vault file cannot silently ask the device for the master key.

use trezor_client::client::common::TrezorResponse;
use trezor_client::client::Trezor;
use trezor_client::protos;

use crate::crypto::SecretKey;
use crate::error::{Error, Result};

/// SLIP-0016 style path m/10016'/0'
const DERIVATION_PATH: [u32; 2] = [10016 | 0x8000_0000, 0x8000_0000];
/// Must stay in sync with the Python v1 app key — it is mixed into the
/// CipherKeyValue derivation, so changing it changes the wrapping key.
const APP_KEY: &str = "TrezorProtector";

/// How the caller answers device interaction requests.
///
/// The CLI prompts on the terminal; the native-messaging host relays the
/// request to the extension popup.
pub trait Interaction {
    /// A PIN matrix is displayed on the device; return the *positions* the
    /// user selected (digits 1-9 as shown on the classic scrambled grid).
    fn pin(&mut self) -> Result<String>;
    /// A passphrase was requested. Return `None` to enter it on the device
    /// itself (always preferred — the host machine never sees it).
    fn passphrase(&mut self) -> Result<Option<String>>;
    /// The device is waiting for a physical button press.
    fn notify_button(&mut self);
}

pub struct DeviceInfo {
    pub model: String,
    pub label: String,
    pub firmware: String,
    pub initialized: bool,
}

pub struct TrezorManager {
    client: Trezor,
}

impl TrezorManager {
    /// Connect to the first available Trezor device.
    pub fn connect() -> Result<Self> {
        let devices = trezor_client::find_devices(false);
        let device = devices.into_iter().next().ok_or_else(|| {
            Error::Trezor(
                "no Trezor device found — plug it in and make sure the WinUSB \
                 driver (installed with Trezor Suite) is present"
                    .into(),
            )
        })?;
        let mut client = device
            .connect()
            .map_err(|e| Error::Trezor(format!("cannot open device: {e}")))?;
        client
            .init_device(None)
            .map_err(|e| Error::Trezor(format!("device initialization failed: {e}")))?;
        Ok(Self { client })
    }

    pub fn info(&self) -> Result<DeviceInfo> {
        let f = self
            .client
            .features()
            .ok_or_else(|| Error::Trezor("device features unavailable".into()))?;
        // The firmware reports terse model codes ("1", "T", "T2B1", …).
        let model = match f.model() {
            "" => "Trezor".to_string(),
            "1" => "Trezor One".to_string(),
            "T" => "Trezor Model T".to_string(),
            "T2B1" | "Safe 3" => "Trezor Safe 3".to_string(),
            "T3T1" | "Safe 5" => "Trezor Safe 5".to_string(),
            other => format!("Trezor {other}"),
        };
        Ok(DeviceInfo {
            model,
            label: if f.label().is_empty() { "(no label)".into() } else { f.label().into() },
            firmware: format!(
                "{}.{}.{}",
                f.major_version(),
                f.minor_version(),
                f.patch_version()
            ),
            initialized: f.initialized(),
        })
    }

    /// Wrap a 32-byte master key on the device. The result is safe to store
    /// on disk: it can only be unwrapped by the same seed + passphrase.
    pub fn encrypt_master_key(
        &mut self,
        raw_key: &SecretKey,
        interaction: &mut dyn Interaction,
    ) -> Result<Vec<u8>> {
        self.cipher_key_value(raw_key.as_bytes().to_vec(), true, interaction)
    }

    /// Unwrap a previously wrapped master key.
    pub fn decrypt_master_key(
        &mut self,
        wrapped: &[u8],
        interaction: &mut dyn Interaction,
    ) -> Result<SecretKey> {
        if wrapped.len() != 32 {
            return Err(Error::Trezor("wrapped master key must be 32 bytes".into()));
        }
        let mut value = self.cipher_key_value(wrapped.to_vec(), false, interaction)?;
        let key = SecretKey::from_slice(&value)?;
        // Wipe the intermediate buffer.
        value.iter_mut().for_each(|b| *b = 0);
        Ok(key)
    }

    fn cipher_key_value(
        &mut self,
        value: Vec<u8>,
        encrypt: bool,
        interaction: &mut dyn Interaction,
    ) -> Result<Vec<u8>> {
        let mut req = protos::CipherKeyValue::new();
        req.address_n = DERIVATION_PATH.to_vec();
        req.set_key(APP_KEY.to_owned());
        req.set_value(value);
        req.set_encrypt(encrypt);
        req.set_ask_on_encrypt(true);
        req.set_ask_on_decrypt(true);

        let resp: TrezorResponse<'_, protos::CipheredKeyValue, protos::CipheredKeyValue> = self
            .client
            .call(req, Box::new(|_, m| Ok(m)))
            .map_err(|e| Error::Trezor(format!("CipherKeyValue failed: {e}")))?;

        let result = drive(resp, interaction)?;
        Ok(result.value().to_vec())
    }
}

/// Drive a device interaction to completion, answering PIN / passphrase /
/// button requests through the supplied handler.
fn drive<'a, T, R: trezor_client::TrezorMessage>(
    mut resp: TrezorResponse<'a, T, R>,
    interaction: &mut dyn Interaction,
) -> Result<T> {
    loop {
        resp = match resp {
            TrezorResponse::Ok(value) => return Ok(value),
            TrezorResponse::Failure(f) => {
                return Err(Error::Trezor(format!(
                    "device refused: {}",
                    f.message()
                )));
            }
            TrezorResponse::ButtonRequest(req) => {
                interaction.notify_button();
                req.ack()
                    .map_err(|e| Error::Trezor(format!("button ack failed: {e}")))?
            }
            TrezorResponse::PinMatrixRequest(req) => {
                let pin = interaction.pin()?;
                if !pin.chars().all(|c| ('1'..='9').contains(&c)) || pin.is_empty() {
                    return Err(Error::InvalidInput(
                        "PIN must be 1-9 matrix positions".into(),
                    ));
                }
                req.ack_pin(pin)
                    .map_err(|e| Error::Trezor(format!("PIN rejected: {e}")))?
            }
            TrezorResponse::PassphraseRequest(req) => match interaction.passphrase()? {
                Some(phrase) => req
                    .ack_passphrase(phrase)
                    .map_err(|e| Error::Trezor(format!("passphrase failed: {e}")))?,
                None => req
                    .ack(true)
                    .map_err(|e| Error::Trezor(format!("passphrase failed: {e}")))?,
            },
        };
    }
}
