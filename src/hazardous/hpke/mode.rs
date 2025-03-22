// MIT License

// Copyright (c) 2025 The orion Developers

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use crate::errors::UnknownCryptoError;

#[repr(u8)]
/// HPKE modes.
pub enum HpkeMode {
    /// Base mode.
    Base = 0x00u8,
    /// PSK mode.
    Psk = 0x01u8,
    /// Auth mode.
    Auth = 0x02u8,
    /// Auth+PSK mode.
    AuthPsk = 0x03u8,
}

impl TryFrom<u8> for HpkeMode {
    type Error = UnknownCryptoError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Base),
            0x01 => Ok(Self::Psk),
            0x02 => Ok(Self::Auth),
            0x03 => Ok(Self::AuthPsk),
            _ => Err(UnknownCryptoError),
        }
    }
}

impl HpkeMode {
    pub(crate) fn verify_psk_inputs(
        &self,
        psk: &[u8],
        psk_id: &[u8],
    ) -> Result<(), UnknownCryptoError> {
        match *self {
            HpkeMode::Base | HpkeMode::Auth => {
                // "default" is just empty string
                match (psk.is_empty(), psk_id.is_empty()) {
                    (true, true) => Ok(()),
                    (_, _) => Err(UnknownCryptoError), // not PSK or AuthPSK mode
                }
            }
            HpkeMode::Psk | HpkeMode::AuthPsk => {
                // "default" is just empty string
                match (psk.is_empty(), psk_id.is_empty()) {
                    (false, false) => Ok(()),          // require consistent input if provided
                    (_, _) => Err(UnknownCryptoError), // not PSK or AuthPSK mode
                }
            }
        }
    }

    /// Returns the `mode_id` for this HPKE mode.
    pub fn mode_id(&self) -> u8 {
        match self {
            Self::Base => 0x00u8,
            Self::Psk => 0x01u8,
            Self::Auth => 0x02u8,
            Self::AuthPsk => 0x03u8,
        }
    }
}
