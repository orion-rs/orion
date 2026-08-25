// MIT License

// Copyright (c) 2026 The orion Developers

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
use crate::generics::sealed::Sealed;
use crate::hazardous::hash::sha2::sha256::SHA256_OUTSIZE;
use crate::hazardous::hash::sha3::shake256::Shake256;
use crate::hazardous::hpke::kem::{VERSION_ID, length_prefix};
use crate::hazardous::hpke::mode::private::HpkeMode;
use crate::hazardous::hpke::suite::private::HpkeKdf;
use crate::hazardous::kdf::hkdf::{Hkdf, SHA256};

impl Sealed for Hkdf<SHA256> {}

impl HpkeKdf for Hkdf<SHA256> {
    const KDF_ID: [u8; 2] = 0x0001u16.to_be_bytes();
    const NH: usize = SHA256_OUTSIZE;

    type ExporterSecret = [u8; SHA256_OUTSIZE];
    const EXPORTER_SECRET_INIT: Self::ExporterSecret = [0u8; SHA256_OUTSIZE];

    /// <https://datatracker.ietf.org/doc/html/rfc9180>
    fn combine_secrets(
        suite_id: &[u8; 10],
        mode: &HpkeMode,
        shared_secret: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        nk: usize,
        nn: usize,
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        debug_assert_eq!(out.len(), nk + nn + Self::NH);

        // key_schedule_context: [ mode || psk_id_hash || info_hash ]
        let mut key_schedule_context = zeroize_wrap!([0u8; { (SHA256_OUTSIZE * 2) + 1 }]);
        key_schedule_context[0] = mode.mode_id();
        Self::hpke_labeled_extract(
            VERSION_ID,
            suite_id,
            b"",
            b"psk_id_hash",
            psk_id,
            &mut key_schedule_context[1..1 + SHA256_OUTSIZE],
        )?;
        Self::hpke_labeled_extract(
            VERSION_ID,
            suite_id,
            b"",
            b"info_hash",
            info,
            &mut key_schedule_context[1 + SHA256_OUTSIZE..],
        )?;

        let mut secret = zeroize_wrap!([0u8; SHA256_OUTSIZE]);
        Self::hpke_labeled_extract(
            VERSION_ID,
            suite_id,
            shared_secret,
            b"secret",
            psk,
            secret.as_mut(),
        )?;

        let (key, rest) = out.split_at_mut(nk);
        let (base_nonce, exporter_secret) = rest.split_at_mut(nn);

        Self::hpke_labeled_expand(
            VERSION_ID,
            suite_id,
            secret.as_ref(),
            b"key",
            key_schedule_context.as_ref(),
            key,
        )?;
        Self::hpke_labeled_expand(
            VERSION_ID,
            suite_id,
            secret.as_ref(),
            b"base_nonce",
            key_schedule_context.as_ref(),
            base_nonce,
        )?;
        Self::hpke_labeled_expand(
            VERSION_ID,
            suite_id,
            secret.as_ref(),
            b"exp",
            key_schedule_context.as_ref(),
            exporter_secret,
        )
    }

    /// <https://datatracker.ietf.org/doc/html/rfc9180#name-secret-export-2>.
    fn export(
        suite_id: &[u8; 10],
        exporter_secret: &[u8],
        exporter_context: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        Self::hpke_labeled_expand(
            VERSION_ID,
            suite_id,
            exporter_secret,
            b"sec",
            exporter_context,
            out,
        )
    }
}

impl Sealed for Shake256 {}

impl HpkeKdf for Shake256 {
    const KDF_ID: [u8; 2] = 0x0011u16.to_be_bytes();
    const NH: usize = 64;

    type ExporterSecret = [u8; 64];
    const EXPORTER_SECRET_INIT: Self::ExporterSecret = [0u8; 64];

    /// `CombineSecrets_OneStage()` one-stage KDF:
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-04#section-5.1>.
    fn combine_secrets(
        suite_id: &[u8; 10],
        mode: &HpkeMode,
        shared_secret: &[u8],
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
        nk: usize,
        nn: usize,
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        debug_assert_eq!(out.len(), nk + nn + Self::NH);

        // secrets: lengthPrefixed(psk) || lengthPrefixed(shared_secret)
        let psk_len = length_prefix(psk)?;
        let shared_secret_len = length_prefix(shared_secret)?;
        let secrets: [&[u8]; 4] = [&psk_len, psk, &shared_secret_len, shared_secret];

        // context: mode || lengthPrefixed(psk_id) || lengthPrefixed(info)
        let mode_id = [mode.mode_id()];
        let psk_id_len = length_prefix(psk_id)?;
        let info_len = length_prefix(info)?;
        let context: [&[u8]; 5] = [&mode_id, &psk_id_len, psk_id, &info_len, info];

        Self::hpke_labeled_derive(VERSION_ID, suite_id, &secrets, b"secret", &context, out)
    }

    /// `Context.Export_OneStage()` one-stage KDF:
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-04#section-5.3>.
    fn export(
        suite_id: &[u8; 10],
        exporter_secret: &[u8],
        exporter_context: &[u8],
        out: &mut [u8],
    ) -> Result<(), UnknownCryptoError> {
        Self::hpke_labeled_derive(
            VERSION_ID,
            suite_id,
            &[exporter_secret],
            b"sec",
            &[exporter_context],
            out,
        )
    }
}
