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

use core::fmt::Debug;
use core::marker::PhantomData;
use core::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};
use core::ops::{Index, IndexMut};

use subtle::{Choice, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use crate::errors::UnknownCryptoError;
use crate::hazardous::dsa::ml_dsa::internal::MlDsaParameters;

pub(crate) const DILITHIUM_Q: u32 = 8380417;

/// -q^(-1) % 2^(32)
pub(crate) const QNEGINV: u32 = 4236238847;

/// `256^{1} \cdot R^{2} mod q`
pub(crate) const INV_R2: MontSquareFactor = MontSquareFactor(41978);

#[cfg(test)]
#[cfg(feature = "safe_api")] // NOTE: Used for randomized tests only.
/// `256^{1} \cdot R mod q`
pub(crate) const INV: MontFactor = MontFactor(16382);

// Constant-time conditional subtraction
pub(crate) const fn conditional_sub_u32(a: u32) -> u32 {
    // Calculate a - mod
    let t: u32 = a.overflowing_sub(DILITHIUM_Q).0;

    // Check if a >= mod (if t is non-negative)
    // If a >= mod, mask will be 0xFFFFFFFF, otherwise 0
    let mask: u32 = 0u32.overflowing_sub(t >> 31).0;

    // If mask is 0, return a (no subtraction), otherwise return t (a - mod)
    (t & !mask) | (a & mask)
}

const fn montgomery_reduce(value: u64) -> u32 {
    // cast to u32 and wrapping_mul to use lower 32 bits
    let t: u32 = (value as u32).wrapping_mul(QNEGINV);
    let r: u32 = (value
        .overflowing_add((t as u64).overflowing_mul(DILITHIUM_Q as u64).0)
        .0
        >> 32) as u32;

    conditional_sub_u32(r)
}

mod sealed {
    pub trait Sealed {}
}

pub trait Domain: sealed::Sealed + Copy + Debug + PartialEq + Eq {}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
/// Marker for field elements in Z_q _not_ in Montgomery form.
pub struct Standard;
impl sealed::Sealed for Standard {}
impl Domain for Standard {}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
/// Marker for field elements produced by scaling in Montgomery multiplication.
pub struct RInv;
impl sealed::Sealed for RInv {}
impl Domain for RInv {}

#[derive(Clone, Copy, PartialEq, Debug)]
/// Montgomery factor.
pub struct MontFactor(pub(crate) u32);

impl MontFactor {
    pub(crate) const fn from_spec(n: u32) -> Self {
        debug_assert!(n < DILITHIUM_Q);
        Self(n)
    }
}

impl<D: Domain> Mul<FieldElement<D>> for MontFactor {
    type Output = FieldElement<D>;

    fn mul(self, rhs: FieldElement<D>) -> Self::Output {
        FieldElement::<D>(montgomery_reduce(self.0 as u64 * rhs.0 as u64), PhantomData)
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
/// Montgomery square factor.
pub struct MontSquareFactor(pub(crate) u32);

impl MontSquareFactor {
    pub(crate) const fn apply(self, rhs: FieldElement<RInv>) -> FieldElement<Standard> {
        FieldElement::<Standard>::new(montgomery_reduce(self.0 as u64 * rhs.0 as u64))
    }
}

const fn mont_factor_tables(spec: &[u32; 256]) -> [MontFactor; 256] {
    let mut mont_spec = [MontFactor::from_spec(0); 256];
    let mut idx = 0;
    while idx < 256 {
        // NOTE(brycx): for or iter not in const
        mont_spec[idx] = MontFactor::from_spec(spec[idx]);
        idx += 1;
    }

    mont_spec
}

pub const ZETA_ALL_MONT: [MontFactor; 256] = mont_factor_tables(&ZETA_ALL_SPEC);
pub const NEG_ZETA_ALL_MONT: [MontFactor; 256] = mont_factor_tables(&NEG_ZETA_ALL_SPEC);

#[derive(Clone, Copy, PartialEq, Debug)]
/// Element in the field Z_q.
pub struct FieldElement<D: Domain>(pub(crate) u32, PhantomData<D>);

#[cfg(feature = "zeroize")]
impl<D: Domain> Zeroize for FieldElement<D> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Specific routines for non-Montgomery domain field elements.
impl FieldElement<Standard> {
    pub(crate) const fn new(n: u32) -> Self {
        debug_assert!(n < DILITHIUM_Q);
        Self(n, PhantomData)
    }

    pub(crate) const fn power2round<P: MlDsaParameters>(&self) -> (u32, u32) {
        debug_assert!(self.0 < DILITHIUM_Q);
        let r1 = (self.0.overflowing_add((1 << (P::D - 1)) - 1).0) >> P::D;
        let r0 = self.0.overflowing_add(DILITHIUM_Q - (r1 << P::D)).0;

        (r1, conditional_sub_u32(r0))
    }

    pub(crate) fn is_outside_bound(&self, bound: u32) -> Choice {
        debug_assert!(self.0 < DILITHIUM_Q);
        debug_assert!(bound < u32::MAX / 2); // required for panic-free 2*bound-1 range window.

        // SECURITY: `bound` is public, so we do vartime branch here.
        if (bound == 0) | (bound > (DILITHIUM_Q - 1) / 8) {
            return Choice::from(1u8);
        }

        // "For an element w ∈ Z ±  q,‖w‖ = ∣w mod q∣"
        // FIPS-204, p. 6.
        let range = 2 * bound - 1;
        !conditional_sub_u32(self.0 + bound - 1).ct_lt(&range)
    }

    /// FIPS-204, Algorithm 36.
    /// Returns (r1, r0) with r = r1*2γ2 + r0 (mod q)
    pub(crate) fn decompose<P: MlDsaParameters>(&self) -> (u32, u32) {
        debug_assert!(self.0 < DILITHIUM_Q);
        // 2γ2
        let two_gamma2 = 2 * P::GAMMA_2;

        let mut r1 = (self.0 * P::DECOMPOSE_BARRETT_M) >> P::DECOMPOSE_BARRETT_SHIFT;
        let mut rem = self.0 - r1 * two_gamma2;
        debug_assert!((0..2 * two_gamma2).contains(&rem));

        let c = (rem.wrapping_sub(two_gamma2) >> 31) ^ 1;
        r1 += c;
        rem -= c * two_gamma2;
        debug_assert!((0..two_gamma2).contains(&rem));
        r1 += (rem.wrapping_sub(P::GAMMA_2 + 1) >> 31) ^ 1;

        let mask = 0u32.wrapping_sub(P::DECOMPOSE_W1_MAX.wrapping_sub(r1) >> 31);
        r1 &= !mask;

        let r0 = conditional_sub_u32(self.0 + DILITHIUM_Q - r1 * two_gamma2);

        (r1, r0)
    }

    /// FIPS-204, Algorithm 37.
    pub(crate) fn high_bits<P: MlDsaParameters>(&self) -> u32 {
        self.decompose::<P>().0
    }

    /// FIPS-204, Algorithm 39.
    pub(crate) fn make_hint<P: MlDsaParameters>(&self, z: &Self) -> Choice {
        let hibits_clean = self.high_bits::<P>();
        let hibits_add = (*self + z).high_bits::<P>();

        hibits_clean.ct_ne(&hibits_add)
    }

    /// FIPS-204, Algorithm 40.
    pub(crate) fn use_hint<P: MlDsaParameters>(&self, hint: u32) -> u32 {
        debug_assert!(hint == 0 || hint == 1); // hint is bit

        let (r1, r0) = self.decompose::<P>();
        let is_positive = !r0.ct_lt(&1) & !r0.ct_gt(&P::GAMMA_2);
        // r1 + 1 mod m with m W1_MAX_VALUE + 1
        let u = r1 + 1;
        let u = u & !0u32.wrapping_sub(P::W1_MAX_VALUE.wrapping_sub(u) >> 31);
        // r1 - 1 mod m
        let d = r1.wrapping_sub(1);
        let mask = 0u32.wrapping_sub(d >> 31);
        let d = (d & !mask) | (P::W1_MAX_VALUE & mask);

        let positive_mask = 0u32.wrapping_sub(u32::from(is_positive.unwrap_u8()));
        let adjust = (u & positive_mask) | (d & !positive_mask);
        let hint = 0u32.wrapping_sub(hint);

        (adjust & hint) | (r1 & !hint)
    }

    pub(crate) fn bitpack_gamma1_offset<P: MlDsaParameters>(&self) -> u32 {
        debug_assert!(self.0 < DILITHIUM_Q);
        let t = conditional_sub_u32(P::GAMMA_1 + DILITHIUM_Q - self.0);
        debug_assert!(t < 2 * P::GAMMA_1); // ||z||infinity norm bound on gamma1

        t
    }
}

impl<D: Domain> FieldElement<D> {
    pub(crate) const fn zero() -> Self {
        Self(0, PhantomData)
    }

    #[cfg(test)]
    pub(crate) const fn from_raw_u32(n: u32) -> Self {
        Self(n, PhantomData)
    }
}

impl<D: Domain> Add<&Self> for FieldElement<D> {
    type Output = Self;

    fn add(mut self, other: &Self) -> Self {
        self += other;

        self
    }
}

impl<D: Domain> AddAssign<&Self> for FieldElement<D> {
    fn add_assign(&mut self, rhs: &Self) {
        self.0 = conditional_sub_u32(self.0 + rhs.0)
    }
}

impl<D: Domain> Sub<&Self> for FieldElement<D> {
    type Output = Self;

    fn sub(mut self, other: &Self) -> Self {
        self -= other;

        self
    }
}

impl<D: Domain> SubAssign<&Self> for FieldElement<D> {
    fn sub_assign(&mut self, rhs: &Self) {
        self.0 = conditional_sub_u32(self.0.wrapping_sub(rhs.0).wrapping_add(DILITHIUM_Q));
    }
}

// Montgomery mulitplication thus output is in `RInv`.
impl Mul for FieldElement<Standard> {
    type Output = FieldElement<RInv>;

    fn mul(self, other: Self) -> Self::Output {
        FieldElement::<RInv>(
            montgomery_reduce(self.0 as u64 * other.0 as u64),
            PhantomData,
        )
    }
}

impl Neg for FieldElement<Standard> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(conditional_sub_u32(DILITHIUM_Q - self.0), PhantomData)
    }
}

#[derive(PartialEq, Debug, Clone, Copy)]
/// Element in R_q.
///
/// Ring elements are the same as polynomials, which are the same as vectors
/// of coefficients.
///
/// Adding and subtracting polynomials works the same way in NTT and NTT^{-1},
/// it is however illegal to operate on two polynomials from different domains
/// at the same time.
pub struct RingElement {
    pub coefficients: [FieldElement<Standard>; 256],
}

#[cfg(feature = "zeroize")]
impl Zeroize for RingElement {
    fn zeroize(&mut self) {
        self.coefficients.iter_mut().zeroize();
    }
}

impl RingElement {
    pub fn zero() -> Self {
        Self {
            coefficients: [FieldElement::zero(); 256],
        }
    }

    pub(crate) fn into_ntt(mut self) -> RingElementNTT<Standard> {
        to_ntt(&mut self.coefficients);
        RingElementNTT {
            coefficients: self.coefficients,
        }
    }

    pub(crate) fn is_outside_bound(&self, bound: u32) -> Choice {
        let mut ret = Choice::from(0u8);
        for coeff in self.coefficients {
            ret |= coeff.is_outside_bound(bound);
        }

        ret
    }

    /// FIPS-204, Algorithm 36 (component-wise form sec. 7.4)
    pub(crate) fn decompose<P: MlDsaParameters>(&self) -> (Self, Self) {
        let mut w1 = Self::zero();
        let mut w0 = Self::zero();
        for idx in 0..256 {
            let (r1, r0) = self[idx].decompose::<P>();
            w1[idx] = FieldElement::new(r1);
            w0[idx] = FieldElement::new(r0);
        }

        (w1, w0)
    }

    #[cfg(all(test, feature = "safe_api"))]
    pub(crate) fn random_element() -> Self {
        use rand::{prelude::*, rng};

        let mut rng = rng();
        let mut coefficients = [FieldElement::zero(); 256];

        for rand_coeff in coefficients.iter_mut() {
            let new = rng.random_range(0..DILITHIUM_Q);
            *rand_coeff = FieldElement::new(new);
        }

        Self { coefficients }
    }
}

impl Add<&Self> for RingElement {
    type Output = Self;

    fn add(mut self, rhs: &Self) -> Self::Output {
        self += rhs;

        self
    }
}

impl AddAssign<&Self> for RingElement {
    fn add_assign(&mut self, rhs: &Self) {
        for (coeff_ret, coeff_rhs) in self.coefficients.iter_mut().zip(rhs.coefficients.iter()) {
            *coeff_ret += coeff_rhs;
        }
    }
}

impl Sub<&Self> for RingElement {
    type Output = Self;

    fn sub(mut self, rhs: &Self) -> Self::Output {
        self -= rhs;

        self
    }
}

impl SubAssign<&Self> for RingElement {
    fn sub_assign(&mut self, rhs: &Self) {
        for (coeff_ret, coeff_rhs) in self.coefficients.iter_mut().zip(rhs.coefficients.iter()) {
            *coeff_ret -= coeff_rhs;
        }
    }
}

impl Index<usize> for RingElement {
    type Output = FieldElement<Standard>;

    fn index(&self, index: usize) -> &Self::Output {
        debug_assert!(index <= 255);

        &self.coefficients[index]
    }
}

impl IndexMut<usize> for RingElement {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        debug_assert!(index <= 255);
        &mut self.coefficients[index]
    }
}

#[derive(PartialEq, Debug, Clone, Copy)]
/// Element in T_q.
pub struct RingElementNTT<D: Domain> {
    pub coefficients: [FieldElement<D>; 256],
}

#[cfg(feature = "zeroize")]
impl<D: Domain> Zeroize for RingElementNTT<D> {
    fn zeroize(&mut self) {
        self.coefficients.iter_mut().zeroize();
    }
}

impl<D: Domain> RingElementNTT<D> {
    pub fn zero() -> Self {
        Self {
            coefficients: [FieldElement::zero(); 256],
        }
    }
}

impl RingElementNTT<RInv> {
    pub(crate) fn inverse_ntt_mont(mut self) -> RingElement {
        inverse_ntt(&mut self.coefficients);

        RingElement {
            coefficients: core::array::from_fn(|rinv_elem| {
                INV_R2.apply(self.coefficients[rinv_elem])
            }),
        }
    }
}

#[cfg(test)]
#[cfg(feature = "safe_api")] // NOTE: Used for randomized tests only.
impl RingElementNTT<Standard> {
    pub(crate) fn inverse_ntt(mut self) -> RingElement {
        inverse_ntt(&mut self.coefficients);
        for coeff in self.coefficients.iter_mut() {
            *coeff = INV * *coeff;
        }

        RingElement {
            coefficients: self.coefficients,
        }
    }
}

// FIPS-204, Algorithm 44.
impl<D: Domain> Add<&Self> for RingElementNTT<D> {
    type Output = Self;

    fn add(mut self, rhs: &Self) -> Self::Output {
        self += rhs;

        self
    }
}

// FIPS-204, Algorithm 44.
impl<D: Domain> AddAssign<&Self> for RingElementNTT<D> {
    fn add_assign(&mut self, rhs: &Self) {
        for (coeff_ret, coeff_rhs) in self.coefficients.iter_mut().zip(rhs.coefficients.iter()) {
            *coeff_ret += coeff_rhs;
        }
    }
}

impl<D: Domain> Sub<&Self> for RingElementNTT<D> {
    type Output = Self;

    fn sub(mut self, rhs: &Self) -> Self::Output {
        self -= rhs;

        self
    }
}

impl<D: Domain> SubAssign<&Self> for RingElementNTT<D> {
    fn sub_assign(&mut self, rhs: &Self) {
        for (coeff_ret, coeff_rhs) in self.coefficients.iter_mut().zip(rhs.coefficients.iter()) {
            *coeff_ret -= coeff_rhs;
        }
    }
}

// FIPS-204, Algorithm 45.
impl Mul for RingElementNTT<Standard> {
    type Output = RingElementNTT<RInv>;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut coefficients = RingElementNTT::<RInv>::zero();
        for idx in 0..256 {
            coefficients[idx] = self[idx] * rhs[idx];
        }

        coefficients
    }
}

impl<const N: usize> Mul<&VectorNTT<N, Standard>> for &RingElementNTT<Standard> {
    type Output = VectorNTT<N, RInv>;
    /// FIPS-204, Algorithm 47.
    fn mul(self, rhs: &VectorNTT<N, Standard>) -> Self::Output {
        let mut out = VectorNTT::<N, RInv>::zero();
        for i in 0..N {
            out[i] = *self * rhs[i];
        }
        out
    }
}

impl<D: Domain> Index<usize> for RingElementNTT<D> {
    type Output = FieldElement<D>;

    fn index(&self, index: usize) -> &Self::Output {
        debug_assert!(index <= 255);
        &self.coefficients[index]
    }
}

impl<D: Domain> IndexMut<usize> for RingElementNTT<D> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        debug_assert!(index <= 255);
        &mut self.coefficients[index]
    }
}

#[derive(PartialEq, Debug, Clone, Copy)]
/// Vector of ring elements/polynomials in T_q.
pub struct Vector<const N: usize> {
    pub elems: [RingElement; N],
}

#[cfg(feature = "zeroize")]
impl<const N: usize> Zeroize for Vector<N> {
    fn zeroize(&mut self) {
        self.elems.iter_mut().zeroize();
    }
}

impl<const N: usize> Vector<N> {
    pub fn zero() -> Self {
        Self {
            elems: [RingElement::zero(); N],
        }
    }

    pub fn ntt(mut self) -> VectorNTT<N, Standard> {
        for elem in self.elems.iter_mut() {
            to_ntt(&mut elem.coefficients);
        }

        VectorNTT {
            elems: self.elems.map(|elem| RingElementNTT {
                coefficients: elem.coefficients,
            }),
        }
    }

    /// FIPS-204, Algorithm 6.
    /// Component-wise Power2Round returning: (t1, t0)
    pub fn power2round<P: MlDsaParameters>(&self) -> (Vector<N>, Vector<N>) {
        let mut t0 = Self::zero();
        let mut t1 = Self::zero();

        for ringelemidx in 0..N {
            for feelemidx in 0..256 {
                let (r1, r0) = self[ringelemidx][feelemidx].power2round::<P>();
                t0[ringelemidx][feelemidx] = FieldElement::new(r0);
                t1[ringelemidx][feelemidx] = FieldElement::new(r1);
            }
        }

        (t1, t0)
    }

    pub(crate) fn is_outside_bound(&self, bound: u32) -> Choice {
        let mut ret = Choice::from(0u8);
        for elem in self.elems.iter() {
            ret |= elem.is_outside_bound(bound);
        }
        ret
    }

    /// FIPS-204, Algorithm 36 (component-wise form sec. 7.4)
    pub(crate) fn decompose<P: MlDsaParameters>(&self) -> (Self, Self) {
        let mut w1 = Self::zero();
        let mut w0 = Self::zero();

        for ((src, hi), lo) in self
            .elems
            .iter()
            .zip(w1.elems.iter_mut())
            .zip(w0.elems.iter_mut())
        {
            let (r1, r0) = src.decompose::<P>();
            *hi = r1;
            *lo = r0;
        }

        (w1, w0)
    }

    /// FIPS-204, Algorithm 37.
    pub(crate) fn high_bits<P: MlDsaParameters>(&self) -> Self {
        self.decompose::<P>().0
    }

    /// FIPS-204, Algorithm 38.
    pub(crate) fn low_bits<P: MlDsaParameters>(&self) -> Self {
        self.decompose::<P>().1
    }

    /// FIPS-204, Algorithm 8. t1 \cdot 2^{d}./
    pub(crate) fn shift_left_d<P: MlDsaParameters>(&self) -> Self {
        let mut ret = Self::zero();
        for (src_re, out) in self.elems.iter().zip(ret.elems.iter_mut()) {
            for i in 0..P::N {
                debug_assert!(src_re[i].0 < 1 << (23 - P::D));
                out[i] = FieldElement::new(src_re[i].0 << P::D);
            }
        }

        ret
    }
}

impl<const N: usize> Add<&Self> for Vector<N> {
    type Output = Self;

    fn add(mut self, rhs: &Self) -> Self::Output {
        self += rhs;

        self
    }
}

impl<const N: usize> AddAssign<&Self> for Vector<N> {
    fn add_assign(&mut self, rhs: &Self) {
        for (elem_ret, elem_rhs) in self.elems.iter_mut().zip(rhs.elems.iter()) {
            *elem_ret += elem_rhs;
        }
    }
}

impl<const N: usize> Sub<&Self> for Vector<N> {
    type Output = Self;

    fn sub(mut self, rhs: &Self) -> Self::Output {
        self -= rhs;

        self
    }
}

impl<const N: usize> SubAssign<&Self> for Vector<N> {
    fn sub_assign(&mut self, rhs: &Self) {
        for (elem_ret, elem_rhs) in self.elems.iter_mut().zip(rhs.elems.iter()) {
            *elem_ret -= elem_rhs;
        }
    }
}

impl<const N: usize> Neg for Vector<N> {
    type Output = Vector<N>;

    fn neg(self) -> Self::Output {
        let mut ret = Vector::<N>::zero();
        for idx in 0..N {
            for c in 0..256 {
                ret[idx][c] = -self[idx][c];
            }
        }

        ret
    }
}

impl<const N: usize> Index<usize> for Vector<N> {
    type Output = RingElement;

    fn index(&self, index: usize) -> &Self::Output {
        debug_assert!(index < N);

        &self.elems[index]
    }
}

impl<const N: usize> IndexMut<usize> for Vector<N> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        debug_assert!(index <= N);
        &mut self.elems[index]
    }
}

#[derive(PartialEq, Debug, Clone, Copy)]
/// Vector of ring elements/polynomials in T_q, in NTT domain.
pub struct VectorNTT<const N: usize, D: Domain> {
    pub elems: [RingElementNTT<D>; N],
}

#[cfg(feature = "zeroize")]
impl<const N: usize, D: Domain> Zeroize for VectorNTT<N, D> {
    fn zeroize(&mut self) {
        self.elems.iter_mut().zeroize();
    }
}

impl<const N: usize> VectorNTT<N, RInv> {
    pub(crate) fn inverse_ntt_mont(self) -> Vector<N> {
        Vector {
            elems: self.elems.map(|elem| elem.inverse_ntt_mont()),
        }
    }
}

impl<const N: usize, D: Domain> VectorNTT<N, D> {
    pub fn zero() -> Self {
        Self {
            elems: [RingElementNTT::zero(); N],
        }
    }
}

impl<const N: usize, D: Domain> Add<&Self> for VectorNTT<N, D> {
    type Output = Self;

    fn add(mut self, rhs: &Self) -> Self::Output {
        self += rhs;

        self
    }
}

impl<const N: usize, D: Domain> AddAssign<&Self> for VectorNTT<N, D> {
    fn add_assign(&mut self, rhs: &Self) {
        for (elem_ret, elem_rhs) in self.elems.iter_mut().zip(rhs.elems.iter()) {
            *elem_ret += elem_rhs;
        }
    }
}

impl<const N: usize, D: Domain> Sub<&Self> for VectorNTT<N, D> {
    type Output = Self;

    fn sub(mut self, rhs: &Self) -> Self::Output {
        self -= rhs;

        self
    }
}

impl<const N: usize, D: Domain> SubAssign<&Self> for VectorNTT<N, D> {
    fn sub_assign(&mut self, rhs: &Self) {
        for (elem_ret, elem_rhs) in self.elems.iter_mut().zip(rhs.elems.iter()) {
            *elem_ret -= elem_rhs;
        }
    }
}

impl<const N: usize, D: Domain> Index<usize> for VectorNTT<N, D> {
    type Output = RingElementNTT<D>;

    fn index(&self, index: usize) -> &Self::Output {
        debug_assert!(index < N);
        &self.elems[index]
    }
}

impl<const N: usize, D: Domain> IndexMut<usize> for VectorNTT<N, D> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        debug_assert!(index < N);
        &mut self.elems[index]
    }
}

#[derive(Clone, PartialEq)]
/// Hint used during signing/verification. Values are only ever [0, 1].
pub struct Hint<const K: usize> {
    pub(crate) bits: [[u8; 256]; K],
}

impl<const K: usize> Drop for Hint<K> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            // SECURITY: This is sensitive value during rejection loop in signing.
            // As soon as rejection passes, this is a public value. Never released
            // outside during signing, so PartialEq is var-time.
            self.bits.iter_mut().zeroize();
        }
    }
}

impl<const K: usize> Debug for Hint<K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // SECURITY: This is sensitive value during rejection loop in signing.
        // As soon as rejection passes, this is a public value. Never released
        // outside during signing, so PartialEq is var-time.
        write!(f, "{} {{***OMITTED***}}", stringify!(Hint))
    }
}

impl<const K: usize> Hint<K> {
    pub fn zero() -> Self {
        Self {
            bits: [[0u8; 256]; K],
        }
    }

    /// FIPS-204, Algorithm 39, component-wise.
    pub fn make<P: MlDsaParameters>(z: &Vector<K>, r: &Vector<K>) -> Self {
        let mut out = Self::zero();
        for i in 0..K {
            for j in 0..256 {
                out.bits[i][j] = r[i][j].make_hint::<P>(&z[i][j]).unwrap_u8();
                debug_assert!(out.bits[i][j] == 0 || out.bits[i][j] == 1);
            }
        }
        out
    }

    /// Number of 1 bits.
    pub fn weight(&self) -> u32 {
        // SECURITY: This does touch secret data but there's no abort
        // and loop-size is constant.
        let mut n = 0u32;
        for poly in self.bits.iter() {
            for &b in poly.iter() {
                n += b as u32;
            }
        }
        n
    }

    pub fn hint_bitpack<P: MlDsaParameters>(&self, out: &mut [u8]) {
        debug_assert_eq!(out.len(), P::OMEGA as usize + K);
        // CORRECTNESS/SECURITY: This method is used during signature encoding
        // and assumes the rejection sampling has finished before this routine is run.
        debug_assert!(self.weight() as usize <= P::OMEGA as usize);

        let mut index = 0usize;

        for i in 0..K {
            for j in 0..256 {
                if self.bits[i][j] != 0 {
                    out[index] = j as u8;
                    index += 1;
                }
            }

            out[P::OMEGA as usize + i] = index as u8;
        }
    }

    pub fn hint_bitunpack<P: MlDsaParameters>(bytes: &[u8]) -> Result<Self, UnknownCryptoError> {
        debug_assert_eq!(bytes.len(), P::OMEGA as usize + K);

        let mut hint = Self::zero();
        let mut index = 0usize;

        for i in 0..K {
            let end = bytes[P::OMEGA as usize + i] as usize;

            if end < index || end > P::OMEGA as usize {
                return Err(UnknownCryptoError);
            }

            let first = index;
            while index < end {
                if index > first && bytes[index - 1] >= bytes[index] {
                    return Err(UnknownCryptoError);
                }

                hint.bits[i][bytes[index] as usize] = 1;
                index += 1;
            }
        }

        if bytes[index..P::OMEGA as usize].iter().any(|x| x != &0) {
            return Err(UnknownCryptoError);
        }

        Ok(hint)
    }

    #[cfg(all(test, feature = "safe_api"))]
    pub(crate) fn random_hint<P: MlDsaParameters>() -> Self {
        use rand::{prelude::*, rng};
        let mut rng = rng();

        // Randomly select a valid mount of total hint weight
        let mut hint = Hint::<K>::zero();
        let weight = rng.random_range(0..=P::OMEGA);
        if weight != 0 {
            debug_assert_ne!(weight, hint.weight());
        }

        let mut set = 0;
        while set < weight {
            let i = rng.random_range(0..P::DIM_K);
            let j = rng.random_range(0..256);

            if hint.bits[i][j] == 0 {
                hint.bits[i][j] = 1;
                set += 1;
            }
        }

        debug_assert_eq!(weight, hint.weight());

        hint
    }
}

impl<const K: usize> Vector<K> {
    /// FIPS-204, Algorithm 40 (component-wise).
    pub fn use_hint<P: MlDsaParameters>(&self, hint: &Hint<K>) -> Self {
        let mut out = Self::zero();
        for i in 0..K {
            for j in 0..256 {
                out[i][j] = FieldElement::new(self[i][j].use_hint::<P>(hint.bits[i][j] as u32));
            }
        }
        out
    }
}

pub(crate) const ZETA_ALL_SPEC: [u32; 256] = [
    4193792, 25847, 5771523, 7861508, 237124, 7602457, 7504169, 466468, 1826347, 2353451, 8021166,
    6288512, 3119733, 5495562, 3111497, 2680103, 2725464, 1024112, 7300517, 3585928, 7830929,
    7260833, 2619752, 6271868, 6262231, 4520680, 6980856, 5102745, 1757237, 8360995, 4010497,
    280005, 2706023, 95776, 3077325, 3530437, 6718724, 4788269, 5842901, 3915439, 4519302, 5336701,
    3574422, 5512770, 3539968, 8079950, 2348700, 7841118, 6681150, 6736599, 3505694, 4558682,
    3507263, 6239768, 6779997, 3699596, 811944, 531354, 954230, 3881043, 3900724, 5823537, 2071892,
    5582638, 4450022, 6851714, 4702672, 5339162, 6927966, 3475950, 2176455, 6795196, 7122806,
    1939314, 4296819, 7380215, 5190273, 5223087, 4747489, 126922, 3412210, 7396998, 2147896,
    2715295, 5412772, 4686924, 7969390, 5903370, 7709315, 7151892, 8357436, 7072248, 7998430,
    1349076, 1852771, 6949987, 5037034, 264944, 508951, 3097992, 44288, 7280319, 904516, 3958618,
    4656075, 8371839, 1653064, 5130689, 2389356, 8169440, 759969, 7063561, 189548, 4827145,
    3159746, 6529015, 5971092, 8202977, 1315589, 1341330, 1285669, 6795489, 7567685, 6940675,
    5361315, 4499357, 4751448, 3839961, 2091667, 3407706, 2316500, 3817976, 5037939, 2244091,
    5933984, 4817955, 266997, 2434439, 7144689, 3513181, 4860065, 4621053, 7183191, 5187039,
    900702, 1859098, 909542, 819034, 495491, 6767243, 8337157, 7857917, 7725090, 5257975, 2031748,
    3207046, 4823422, 7855319, 7611795, 4784579, 342297, 286988, 5942594, 4108315, 3437287,
    5038140, 1735879, 203044, 2842341, 2691481, 5790267, 1265009, 4055324, 1247620, 2486353,
    1595974, 4613401, 1250494, 2635921, 4832145, 5386378, 1869119, 1903435, 7329447, 7047359,
    1237275, 5062207, 6950192, 7929317, 1312455, 3306115, 6417775, 7100756, 1917081, 5834105,
    7005614, 1500165, 777191, 2235880, 3406031, 7838005, 5548557, 6709241, 6533464, 5796124,
    4656147, 594136, 4603424, 6366809, 2432395, 2454455, 8215696, 1957272, 3369112, 185531,
    7173032, 5196991, 162844, 1616392, 3014001, 810149, 1652634, 4686184, 6581310, 5341501,
    3523897, 3866901, 269760, 2213111, 7404533, 1717735, 472078, 7953734, 1723600, 6577327,
    1910376, 6712985, 7276084, 8119771, 4546524, 5441381, 6144432, 7959518, 6094090, 183443,
    7403526, 1612842, 4834730, 7826001, 3919660, 8332111, 7018208, 3937738, 1400424, 7534263,
    1976782,
];

pub(crate) const NEG_ZETA_ALL_SPEC: [u32; 256] = [
    4186625, 8354570, 2608894, 518909, 8143293, 777960, 876248, 7913949, 6554070, 6026966, 359251,
    2091905, 5260684, 2884855, 5268920, 5700314, 5654953, 7356305, 1079900, 4794489, 549488,
    1119584, 5760665, 2108549, 2118186, 3859737, 1399561, 3277672, 6623180, 19422, 4369920,
    8100412, 5674394, 8284641, 5303092, 4849980, 1661693, 3592148, 2537516, 4464978, 3861115,
    3043716, 4805995, 2867647, 4840449, 300467, 6031717, 539299, 1699267, 1643818, 4874723,
    3821735, 4873154, 2140649, 1600420, 4680821, 7568473, 7849063, 7426187, 4499374, 4479693,
    2556880, 6308525, 2797779, 3930395, 1528703, 3677745, 3041255, 1452451, 4904467, 6203962,
    1585221, 1257611, 6441103, 4083598, 1000202, 3190144, 3157330, 3632928, 8253495, 4968207,
    983419, 6232521, 5665122, 2967645, 3693493, 411027, 2477047, 671102, 1228525, 22981, 1308169,
    381987, 7031341, 6527646, 1430430, 3343383, 8115473, 7871466, 5282425, 8336129, 1100098,
    7475901, 4421799, 3724342, 8578, 6727353, 3249728, 5991061, 210977, 7620448, 1316856, 8190869,
    3553272, 5220671, 1851402, 2409325, 177440, 7064828, 7039087, 7094748, 1584928, 812732,
    1439742, 3019102, 3881060, 3628969, 4540456, 6288750, 4972711, 6063917, 4562441, 3342478,
    6136326, 2446433, 3562462, 8113420, 5945978, 1235728, 4867236, 3520352, 3759364, 1197226,
    3193378, 7479715, 6521319, 7470875, 7561383, 7884926, 1613174, 43260, 522500, 655327, 3122442,
    6348669, 5173371, 3556995, 525098, 768622, 3595838, 8038120, 8093429, 2437823, 4272102,
    4943130, 3342277, 6644538, 8177373, 5538076, 5688936, 2590150, 7115408, 4325093, 7132797,
    5894064, 6784443, 3767016, 7129923, 5744496, 3548272, 2994039, 6511298, 6476982, 1050970,
    1333058, 7143142, 3318210, 1430225, 451100, 7067962, 5074302, 1962642, 1279661, 6463336,
    2546312, 1374803, 6880252, 7603226, 6144537, 4974386, 542412, 2831860, 1671176, 1846953,
    2584293, 3724270, 7786281, 3776993, 2013608, 5948022, 5925962, 164721, 6423145, 5011305,
    8194886, 1207385, 3183426, 8217573, 6764025, 5366416, 7570268, 6727783, 3694233, 1799107,
    3038916, 4856520, 4513516, 8110657, 6167306, 975884, 6662682, 7908339, 426683, 6656817,
    1803090, 6470041, 1667432, 1104333, 260646, 3833893, 2939036, 2235985, 420899, 2286327,
    8196974, 976891, 6767575, 3545687, 554416, 4460757, 48306, 1362209, 4442679, 6979993, 846154,
    6403635,
];

// FIPS-204, Algorithm 41.
pub fn to_ntt(coefficients: &mut [FieldElement<Standard>; 256]) {
    let mut m = 0;
    let mut len = 128;

    while len >= 1 {
        let mut start = 0;
        while start < 256 {
            m += 1;
            let z = ZETA_ALL_MONT[m];

            let (lo, hi) = coefficients[start..start + 2 * len].split_at_mut(len);
            for (a, b) in lo.iter_mut().zip(hi.iter_mut()) {
                let t = z.mul(*b);
                *b = *a - &t;
                *a += &t;
            }
            start += 2 * len;
        }
        len >>= 1; // Same as division by 2
    }
}

// FIPS-204, Algorithm 41.
pub fn inverse_ntt<D: Domain>(coefficients: &mut [FieldElement<D>; 256]) {
    let mut len = 1;
    let mut m = 256;

    while len < 256 {
        let mut start = 0;
        while start < 256 {
            m -= 1;
            let z = NEG_ZETA_ALL_MONT[m];

            let (lo, hi) = coefficients[start..start + 2 * len].split_at_mut(len);
            for (a, b) in lo.iter_mut().zip(hi.iter_mut()) {
                let t = *a;
                *a = t + b;
                *b = z * (t - b);
            }

            start += 2 * len;
        }
        len *= 2;
    }
}

#[cfg(test)]
#[cfg(feature = "safe_api")]
mod test_hint {
    use super::*;
    use crate::hazardous::dsa::ml_dsa::internal::{MlDsa44, MlDsa65, MlDsa87};

    #[test]
    fn bitpacking_roundtrip() {
        for _ in 0..100 {
            let mut buf44 = vec![0u8; MlDsa44::OMEGA as usize + MlDsa44::DIM_K];
            let mut buf65 = vec![0u8; MlDsa65::OMEGA as usize + MlDsa65::DIM_K];
            let mut buf87 = vec![0u8; MlDsa87::OMEGA as usize + MlDsa87::DIM_K];

            let random_hint = Hint::<{ MlDsa44::DIM_K }>::random_hint::<MlDsa44>();
            random_hint.hint_bitpack::<MlDsa44>(&mut buf44);
            let roundtrip = Hint::<{ MlDsa44::DIM_K }>::hint_bitunpack::<MlDsa44>(&buf44).unwrap();
            assert_eq!(random_hint, roundtrip);

            let random_hint = Hint::<{ MlDsa65::DIM_K }>::random_hint::<MlDsa65>();
            random_hint.hint_bitpack::<MlDsa65>(&mut buf65);
            let roundtrip = Hint::<{ MlDsa65::DIM_K }>::hint_bitunpack::<MlDsa65>(&buf65).unwrap();
            assert_eq!(random_hint, roundtrip);

            let random_hint = Hint::<{ MlDsa87::DIM_K }>::random_hint::<MlDsa87>();
            random_hint.hint_bitpack::<MlDsa87>(&mut buf87);
            let roundtrip = Hint::<{ MlDsa87::DIM_K }>::hint_bitunpack::<MlDsa87>(&buf87).unwrap();
            assert_eq!(random_hint, roundtrip);
        }
    }
}

#[cfg(all(test, feature = "safe_api"))]
mod test_ntt_transform {
    use super::*;

    #[test]
    fn neg_zetas_correctly_negated() {
        for i in 0..256 {
            assert_eq!(
                (ZETA_ALL_SPEC[i] as u64 + NEG_ZETA_ALL_SPEC[i] as u64) % DILITHIUM_Q as u64,
                0
            );
            assert_eq!(NEG_ZETA_ALL_SPEC[i], DILITHIUM_Q - ZETA_ALL_SPEC[i]);
            assert!(NEG_ZETA_ALL_SPEC[i] > 0 && NEG_ZETA_ALL_SPEC[i] < DILITHIUM_Q);
        }
    }

    #[test]
    fn test_to_from_ntt_roundtrips() {
        for _ in 0..100 {
            let f = RingElement::random_element();
            assert_eq!(f, f.into_ntt().inverse_ntt());

            let f_hat = RingElement::random_element().into_ntt();
            assert_eq!(f_hat, f_hat.inverse_ntt().into_ntt());
        }
    }
}

#[cfg(test)]
mod test_arithmetic {
    use super::*;

    /// R mod Q, where R is the montgomery value 2**32
    const R: u64 = 4193792;

    /// R^{-1} mod Q
    const R_INV: u64 = 8265825;

    const EDGE_CASE_TRIGGERS: &[u32] = &[
        0,
        1,
        2,
        DILITHIUM_Q - 1,
        DILITHIUM_Q - 2,
        DILITHIUM_Q / 2,
        DILITHIUM_Q / 2 - 1,
        DILITHIUM_Q / 2 + 1,
    ];

    #[test]
    fn test_conditional_subtraction() {
        for value in 0..DILITHIUM_Q * 2 {
            let ret = conditional_sub_u32(value);
            let expected = if value >= DILITHIUM_Q {
                value - DILITHIUM_Q
            } else {
                value
            };

            assert_eq!(ret, expected);
        }
    }

    #[test]
    fn test_montgomery_reduce() {
        // Output: n * R^{-1} mod Q
        // Considered canonical for any n < Q * 2^{32}.

        let limit = (DILITHIUM_Q as u64) << 32;
        let probes = [
            0u64,
            1,
            (DILITHIUM_Q as u64) - 1,
            (DILITHIUM_Q as u64),
            (DILITHIUM_Q as u64) + 1,
            (DILITHIUM_Q as u64 - 1).pow(2),
            9 * (DILITHIUM_Q as u64) * ((DILITHIUM_Q as u64) - 1),
            limit - 1,
        ];

        for v in probes {
            let r = montgomery_reduce(v);
            assert!(r < DILITHIUM_Q);
            assert_eq!(
                r as u64,
                v % (DILITHIUM_Q as u64) * R_INV % (DILITHIUM_Q as u64)
            );
        }
    }

    fn field_ops_add<D: Domain>() {
        for x in EDGE_CASE_TRIGGERS {
            for y in 0..DILITHIUM_Q {
                let fe_add_ret =
                    FieldElement::<D>::from_raw_u32(*x) + &FieldElement::<D>::from_raw_u32(y);
                let num_add_ret = (x + y) % DILITHIUM_Q;

                assert!(fe_add_ret.0 < DILITHIUM_Q);
                assert_eq!(fe_add_ret.0, num_add_ret);
            }
        }
    }

    fn field_ops_sub<D: Domain>() {
        for x in EDGE_CASE_TRIGGERS {
            for y in 0..DILITHIUM_Q {
                let fe_sub_ret =
                    FieldElement::<D>::from_raw_u32(*x) - &FieldElement::<D>::from_raw_u32(y);
                let num_sub_ret = (*x as i32 - y as i32 + DILITHIUM_Q as i32) % DILITHIUM_Q as i32;

                assert!(fe_sub_ret.0 < DILITHIUM_Q);
                assert_eq!(fe_sub_ret.0, num_sub_ret as u32);
            }
        }
    }

    #[test]
    fn test_field_ops_add() {
        field_ops_add::<Standard>();
        field_ops_add::<RInv>();
    }

    #[test]
    fn test_field_ops_sub() {
        field_ops_sub::<Standard>();
        field_ops_sub::<RInv>();
    }

    #[test]
    fn test_field_ops_mul() {
        for x in EDGE_CASE_TRIGGERS {
            let xfe = FieldElement::new(*x);

            for y in 0..DILITHIUM_Q {
                let yfe = FieldElement::new(y);
                let fe_mul_ret: FieldElement<RInv> = xfe * yfe;
                let num_sub_ret: i64 = (*x as i64 * y as i64) % DILITHIUM_Q as i64;

                assert!(fe_mul_ret.0 < DILITHIUM_Q);
                assert_eq!(
                    (fe_mul_ret.0 as u64 * R) % DILITHIUM_Q as u64,
                    num_sub_ret as u64,
                );
            }
        }
    }

    fn centered_abs(v: u32) -> u32 {
        // |w mod+- q|
        if v > DILITHIUM_Q / 2 {
            DILITHIUM_Q - v
        } else {
            v
        }
    }

    #[test]
    fn test_field_element_is_outside_bound() {
        for &bound in &[1u32, 2, 1023, 1 << 17, (DILITHIUM_Q - 1) / 8] {
            for v in 0..DILITHIUM_Q {
                let actual = bool::from(FieldElement::new(v).is_outside_bound(bound));
                assert_eq!(actual, centered_abs(v) >= bound);
            }

            for v in [
                bound - 1,
                bound,
                DILITHIUM_Q - bound,
                (DILITHIUM_Q - bound + 1) % DILITHIUM_Q, // wraparound to 0 when bound is 1
            ] {
                let actual = bool::from(FieldElement::new(v).is_outside_bound(bound));
                assert_eq!(actual, centered_abs(v) >= bound);
            }
        }

        assert!(bool::from(FieldElement::new(0).is_outside_bound(0)));
        assert!(bool::from(
            FieldElement::new(0).is_outside_bound((DILITHIUM_Q - 1) / 8 + 1)
        ));
    }
}
