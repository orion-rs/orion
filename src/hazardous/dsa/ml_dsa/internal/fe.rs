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

use core::ops::{Add, AddAssign, Mul, Sub};
use core::ops::{Index, IndexMut};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

use crate::hazardous::dsa::ml_dsa::internal::MlDsaParameters;

pub(crate) const DILITHIUM_Q: u32 = 8380417;

pub(crate) const QINV: u32 = 58728449;

/// -q^(-1) % 2^(32)
pub(crate) const QNEGINV: u32 = 4236238847;

/// R**2 % q
pub(crate) const R2MODQ: u32 = 2365951;

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
    // cast to u32 and warpping_mul to use lower 32 bits
    let t: u32 = (value as u32).wrapping_mul(QNEGINV);
    let r: u32 = (value
        .overflowing_add((t as u64).overflowing_mul(DILITHIUM_Q as u64).0)
        .0
        >> 32) as u32;

    conditional_sub_u32(r)
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub struct MontgomeryFieldElement(pub(crate) u32);

#[cfg(feature = "zeroize")]
impl Zeroize for MontgomeryFieldElement {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Mul<MontgomeryFieldElement> for MontgomeryFieldElement {
    type Output = Self;

    fn mul(self, rhs: MontgomeryFieldElement) -> Self::Output {
        let r = (self.0 as u64).overflowing_mul(rhs.0 as u64);
        debug_assert!(!r.1);
        Self(montgomery_reduce(r.0))
    }
}

impl From<FieldElement> for MontgomeryFieldElement {
    fn from(value: FieldElement) -> Self {
        Self(montgomery_reduce(value.0 as u64 * R2MODQ as u64))
    }
}

impl From<MontgomeryFieldElement> for FieldElement {
    fn from(value: MontgomeryFieldElement) -> Self {
        Self(montgomery_reduce(value.0 as u64))
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
/// Element in the field Z_q.
///
/// NOTE(brycx): While for Kyber q = 3329 a field element would fit in u16, but Dilithium q = 8380417 which only fits in u32.
/// Thus, for possible future re-usability, we use 32-bit integer here.
pub struct FieldElement(pub(crate) u32);

impl FieldElement {
    pub(crate) const fn power2round<P: MlDsaParameters>(&self) -> (u32, u32) {
        debug_assert!(self.0 < DILITHIUM_Q);
        let r1 = (self.0.overflowing_add((1 << (P::D - 1)) - 1).0) >> P::D;
        let r0 = self.0.overflowing_add(DILITHIUM_Q - (r1 << P::D)).0;

        (r1, conditional_sub_u32(r0))
    }
}

impl Add for FieldElement {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let x: u32 = self.0 + other.0;
        Self(conditional_sub_u32(x))
    }
}

impl Sub for FieldElement {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let x: u32 = self
            .0
            .overflowing_sub(other.0)
            .0
            .overflowing_add(DILITHIUM_Q)
            .0;
        Self(conditional_sub_u32(x))
    }
}

impl Mul for FieldElement {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        Self(montgomery_reduce(self.0 as u64 * other.0 as u64))
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
    pub coefficients: [FieldElement; 256],
}

impl RingElement {
    pub fn zero() -> Self {
        Self {
            coefficients: [FieldElement::zero(); 256],
        }
    }

    /// NOTE: This should not be accessible by a user.
    pub(crate) fn copy_from_ntt(ntt: &RingElementNTT) -> Self {
        Self {
            coefficients: ntt.coefficients,
        }
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

impl Index<usize> for RingElement {
    type Output = FieldElement;

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

impl FieldElement {
    pub fn new(value: u32) -> Self {
        debug_assert!((0..DILITHIUM_Q).contains(&value));

        Self(value)
    }

    pub fn zero() -> Self {
        Self(0)
    }
}

#[derive(PartialEq, Debug, Clone, Copy)]
/// Element in T_q.
pub struct RingElementNTT {
    pub coefficients: [FieldElement; 256],
}

// FIPS-204, Algorithm 44.
impl Add for RingElementNTT {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let mut c = Self::zero();
        for idx in 0..256 {
            c[idx] = self[idx] + other[idx];
        }

        c
    }
}

// FIPS-204, Algorithm 45.
impl Mul for RingElementNTT {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        let mut c = Self::zero();
        for idx in 0..256 {
            c[idx] = self[idx] * other[idx];
        }

        c
    }
}

impl RingElementNTT {
    pub fn zero() -> Self {
        Self {
            coefficients: [FieldElement::zero(); 256],
        }
    }

    /// NOTE: This should not be accessible by a user.
    pub(crate) fn copy_from_non_ntt(not_ntt: &RingElement) -> Self {
        Self {
            coefficients: not_ntt.coefficients,
        }
    }
}

impl Index<usize> for RingElementNTT {
    type Output = FieldElement;

    fn index(&self, index: usize) -> &Self::Output {
        debug_assert!(index <= 255);
        &self.coefficients[index]
    }
}

impl IndexMut<usize> for RingElementNTT {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        debug_assert!(index <= 255);
        &mut self.coefficients[index]
    }
}

pub(crate) const ZETA_ALL: [u32; 256] = [
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

pub(crate) const NEG_ZETA_ALL: [u32; 256] = [
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
pub fn to_ntt(w: &RingElement) -> RingElementNTT {
    let mut m = 0;
    let mut len = 128;
    let mut w_hat = RingElementNTT::copy_from_non_ntt(w);

    while len >= 1 {
        let mut start = 0;
        while start < 256 {
            m += 1;
            let z = ZETA_ALL[m] as u64;

            for j in start..(start + len) {
                let t: FieldElement =
                    FieldElement::new(montgomery_reduce(z * (w_hat[j + len].0 as u64)));
                w_hat[j + len] = w_hat[j] - t;
                w_hat[j] = w_hat[j] + t;
            }
            start += 2 * len;
        }
        len >>= 1; // Same as division by 2
    }

    w_hat
}

// FIPS-204, Algorithm 41.
pub fn inverse_ntt(w_hat: &RingElementNTT) -> RingElement {
    debug_assert!(
        w_hat.coefficients.iter().all(|&c| c.0 < DILITHIUM_Q),
        "input must be canonical"
    );

    const N_INV: u32 = 8347681;
    const N_INV_MONT: FieldElement = FieldElement(montgomery_reduce(N_INV as u64 * R2MODQ as u64));

    let mut w = RingElement::copy_from_ntt(w_hat);

    let mut len = 1;
    let mut m = 256;
    while len < 256 {
        let mut start = 0;
        while start < 256 {
            m -= 1;
            let z = NEG_ZETA_ALL[m] as u64;

            for j in start..(start + len) {
                let t: FieldElement = w[j];
                w[j] = t + w[j + len];
                w[j + len] = t - (w[j + len]);
                w[j + len] = FieldElement::new(montgomery_reduce(z * w[j + len].0 as u64));
            }

            start += 2 * len;
        }
        len *= 2;
    }

    for fe in w.coefficients.iter_mut() {
        *fe = *fe * N_INV_MONT;
    }

    w
}

#[cfg(all(test, feature = "safe_api"))]
mod test_ntt_transform {
    use super::*;

    #[test]
    fn neg_zetas_correctly_negated() {
        for i in 0..256 {
            assert_eq!(
                (ZETA_ALL[i] as u64 + NEG_ZETA_ALL[i] as u64) % DILITHIUM_Q as u64,
                0
            );
            assert_eq!(NEG_ZETA_ALL[i], DILITHIUM_Q - ZETA_ALL[i]);
            assert!(NEG_ZETA_ALL[i] > 0 && NEG_ZETA_ALL[i] < DILITHIUM_Q);
        }
    }

    #[test]
    fn test_to_from_ntt_roundtrips() {
        for _ in 0..100 {
            let f: RingElement = RingElement::random_element();
            let f_hat: RingElementNTT = to_ntt(&RingElement::random_element());

            assert_eq!(f, inverse_ntt(&to_ntt(&f)),);
            assert_eq!(f_hat, to_ntt(&inverse_ntt(&f_hat)));
        }
    }
}

#[cfg(test)]
mod test_arithmetic {
    use super::*;

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
    fn test_mont_domain_mapping() {
        assert_eq!(
            MontgomeryFieldElement::from(FieldElement::new(1)).0,
            4193792u32,
        );

        for value in 2..DILITHIUM_Q {
            let fe = FieldElement::new(value);
            let mont_fe: MontgomeryFieldElement = fe.into();
            let fe_roundtrip: FieldElement = mont_fe.into();

            assert_eq!(fe, fe_roundtrip);
        }
    }

    #[test]
    fn test_field_ops_add() {
        for x in EDGE_CASE_TRIGGERS {
            for y in 0..DILITHIUM_Q {
                let fe_add_ret = FieldElement(*x) + FieldElement(y);
                let num_add_ret = (x + y) % DILITHIUM_Q;

                assert!(fe_add_ret.0 < DILITHIUM_Q);
                assert_eq!(fe_add_ret.0, num_add_ret);
            }
        }
    }

    #[test]
    fn test_field_ops_sub() {
        for x in EDGE_CASE_TRIGGERS {
            for y in 0..DILITHIUM_Q {
                let fe_sub_ret = FieldElement(*x) - FieldElement(y);
                let num_sub_ret = (*x as i32 - y as i32 + DILITHIUM_Q as i32) % DILITHIUM_Q as i32;

                assert!(fe_sub_ret.0 < DILITHIUM_Q);
                assert_eq!(fe_sub_ret.0, num_sub_ret as u32);
            }
        }
    }

    #[test]
    fn test_field_ops_mul() {
        for x in EDGE_CASE_TRIGGERS {
            let xfe = FieldElement::new(*x);

            for y in 0..DILITHIUM_Q {
                let yfe = FieldElement::new(y);

                let fe_mul_ret =
                    MontgomeryFieldElement::from(xfe) * MontgomeryFieldElement::from(yfe);
                let num_sub_ret = (*x as i64 * y as i64) % DILITHIUM_Q as i64;

                assert!(fe_mul_ret.0 < DILITHIUM_Q);
                assert_eq!(
                    fe_mul_ret.0,
                    MontgomeryFieldElement::from(FieldElement::new(num_sub_ret as u32)).0
                );
                assert_eq!(FieldElement::from(fe_mul_ret).0, num_sub_ret as u32);
            }
        }
    }
}
