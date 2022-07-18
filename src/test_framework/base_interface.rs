use crate::{
    hazardous::base::{Context, Data, Generate},
    Public, Secret,
};
use core::marker::PhantomData;

// TODO: Do we need to export this? Is it bad if we do?
#[macro_export]
macro_rules! test_base {
    ($newtype_alias:ident, $gen_test_data:ident, public) => {
        #[test]
        fn test_normal_debug() {
            crate::test_framework::base_interface::test_normal_debug($gen_test_data());
        }

        #[test]
        fn test_as_bytes_public() {
            crate::test_framework::base_interface::test_as_bytes_public($gen_test_data());
        }
    };

    ($newtype_alias:ident, generate, public) => {
        #[test]
        fn test_normal_debug() {
            let generated_newtype = $newtype_alias::generate();
            crate::test_framework::base_interface::test_normal_debug($gen_test_data());
        }

        #[test]
        fn test_as_bytes_public() {
            crate::test_framework::base_interface::test_as_bytes_public($gen_test_data());
        }
    };

    ($newtype_alias:ident, private, $newtype_mod:ident, $gen_test_data: ident) => {};
}

pub(crate) fn test_omitted_debug<C, D>(secret: Secret<C, D>)
where
    C: Context,
    D: Data,
{
    let secret_data = format!("{:?}", secret.unprotected_as_bytes());
    let debug_contents = format!("{:?}", secret_data);
    assert!(!debug_contents.contains(&secret_data));
}

pub(crate) fn test_normal_debug<C, D>(public: Public<C, D>)
where
    C: Context,
    D: Data,
{
    let public_data = format!("{:?}", public.as_ref());
    let debug_contents = format!("{:?}", public_data);
    assert!(debug_contents.contains(&public_data));
}

pub(crate) fn test_as_bytes_secret<C, D>(secret: Secret<C, D>)
where
    C: Context,
    D: Data,
{
    if C::MIN == C::MAX {
        // Test fixed-length definitions
        assert_eq!(secret.unprotected_as_bytes().len(), secret.len());
        assert!(!secret.is_empty());
        assert_eq!(secret.len(), C::MIN);
        assert_eq!(secret.len(), C::MAX);
    } else {
        // Test non-fixed-length definitions
        let data = secret.unprotected_as_bytes();
        let secret_lower = Secret::<C, D>::from_slice(&data[..C::MIN]).unwrap();
        let secret_upper = Secret::<C, D>::from_slice(&data[..C::MAX]).unwrap();

        assert_eq!(secret_lower.len(), C::MIN);
        assert_eq!(secret_upper.len(), C::MAX);

        assert_eq!(
            secret_lower.unprotected_as_bytes().len(),
            secret_lower.len()
        );
        assert_eq!(
            secret_upper.unprotected_as_bytes().len(),
            secret_upper.len()
        );

        assert_eq!(secret_lower.is_empty(), false);
        assert_eq!(secret_upper.is_empty(), false);
    }
}

pub(crate) fn test_as_bytes_public<C, D>(public: Public<C, D>)
where
    C: Context,
    D: Data,
{
    if C::MIN == C::MAX {
        // Test fixed-length definitions
        assert_eq!(public.as_ref().len(), public.len());
        assert!(!public.is_empty());
        assert_eq!(public.len(), C::MIN);
        assert_eq!(public.len(), C::MAX);
    } else {
        // Test non-fixed-length definitions
        let data = public.as_ref();
        let public_lower = Public::<C, D>::from_slice(&data[..C::MIN]).unwrap();
        let public_upper = Public::<C, D>::from_slice(&data[..C::MAX]).unwrap();

        assert_eq!(public_lower.len(), C::MIN);
        assert_eq!(public_upper.len(), C::MAX);

        assert_eq!(public_lower.as_ref().len(), public_lower.len());
        assert_eq!(public_upper.as_ref().len(), public_upper.len());

        assert_eq!(public_lower.is_empty(), false);
        assert_eq!(public_upper.is_empty(), false);
    }
}

#[cfg(feature = "safe_api")]
pub(crate) fn test_generate_secret<C, D>(_phantom: PhantomData<Public<C, D>>)
where
    C: Context + Generate,
    D: Data,
{
    let generated = Secret::<C, D>::generate();

    assert!(!generated
        .unprotected_as_bytes()
        .iter()
        .copied()
        .all(|b| b == 0));

    assert_eq!(generated.len(), C::GEN_SIZE);
    assert_eq!(generated.unprotected_as_bytes().len(), C::GEN_SIZE);
}

#[cfg(feature = "safe_api")]
pub(crate) fn test_generate_public<C, D>(_phantom: PhantomData<Public<C, D>>)
where
    C: Context + Generate,
    D: Data,
{
    let generated = Public::<C, D>::generate();
    assert!(!generated.as_ref().iter().copied().all(|b| b == 0));
    assert_eq!(generated.len(), C::GEN_SIZE);
    assert_eq!(generated.as_ref().len(), C::GEN_SIZE);
}

#[cfg(feature = "safe_api")]
pub(crate) fn test_generate_with_size_secret<C, D>()
where
    C: Context + Generate,
    D: Data,
{
    // least, middle, greatest possible value
    let sizes = Vec::from([C::MIN, (C::MIN + (C::MAX - C::MIN) / 2), C::MAX]);

    for size in sizes {
        let generated = Secret::<C, D>::generate_with_size(size).unwrap();
        assert!(!generated
            .unprotected_as_bytes()
            .iter()
            .copied()
            .all(|b| b == 0));
        assert_eq!(generated.len(), size);
        assert_eq!(generated.unprotected_as_bytes().len(), size);
    }
}

#[cfg(feature = "safe_api")]
pub(crate) fn test_generate_with_size_public<C, D>(_phantom: PhantomData<Public<C, D>>)
where
    C: Context + Generate,
    D: Data,
{
    // least, middle, greatest possible value
    let sizes = Vec::from([C::MIN, (C::MIN + (C::MAX - C::MIN) / 2), C::MAX]);

    for size in sizes {
        let generated = Public::<C, D>::generate_with_size(size).unwrap();
        assert!(!generated.as_ref().iter().copied().all(|b| b == 0));
        assert_eq!(generated.len(), size);
        assert_eq!(generated.as_ref().len(), size);
    }
}
