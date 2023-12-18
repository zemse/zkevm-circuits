//! precompile helpers

use eth_types::Address;
#[cfg(not(feature = "wasm"))]
use revm_precompile::{Precompile, Precompiles};

#[allow(unused_variables)]
/// Check if address is a precompiled or not.
pub fn is_precompiled(address: &Address) -> bool {
    // TODO do a proper wasm fix here
    #[cfg(not(feature = "wasm"))]
    return Precompiles::berlin()
        .get(address.as_fixed_bytes())
        .is_some();

    #[cfg(feature = "wasm")]
    false
}

#[allow(unused_variables)]
pub(crate) fn execute_precompiled(address: &Address, input: &[u8], gas: u64) -> (Vec<u8>, u64) {
    #[cfg(feature = "wasm")]
    return (vec![], 0);

    #[cfg(not(feature = "wasm"))]
    let Some(Precompile::Standard(precompile_fn)) = Precompiles::berlin()
    .get(address.as_fixed_bytes())  else {
        panic!("calling non-exist precompiled contract address")
    };

    #[cfg(not(feature = "wasm"))]
    match precompile_fn(input, gas) {
        Ok((gas_cost, return_value)) => (return_value, gas_cost),
        Err(_) => (vec![], gas),
    }
}
