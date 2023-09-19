//! Init State Circuit

use crate::{
    table::{BlockTable, InitStateTable, RwTable},
    util::{SubCircuit, SubCircuitConfig},
    witness::RwMap,
};
use eth_types::Field;
// use halo2_proofs::plonk::circuit::Circuit;
use std::marker::PhantomData;

use axiom_eth::{util::EthConfigParams, MPTConfig};

/// Config for InitStateCircuit
#[derive(Clone, Debug)]
pub struct InitStateCircuitConfig<F: Field> {
    block_table: BlockTable,
    init_state_table: InitStateTable,
    rw_table: RwTable,
    axiom: MPTConfig<F>,
    _marker: PhantomData<F>,
}

/// Circuit configuration arguments
pub struct InitStateCircuitConfigArgs {
    /// Block Table
    pub block_table: BlockTable,
    /// Init State Table
    pub init_state_table: InitStateTable,
    /// RW Table
    pub rw_table: RwTable,
}

impl<F: Field> SubCircuitConfig<F> for InitStateCircuitConfig<F> {
    type ConfigArgs = InitStateCircuitConfigArgs;

    fn new(
        meta: &mut halo2_proofs::plonk::ConstraintSystem<F>,
        Self::ConfigArgs {
            block_table,
            init_state_table,
            rw_table,
        }: Self::ConfigArgs,
    ) -> Self {
        // TODO constraints to ensure init state table is correct as per state root in
        // block table. Basically this is MPT proof verification, need to use
        // axiom here.

        // Also ensure that all storage reads in RW table exist somewhere in IS table.
        // This can be a lookup, might need to add a column RW table.
        // This does not involve Axiom.

        // Circuit
        // EthCircuitBuilder::<F>::configure(meta);

        // EthBlockStorageCircuit::

        Self {
            block_table,
            init_state_table,
            rw_table,
            axiom: MPTConfig::configure(
                meta,
                EthConfigParams {
                    degree: 19,
                    num_rlc_columns: 2,
                    num_range_advice: vec![17, 10, 0],
                    num_lookup_advice: vec![1, 1, 0],
                    num_fixed: 1,
                    unusable_rows: 77,
                    keccak_rows_per_round: 50,
                    lookup_bits: Some(3),
                },
            ),
            _marker: PhantomData,
        }
    }
}

/// Init State Circuit
#[derive(Clone, Default, Debug)]
pub struct InitStateCircuit<F: Field> {
    rws: RwMap,
    _marker: PhantomData<F>,
}

impl<F: Field> SubCircuit<F> for InitStateCircuit<F> {
    type Config = InitStateCircuitConfig<F>;

    fn unusable_rows() -> usize {
        0
    }

    fn new_from_block(block: &crate::witness::Block<F>) -> Self {
        Self {
            rws: block.rws.clone(),
            _marker: PhantomData,
        }
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &crate::util::Challenges<halo2_proofs::circuit::Value<F>>,
        layouter: &mut impl halo2_proofs::circuit::Layouter<F>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        // TODO
        // take self.rws and assign them in the table. but that should be happening
        // in the table load.
        config
            .init_state_table
            .load(layouter, &self.rws, challenges.evm_word())?;

        // Assign witness to link the storage reads to the state root.

        Ok(())
    }

    fn min_num_rows_block(block: &crate::witness::Block<F>) -> (usize, usize) {
        // TODO
        (0, 10)
    }
}
