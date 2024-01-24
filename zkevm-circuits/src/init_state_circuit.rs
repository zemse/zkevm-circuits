//! Init State Circuit
use crate::{
    evm_circuit::util::from_bytes,
    table::{init_state_table::InitStateTable, BlockTable, RwTable},
    util::{SubCircuit, SubCircuitConfig},
    witness::RwMap,
};
use eth_types::{BigEndianHash, Field, ToScalar, U256};
use gadgets::util::Expr;
use halo2_proofs::{
    plonk::{Column, Instance},
    poly::Rotation,
};

#[allow(unused_imports)]
use std::{env::set_var, marker::PhantomData};

use axiom_eth::halo2_base::gates::circuit::{BaseCircuitParams, BaseConfig};

/// Config for InitStateCircuit
#[derive(Clone, Debug)]
pub struct InitStateCircuitConfig<F: Field> {
    block_table: BlockTable,
    init_state_table: InitStateTable,
    rw_table: RwTable,
    // axiom_eth_config: EthConfig<F>,
    // axiom_base_config: BaseConfig<F>,
    instance: Column<Instance>,
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
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        // TODO

        Self {
            block_table,
            init_state_table,
            rw_table,
            // axiom_eth_config: EthConfig::configure(meta, eth_config_params),
            // axiom_base_config: BaseConfig::configure(meta, BaseCircuitParams::default()),
            instance,
            _marker: PhantomData,
        }
    }
}

/// Init State Circuit
#[derive(Clone, Default, Debug)]
pub struct InitStateCircuit<F: Field> {
    rws: RwMap,
    // axiom_inputs: EthBlockStorageInput,
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
            // axiom_inputs: block.axiom_inputs.clone(),
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

        Ok(())
    }

    fn min_num_rows_block(_block: &crate::witness::Block<F>) -> (usize, usize) {
        // TODO
        (0, 10)
    }

    fn instance(&self) -> Vec<Vec<F>> {
        let mut instance: Vec<F> = vec![];
        // TODO
        vec![instance]
    }
}
