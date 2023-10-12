//! Init State Circuit

use crate::{
    evm_circuit::util::from_bytes,
    table::{BlockTable, InitStateTable, RwTable},
    util::{SubCircuit, SubCircuitConfig},
    witness::RwMap,
};
use eth_types::{BigEndianHash, Field, ToScalar, U256};
use gadgets::util::Expr;
use halo2_proofs::{
    plonk::{Column, Instance},
    poly::Rotation,
};

use std::{env::set_var, marker::PhantomData};

use axiom_eth::{
    rlp::builder::{FnSynthesize, RlcThreadBreakPoints, RlcThreadBuilder},
    storage::{EthBlockStorageCircuitGeneric, EthBlockStorageInput},
    util::EthConfigParams,
    EthConfig,
};

/// Config for InitStateCircuit
#[derive(Clone, Debug)]
pub struct InitStateCircuitConfig<F: Field> {
    block_table: BlockTable,
    init_state_table: InitStateTable,
    rw_table: RwTable,
    axiom_eth_config: EthConfig<F>,
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

        // All Account and AccountStorage entries in RW table should exist in InitState table.
        meta.lookup_any("exhaustive init state", |meta| {
            // RW table
            let s = meta.query_advice(rw_table.is_state, Rotation::cur());
            let address_rw = meta.query_advice(rw_table.address, Rotation::cur());
            let field_tag_rw = meta.query_advice(rw_table.field_tag, Rotation::cur());
            let storage_key_rw = meta.query_advice(rw_table.storage_key, Rotation::cur());
            let value_rw = meta.query_advice(rw_table.value, Rotation::cur());

            // InitState table
            let address_is = meta.query_advice(init_state_table.address, Rotation::cur());
            let field_tag_is = meta.query_advice(init_state_table.field_tag, Rotation::cur());
            let storage_key_is = meta.query_advice(init_state_table.storage_key, Rotation::cur());
            let value_is = meta.query_advice(init_state_table.value, Rotation::cur());

            vec![
                (s.expr() * address_rw, address_is),
                (s.expr() * field_tag_rw, field_tag_is),
                (s.expr() * storage_key_rw, storage_key_is),
                (s * value_rw, value_is),
            ]
        });

        // TODO constraints to ensure init state table is correct as per state root in
        // block table. Basically this is MPT proof verification, need to use
        // axiom here.

        // Circuit
        // EthCircuitBuilder::<F>::configure(meta);

        // EthBlockStorageCircuit::

        let eth_config_params = EthConfigParams {
            degree: 19,
            num_rlc_columns: 2,
            num_range_advice: vec![17, 10, 0],
            num_lookup_advice: vec![1, 1, 0],
            num_fixed: 1,
            unusable_rows: 77,
            keccak_rows_per_round: 25,
            lookup_bits: Some(8),
            skip_instance: true,
        };

        set_var(
            "ETH_CONFIG_PARAMS",
            serde_json::to_string(&eth_config_params).unwrap(),
        );
        set_var(
            "KECCAK_ROWS",
            eth_config_params.keccak_rows_per_round.to_string(),
        );
        let bits = eth_config_params.lookup_bits.unwrap();
        set_var("LOOKUP_BITS", bits.to_string());

        Self {
            block_table,
            init_state_table,
            rw_table,
            axiom_eth_config: EthConfig::configure(meta, eth_config_params),
            instance,
            _marker: PhantomData,
        }
    }
}

/// Init State Circuit
#[derive(Clone, Default, Debug)]
pub struct InitStateCircuit<F: Field> {
    rws: RwMap,
    axiom_inputs: EthBlockStorageInput,
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
            axiom_inputs: block.axiom_inputs.clone(),
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
        let axiom_eth_block_storage_circuit = EthBlockStorageCircuitGeneric::new(
            self.axiom_inputs.clone(),
            axiom_eth::Network::Goerli,
        );

        let builder = RlcThreadBuilder::new(false);
        let axiom_eth_circuit_builder = axiom_eth_block_storage_circuit.create(
            builder,
            Some(RlcThreadBreakPoints {
                gate: vec![
                    vec![
                        524226, 524226, 524228, 524228, 524228, 524228, 524227, 524228, 524227,
                        524228, 524227, 524228, 524226, 524226, 524226, 524226,
                    ],
                    vec![
                        524228, 524228, 524226, 524228, 524228, 524228, 524228, 524228, 524228,
                    ],
                    vec![],
                ],
                rlc: vec![524227],
            }),
        );

        let witness_gen_only = axiom_eth_circuit_builder
            .circuit
            .builder
            .borrow()
            .witness_gen_only();

        let assigned_advices = axiom_eth_circuit_builder
            .circuit
            .two_phase_synthesize(&config.axiom_eth_config.mpt, layouter);

        if !witness_gen_only {
            for (i, instance) in axiom_eth_circuit_builder
                .assigned_instances
                .iter()
                .enumerate()
            {
                println!("{:?}", instance); // removing this println somehow causes this code to not run. weird.
                let cell = instance.cell.unwrap();
                let val = assigned_advices.get(&(cell.context_id, cell.offset));
                if let Some((cell, _)) = val {
                    // println!("{:?}", cell);
                    layouter.constrain_instance(*cell, config.instance, i)?;
                }
            }
        }

        Ok(())
    }

    fn min_num_rows_block(_block: &crate::witness::Block<F>) -> (usize, usize) {
        // TODO
        (0, 10)
    }

    fn instance(&self) -> Vec<Vec<F>> {
        let mut instance: Vec<F> = vec![];

        let block_hash = hi_lo(&self.axiom_inputs.block_hash.into_uint());
        instance.push(block_hash.0);
        instance.push(block_hash.1);

        let block_number = F::from(self.axiom_inputs.block_number as u64);
        instance.push(block_number);

        let address = self.axiom_inputs.storage.addr.to_scalar().unwrap();
        instance.push(address);

        for (key, value, _) in self.axiom_inputs.storage.storage_pfs.iter() {
            let key = hi_lo(&key.into_uint());
            instance.push(key.0);
            instance.push(key.1);

            let value = hi_lo(value);
            instance.push(value.0);
            instance.push(value.1);
        }

        // println!("generated instance: {:?}", instance);

        vec![instance]
    }
}

fn hi_lo<F: Field>(value: &U256) -> (F, F) {
    let mut bytes: [u8; 32] = [0u8; 32];
    value.to_little_endian(&mut bytes);
    (
        from_bytes::value(&bytes[16..]),
        from_bytes::value(&bytes[..16]),
    )
}
