#![allow(missing_docs)]
//! wrapping of mpt-circuit
// #[cfg(test)]
// use crate::mpt_circuit::mpt;
use crate::{
    table::{LookupTable, MptTable, PoseidonTable},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness,
};
use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed},
};
use itertools::Itertools;
use mpt_zktrie::mpt_circuits::{
    gadgets::{mpt_update::hash_traces, poseidon::PoseidonLookup},
    mpt,
    types::Proof,
};

impl PoseidonLookup for PoseidonTable {
    fn lookup_columns_generic(&self) -> (Column<Fixed>, [Column<Advice>; 6]) {
        (
            self.q_enable,
            [
                self.hash_id,
                self.input0,
                self.input1,
                self.control,
                self.domain_spec,
                self.heading_mark,
            ],
        )
    }
}

/// Circuit wrapped with mpt table data
#[derive(Clone, Debug, Default)]
pub struct MptCircuit<F: Field> {
    row_limit: usize,
    proofs: Vec<Proof>,
    mpt_updates: witness::MptUpdates,
    _phantom: std::marker::PhantomData<F>,
}

/// Circuit configuration argument ts
pub struct MptCircuitConfigArgs {
    /// PoseidonTable
    pub poseidon_table: PoseidonTable,
    /// MptTable
    pub mpt_table: MptTable,
    /// Challenges
    pub challenges: Challenges,
}

/// re-wrapping for mpt config
#[derive(Clone)]
pub struct MptCircuitConfig<F: Field>(
    pub(crate) mpt::MptCircuitConfig,
    pub(crate) MptTable,
    std::marker::PhantomData<F>,
);

impl SubCircuitConfig<Fr> for MptCircuitConfig<Fr> {
    type ConfigArgs = MptCircuitConfigArgs;

    fn new(
        meta: &mut ConstraintSystem<Fr>,
        Self::ConfigArgs {
            poseidon_table,
            mpt_table,
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {
        let conf = mpt::MptCircuitConfig::configure(meta, challenges.evm_word(), &poseidon_table);
        meta.lookup_any("updates in mpt table proven in mpt circuit", |meta| {
            mpt_table
                .table_exprs(meta)
                .into_iter()
                .zip_eq(conf.lookup_exprs(meta))
                .collect()
        });

        Self(conf, mpt_table, Default::default())
    }
}

#[cfg(any(feature = "test", test))]
impl SubCircuit<Fr> for MptCircuit<Fr> {
    type Config = MptCircuitConfig<Fr>;

    fn new_from_block(block: &witness::Block<Fr>) -> Self {
        // 0 means "dynamic"
        if block.circuits_params.max_mpt_rows != 0 {
            // Fixed byte-bit-index lookup needs 2049 rows.
            if block.circuits_params.max_mpt_rows < 2049 {
                panic!(
                    "invalid max_mpt_rows {}",
                    block.circuits_params.max_mpt_rows
                );
            }
        }
        let traces: Vec<_> = block
            .mpt_updates
            .proof_types
            .iter()
            .cloned()
            .zip_eq(block.mpt_updates.smt_traces.iter().cloned())
            .collect();

        Self {
            proofs: traces.into_iter().map(Proof::from).collect(),
            row_limit: block.circuits_params.max_mpt_rows,
            mpt_updates: block.mpt_updates.clone(),
            ..Default::default()
        }
    }

    fn min_num_rows_block(block: &witness::Block<Fr>) -> (usize, usize) {
        (
            // For an empty storage proof, we may need to lookup the canonical representations of
            // three different keys. Each lookup requires 32 rows.
            // The key bit lookup within the mpt circuit requires a minimum of 8 * 256 rows. The +1
            // comes from the fact that the mpt circuit starts assigning at offset = 1.
            3 * 32 * block.mpt_updates.len(),
            block.circuits_params.max_mpt_rows.max(8 * 256 + 1),
        )
    }

    /// Make the assignments to the MptCircuit, notice it fill mpt table
    /// but not fill hash table
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<Fr>>,
        layouter: &mut impl Layouter<Fr>,
    ) -> Result<(), Error> {
        config.0.assign(layouter, &self.proofs, self.row_limit)?;
        // use par assignment of mpt table by default.
        // to use serial version, you must set `PARALLEL_SYN=false`.
        let use_seq = std::env::var("PARALLEL_SYN").map_or(false, |s| s == *"false");
        if !use_seq {
            config.1.load_par(
                layouter,
                &self.mpt_updates,
                self.row_limit,
                challenges.evm_word(),
            )?;
        } else {
            config.1.load(
                layouter,
                &self.mpt_updates,
                self.row_limit,
                challenges.evm_word(),
            )?;
        }
        Ok(())
    }

    /// powers of randomness for instance columns
    fn instance(&self) -> Vec<Vec<Fr>> {
        vec![]
    }
}

impl Circuit<Fr> for MptCircuit<Fr> {
    type Config = (MptCircuitConfig<Fr>, PoseidonTable, Challenges);
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            row_limit: self.row_limit,
            ..Default::default()
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let challenges = Challenges::construct(meta, None);
        let poseidon_table = PoseidonTable::construct(meta);
        let mpt_table = MptTable::construct(meta);

        let config = {
            MptCircuitConfig::new(
                meta,
                MptCircuitConfigArgs {
                    poseidon_table,
                    mpt_table,
                    challenges,
                },
            )
        };

        (config, poseidon_table, challenges)
    }

    fn synthesize(
        &self,
        (mpt_config, poseidon_table, challenges): Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let poseidon_table_rows: Vec<_> = hash_traces(&self.proofs)
            .iter()
            .map(|([left, right], domain, hash)| {
                [*hash, *left, *right, Fr::zero(), *domain, Fr::one()].map(Value::known)
            })
            .collect();
        poseidon_table.load(&mut layouter, &poseidon_table_rows)?;
        let challenges = challenges.values(&layouter);
        self.synthesize_sub(&mpt_config, &challenges, &mut layouter)
    }
}
