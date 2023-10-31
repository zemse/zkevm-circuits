//! Public Input Circuit implementation
mod param;

#[cfg(any(test, feature = "test-circuits"))]
mod dev;
#[cfg(test)]
mod test;
use std::marker::PhantomData;

#[cfg(feature = "test-circuits")]
pub use PiCircuit as TestPiCircuit;

use bus_mapping::operation::Target;
use eth_types::{self, Field, ToLittleEndian};
use halo2_proofs::plonk::{Expression, Instance, SecondPhase};
use itertools::Itertools;
use param::*;

use crate::{
    evm_circuit::{
        param::{N_BYTES_BLOCK, N_BYTES_EXTRA_VALUE, N_BYTES_HALF_WORD, N_BYTES_WORD},
        util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
    },
    instance::{public_data_convert, BlockValues, ExtraValues, PublicData},
    table::{AccountFieldTag, BlockTable, KeccakTable, LookupTable, RwTable},
    util::{word::Word, Challenges, SubCircuit, SubCircuitConfig},
    witness,
};
use gadgets::util::{not, Expr};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Selector},
    poly::Rotation,
};

/// Config for PiCircuit
#[derive(Clone, Debug)]
pub struct PiCircuitConfig<F: Field> {
    // q_digest_last: will be 1 on last byte of keccak digest, others are 0
    q_digest_last: Selector,
    // q_bytes_last: will be 1 on last byte of raw public input last byte, others are 0
    q_bytes_last: Selector,

    // q_rpi_keccak_lookup: enable keccak lookup
    q_rpi_keccak_lookup: Selector,
    // q_rpi_value_start: assure rpi_bytes sync with rpi_value_lc when cross boundary.
    // because we layout rpi bytes vertically, which is concated from multiple original values.
    // The value can be one byte or multiple bytes. The order of values is pre-defined and
    // hardcode. can't use selector here because we need rotation
    q_rpi_value_start: Column<Fixed>,
    // q_digest_value_start: mark starting of hi and low. can't use selector here because we need
    // rotation
    q_digest_value_start: Column<Fixed>,

    // rpi_bytes: raw public input bytes laid verticlly
    rpi_bytes: Column<Advice>,
    // rpi_bytes_keccakrlc: rpi_bytes rlc by keccak challenge. This is for Keccak lookup input
    // rlc
    rpi_bytes_keccakrlc: Column<Advice>,
    // rpi_value_lc: This is similar with rpi_bytes_keccakrlc, while the key differences is
    // it's linear combination with base 256.
    rpi_value_lc: Column<Advice>,
    // rpi_digest_bytes: Keccak digest raw bytes laid verticlly in this column
    rpi_digest_bytes: Column<Advice>,
    // rpi_digest_bytes_limbs: hi, lo limbs of digest
    rpi_digest_bytes_limbs: Column<Advice>,

    q_rpi_byte_enable: Selector,

    // q_pox_challenge_codehash: 1 on the row of challenge codehash in block table
    q_pox_challenge_codehash: Selector,

    pi_instance: Column<Instance>, // keccak_digest_hi, keccak_digest_lo

    _marker: PhantomData<F>,

    // External tables
    block_table: BlockTable,
    keccak_table: KeccakTable,
}

/// Circuit configuration arguments
pub struct PiCircuitConfigArgs<F: Field> {
    /// RwTable
    pub rw_table: RwTable,
    /// BlockTable
    pub block_table: BlockTable,
    /// Keccak Table
    pub keccak_table: KeccakTable,
    /// Challenges
    pub challenges: Challenges<Expression<F>>,
}

impl<F: Field> SubCircuitConfig<F> for PiCircuitConfig<F> {
    type ConfigArgs = PiCircuitConfigArgs<F>;

    /// Return a new PiCircuitConfig
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            rw_table,
            block_table,
            keccak_table,
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {
        let q_rpi_keccak_lookup = meta.complex_selector();

        let q_digest_last = meta.complex_selector();
        let q_bytes_last = meta.complex_selector();
        let q_rpi_byte_enable = meta.complex_selector();
        let q_pox_challenge_codehash = meta.complex_selector();

        let q_rpi_value_start = meta.fixed_column();
        let q_digest_value_start = meta.fixed_column();

        let rpi_bytes = meta.advice_column();
        let rpi_bytes_keccakrlc = meta.advice_column_in(SecondPhase);
        let rpi_value_lc = meta.advice_column();
        let rpi_digest_bytes = meta.advice_column();
        let rpi_digest_bytes_limbs = meta.advice_column();

        let pi_instance = meta.instance_column();

        // Annotate table columns
        block_table.annotate_columns(meta);

        meta.enable_equality(block_table.value.lo());
        meta.enable_equality(block_table.value.hi());

        meta.enable_equality(rpi_value_lc);
        meta.enable_equality(rpi_bytes_keccakrlc);

        meta.enable_equality(rpi_digest_bytes_limbs);

        meta.enable_equality(pi_instance);

        // gate 1 and gate 2 are compensation branch
        // 1: rpi_bytes_keccakrlc[last] = rpi_bytes[last]
        meta.create_gate("rpi_bytes_keccakrlc[last] = rpi_bytes[last]", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "rpi_bytes_keccakrlc[last] = rpi_bytes[last]",
                meta.query_advice(rpi_bytes_keccakrlc, Rotation::cur()),
                meta.query_advice(rpi_bytes, Rotation::cur()),
            );

            cb.gate(meta.query_selector(q_bytes_last) * meta.query_selector(q_rpi_byte_enable))
        });

        // 2: rpi_bytes_keccakrlc[i] = keccak_rand * rpi_bytes_keccakrlc[i+1] + rpi_bytes[i]"
        meta.create_gate(
            "rpi_bytes_keccakrlc[i] = keccak_rand * rpi_bytes_keccakrlc[i+1] + rpi_bytes[i]",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

                let rpi_bytes_keccakrlc_cur =
                    meta.query_advice(rpi_bytes_keccakrlc, Rotation::cur());
                let rpi_bytes_keccakrlc_next =
                    meta.query_advice(rpi_bytes_keccakrlc, Rotation::next());
                let rpi_bytes_cur = meta.query_advice(rpi_bytes, Rotation::cur());

                let keccak_rand = challenges.keccak_input();
                cb.require_equal(
                    "rpi_bytes_keccakrlc[i] = keccak_rand * rpi_bytes_keccakrlc[i+1] + rpi_bytes[i]",
                    rpi_bytes_keccakrlc_cur,
                    rpi_bytes_keccakrlc_next * keccak_rand + rpi_bytes_cur,
                );

                cb.gate(
                    not::expr(meta.query_selector(q_bytes_last)) *
                    meta.query_selector(q_rpi_byte_enable)
                )
            },
        );

        // gate 3 and gate 4 are compensation branch
        // 3: rpi_value_lc[i] = rpi_value_lc[i+1] * byte_pow_base
        // + rpi_bytes[i]
        meta.create_gate(
            "rpi_value_lc[i] = rpi_value_lc[i-1] * byte_pow_base + rpi_bytes[i]",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();
                let q_rpi_value_start_cur = meta.query_fixed(q_rpi_value_start, Rotation::cur());
                let rpi_value_lc_next = meta.query_advice(rpi_value_lc, Rotation::next());
                let rpi_value_lc_cur = meta.query_advice(rpi_value_lc, Rotation::cur());
                let rpi_bytes_cur = meta.query_advice(rpi_bytes, Rotation::cur());

                cb.require_equal(
                    "rpi_value_lc[i] = rpi_value_lc[i+1] * r + rpi_bytes[i]",
                    rpi_value_lc_cur,
                    rpi_value_lc_next * BYTE_POW_BASE.expr() + rpi_bytes_cur,
                );

                cb.gate(not::expr(q_rpi_value_start_cur) * meta.query_selector(q_rpi_byte_enable))
            },
        );

        // 4. rpi_value_lc[i] = rpi_bytes[i]
        meta.create_gate("rpi_value_lc[i] = rpi_bytes[i]", |meta| {
            let mut cb = BaseConstraintBuilder::default();
            let q_rpi_value_start_cur = meta.query_fixed(q_rpi_value_start, Rotation::cur());

            cb.require_equal(
                "rpi_value_lc[i] = rpi_bytes[i]",
                meta.query_advice(rpi_bytes, Rotation::cur()),
                meta.query_advice(rpi_value_lc, Rotation::cur()),
            );

            cb.gate(q_rpi_value_start_cur * meta.query_selector(q_rpi_byte_enable))
        });

        // 5. lookup rpi_bytes_keccakrlc against rpi_digest_bytes_limbs
        meta.lookup_any(
            "lookup rpi_bytes_keccakrlc against rpi_digest_bytes_limbs",
            |meta| {
                let circuit_len = PiCircuitConfig::<F>::circuit_len().expr();
                let is_enabled = meta.query_advice(keccak_table.is_enabled, Rotation::cur());
                let input_rlc = meta.query_advice(keccak_table.input_rlc, Rotation::cur());
                let input_len = meta.query_advice(keccak_table.input_len, Rotation::cur());
                let output_lo = meta.query_advice(keccak_table.output.lo(), Rotation::cur());
                let output_hi = meta.query_advice(keccak_table.output.hi(), Rotation::cur());

                // is_enabled
                let q_rpi_keccak_lookup = meta.query_selector(q_rpi_keccak_lookup);
                // input_rlc
                let rpi_bytes_keccakrlc_cur =
                    meta.query_advice(rpi_bytes_keccakrlc, Rotation::cur());
                // output
                let rpi_digest_lo = meta.query_advice(rpi_digest_bytes_limbs, Rotation::cur());
                let rpi_digest_hi = meta.query_advice(rpi_digest_bytes_limbs, Rotation::next());

                vec![
                    (q_rpi_keccak_lookup.expr() * 1.expr(), is_enabled),
                    (
                        q_rpi_keccak_lookup.expr() * rpi_bytes_keccakrlc_cur,
                        input_rlc,
                    ),
                    (q_rpi_keccak_lookup.expr() * circuit_len, input_len),
                    (q_rpi_keccak_lookup.expr() * rpi_digest_lo, output_lo),
                    (q_rpi_keccak_lookup * rpi_digest_hi, output_hi),
                ]
            },
        );

        meta.lookup_any(
            "lookup pox challenge bytecode hash in the rw table",
            |meta| {
                let selector = meta.query_selector(q_pox_challenge_codehash);

                // data assigned in block table and exposed to public inputs
                let codehash_block_hi = meta.query_advice(block_table.value.hi(), Rotation::cur());
                let codehash_block_lo = meta.query_advice(block_table.value.lo(), Rotation::cur());

                // table expression
                let rw_counter = meta.query_advice(rw_table.rw_counter, Rotation::cur());
                let rw_tag = meta.query_advice(rw_table.tag, Rotation::cur());
                let rw_field_tag = meta.query_advice(rw_table.field_tag, Rotation::cur());
                let codehash_rw_hi = meta.query_advice(rw_table.value.hi(), Rotation::cur());
                let codehash_rw_lo = meta.query_advice(rw_table.value.lo(), Rotation::cur());

                vec![
                    (selector.expr() * 1.expr(), rw_counter), // First RW
                    (selector.expr() * Target::Account.expr(), rw_tag),
                    (
                        selector.expr() * AccountFieldTag::CodeHash.expr(),
                        rw_field_tag,
                    ),
                    (selector.expr() * codehash_block_hi, codehash_rw_hi),
                    (selector.expr() * codehash_block_lo, codehash_rw_lo),
                ]
            },
        );

        meta.lookup_any("lookup pox exploit balance in the rw table", |meta| {
            let selector = meta.query_selector(q_pox_challenge_codehash);

            // data assigned in block table and exposed to public inputs
            let exp_bal_block_hi = meta.query_advice(block_table.value.hi(), Rotation::next());
            let exp_bal_block_lo = meta.query_advice(block_table.value.lo(), Rotation::next());

            // table expression
            let rw_counter = meta.query_advice(rw_table.rw_counter, Rotation::cur());
            let rw_tag = meta.query_advice(rw_table.tag, Rotation::cur());
            let rw_field_tag = meta.query_advice(rw_table.field_tag, Rotation::cur());
            let exp_bal_rw_hi = meta.query_advice(rw_table.value.hi(), Rotation::cur());
            let exp_bal_rw_lo = meta.query_advice(rw_table.value.lo(), Rotation::cur());

            vec![
                (selector.expr() * 3.expr(), rw_counter), // Third RW
                (selector.expr() * Target::Account.expr(), rw_tag),
                (
                    selector.expr() * AccountFieldTag::Balance.expr(),
                    rw_field_tag,
                ),
                (selector.expr() * exp_bal_block_hi, exp_bal_rw_hi),
                (selector.expr() * exp_bal_block_lo, exp_bal_rw_lo),
            ]
        });

        Self {
            block_table,
            q_digest_last,
            q_bytes_last,
            q_rpi_keccak_lookup,
            q_rpi_value_start,
            q_digest_value_start,
            keccak_table,
            rpi_bytes,
            rpi_bytes_keccakrlc,
            rpi_value_lc,
            rpi_digest_bytes,
            rpi_digest_bytes_limbs,
            q_rpi_byte_enable,
            q_pox_challenge_codehash,
            pi_instance,
            _marker: PhantomData,
        }
    }
}

impl<F: Field> PiCircuitConfig<F> {
    /// Return the number of rows in the circuit
    #[inline]
    fn circuit_len() -> usize {
        N_BYTES_ONE + N_BYTES_BLOCK + N_BYTES_EXTRA_VALUE
    }

    fn reset_rpi_digest_row(&self, region: &mut Region<'_, F>, offset: usize) -> Result<(), Error> {
        region.assign_advice(
            || "rpi_digest_bytes_limbs",
            self.rpi_digest_bytes_limbs,
            offset,
            || Value::known(F::ZERO),
        )?;

        Ok(())
    }

    fn reset_rpi_bytes_row(&self, region: &mut Region<'_, F>, offset: usize) -> Result<(), Error> {
        // assign q_rpi_value_start
        region.assign_fixed(
            || "q_rpi_value_start",
            self.q_rpi_value_start,
            offset,
            || Value::known(F::ZERO),
        )?;

        // assign rpi bytes
        region.assign_advice(
            || "rpi_bytes",
            self.rpi_bytes,
            offset,
            || Value::known(F::ZERO),
        )?;

        // assign rpi_bytes_keccakrlc
        region.assign_advice(
            || "rpi_bytes_keccakrlc",
            self.rpi_bytes_keccakrlc,
            offset,
            || Value::known(F::ZERO),
        )?;

        // assign rpi_value_lc
        region.assign_advice(
            || "rpi_value_lc",
            self.rpi_value_lc,
            offset,
            || Value::known(F::ZERO),
        )?;

        Ok(())
    }

    /// assign raw bytes
    #[allow(clippy::too_many_arguments)]
    fn assign_raw_bytes(
        &self,
        region: &mut Region<'_, F>,
        value_bytes_le: &[u8],
        rpi_bytes_keccakrlc: &mut Value<F>,
        rpi_bytes: &mut [u8],
        current_offset: &mut usize,
        challenges: &Challenges<Value<F>>,
        zero_cell: AssignedCell<F, F>,
    ) -> Result<AssignedByteCells<F>, Error> {
        assert!(!value_bytes_le.is_empty());
        assert!(value_bytes_le.len() <= N_BYTES_WORD);

        let keccak_rand = challenges.keccak_input();

        let mut rpi_value_lc_cells: Vec<AssignedCell<F, F>> = vec![];
        let mut rpi_bytes_keccakrlc_cells: Vec<AssignedCell<F, F>> = vec![];
        let start_offset = *current_offset;

        let value_bytes_be: Vec<u8> = value_bytes_le.iter().rev().copied().collect_vec();
        let value_bytes_chunk: Vec<Vec<u8>> = value_bytes_be
            .rchunks(N_BYTES_HALF_WORD)
            // chunks will go from right to left first, here we reverse the order to assure left to
            // right
            .rev()
            .map(|x| x.to_vec())
            .collect();

        *current_offset = value_bytes_chunk.iter().try_fold(
            // after rchunk
            start_offset,
            |mut offset, bytes| -> Result<usize, Error> {
                bytes.iter().enumerate().try_fold(
                    Value::known(F::ZERO),
                    |rpi_value_lc, (i, byte)| -> Result<Value<F>, Error> {
                        // assign q_rpi_value_start when index match beginning of chunk size
                        region.assign_fixed(
                            || "q_rpi_value_start",
                            self.q_rpi_value_start,
                            offset,
                            || Value::known(if i == 0 { F::ONE } else { F::ZERO }),
                        )?;

                        let rpi_value_lc = if i == 0 {
                            Value::known(F::ZERO)
                        } else {
                            rpi_value_lc
                        }
                        .zip(Value::known(F::from(BYTE_POW_BASE)))
                        .and_then(|(acc, rand)| Value::known(acc * rand + F::from(*byte as u64)));

                        // assign rpi_value_lc
                        let rpi_value_lc_cell = region.assign_advice(
                            || "rpi_value_lc",
                            self.rpi_value_lc,
                            offset,
                            || rpi_value_lc,
                        )?;

                        // for rpi_value_lc_cell, it accumulated per N_BYTES_HALF_WORD chunk size,
                        // and the remains
                        if i == bytes.len() - 1 {
                            rpi_value_lc_cells.push(rpi_value_lc_cell);
                        }

                        rpi_bytes[offset] = *byte;

                        // this is mutable for accumulated across value
                        *rpi_bytes_keccakrlc =
                            rpi_bytes_keccakrlc
                                .zip(keccak_rand)
                                .and_then(|(acc, rand)| {
                                    Value::known(acc * rand + F::from(*byte as u64))
                                });

                        // enable
                        self.q_rpi_byte_enable.enable(region, offset)?;

                        // assign rpi bytes
                        region.assign_advice(
                            || "rpi_bytes",
                            self.rpi_bytes,
                            offset,
                            || Value::known(F::from(*byte as u64)),
                        )?;

                        // assign rpi_bytes_keccakrlc
                        let rpi_bytes_keccakrlc_cell = region.assign_advice(
                            || "rpi_bytes_keccakrlc",
                            self.rpi_bytes_keccakrlc,
                            offset,
                            || *rpi_bytes_keccakrlc,
                        )?;

                        if start_offset - offset == value_bytes_le.len() - 1 {
                            rpi_bytes_keccakrlc_cells.push(rpi_bytes_keccakrlc_cell);
                        }

                        offset = offset.saturating_sub(1);

                        Ok(rpi_value_lc)
                    },
                )?;
                Ok(offset)
            },
        )?;

        assert!(rpi_value_lc_cells.len() <= 2); // at most hi, lo 2 cells
        rpi_value_lc_cells.reverse(); // reverse to lo, hi order
        assert!(rpi_bytes_keccakrlc_cells.len() == 1); // keccak rlc only 1 cell

        Ok((
            rpi_bytes_keccakrlc_cells[0].clone(),
            Word::new(
                (0..2) // padding rpi_value_lc_cells to 2 limbs if less then 2
                    .map(|i| rpi_value_lc_cells.get(i).unwrap_or(&zero_cell).clone())
                    .collect_vec()
                    .try_into()
                    .unwrap(),
            ),
        ))
    }

    /// Assigns the values for block table in the block_table column
    /// and rpi_bytes columns. Copy constraints will be enable
    /// to assure block_table value cell equal with respective rpi_byte_rlc cell
    #[allow(clippy::too_many_arguments)]
    fn assign_block_table(
        &self,
        region: &mut Region<'_, F>,
        block_table_offset: &mut usize,
        block_values: BlockValues,
        rpi_bytes_keccakrlc: &mut Value<F>,
        challenges: &Challenges<Value<F>>,
        current_offset: &mut usize,
        rpi_bytes: &mut [u8],
        zero_cell: AssignedCell<F, F>,
        q_pox_challenge_codehash: Selector,
    ) -> Result<(), Error> {
        let mut block_copy_cells = vec![];

        // coinbase
        let block_value = Word::from(block_values.coinbase)
            .into_value()
            .assign_advice(
                region,
                || "coinbase",
                self.block_table.value,
                *block_table_offset,
            )?;
        let (_, word) = self.assign_raw_bytes(
            region,
            &block_values
                .coinbase
                .to_fixed_bytes()
                .iter()
                .rev()
                .copied()
                .collect_vec(),
            rpi_bytes_keccakrlc,
            rpi_bytes,
            current_offset,
            challenges,
            zero_cell.clone(),
        )?;
        block_copy_cells.push((block_value, word));
        *block_table_offset += 1;

        // gas_limit
        let block_value = Word::from(block_values.gas_limit)
            .into_value()
            .assign_advice(
                region,
                || "gas_limit",
                self.block_table.value,
                *block_table_offset,
            )?;
        let (_, word) = self.assign_raw_bytes(
            region,
            &block_values.gas_limit.to_le_bytes(),
            rpi_bytes_keccakrlc,
            rpi_bytes,
            current_offset,
            challenges,
            zero_cell.clone(),
        )?;
        block_copy_cells.push((block_value, word));
        *block_table_offset += 1;

        // number
        let block_value = Word::from(block_values.number).into_value().assign_advice(
            region,
            || "number",
            self.block_table.value,
            *block_table_offset,
        )?;
        let (_, word) = self.assign_raw_bytes(
            region,
            &block_values.number.to_le_bytes(),
            rpi_bytes_keccakrlc,
            rpi_bytes,
            current_offset,
            challenges,
            zero_cell.clone(),
        )?;
        block_copy_cells.push((block_value, word));
        *block_table_offset += 1;

        // timestamp
        let block_value = Word::from(block_values.timestamp)
            .into_value()
            .assign_advice(
                region,
                || "timestamp",
                self.block_table.value,
                *block_table_offset,
            )?;
        let (_, word) = self.assign_raw_bytes(
            region,
            &block_values.timestamp.to_le_bytes(),
            rpi_bytes_keccakrlc,
            rpi_bytes,
            current_offset,
            challenges,
            zero_cell.clone(),
        )?;
        block_copy_cells.push((block_value, word));
        *block_table_offset += 1;

        // difficulty
        let block_value = Word::from(block_values.difficulty)
            .into_value()
            .assign_advice(
                region,
                || "difficulty",
                self.block_table.value,
                *block_table_offset,
            )?;
        let (_, word) = self.assign_raw_bytes(
            region,
            &block_values.difficulty.to_le_bytes(),
            rpi_bytes_keccakrlc,
            rpi_bytes,
            current_offset,
            challenges,
            zero_cell.clone(),
        )?;
        block_copy_cells.push((block_value, word));
        *block_table_offset += 1;

        // base_fee
        let block_value = Word::from(block_values.base_fee)
            .into_value()
            .assign_advice(
                region,
                || "base_fee",
                self.block_table.value,
                *block_table_offset,
            )?;
        let (_, word) = self.assign_raw_bytes(
            region,
            &block_values.base_fee.to_le_bytes(),
            rpi_bytes_keccakrlc,
            rpi_bytes,
            current_offset,
            challenges,
            zero_cell.clone(),
        )?;
        block_copy_cells.push((block_value, word));
        *block_table_offset += 1;

        // chain_id
        let block_value = Word::from(block_values.chain_id)
            .into_value()
            .assign_advice(
                region,
                || "chain_id",
                self.block_table.value,
                *block_table_offset,
            )?;
        let (_, word) = self.assign_raw_bytes(
            region,
            &block_values.chain_id.to_le_bytes(),
            rpi_bytes_keccakrlc,
            rpi_bytes,
            current_offset,
            challenges,
            zero_cell.clone(),
        )?;
        block_copy_cells.push((block_value, word));
        *block_table_offset += 1;

        for prev_hash in block_values.history_hashes {
            let block_value = Word::from(prev_hash).into_value().assign_advice(
                region,
                || "prev_hash",
                self.block_table.value,
                *block_table_offset,
            )?;
            let (_, word) = self.assign_raw_bytes(
                region,
                &prev_hash
                    .to_fixed_bytes()
                    .iter()
                    .rev()
                    .copied()
                    .collect_vec(),
                rpi_bytes_keccakrlc,
                rpi_bytes,
                current_offset,
                challenges,
                zero_cell.clone(),
            )?;
            block_copy_cells.push((block_value, word));
            *block_table_offset += 1;
        }

        // pox challenge bytecode hash
        q_pox_challenge_codehash.enable(region, *block_table_offset)?;
        let block_value = Word::from(block_values.pox_challenge_codehash)
            .into_value()
            .assign_advice(
                region,
                || "pox_challenge_codehash",
                self.block_table.value,
                *block_table_offset,
            )?;
        let (_, word) = self.assign_raw_bytes(
            region,
            &block_values
                .pox_challenge_codehash
                .to_fixed_bytes()
                .iter()
                .copied()
                .rev()
                .collect_vec(),
            rpi_bytes_keccakrlc,
            rpi_bytes,
            current_offset,
            challenges,
            zero_cell.clone(),
        )?;
        block_copy_cells.push((block_value, word));
        *block_table_offset += 1;

        // pox exploit balance
        let block_value = Word::from(block_values.pox_exploit_balance)
            .into_value()
            .assign_advice(
                region,
                || "pox_exploit_balance",
                self.block_table.value,
                *block_table_offset,
            )?;
        let (_, word) = self.assign_raw_bytes(
            region,
            &block_values.pox_exploit_balance.to_le_bytes(),
            rpi_bytes_keccakrlc,
            rpi_bytes,
            current_offset,
            challenges,
            zero_cell,
        )?;
        block_copy_cells.push((block_value, word));
        *block_table_offset += 1;

        block_copy_cells.iter().try_for_each(|(left, right)| {
            region.constrain_equal(left.lo().cell(), right.lo().cell())?;
            region.constrain_equal(left.hi().cell(), right.hi().cell())?;
            Ok::<(), Error>(())
        })?;

        Ok(())
    }

    /// Assigns the extra fields (not in block or tx tables):
    ///   - block hash
    ///   - state root
    ///   - previous block state root
    /// to the rpi_byte column
    #[allow(clippy::too_many_arguments)]
    fn assign_extra_fields(
        &self,
        region: &mut Region<'_, F>,
        extra: ExtraValues,
        rpi_bytes_keccakrlc: &mut Value<F>,
        challenges: &Challenges<Value<F>>,
        current_offset: &mut usize,
        rpi_bytes: &mut [u8],
        zero_cell: AssignedCell<F, F>,
    ) -> Result<(), Error> {
        // block hash
        self.assign_raw_bytes(
            region,
            &extra
                .block_hash
                .to_fixed_bytes()
                .iter()
                .copied()
                .rev()
                .collect_vec(),
            rpi_bytes_keccakrlc,
            rpi_bytes,
            current_offset,
            challenges,
            zero_cell.clone(),
        )?;

        // block state root
        self.assign_raw_bytes(
            region,
            &extra
                .state_root
                .to_fixed_bytes()
                .iter()
                .copied()
                .rev()
                .collect_vec(),
            rpi_bytes_keccakrlc,
            rpi_bytes,
            current_offset,
            challenges,
            zero_cell.clone(),
        )?;

        // previous block state root
        self.assign_raw_bytes(
            region,
            &extra
                .prev_state_root
                .to_fixed_bytes()
                .iter()
                .copied()
                .rev()
                .collect_vec(),
            rpi_bytes_keccakrlc,
            rpi_bytes,
            current_offset,
            challenges,
            zero_cell,
        )?;

        Ok(())
    }

    /// Assign digest word
    fn assign_rpi_digest_word(
        &self,
        region: &mut Region<'_, F>,
        digest_word: Word<F>,
    ) -> Result<Word<AssignedCell<F, F>>, Error> {
        let lo_assigned_cell = region.assign_advice(
            || "rpi_digest_bytes_limbs_lo",
            self.rpi_digest_bytes_limbs,
            0,
            || digest_word.into_value().lo(),
        )?;
        let hi_assigned_cell = region.assign_advice(
            || "rpi_digest_bytes_limbs_hi",
            self.rpi_digest_bytes_limbs,
            1,
            || digest_word.into_value().hi(),
        )?;
        Ok(Word::new([lo_assigned_cell, hi_assigned_cell]))
    }
}

/// Public Inputs Circuit
#[derive(Clone, Default, Debug)]
pub struct PiCircuit<F: Field> {
    max_txs: usize,
    max_calldata: usize,
    /// PublicInputs data known by the verifier
    pub public_data: PublicData,
    _marker: PhantomData<F>,
}

impl<F: Field> PiCircuit<F> {
    /// Creates a new PiCircuit
    pub fn new(max_txs: usize, max_calldata: usize, public_data: PublicData) -> Self {
        Self {
            max_txs,
            max_calldata,
            public_data,
            _marker: PhantomData,
        }
    }
}

impl<F: Field> SubCircuit<F> for PiCircuit<F> {
    type Config = PiCircuitConfig<F>;

    fn unusable_rows() -> usize {
        // No column queried at more than 3 distinct rotations, so returns 6 as
        // minimum unusable rows.
        6
    }

    fn new_from_block(block: &witness::Block<F>) -> Self {
        let public_data = public_data_convert(block);
        PiCircuit::new(
            block.circuits_params.max_txs,
            block.circuits_params.max_calldata,
            public_data,
        )
    }

    /// Return the minimum number of rows required to prove the block
    fn min_num_rows_block(_block: &witness::Block<F>) -> (usize, usize) {
        (Self::Config::circuit_len(), Self::Config::circuit_len())
    }

    /// Compute the public inputs for this circuit.
    fn instance(&self) -> Vec<Vec<F>> {
        let rpi_digest_byte_field = self.public_data.get_rpi_digest_word();

        vec![vec![rpi_digest_byte_field.lo(), rpi_digest_byte_field.hi()]]
    }

    /// Make the assignments to the PiCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let digest_word_assigned = layouter.assign_region(
            || "region 0",
            |mut region| {
                // Annotate columns

                config.block_table.annotate_columns_in_region(&mut region);
                config.keccak_table.annotate_columns_in_region(&mut region);

                region.name_column(|| "q_rpi_value_start", config.q_rpi_value_start);
                region.name_column(|| "rpi_bytes", config.rpi_bytes);
                region.name_column(|| "rpi_bytes_keccakrlc", config.rpi_bytes_keccakrlc);
                region.name_column(|| "rpi_value_lc", config.rpi_value_lc);
                region.name_column(|| "q_digest_value_start", config.q_digest_value_start);
                region.name_column(|| "rpi_digest_bytes", config.rpi_digest_bytes);
                region.name_column(|| "rpi_digest_bytes_lc", config.rpi_digest_bytes_limbs);

                region.name_column(|| "Public_Inputs", config.pi_instance);

                let circuit_len = Self::Config::circuit_len();
                let mut rpi_bytes = vec![0u8; circuit_len];

                let mut rpi_bytes_keccakrlc = Value::known(F::ZERO);

                // traverse reversely of the region
                let mut current_offset: usize = circuit_len - 1;
                let start_offset = current_offset;

                config.q_digest_last.enable(&mut region, N_BYTES_WORD - 1)?; // digest is 32 bytes
                config.q_bytes_last.enable(&mut region, start_offset)?;

                // assign last + 1 to 0 to as wordaround to skip CellNotAssigned Error from
                // Mock_prover
                config.reset_rpi_bytes_row(&mut region, start_offset + 1)?;
                config.reset_rpi_digest_row(&mut region, N_BYTES_WORD)?;

                // Assign block table
                let block_values = self.public_data.get_block_table_values();
                let mut block_table_offset = 0;

                // assign empty row in block table
                let zero_word = Word::default().into_value().assign_advice(
                    &mut region,
                    || "zero",
                    config.block_table.value,
                    block_table_offset,
                )?;
                let zero_cell = zero_word.hi();
                let (_, _) = config.assign_raw_bytes(
                    &mut region,
                    &0u8.to_le_bytes(),
                    &mut rpi_bytes_keccakrlc,
                    &mut rpi_bytes,
                    &mut current_offset,
                    challenges,
                    zero_cell.clone(),
                )?;
                block_table_offset += 1;
                config.assign_block_table(
                    &mut region,
                    &mut block_table_offset,
                    block_values,
                    &mut rpi_bytes_keccakrlc,
                    challenges,
                    &mut current_offset,
                    &mut rpi_bytes,
                    zero_cell.clone(),
                    config.q_pox_challenge_codehash,
                )?;
                assert_eq!(start_offset - current_offset, N_BYTES_ONE + N_BYTES_BLOCK);

                // Assign extra fields
                let extra_vals = self.public_data.get_extra_values();
                config.assign_extra_fields(
                    &mut region,
                    extra_vals,
                    &mut rpi_bytes_keccakrlc,
                    challenges,
                    &mut current_offset,
                    &mut rpi_bytes,
                    zero_cell,
                )?;
                assert_eq!(
                    start_offset - current_offset,
                    N_BYTES_BLOCK + N_BYTES_EXTRA_VALUE
                );

                assert_eq!(current_offset, 0);

                // assign keccak digest
                let digest_word = self.public_data.get_rpi_digest_word::<F>();

                let digest_word_assigned =
                    config.assign_rpi_digest_word(&mut region, digest_word)?;

                // keccak lookup occur on offset 0
                config.q_rpi_keccak_lookup.enable(&mut region, 0)?;

                Ok(digest_word_assigned)
            },
        )?;

        // Constrain raw_public_input cells to public inputs

        layouter.constrain_instance(digest_word_assigned.lo().cell(), config.pi_instance, 0)?;
        layouter.constrain_instance(digest_word_assigned.hi().cell(), config.pi_instance, 1)?;

        Ok(())
    }
}
