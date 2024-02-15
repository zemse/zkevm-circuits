//! The bytecode circuit implementation.

#[cfg(any(test, feature = "test-circuits"))]
mod dev;
/// Bytecode circuit tester
#[cfg(test)]
mod test;
#[cfg(feature = "test-circuits")]
pub use dev::BytecodeCircuit as TestBytecodeCircuit;

use crate::{
    evm_circuit::util::{
        and,
        constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
        not, or, select,
    },
    table::{BytecodeFieldTag, BytecodeTable, KeccakTable, LookupTable},
    util::{
        get_push_size,
        word::{empty_code_hash_word_value, Word32, WordExpr, WordLoHi},
        Challenges, Expr, SubCircuit, SubCircuitConfig,
    },
    witness::{self},
};
use bus_mapping::state_db::{CodeDB, EMPTY_CODE_HASH_LE};
use eth_types::{Bytecode, Field};
use gadgets::is_zero::{IsZeroChip, IsZeroInstruction};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, Fixed, SecondPhase, VirtualCells,
    },
    poly::Rotation,
};
use itertools::Itertools;
use std::{iter, ops::Deref, vec};

const PUSH_TABLE_WIDTH: usize = 2;

#[derive(Debug, Clone, Default)]
/// Row for assignment
pub(crate) struct BytecodeCircuitRow<F: Field> {
    pub(crate) code_hash: WordLoHi<Value<F>>,
    tag: F,
    pub(crate) index: F,
    pub(crate) is_code: F,
    pub(crate) value: F,
    push_data_left: u64,
    value_rlc: Value<F>,
    length: F,
    push_data_size: F,
}
impl<F: Field> BytecodeCircuitRow<F> {
    #[cfg(test)]
    pub(crate) fn new(
        code_hash: WordLoHi<Value<F>>,
        tag: F,
        index: F,
        is_code: F,
        value: F,
    ) -> Self {
        Self {
            code_hash,
            tag,
            index,
            is_code,
            value,
            push_data_left: 0,
            value_rlc: Value::known(F::ZERO),
            length: F::ZERO,
            push_data_size: F::ZERO,
        }
    }

    /// Padding must be a header, according to the q_last constraints
    fn pad() -> Self {
        Self {
            code_hash: empty_code_hash_word_value(),
            tag: F::from(BytecodeFieldTag::Header as u64),
            value_rlc: Value::known(F::ZERO),
            ..Default::default()
        }
    }

    /// Witness to IsZero chip to determine if we are at the last row of a bytecode instance
    fn diff(&self) -> F {
        self.index + F::ONE - self.length
    }
}

#[derive(Clone, Default, Debug)]
pub(crate) struct BytecodeCircuitAssignment<F: Field>(pub(crate) Vec<BytecodeCircuitRow<F>>);

impl<F: Field> From<Vec<Bytecode>> for BytecodeCircuitAssignment<F> {
    fn from(codes: Vec<Bytecode>) -> Self {
        let mut rows = vec![];
        for bytecode in codes.iter() {
            let code_hash = WordLoHi::from(bytecode.hash()).into_value();
            let code_size = bytecode.codesize();
            let head = BytecodeCircuitRow {
                code_hash,
                tag: F::from(BytecodeFieldTag::Header as u64),
                index: F::ZERO,
                is_code: F::ZERO,
                value: F::from(code_size as u64),
                push_data_left: 0,
                value_rlc: Value::known(F::ZERO),
                length: F::from(code_size as u64),
                push_data_size: F::ZERO,
            };
            rows.push(head);
            let mut push_data_left = 0;

            for (index, &(value, is_code)) in bytecode.code_vec().iter().enumerate() {
                let push_data_size = get_push_size(value);
                let value = F::from(value as u64);

                let body = BytecodeCircuitRow {
                    code_hash,
                    tag: F::from(BytecodeFieldTag::Byte as u64),
                    index: F::from(index as u64),
                    is_code: F::from(is_code as u64),
                    value,
                    push_data_left,
                    value_rlc: Value::unknown(),
                    length: F::from(code_size as u64),
                    push_data_size: F::from(push_data_size),
                };
                rows.push(body);
                push_data_left = if is_code {
                    push_data_size
                } else {
                    push_data_left - 1
                };
            }
        }
        Self(rows)
    }
}

impl<F: Field> From<CodeDB> for BytecodeCircuitAssignment<F> {
    fn from(code_db: CodeDB) -> Self {
        // CodeDB use hash maps, so the bytecodes will be reordered.
        code_db.into_iter().collect_vec().into()
    }
}

impl<F: Field> From<Vec<Vec<u8>>> for BytecodeCircuitAssignment<F> {
    fn from(codes: Vec<Vec<u8>>) -> Self {
        // We don't go through BytecodeCollection struct to preserve bytecode order.
        codes
            .iter()
            .map(|bytes| Bytecode::from(bytes.clone()))
            .collect_vec()
            .into()
    }
}

impl<F: Field> Deref for BytecodeCircuitAssignment<F> {
    type Target = Vec<BytecodeCircuitRow<F>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug)]
/// Bytecode circuit configuration
pub struct BytecodeCircuitConfig<F> {
    q_enable: Column<Fixed>,
    q_first: Column<Fixed>,
    q_last: Column<Fixed>,
    bytecode_table: BytecodeTable,
    push_data_left: Column<Advice>,
    value_rlc: Column<Advice>,
    length: Column<Advice>,
    push_data_size: Column<Advice>,
    push_data_left_is_zero: IsZeroChip<F>,
    index_length_diff_is_zero: IsZeroChip<F>,
    push_table: [Column<Fixed>; PUSH_TABLE_WIDTH],
    // External tables
    pub(crate) keccak_table: KeccakTable,
}

/// Circuit configuration arguments
pub struct BytecodeCircuitConfigArgs<F: Field> {
    /// BytecodeTable
    pub bytecode_table: BytecodeTable,
    /// KeccakTable
    pub keccak_table: KeccakTable,
    /// Challenges
    pub challenges: Challenges<Expression<F>>,
}

impl<F: Field> SubCircuitConfig<F> for BytecodeCircuitConfig<F> {
    type ConfigArgs = BytecodeCircuitConfigArgs<F>;

    /// Return a new BytecodeCircuitConfig
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            bytecode_table,
            keccak_table,
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {
        let q_enable = meta.fixed_column();
        let q_first = meta.fixed_column();
        let q_last = meta.fixed_column();
        let value = bytecode_table.value;
        let push_data_left = meta.advice_column();
        let value_rlc = meta.advice_column_in(SecondPhase);
        let length = meta.advice_column();
        let push_data_size = meta.advice_column();
        let push_data_left_inv = meta.advice_column();
        let index_length_diff_inv = meta.advice_column();
        let push_table = array_init::array_init(|_| meta.fixed_column());

        // annotate columns
        bytecode_table.annotate_columns(meta);
        keccak_table.annotate_columns(meta);
        push_table.iter().enumerate().for_each(|(idx, &col)| {
            meta.annotate_lookup_any_column(col, || format!("push_table_{}", idx))
        });

        let is_header_to_header = |meta: &mut VirtualCells<F>| {
            and::expr(vec![
                not::expr(meta.query_advice(bytecode_table.tag, Rotation::cur())),
                not::expr(meta.query_advice(bytecode_table.tag, Rotation::next())),
            ])
        };

        let is_header_to_byte = |meta: &mut VirtualCells<F>| {
            and::expr(vec![
                not::expr(meta.query_advice(bytecode_table.tag, Rotation::cur())),
                meta.query_advice(bytecode_table.tag, Rotation::next()),
            ])
        };

        let is_byte_to_header = |meta: &mut VirtualCells<F>| {
            and::expr(vec![
                meta.query_advice(bytecode_table.tag, Rotation::cur()),
                not::expr(meta.query_advice(bytecode_table.tag, Rotation::next())),
            ])
        };

        let is_byte_to_byte = |meta: &mut VirtualCells<F>| {
            and::expr(vec![
                meta.query_advice(bytecode_table.tag, Rotation::cur()),
                meta.query_advice(bytecode_table.tag, Rotation::next()),
            ])
        };

        let is_header = |meta: &mut VirtualCells<F>| {
            not::expr(meta.query_advice(bytecode_table.tag, Rotation::cur()))
        };

        let is_byte =
            |meta: &mut VirtualCells<F>| meta.query_advice(bytecode_table.tag, Rotation::cur());

        // A byte is an opcode when `push_data_left == 0` on the current row,
        // else it's push data.
        let push_data_left_is_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_fixed(q_enable, Rotation::cur()),
            |meta| meta.query_advice(push_data_left, Rotation::cur()),
            push_data_left_inv,
        );

        let index_length_diff_is_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_fixed(q_enable, Rotation::cur()),
            |meta| {
                meta.query_advice(bytecode_table.index, Rotation::cur()) + 1.expr()
                    - meta.query_advice(length, Rotation::cur())
            },
            index_length_diff_inv,
        );

        // When q_first || q_last ->
        // assert cur.tag == Header
        meta.create_gate("first and last row", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_zero(
                "cur.tag == Header",
                meta.query_advice(bytecode_table.tag, Rotation::cur()),
            );

            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                or::expr(vec![
                    meta.query_fixed(q_first, Rotation::cur()),
                    meta.query_fixed(q_last, Rotation::cur()),
                ]),
            ]))
        });

        // When is_header ->
        // assert cur.index == 0
        // assert cur.value == cur.length
        meta.create_gate("Header row", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_zero(
                "cur.index == 0",
                meta.query_advice(bytecode_table.index, Rotation::cur()),
            );

            cb.require_equal(
                "cur.value == cur.length",
                meta.query_advice(bytecode_table.value, Rotation::cur()),
                meta.query_advice(length, Rotation::cur()),
            );

            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(meta.query_fixed(q_last, Rotation::cur())),
                is_header(meta),
            ]))
        });

        // When is_byte ->
        // assert push_data_size_table_lookup(cur.value, cur.push_data_size)
        // assert cur.is_code == (cur.push_data_left == 0)
        meta.create_gate("Byte row", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "cur.is_code == (cur.push_data_left == 0)",
                meta.query_advice(bytecode_table.is_code, Rotation::cur()),
                push_data_left_is_zero.clone().is_zero_expression,
            );

            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(meta.query_fixed(q_last, Rotation::cur())),
                is_byte(meta),
            ]))
        });
        meta.lookup_any(
            "push_data_size_table_lookup(cur.value, cur.push_data_size)",
            |meta| {
                let enable = and::expr(vec![
                    meta.query_fixed(q_enable, Rotation::cur()),
                    not::expr(meta.query_fixed(q_last, Rotation::cur())),
                    is_byte(meta),
                ]);

                let lookup_columns = vec![value, push_data_size];

                let mut constraints = vec![];

                for i in 0..PUSH_TABLE_WIDTH {
                    constraints.push((
                        enable.clone() * meta.query_advice(lookup_columns[i], Rotation::cur()),
                        meta.query_fixed(push_table[i], Rotation::cur()),
                    ))
                }
                constraints
            },
        );

        // When is_header_to_header or q_last ->
        // assert cur.length == 0
        // assert cur.hash == EMPTY_HASH
        meta.create_gate("Header to header row", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_zero(
                "cur.length == 0",
                meta.query_advice(length, Rotation::cur()),
            );

            let empty_hash_word: WordLoHi<Expression<F>> =
                Word32::new(*EMPTY_CODE_HASH_LE).to_expr().to_word();

            cb.require_equal_word(
                "assert cur.hash == EMPTY_HASH",
                bytecode_table.code_hash.query_advice(meta, Rotation::cur()),
                empty_hash_word,
            );

            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                or::expr(vec![
                    is_header_to_header(meta),
                    meta.query_fixed(q_last, Rotation::cur()),
                ]),
            ]))
        });

        // When is_header_to_byte ->
        // assert next.length == cur.length
        // assert next.index == 0
        // assert next.is_code == 1
        // assert next.hash == cur.hash
        // assert next.value_rlc == next.value
        meta.create_gate("Header to byte row", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "next.length == cur.length",
                meta.query_advice(length, Rotation::next()),
                meta.query_advice(length, Rotation::cur()),
            );

            cb.require_zero(
                "next.index == 0",
                meta.query_advice(bytecode_table.index, Rotation::next()),
            );

            cb.require_equal(
                "next.is_code == 1",
                meta.query_advice(bytecode_table.is_code, Rotation::next()),
                1.expr(),
            );

            cb.require_equal_word(
                "next.hash == cur.hash",
                bytecode_table
                    .code_hash
                    .query_advice(meta, Rotation::next()),
                bytecode_table.code_hash.query_advice(meta, Rotation::cur()),
            );

            cb.require_equal(
                "next.value_rlc == next.value",
                meta.query_advice(value_rlc, Rotation::next()),
                meta.query_advice(bytecode_table.value, Rotation::next()),
            );

            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(meta.query_fixed(q_last, Rotation::cur())),
                is_header_to_byte(meta),
            ]))
        });

        // When is_byte_to_byte ->
        // assert next.length == cur.length
        // assert next.index == cur.index + 1
        // assert next.hash == cur.hash
        // assert next.value_rlc == cur.value_rlc * randomness + next.value
        // if cur.is_code:
        //     assert next.push_data_left == cur.push_data_size
        // else:
        //     assert next.push_data_left == cur.push_data_left - 1
        meta.create_gate("Byte to Byte row", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "next.length == cur.length",
                meta.query_advice(length, Rotation::next()),
                meta.query_advice(length, Rotation::cur()),
            );

            cb.require_equal(
                "next.index == cur.index + 1",
                meta.query_advice(bytecode_table.index, Rotation::next()),
                meta.query_advice(bytecode_table.index, Rotation::cur()) + 1.expr(),
            );

            cb.require_equal_word(
                "next.hash == cur.hash",
                bytecode_table
                    .code_hash
                    .query_advice(meta, Rotation::next()),
                bytecode_table.code_hash.query_advice(meta, Rotation::cur()),
            );

            cb.require_equal(
                "next.value_rlc == cur.value_rlc * randomness + next.value",
                meta.query_advice(value_rlc, Rotation::next()),
                meta.query_advice(value_rlc, Rotation::cur()) * challenges.keccak_input()
                    + meta.query_advice(value, Rotation::next()),
            );

            cb.require_equal(
                "next.push_data_left == cur.is_code ? cur.push_data_size : cur.push_data_left - 1",
                meta.query_advice(push_data_left, Rotation::next()),
                select::expr(
                    meta.query_advice(bytecode_table.is_code, Rotation::cur()),
                    meta.query_advice(push_data_size, Rotation::cur()),
                    meta.query_advice(push_data_left, Rotation::cur()) - 1.expr(),
                ),
            );

            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(meta.query_fixed(q_last, Rotation::cur())),
                is_byte_to_byte(meta),
            ]))
        });

        // When cur.tag == Byte and cur.index + 1 == cur.length ->
        // assert next.tag == Header
        meta.create_gate("cur.tag == Byte and cur.index + 1 == cur.length", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_zero(
                "next.tag == Header",
                meta.query_advice(bytecode_table.tag, Rotation::next()),
            );

            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(bytecode_table.tag, Rotation::cur()),
                index_length_diff_is_zero.clone().is_zero_expression,
            ]))
        });

        // When is_byte_to_header ->
        // assert cur.index + 1 == cur.length
        // assert keccak256_table_lookup(cur.hash, cur.length, cur.value_rlc)
        meta.create_gate("Byte to Header row", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "cur.index + 1 == cur.length",
                meta.query_advice(bytecode_table.index, Rotation::cur()) + 1.expr(),
                meta.query_advice(length, Rotation::cur()),
            );

            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(meta.query_fixed(q_last, Rotation::cur())),
                is_byte_to_header(meta),
            ]))
        });
        meta.lookup_any(
            "keccak256_table_lookup(cur.value_rlc, cur.length, cur.hash_word)",
            |meta| {
                let enable = and::expr(vec![
                    meta.query_fixed(q_enable, Rotation::cur()),
                    not::expr(meta.query_fixed(q_last, Rotation::cur())),
                    is_byte_to_header(meta),
                ]);

                let mut constraints = vec![(
                    enable.clone(),
                    meta.query_advice(keccak_table.is_enabled, Rotation::cur()),
                )];

                for (circuit_column, table_column) in
                    keccak_table.match_columns(value_rlc, length, bytecode_table.code_hash)
                {
                    constraints.push((
                        enable.clone() * meta.query_advice(circuit_column, Rotation::cur()),
                        meta.query_advice(table_column, Rotation::cur()),
                    ))
                }

                constraints
            },
        );

        let push_data_left_is_zero = IsZeroChip::construct(push_data_left_is_zero);
        let index_length_diff_is_zero = IsZeroChip::construct(index_length_diff_is_zero);

        BytecodeCircuitConfig {
            q_enable,
            q_first,
            q_last,
            bytecode_table,
            push_data_left,
            value_rlc,
            length,
            push_data_size,
            push_data_left_is_zero,
            index_length_diff_is_zero,
            push_table,
            keccak_table,
        }
    }
}

impl<F: Field> BytecodeCircuitConfig<F> {
    pub(crate) fn assign_internal(
        &self,
        layouter: &mut impl Layouter<F>,
        max_rows: usize,
        witness: &BytecodeCircuitAssignment<F>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        let last_row_offset = max_rows - 1;

        if witness.len() > last_row_offset {
            // The last_row_offset-th row must be reserved for padding.
            // so we have "last_row_offset rows" usable
            log::error!(
                "the witness has size {}, but only {} rows usable. Some witness will not be assigned",
                witness.len(),
                last_row_offset
            );
        }
        layouter.assign_region(
            || "assign bytecode",
            |mut region| {
                // annotate columns
                self.annotate_circuit(&mut region);

                let mut value_rlc = Value::known(F::ZERO);
                // Chain the witness rows with as many padding rows as we like.
                // We take only the first "last_row_offset" rows.
                for (offset, row) in witness
                    .iter()
                    .chain(iter::repeat(&BytecodeCircuitRow::pad()))
                    .take(last_row_offset)
                    .enumerate()
                {
                    let mut row = row.clone();
                    // unfortunately this is the only place we can set the RLC.
                    // The RLC of the padding rows are unaffected. As they are always with the
                    // Header tag, the RLC value for them are always zero.
                    if row.tag == F::from(BytecodeFieldTag::Byte as u64) {
                        value_rlc.as_mut().zip(challenges.keccak_input()).map(
                            |(value_rlc, challenge)| {
                                *value_rlc = *value_rlc * challenge + row.value
                            },
                        );
                    } else {
                        value_rlc = Value::known(F::ZERO);
                    }
                    row.value_rlc = value_rlc;
                    self.set_row(&mut region, offset, last_row_offset, &row)?;
                }

                // Last row must be a padding row
                self.set_row(
                    &mut region,
                    last_row_offset,
                    last_row_offset,
                    &BytecodeCircuitRow::pad(),
                )?;

                Ok(())
            },
        )
    }

    fn set_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        last_row_offset: usize,
        row: &BytecodeCircuitRow<F>,
    ) -> Result<(), Error> {
        // q_enable
        region.assign_fixed(
            || format!("assign q_enable {}", offset),
            self.q_enable,
            offset,
            || Value::known(F::from((offset <= last_row_offset) as u64)),
        )?;

        // q_first
        region.assign_fixed(
            || format!("assign q_first {}", offset),
            self.q_first,
            offset,
            || Value::known(F::from((offset == 0) as u64)),
        )?;

        // q_last
        region.assign_fixed(
            || format!("assign q_last {}", offset),
            self.q_last,
            offset,
            || Value::known(F::from((offset == last_row_offset) as u64)),
        )?;

        // Advices
        for (name, column, value) in [
            ("tag", self.bytecode_table.tag, row.tag),
            ("index", self.bytecode_table.index, row.index),
            ("is_code", self.bytecode_table.is_code, row.is_code),
            ("value", self.bytecode_table.value, row.value),
            (
                "push_data_left",
                self.push_data_left,
                F::from(row.push_data_left),
            ),
            ("length", self.length, row.length),
            ("push_data_size", self.push_data_size, row.push_data_size),
        ] {
            region.assign_advice(
                || format!("assign {} {}", name, offset),
                column,
                offset,
                || Value::known(value),
            )?;
        }

        region.assign_advice(
            || format!("assign value_rlc {}", offset),
            self.value_rlc,
            offset,
            || row.value_rlc,
        )?;

        row.code_hash.assign_advice(
            region,
            || format!("assign code_hash {}", offset),
            self.bytecode_table.code_hash,
            offset,
        )?;

        self.push_data_left_is_zero.assign(
            region,
            offset,
            Value::known(F::from(row.push_data_left)),
        )?;

        self.index_length_diff_is_zero
            .assign(region, offset, Value::known(row.diff()))?;

        Ok(())
    }

    fn annotate_circuit(&self, region: &mut Region<F>) {
        self.bytecode_table.annotate_columns_in_region(region);
        self.keccak_table.annotate_columns_in_region(region);

        self.push_data_left_is_zero
            .annotate_columns_in_region(region, "BYTECODE");
        self.index_length_diff_is_zero
            .annotate_columns_in_region(region, "BYTECODE");
        region.name_column(|| "BYTECODE_q_enable", self.q_enable);
        region.name_column(|| "BYTECODE_q_first", self.q_first);
        region.name_column(|| "BYTECODE_q_last", self.q_last);
        region.name_column(|| "BYTECODE_length", self.length);
        region.name_column(|| "BYTECODE_push_data_left", self.push_data_left);
        region.name_column(|| "BYTECODE_push_data_size", self.push_data_size);
        region.name_column(|| "BYTECODE_value_rlc", self.value_rlc);
    }

    /// load fixed tables
    pub(crate) fn load_aux_tables(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        // push table: BYTE -> NUM_PUSHED:
        // byte < OpcodeId::PUSH1 => 0
        // byte >= OpcodeId::PUSH1 && byte <= OpcodeId::PUSH32 => [1..32]
        // byte > OpcodeId::PUSH32 && byte < 256 => 0
        layouter.assign_region(
            || "push table",
            |mut region| {
                for byte in 0usize..256 {
                    let push_size = get_push_size(byte as u8);
                    for (name, column, value) in &[
                        ("byte", self.push_table[0], byte as u64),
                        ("push_size", self.push_table[1], push_size),
                    ] {
                        region.assign_fixed(
                            || format!("Push table assign {} {}", name, byte),
                            *column,
                            byte,
                            || Value::known(F::from(*value)),
                        )?;
                    }
                }
                Ok(())
            },
        )?;

        Ok(())
    }
}

/// BytecodeCircuit
#[derive(Clone, Default, Debug)]
pub struct BytecodeCircuit<F: Field> {
    pub(crate) bytecodes: CodeDB,
    /// Unrolled bytecodes
    pub(crate) rows: BytecodeCircuitAssignment<F>,
    /// The number of Halo2 rows that can be utilized
    ///
    /// In tests, we set the number as small as possible to reduce MockProver's overhead.
    /// In production, this number must be the power of degree minus unusable rows.
    pub max_rows: usize,
}

impl<F: Field> BytecodeCircuit<F> {
    /// new BytecodeCircuitTester
    pub fn new(bytecodes: CodeDB, max_rows: usize) -> Self {
        let rows: BytecodeCircuitAssignment<F> = bytecodes.clone().into();
        Self {
            bytecodes,
            rows,
            max_rows,
        }
    }
}

impl<F: Field> SubCircuit<F> for BytecodeCircuit<F> {
    type Config = BytecodeCircuitConfig<F>;

    fn unusable_rows() -> usize {
        // No column queried at more than 3 distinct rotations, so returns 6 as
        // minimum unusable rows.
        6
    }

    fn new_from_block(block: &witness::Block<F>) -> Self {
        Self::new(block.bytecodes.clone(), block.circuits_params.max_bytecode)
    }

    /// Return the minimum number of rows required to prove the block
    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        (
            block.bytecodes.num_rows_required_for_bytecode_table(),
            block.circuits_params.max_bytecode,
        )
    }

    /// Make the assignments to the TxCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        config.load_aux_tables(layouter)?;
        config.assign_internal(layouter, self.max_rows, &self.rows, challenges)
    }
}
