pub use crate::table::TxContextFieldTag;
use crate::{
    evm_circuit::step::{ExecutionState, ResponsibleOp},
    impl_expr,
};
use bus_mapping::{evm::OpcodeId, precompile::PrecompileCalls};
use eth_types::Field;
use gadgets::util::Expr;
use halo2_proofs::plonk::Expression;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

#[derive(Clone, Copy, Debug, EnumIter)]
pub enum FixedTableTag {
    Zero = 0,
    Range3,
    Range5,
    Range8,
    Range16,
    Range32,
    Range64,
    Range128,
    Range192,
    Range256,
    Range512,
    Range1024,
    SignByte,
    BitwiseAnd,
    BitwiseOr,
    BitwiseXor,
    ResponsibleOpcode,
    Pow2,
    ConstantGasCost,
    PrecompileInfo,
}
impl_expr!(FixedTableTag);

impl FixedTableTag {
    pub fn build<F: Field>(&self) -> Box<dyn Iterator<Item = [F; 4]>> {
        let tag = F::from(*self as u64);
        match self {
            Self::Zero => Box::new((0..1).map(move |_| [tag, F::ZERO, F::ZERO, F::ZERO])),
            Self::Range3 => {
                Box::new((0..3).map(move |value| [tag, F::from(value), F::ZERO, F::ZERO]))
            }
            Self::Range5 => {
                Box::new((0..5).map(move |value| [tag, F::from(value), F::ZERO, F::ZERO]))
            }
            Self::Range8 => {
                Box::new((0..8).map(move |value| [tag, F::from(value), F::ZERO, F::ZERO]))
            }
            Self::Range16 => {
                Box::new((0..16).map(move |value| [tag, F::from(value), F::ZERO, F::ZERO]))
            }
            Self::Range32 => {
                Box::new((0..32).map(move |value| [tag, F::from(value), F::ZERO, F::ZERO]))
            }
            Self::Range64 => {
                Box::new((0..64).map(move |value| [tag, F::from(value), F::ZERO, F::ZERO]))
            }
            Self::Range128 => {
                Box::new((0..128).map(move |value| [tag, F::from(value), F::ZERO, F::ZERO]))
            }
            Self::Range192 => {
                Box::new((0..192).map(move |value| [tag, F::from(value), F::ZERO, F::ZERO]))
            }
            Self::Range256 => {
                Box::new((0..256).map(move |value| [tag, F::from(value), F::ZERO, F::ZERO]))
            }
            Self::Range512 => {
                Box::new((0..512).map(move |value| [tag, F::from(value), F::ZERO, F::ZERO]))
            }
            Self::Range1024 => {
                Box::new((0..1024).map(move |value| [tag, F::from(value), F::ZERO, F::ZERO]))
            }
            Self::SignByte => Box::new((0..256).map(move |value| {
                [
                    tag,
                    F::from(value),
                    F::from((value >> 7) * 0xFFu64),
                    F::ZERO,
                ]
            })),
            Self::BitwiseAnd => Box::new((0..256).flat_map(move |lhs| {
                (0..256).map(move |rhs| [tag, F::from(lhs), F::from(rhs), F::from(lhs & rhs)])
            })),
            Self::BitwiseOr => Box::new((0..256).flat_map(move |lhs| {
                (0..256).map(move |rhs| [tag, F::from(lhs), F::from(rhs), F::from(lhs | rhs)])
            })),
            Self::BitwiseXor => Box::new((0..256).flat_map(move |lhs| {
                (0..256).map(move |rhs| [tag, F::from(lhs), F::from(rhs), F::from(lhs ^ rhs)])
            })),
            Self::ResponsibleOpcode => {
                Box::new(ExecutionState::iter().flat_map(move |execution_state| {
                    execution_state.responsible_opcodes().into_iter().map(
                        move |responsible_opcode| {
                            let (op, aux) = match responsible_opcode {
                                ResponsibleOp::Op(op) => (op, F::ZERO),
                                ResponsibleOp::InvalidStackPtr(op, stack_ptr) => {
                                    (op, F::from(u64::from(stack_ptr)))
                                }
                            };
                            [
                                tag,
                                F::from(execution_state.as_u64()),
                                F::from(op.as_u64()),
                                aux,
                            ]
                        },
                    )
                }))
            }
            Self::Pow2 => Box::new((0..256).map(move |value| {
                let (pow_lo, pow_hi) = if value < 128 {
                    (F::from_u128(1_u128 << value), F::from(0))
                } else {
                    (F::from(0), F::from_u128(1 << (value - 128)))
                };
                [tag, F::from(value), pow_lo, pow_hi]
            })),
            Self::ConstantGasCost => Box::new(
                OpcodeId::iter()
                    .filter(move |opcode| opcode.constant_gas_cost().0 > 0)
                    .map(move |opcode| {
                        [
                            tag,
                            F::from(opcode.as_u64()),
                            F::from(opcode.constant_gas_cost().0),
                            F::ZERO,
                        ]
                    }),
            ),
            Self::PrecompileInfo => Box::new(PrecompileCalls::iter().map(move |precompile| {
                [
                    tag,
                    F::from({
                        let state: ExecutionState = precompile.into();
                        state.as_u64()
                    }),
                    F::from(u64::from(precompile)),
                    F::from(precompile.base_gas_cost().0),
                ]
            })),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, EnumIter)]
pub(crate) enum Table {
    Fixed,
    Tx,
    Rw,
    Bytecode,
    Block,
    Copy,
    Keccak,
    Sha256,
    Exp,
    Sig,
    ModExp,
    Ecc,
    PowOfRand,
}

#[derive(Clone, Debug)]
pub struct RwValues<F> {
    pub id: Expression<F>,
    pub address: Expression<F>,
    pub field_tag: Expression<F>,
    pub storage_key: Expression<F>,
    pub value: Expression<F>,
    pub value_prev: Expression<F>,
    pub aux1: Expression<F>,
    pub aux2: Expression<F>,
}

impl<F: Field> RwValues<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Expression<F>,
        address: Expression<F>,
        field_tag: Expression<F>,
        storage_key: Expression<F>,
        value: Expression<F>,
        value_prev: Expression<F>,
        aux1: Expression<F>,
        aux2: Expression<F>,
    ) -> Self {
        Self {
            id,
            address,
            field_tag,
            storage_key,
            value,
            value_prev,
            aux1,
            aux2,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum Lookup<F> {
    /// Lookup to fixed table, which contains several pre-built tables such as
    /// range tables or bitwise tables.
    Fixed {
        /// Tag to specify which table to lookup.
        tag: Expression<F>,
        /// Values that must satisfy the pre-built relationship.
        values: [Expression<F>; 3],
    },
    /// Lookup to tx table, which contains transactions of this block.
    Tx {
        /// Id of transaction, the first transaction has id = 1.
        id: Expression<F>,
        /// Tag to specify which field to read.
        field_tag: Expression<F>,
        /// Index to specify which byte of calldata, which is only used when
        /// field_tag is Calldata, otherwise should be set to 0.
        index: Expression<F>,
        /// Value of the field.
        value: Expression<F>,
    },
    /// Lookup to read-write table, which contains read-write access records of
    /// time-aware data.
    Rw {
        /// Counter for how much read-write have been done, which stands for
        /// the sequential timestamp.
        counter: Expression<F>,
        /// A boolean value to specify if the access record is a read or write.
        is_write: Expression<F>,
        /// Tag to specify which read-write data to access, see RwTableTag for
        /// all tags.
        tag: Expression<F>,
        /// Values corresponding to the tag.
        values: RwValues<F>,
    },
    /// Lookup to bytecode table, which contains all used creation code and
    /// contract code.
    Bytecode {
        /// Hash to specify which code to read.
        hash: Expression<F>,
        /// Tag to specify whether its the bytecode length or byte value in the
        /// bytecode.
        tag: Expression<F>,
        /// Index to specify which byte of bytecode.
        index: Expression<F>,
        /// A boolean value to specify if the value is executable opcode or the
        /// data portion of PUSH* operations.
        is_code: Expression<F>,
        /// Value corresponding to the tag.
        value: Expression<F>,
        /// The RLC of the PUSH data (LE order), or 0.
        /// Warning: If the bytecode is truncated, this is the actual data, without zero-padding.
        push_rlc: Expression<F>,
    },
    /// Lookup to block table, which contains constants of this block.
    Block {
        /// Tag to specify which field to read.
        field_tag: Expression<F>,
        /// Stores the block's number in all cases except `BLOCKHASH` where this
        /// indicates a parent block number.
        number: Expression<F>,
        /// Value of the field.
        value: Expression<F>,
    },
    /// Lookup to copy table.
    CopyTable {
        /// Whether the row is the first row of the copy event.
        is_first: Expression<F>,
        /// The source ID for the copy event.
        src_id: Expression<F>,
        /// The source tag for the copy event.
        src_tag: Expression<F>,
        /// The destination ID for the copy event.
        dst_id: Expression<F>,
        /// The destination tag for the copy event.
        dst_tag: Expression<F>,
        /// The source address where bytes are copied from.
        src_addr: Expression<F>,
        /// The source address where all source-side bytes have been copied.
        /// This does not necessarily mean there no more bytes to be copied, but
        /// any bytes following this address will indicating padding.
        src_addr_end: Expression<F>,
        /// The destination address at which bytes are copied.
        dst_addr: Expression<F>,
        /// The number of bytes to be copied in this copy event.
        length: Expression<F>,
        /// The RLC accumulator value, which is used for SHA3 opcode.
        rlc_acc: Expression<F>,
        /// The RW counter at the start of the copy event.
        rw_counter: Expression<F>,
        /// The RW counter that is incremented by the time all bytes have been
        /// copied specific to this copy event.
        rwc_inc: Expression<F>,
    },
    /// Lookup to keccak table.
    KeccakTable {
        /// Accumulator to the input.
        input_rlc: Expression<F>,
        /// Length of input that is being hashed.
        input_len: Expression<F>,
        /// Output (hash) until this state. This is the RLC representation of
        /// the final output keccak256 hash of the input.
        output_rlc: Expression<F>,
    },
    /// Lookup to sha256 table.
    Sha256Table {
        /// Accumulator to the input.
        input_rlc: Expression<F>,
        /// Length of input that is being hashed.
        input_len: Expression<F>,
        /// Output (hash) until this state. This is the RLC representation of
        /// the final output sha256 hash of the input.
        output_rlc: Expression<F>,
    },
    /// Lookup to exponentiation table.
    ExpTable {
        base_limbs: [Expression<F>; 4],
        exponent_lo_hi: [Expression<F>; 2],
        exponentiation_lo_hi: [Expression<F>; 2],
    },
    SigTable {
        msg_hash_rlc: Expression<F>,
        sig_v: Expression<F>,
        sig_r_rlc: Expression<F>,
        sig_s_rlc: Expression<F>,
        recovered_addr: Expression<F>,
        is_valid: Expression<F>,
    },
    ModExpTable {
        base_limbs: [Expression<F>; 3],
        exp_limbs: [Expression<F>; 3],
        modulus_limbs: [Expression<F>; 3],
        result_limbs: [Expression<F>; 3],
    },
    EccTable {
        op_type: Expression<F>,
        is_valid: Expression<F>,
        arg1_rlc: Expression<F>,
        arg2_rlc: Expression<F>,
        arg3_rlc: Expression<F>,
        arg4_rlc: Expression<F>,
        input_rlc: Expression<F>,
        output1_rlc: Expression<F>,
        output2_rlc: Expression<F>,
    },
    PowOfRandTable {
        exponent: Expression<F>,
        pow_of_rand: Expression<F>,
    },
    /// Conditional lookup enabled by the first element.
    Conditional(Expression<F>, Box<Lookup<F>>),
}

impl<F: Field> Lookup<F> {
    pub(crate) fn conditional(self, condition: Expression<F>) -> Self {
        Self::Conditional(condition, self.into())
    }

    pub(crate) fn table(&self) -> Table {
        match self {
            Self::Fixed { .. } => Table::Fixed,
            Self::Tx { .. } => Table::Tx,
            Self::Rw { .. } => Table::Rw,
            Self::Bytecode { .. } => Table::Bytecode,
            Self::Block { .. } => Table::Block,
            Self::CopyTable { .. } => Table::Copy,
            Self::KeccakTable { .. } => Table::Keccak,
            Self::Sha256Table { .. } => Table::Sha256,
            Self::ExpTable { .. } => Table::Exp,
            Self::SigTable { .. } => Table::Sig,
            Self::ModExpTable { .. } => Table::ModExp,
            Self::EccTable { .. } => Table::Ecc,
            Self::PowOfRandTable { .. } => Table::PowOfRand,
            Self::Conditional(_, lookup) => lookup.table(),
        }
    }

    pub(crate) fn input_exprs(&self) -> Vec<Expression<F>> {
        match self {
            Self::Fixed { tag, values } => [vec![tag.clone()], values.to_vec()].concat(),
            Self::Tx {
                id,
                field_tag,
                index,
                value,
            } => vec![
                1.expr(),
                id.clone(),
                field_tag.clone(),
                index.clone(),
                value.clone(),
            ],
            Self::Rw {
                counter,
                is_write,
                tag,
                values,
            } => {
                vec![
                    1.expr(),
                    counter.clone(),
                    is_write.clone(),
                    tag.clone(),
                    values.id.clone(),
                    values.address.clone(),
                    values.field_tag.clone(),
                    values.storage_key.clone(),
                    values.value.clone(),
                    values.value_prev.clone(),
                    values.aux1.clone(),
                    values.aux2.clone(),
                ]
            }
            Self::Bytecode {
                hash,
                tag,
                index,
                is_code,
                value,
                push_rlc,
            } => {
                vec![
                    1.expr(), // q_enable
                    hash.clone(),
                    tag.clone(),
                    index.clone(),
                    is_code.clone(),
                    value.clone(),
                    push_rlc.clone(),
                ]
            }
            Self::Block {
                field_tag,
                number,
                value,
            } => {
                vec![field_tag.clone(), number.clone(), value.clone()]
            }
            Self::CopyTable {
                is_first,
                src_id,
                src_tag,
                dst_id,
                dst_tag,
                src_addr,
                src_addr_end,
                dst_addr,
                length,
                rlc_acc,
                rw_counter,
                rwc_inc,
            } => vec![
                1.expr(),
                is_first.clone(),
                src_id.clone(),
                src_tag.clone(),
                dst_id.clone(),
                dst_tag.clone(),
                src_addr.clone(),
                src_addr_end.clone(),
                dst_addr.clone(),
                length.clone(),
                rlc_acc.clone(),
                rw_counter.clone(),
                rwc_inc.clone(),
            ],
            Self::KeccakTable {
                input_rlc,
                input_len,
                output_rlc,
            } => vec![
                1.expr(), // q_enable
                1.expr(), // is_final
                input_rlc.clone(),
                input_len.clone(),
                output_rlc.clone(),
            ],
            Self::Sha256Table {
                input_rlc,
                input_len,
                output_rlc,
            } => vec![
                1.expr(), // q_enable
                1.expr(), // is_final
                input_rlc.clone(),
                input_len.clone(),
                output_rlc.clone(),
            ],
            Self::ExpTable {
                base_limbs,
                exponent_lo_hi,
                exponentiation_lo_hi,
            } => vec![
                1.expr(), // q_enable
                1.expr(), // is_step
                base_limbs[0].clone(),
                base_limbs[1].clone(),
                base_limbs[2].clone(),
                base_limbs[3].clone(),
                exponent_lo_hi[0].clone(),
                exponent_lo_hi[1].clone(),
                exponentiation_lo_hi[0].clone(),
                exponentiation_lo_hi[1].clone(),
            ],
            Self::SigTable {
                msg_hash_rlc,
                sig_v,
                sig_r_rlc,
                sig_s_rlc,
                recovered_addr,
                is_valid,
            } => vec![
                1.expr(), // q_enable
                msg_hash_rlc.clone(),
                sig_v.clone(),
                sig_r_rlc.clone(),
                sig_s_rlc.clone(),
                recovered_addr.clone(),
                is_valid.clone(),
            ],
            Self::ModExpTable {
                base_limbs,
                exp_limbs,
                modulus_limbs,
                result_limbs,
            } => vec![
                1.expr(), // q_head
                base_limbs[0].clone(),
                exp_limbs[0].clone(),
                modulus_limbs[0].clone(),
                result_limbs[0].clone(),
                base_limbs[1].clone(),
                exp_limbs[1].clone(),
                modulus_limbs[1].clone(),
                result_limbs[1].clone(),
                base_limbs[2].clone(),
                exp_limbs[2].clone(),
                modulus_limbs[2].clone(),
                result_limbs[2].clone(),
            ],
            Self::EccTable {
                op_type,
                is_valid,
                arg1_rlc,
                arg2_rlc,
                arg3_rlc,
                arg4_rlc,
                input_rlc,
                output1_rlc,
                output2_rlc,
            } => vec![
                op_type.expr(),
                is_valid.expr(),
                arg1_rlc.expr(),
                arg2_rlc.expr(),
                arg3_rlc.expr(),
                arg4_rlc.expr(),
                input_rlc.expr(),
                output1_rlc.expr(),
                output2_rlc.expr(),
            ],
            Self::PowOfRandTable {
                exponent,
                pow_of_rand,
            } => vec![
                1.expr(), /* q_enable */
                exponent.clone(),
                pow_of_rand.clone(),
            ],
            Self::Conditional(condition, lookup) => lookup
                .input_exprs()
                .into_iter()
                .map(|expr| condition.clone() * expr)
                .collect(),
        }
    }

    pub(crate) fn degree(&self) -> usize {
        self.input_exprs()
            .iter()
            .map(|expr| expr.degree())
            .max()
            .unwrap()
    }
}
