//! Table definitions used cross-circuits

use crate::{
    copy_circuit::util::number_or_hash_to_word,
    evm_circuit::util::rlc,
    impl_expr,
    util::{
        build_tx_log_address, keccak,
        word::{self, Word},
        Challenges,
    },
    witness::{Block, BlockContext, MptUpdateRow, MptUpdates, Rw, RwMap, RwRow, Transaction},
};
use bus_mapping::circuit_input_builder::{CopyDataType, CopyEvent, CopyStep};
use core::iter::once;
use eth_types::{Field, ToScalar, U256};
use gadgets::{
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
    util::{split_u256, split_u256_limb64},
};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, *},
    poly::Rotation,
};
use itertools::Itertools;
use std::array;
use strum_macros::{EnumCount, EnumIter};

/// block table
pub(crate) mod block_table;
/// bytecode table
pub(crate) mod bytecode_table;
/// copy Table
pub(crate) mod copy_table;
/// exp(exponentiation) table
pub(crate) mod exp_table;
/// keccak table
pub(crate) mod keccak_table;
/// mpt table
pub(crate) mod mpt_table;
/// rw table
pub(crate) mod rw_table;
/// tx table
pub(crate) mod tx_table;
/// ux table
pub(crate) mod ux_table;

pub(crate) use block_table::{BlockContextFieldTag, BlockTable};
pub(crate) use bytecode_table::{BytecodeFieldTag, BytecodeTable};
pub(crate) use copy_table::CopyTable;
pub(crate) use exp_table::ExpTable;
pub(crate) use keccak_table::KeccakTable;
pub(crate) use ux_table::UXTable;

pub(crate) use mpt_table::{MPTProofType, MptTable};
pub(crate) use rw_table::RwTable;
pub(crate) use tx_table::{
    TxContextFieldTag, TxFieldTag, TxLogFieldTag, TxReceiptFieldTag, TxTable,
};

/// Trait used to define lookup tables
pub trait LookupTable<F: Field> {
    /// Returns the list of ALL the table columns following the table order.
    fn columns(&self) -> Vec<Column<Any>>;

    /// Returns the list of ALL the table advice columns following the table
    /// order.
    fn advice_columns(&self) -> Vec<Column<Advice>> {
        self.columns()
            .iter()
            .map(|&col| col.try_into())
            .filter_map(|res| res.ok())
            .collect()
    }

    /// Returns the String annotations associated to each column of the table.
    fn annotations(&self) -> Vec<String>;

    /// Return the list of expressions used to define the lookup table.
    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        self.columns()
            .iter()
            .map(|&column| meta.query_any(column, Rotation::cur()))
            .collect()
    }

    /// Annotates a lookup table by passing annotations for each of it's
    /// columns.
    fn annotate_columns(&self, cs: &mut ConstraintSystem<F>) {
        self.columns()
            .iter()
            .zip(self.annotations().iter())
            .for_each(|(&col, ann)| cs.annotate_lookup_any_column(col, || ann))
    }

    /// Annotates columns of a table embedded within a circuit region.
    fn annotate_columns_in_region(&self, region: &mut Region<F>) {
        self.columns()
            .iter()
            .zip(self.annotations().iter())
            .for_each(|(&col, ann)| region.name_column(|| ann, col))
    }
}

impl<F: Field, C: Into<Column<Any>> + Copy, const W: usize> LookupTable<F> for [C; W] {
    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        self.iter()
            .map(|column| meta.query_any(*column, Rotation::cur()))
            .collect()
    }

    fn columns(&self) -> Vec<Column<Any>> {
        self.iter().map(|&col| col.into()).collect()
    }

    fn annotations(&self) -> Vec<String> {
        vec![]
    }
}

/// Tag for an AccountField in RwTable
#[derive(Clone, Copy, Debug, EnumIter, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum AccountFieldTag {
    /// Nonce field
    Nonce = 1,
    /// Balance field
    Balance,
    /// CodeHash field
    CodeHash,
    /// NonExisting field
    NonExisting,
}
impl_expr!(AccountFieldTag);

/// Tag for a CallContextField in RwTable
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter)]
pub enum CallContextFieldTag {
    /// RwCounterEndOfReversion
    RwCounterEndOfReversion = 1,
    /// CallerId
    CallerId,
    /// TxId
    TxId,
    /// Depth
    Depth,
    /// CallerAddress
    CallerAddress,
    /// CalleeAddress
    CalleeAddress,
    /// CallDataOffset
    CallDataOffset,
    /// CallDataLength
    CallDataLength,
    /// ReturnDataOffset
    ReturnDataOffset,
    /// ReturnDataLength
    ReturnDataLength,
    /// Value
    Value,
    /// IsSuccess
    IsSuccess,
    /// IsPersistent
    IsPersistent,
    /// IsStatic
    IsStatic,

    /// LastCalleeId
    LastCalleeId,
    /// LastCalleeReturnDataOffset
    LastCalleeReturnDataOffset,
    /// LastCalleeReturnDataLength
    LastCalleeReturnDataLength,

    /// IsRoot
    IsRoot,
    /// IsCreate
    IsCreate,
    /// CodeHash
    CodeHash,
    /// ProgramCounter
    ProgramCounter,
    /// StackPointer
    StackPointer,
    /// GasLeft
    GasLeft,
    /// MemorySize
    MemorySize,
    /// ReversibleWriteCounter
    ReversibleWriteCounter,
}
impl_expr!(CallContextFieldTag);

/// 5 bit field tag for all other field tags
#[derive(Debug, Clone, PartialEq, Eq, Copy, EnumIter, Hash)]
pub enum CommonFieldTag {
    /// Value0
    Value0,
    /// Value1
    Value1,
    /// Value2
    Value2,
    /// Value3
    Value3,
    /// Value4
    Value4,
    /// Value5
    Value5,
    /// Value6
    Value6,
    /// Value7
    Value7,
    /// Value8
    Value8,
    /// Value9
    Value9,
    /// Value10
    Value10,
    /// Value11
    Value11,
    /// Value12
    Value12,
    /// Value13
    Value13,
    /// Value14
    Value14,
    /// Value15
    Value15,
    /// Value16
    Value16,
    /// Value17
    Value17,
    /// Value18
    Value18,
    /// Value19
    Value19,
    /// Value20
    Value20,
    /// Value21
    Value21,
    /// Value22
    Value22,
    /// Value23
    Value23,
    /// Value24
    Value24,
    /// Value25
    Value25,
    /// Value26
    Value26,
    /// Value27
    Value27,
    /// Value28
    Value28,
    /// Value29
    Value29,
    /// Value30
    Value30,
    /// Value31
    Value31,
}

impl From<CommonFieldTag> for usize {
    fn from(value: CommonFieldTag) -> usize {
        value as usize
    }
}

impl From<u64> for CommonFieldTag {
    fn from(value: u64) -> Self {
        match value {
            0 => CommonFieldTag::Value0,
            1 => CommonFieldTag::Value1,
            2 => CommonFieldTag::Value2,
            3 => CommonFieldTag::Value3,
            4 => CommonFieldTag::Value4,
            5 => CommonFieldTag::Value5,
            6 => CommonFieldTag::Value6,
            7 => CommonFieldTag::Value7,
            8 => CommonFieldTag::Value8,
            9 => CommonFieldTag::Value9,
            10 => CommonFieldTag::Value10,
            11 => CommonFieldTag::Value11,
            12 => CommonFieldTag::Value12,
            13 => CommonFieldTag::Value13,
            14 => CommonFieldTag::Value14,
            15 => CommonFieldTag::Value15,
            16 => CommonFieldTag::Value16,
            17 => CommonFieldTag::Value17,
            18 => CommonFieldTag::Value18,
            19 => CommonFieldTag::Value19,
            20 => CommonFieldTag::Value20,
            21 => CommonFieldTag::Value21,
            22 => CommonFieldTag::Value22,
            23 => CommonFieldTag::Value23,
            24 => CommonFieldTag::Value24,
            25 => CommonFieldTag::Value25,
            26 => CommonFieldTag::Value26,
            27 => CommonFieldTag::Value27,
            28 => CommonFieldTag::Value28,
            29 => CommonFieldTag::Value29,
            30 => CommonFieldTag::Value30,
            31 => CommonFieldTag::Value31,
            _ => unreachable!(),
        }
    }
}

impl From<CallContextFieldTag> for CommonFieldTag {
    fn from(value: CallContextFieldTag) -> Self {
        match value {
            CallContextFieldTag::RwCounterEndOfReversion => CommonFieldTag::Value1,
            CallContextFieldTag::CallerId => CommonFieldTag::Value2,
            CallContextFieldTag::TxId => CommonFieldTag::Value3,
            CallContextFieldTag::Depth => CommonFieldTag::Value4,
            CallContextFieldTag::CallerAddress => CommonFieldTag::Value5,
            CallContextFieldTag::CalleeAddress => CommonFieldTag::Value6,
            CallContextFieldTag::CallDataOffset => CommonFieldTag::Value7,
            CallContextFieldTag::CallDataLength => CommonFieldTag::Value8,
            CallContextFieldTag::ReturnDataOffset => CommonFieldTag::Value9,
            CallContextFieldTag::ReturnDataLength => CommonFieldTag::Value10,
            CallContextFieldTag::Value => CommonFieldTag::Value11,
            CallContextFieldTag::IsSuccess => CommonFieldTag::Value12,
            CallContextFieldTag::IsPersistent => CommonFieldTag::Value13,
            CallContextFieldTag::IsStatic => CommonFieldTag::Value14,
            CallContextFieldTag::LastCalleeId => CommonFieldTag::Value15,
            CallContextFieldTag::LastCalleeReturnDataOffset => CommonFieldTag::Value16,
            CallContextFieldTag::LastCalleeReturnDataLength => CommonFieldTag::Value17,
            CallContextFieldTag::IsRoot => CommonFieldTag::Value18,
            CallContextFieldTag::IsCreate => CommonFieldTag::Value19,
            CallContextFieldTag::CodeHash => CommonFieldTag::Value20,
            CallContextFieldTag::ProgramCounter => CommonFieldTag::Value21,
            CallContextFieldTag::StackPointer => CommonFieldTag::Value22,
            CallContextFieldTag::GasLeft => CommonFieldTag::Value23,
            CallContextFieldTag::MemorySize => CommonFieldTag::Value24,
            CallContextFieldTag::ReversibleWriteCounter => CommonFieldTag::Value25,
        }
    }
}
