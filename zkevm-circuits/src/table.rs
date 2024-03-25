//! Table definitions used cross-circuits

use crate::{
    copy_circuit::util::number_or_hash_to_field,
    evm_circuit::util::{
        constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
        rlc,
    },
    exp_circuit::param::{OFFSET_INCREMENT, ROWS_PER_STEP},
    impl_expr,
    util::{build_tx_log_address, Challenges},
    witness::{
        Block, BlockContexts, Bytecode, MptUpdateRow, MptUpdates, RlpFsmWitnessGen, Rw, RwMap,
        RwRow, Transaction,
    },
};
use bus_mapping::{
    circuit_input_builder::{
        BigModExp, CopyDataType, CopyEvent, CopyStep, EcAddOp, EcMulOp, EcPairingOp, ExpEvent,
        PrecompileEcParams, N_BYTES_PER_PAIR, N_PAIRING_PER_OP,
    },
    precompile::PrecompileCalls,
};
use core::iter::once;
use eth_types::{sign_types::SignData, Field, ToLittleEndian, ToScalar, ToWord, Word, U256};
use gadgets::{
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
    util::{and, not, split_u256, split_u256_limb64, Expr},
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    halo2curves::{
        bn256::{Fq, G1Affine},
        group::prime::PrimeCurveAffine,
    },
    plonk::{Advice, Any, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
// use snark_verifier::util::arithmetic::PrimeCurveAffine;

use std::iter::repeat;

#[cfg(feature = "onephase")]
use halo2_proofs::plonk::FirstPhase as SecondPhase;
#[cfg(not(feature = "onephase"))]
use halo2_proofs::plonk::SecondPhase;

use halo2_proofs::plonk::TableColumn;
use itertools::Itertools;
use keccak256::plain::Keccak;
use std::array;
use strum_macros::{EnumCount, EnumIter};

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

    /// Returns the list of ALL the table fixed columns following the table order.
    fn fixed_columns(&self) -> Vec<Column<Fixed>> {
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

/// Tag used to identify each field in the transaction in a row of the
/// transaction table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter)]
pub enum TxFieldTag {
    /// Unused tag
    Null = 0,
    /// CallData
    CallData,
    /// Nonce
    Nonce,
    /// GasPrice
    GasPrice,
    /// Gas
    Gas,
    /// CallerAddress
    CallerAddress,
    /// CalleeAddress
    CalleeAddress,
    /// IsCreate
    IsCreate,
    /// Value
    Value,
    /// CallDataRLC
    CallDataRLC,
    /// CallDataLength
    CallDataLength,
    /// Gas cost for transaction call data (4 for byte == 0, 16 otherwise)
    CallDataGasCost,
    /// Gas cost of the transaction data charged in L1
    TxDataGasCost,
    /// Chain ID
    ChainID,
    /// Signature field V.
    SigV,
    /// Signature field R.
    SigR,
    /// Signature field S.
    SigS,
    /// TxSignLength: Length of the RLP-encoded transaction without the
    /// signature, used for signing
    TxSignLength,
    /// TxSignRLC: RLC of the RLP-encoded transaction without the signature,
    /// used for signing
    TxSignRLC,
    /// TxSignHash: Hash of the transaction without the signature, used for
    /// signing.
    TxSignHash,
    /// TxHashLength: Length of the RLP-encoded transaction without the
    /// signature, used for signing
    TxHashLength,
    /// TxHashRLC: RLC of the RLP-encoded transaction without the signature,
    /// used for signing
    TxHashRLC,
    /// TxHash: Hash of the transaction with the signature
    TxHash,
    /// TxType: Type of the transaction
    TxType,
    /// Access list address
    AccessListAddress,
    /// Access list storage key
    AccessListStorageKey,
    /// Access list address count (EIP-2930)
    AccessListAddressesLen,
    /// Access list all storage key count (EIP-2930)
    AccessListStorageKeysLen,
    /// RLC of access list (EIP-2930)
    AccessListRLC,
    /// The block number in which this tx is included.
    BlockNumber,
    /// Max Priority Fee Per Gas (EIP1559)
    MaxPriorityFeePerGas,
    /// Max Fee Per Gas (EIP1559)
    MaxFeePerGas,
}
impl_expr!(TxFieldTag);

impl From<TxFieldTag> for usize {
    fn from(t: TxFieldTag) -> Self {
        t as usize
    }
}

/// Alias for TxFieldTag used by EVM Circuit
pub type TxContextFieldTag = TxFieldTag;

/// Table that contains the fields of all Transactions in a block
#[derive(Clone, Debug)]
pub struct TxTable {
    /// q_enable
    pub q_enable: Column<Fixed>,
    /// Tx ID
    pub tx_id: Column<Advice>,
    /// Tag (TxContextFieldTag)
    pub tag: Column<Fixed>,
    /// Index for Tag = CallData
    pub index: Column<Advice>,
    /// Value
    pub value: Column<Advice>,
    /// Access list address
    pub access_list_address: Column<Advice>,
}

impl TxTable {
    /// Construct a new TxTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let q_enable = meta.fixed_column();
        let tag = meta.fixed_column();
        Self {
            q_enable,
            tx_id: meta.advice_column(),
            tag,
            index: meta.advice_column(),
            value: meta.advice_column_in(SecondPhase),
            access_list_address: meta.advice_column(),
        }
    }

    /// Assign the `TxTable` from a list of block `Transaction`s, following the
    /// same layout that the Tx Circuit uses.
    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        txs: &[Transaction],
        max_txs: usize,
        max_calldata: usize,
        chain_id: u64,
        challenges: &Challenges<Value<F>>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        assert!(
            txs.len() <= max_txs,
            "txs.len() <= max_txs: txs.len()={}, max_txs={}",
            txs.len(),
            max_txs
        );
        let sum_txs_calldata: usize = txs.iter().map(|tx| tx.call_data.len()).sum();

        // allow dynamic
        if max_calldata != 0 {
            assert!(
                sum_txs_calldata <= max_calldata,
                "sum_txs_calldata <= max_calldata: sum_txs_calldata={sum_txs_calldata}, max_calldata={max_calldata}",
            );
        }

        fn assign_row<F: Field>(
            region: &mut Region<'_, F>,
            offset: usize,
            q_enable: Column<Fixed>,
            advice_columns: &[Column<Advice>],
            tag: &Column<Fixed>,
            row: &[Value<F>; 5],
            msg: &str,
        ) -> Result<AssignedCell<F, F>, Error> {
            let mut value_cell = None;
            for (index, column) in advice_columns.iter().enumerate() {
                let cell = region.assign_advice(
                    || format!("tx table {msg} row {offset}"),
                    *column,
                    offset,
                    || row[if index > 0 { index + 1 } else { index }],
                )?;
                // tx_id, index, value
                if index == 2 {
                    value_cell = Some(cell);
                }
            }
            region.assign_fixed(
                || format!("tx table q_enable row {offset}"),
                q_enable,
                offset,
                || Value::known(F::one()),
            )?;
            region.assign_fixed(
                || format!("tx table {msg} row {offset}"),
                *tag,
                offset,
                || row[1],
            )?;
            Ok(value_cell.unwrap())
        }

        layouter.assign_region(
            || "tx table",
            |mut region| {
                let mut offset = 0;
                let mut tx_value_cells = vec![];
                let advice_columns = [self.tx_id, self.index, self.value];
                assign_row(
                    &mut region,
                    offset,
                    self.q_enable,
                    &advice_columns,
                    &self.tag,
                    &[(); 5].map(|_| Value::known(F::zero())),
                    "all-zero",
                )?;
                offset += 1;

                // Tx Table contains an initial region that has a size parametrized by max_txs
                // with all the tx data except for calldata and access list, and then a second
                // region that has a size parametrized by max_calldata with all
                // the tx calldata and access list.  This is required to achieve a constant fixed
                // column tag regardless of the number of input txs or the
                // calldata/access list size of each tx.

                // Assign Tx data (all tx fields except for calldata and access list)
                let padding_txs = (txs.len()..max_txs)
                    .map(|tx_id| {
                        let mut padding_tx = Transaction::dummy(chain_id);
                        padding_tx.id = tx_id + 1;

                        padding_tx
                    })
                    .collect::<Vec<Transaction>>();
                for (i, tx) in txs.iter().chain(padding_txs.iter()).enumerate() {
                    debug_assert_eq!(i + 1, tx.id);
                    let tx_data = tx.table_assignments_fixed(*challenges);
                    for row in tx_data {
                        tx_value_cells.push(assign_row(
                            &mut region,
                            offset,
                            self.q_enable,
                            &advice_columns,
                            &self.tag,
                            &row,
                            "",
                        )?);
                        offset += 1;
                    }
                }

                // Assign dynamic calldata and access list section
                for tx in txs.iter().chain(padding_txs.iter()) {
                    for row in tx.table_assignments_dyn(*challenges).into_iter() {
                        assign_row(
                            &mut region,
                            offset,
                            self.q_enable,
                            &advice_columns,
                            &self.tag,
                            &row,
                            "",
                        )?;
                        offset += 1;
                    }
                    for row in tx
                        .table_assignments_access_list_dyn(*challenges)
                        .into_iter()
                    {
                        assign_row(
                            &mut region,
                            offset,
                            self.q_enable,
                            &advice_columns,
                            &self.tag,
                            &row,
                            "",
                        )?;
                        offset += 1;
                    }
                }

                Ok(tx_value_cells)
            },
        )
    }
}

impl<F: Field> LookupTable<F> for TxTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.q_enable.into(),
            self.tx_id.into(),
            self.tag.into(),
            self.index.into(),
            self.value.into(),
            self.access_list_address.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("q_enable"),
            String::from("tx_id"),
            String::from("tag"),
            String::from("index"),
            String::from("value"),
            String::from("access_list_address"),
        ]
    }

    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        vec![
            meta.query_fixed(self.q_enable, Rotation::cur()),
            meta.query_advice(self.tx_id, Rotation::cur()),
            meta.query_fixed(self.tag, Rotation::cur()),
            meta.query_advice(self.index, Rotation::cur()),
            meta.query_advice(self.value, Rotation::cur()),
            meta.query_advice(self.access_list_address, Rotation::cur()),
        ]
    }
}

/// Tag to identify the operation type in a RwTable row
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter)]
pub enum RwTableTag {
    /// Start (used for padding)
    Start = 1,
    /// Stack operation
    Stack,
    /// Memory operation
    Memory,
    /// Tx Access List Account operation
    TxAccessListAccount,
    /// Tx Access List Account Storage operation
    TxAccessListAccountStorage,
    /// Tx Refund operation
    TxRefund,
    /// Account operation
    Account,
    /// Account Storage operation
    AccountStorage,
    /// Call Context operation
    CallContext,
    /// Tx Log operation
    TxLog,
    /// Tx Receipt operation
    TxReceipt,
}
impl_expr!(RwTableTag);

impl RwTableTag {
    /// Returns true if the RwTable operation is reversible
    pub fn is_reversible(self) -> bool {
        matches!(
            self,
            RwTableTag::TxAccessListAccount
                | RwTableTag::TxAccessListAccountStorage
                | RwTableTag::TxRefund
                | RwTableTag::Account
                | RwTableTag::AccountStorage
        )
    }
}

impl From<RwTableTag> for usize {
    fn from(t: RwTableTag) -> Self {
        t as usize
    }
}

/// Tag for an AccountField in RwTable
#[derive(Clone, Copy, Debug, EnumIter, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum AccountFieldTag {
    /// Nonce field
    Nonce,
    /// Balance field
    Balance,
    /// Variant representing the keccak hash of an account's code.
    KeccakCodeHash,
    /// Variant representing the poseidon hash of an account's code.
    CodeHash,
    /// Variant representing the code size, i.e. length of account's code.
    CodeSize,
    /// NonExisting field
    NonExisting,
}
impl_expr!(AccountFieldTag);

/// Tag for a TxLogField in RwTable
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter)]
pub enum TxLogFieldTag {
    /// Address field
    Address = 1,
    /// Topic field
    Topic,
    /// Data field
    Data,
}
impl_expr!(TxLogFieldTag);

/// Tag for a TxReceiptField in RwTable
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter, EnumCount)]
pub enum TxReceiptFieldTag {
    /// Tx result
    PostStateOrStatus = 1,
    /// CumulativeGasUsed in the tx
    CumulativeGasUsed,
    /// Number of logs in the tx
    LogLength,
}
impl_expr!(TxReceiptFieldTag);

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

    /// L1Fee
    L1Fee,
}
impl_expr!(CallContextFieldTag);

/// The RwTable shared between EVM Circuit and State Circuit, which contains
/// traces of the EVM state operations.
#[derive(Clone, Copy, Debug)]
pub struct RwTable {
    /// Is enable
    pub q_enable: Column<Fixed>,
    /// Read Write Counter
    pub rw_counter: Column<Advice>,
    /// Is Write
    pub is_write: Column<Advice>,
    /// Tag
    pub tag: Column<Advice>,
    /// Key1 (Id)
    pub id: Column<Advice>,
    /// Key2 (Address)
    pub address: Column<Advice>,
    /// Key3 (FieldTag)
    pub field_tag: Column<Advice>,
    /// Key3 (StorageKey)
    pub storage_key: Column<Advice>,
    /// Value
    pub value: Column<Advice>,
    /// Value Previous
    pub value_prev: Column<Advice>,
    /// Aux1
    pub aux1: Column<Advice>,
    /// Aux2 (Committed Value)
    pub aux2: Column<Advice>,
    /// Is this a state related RW operation
    pub is_state: Column<Advice>,
}

impl<F: Field> LookupTable<F> for RwTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.q_enable.into(),
            self.rw_counter.into(),
            self.is_write.into(),
            self.tag.into(),
            self.id.into(),
            self.address.into(),
            self.field_tag.into(),
            self.storage_key.into(),
            self.value.into(),
            self.value_prev.into(),
            self.aux1.into(),
            self.aux2.into(),
            // self.is_state.into(), // some lookup fails after adding this
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("q_enable"),
            String::from("rw_counter"),
            String::from("is_write"),
            String::from("tag"),
            String::from("id"),
            String::from("address"),
            String::from("field_tag"),
            String::from("storage_key"),
            String::from("value"),
            String::from("value_prev"),
            String::from("aux1"),
            String::from("aux2"),
            // String::from("is_state"), // some lookup fails after adding this
        ]
    }
}
impl RwTable {
    /// Construct a new RwTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            q_enable: meta.fixed_column(),
            rw_counter: meta.advice_column(),
            is_write: meta.advice_column(),
            tag: meta.advice_column(),
            id: meta.advice_column(),
            address: meta.advice_column(),
            field_tag: meta.advice_column(),
            storage_key: meta.advice_column_in(SecondPhase),
            value: meta.advice_column_in(SecondPhase),
            value_prev: meta.advice_column_in(SecondPhase),
            // It seems that aux1 for the moment is not using randomness
            // TODO check in a future review
            aux1: meta.advice_column_in(SecondPhase),
            aux2: meta.advice_column_in(SecondPhase),
            is_state: meta.advice_column(),
        }
    }
    fn assign<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &RwRow<Value<F>>,
    ) -> Result<(), Error> {
        region.assign_fixed(
            || "assign rw row on rw table",
            self.q_enable,
            offset,
            || Value::known(F::one()),
        )?;
        for (column, value) in [
            (self.rw_counter, row.rw_counter),
            (self.is_write, row.is_write),
            (self.tag, row.tag),
            (self.id, row.id),
            (self.address, row.address),
            (self.field_tag, row.field_tag),
            (self.storage_key, row.storage_key),
            (self.value, row.value),
            (self.value_prev, row.value_prev),
            (self.aux1, row.aux1),
            (self.aux2, row.aux2),
            (self.is_state, row.is_state),
        ] {
            region.assign_advice(|| "assign rw row on rw table", column, offset, || value)?;
        }
        Ok(())
    }

    /// Assign the `RwTable` from a `RwMap`, following the same
    /// table layout that the State Circuit uses.
    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        rws: &[Rw],
        n_rows: usize,
        challenges: Value<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "rw table",
            |mut region| self.load_with_region(&mut region, rws, n_rows, challenges),
        )
    }

    pub(crate) fn load_with_region<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        rws: &[Rw],
        n_rows: usize,
        challenges: Value<F>,
    ) -> Result<(), Error> {
        let (rows, _) = RwMap::table_assignments_prepad(rws, n_rows);
        for (offset, row) in rows.iter().enumerate() {
            self.assign(region, offset, &row.table_assignment(challenges))?;
        }
        Ok(())
    }

    pub(crate) fn load_with_region_part<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        rws: &[Rw],
        challenges: Value<F>,
    ) -> Result<(), Error> {
        for (offset, row) in rws.iter().enumerate() {
            self.assign(region, offset, &row.table_assignment(challenges))?;
        }
        Ok(())
    }
}

pub use mpt_zktrie::mpt_circuits::MPTProofType;

impl From<AccountFieldTag> for MPTProofType {
    fn from(tag: AccountFieldTag) -> Self {
        match tag {
            AccountFieldTag::Nonce => Self::NonceChanged,
            AccountFieldTag::Balance => Self::BalanceChanged,
            AccountFieldTag::KeccakCodeHash => Self::CodeHashExists,
            AccountFieldTag::CodeHash => Self::PoseidonCodeHashExists,
            AccountFieldTag::NonExisting => Self::AccountDoesNotExist,
            AccountFieldTag::CodeSize => Self::CodeSizeExists,
        }
    }
}

/// The MptTable shared between MPT Circuit and State Circuit
#[derive(Clone, Copy, Debug)]
pub struct MptTable {
    /// q_enable
    pub q_enable: Column<Fixed>,
    /// Address
    pub address: Column<Advice>,
    /// Storage key
    pub storage_key: Column<Advice>,
    /// Proof type
    pub proof_type: Column<Advice>,
    /// New root
    pub new_root: Column<Advice>,
    /// Old root
    pub old_root: Column<Advice>,
    /// New value
    pub new_value: Column<Advice>,
    /// Old value
    pub old_value: Column<Advice>,
}

impl<F: Field> LookupTable<F> for MptTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.q_enable.into(),
            self.address.into(),
            self.storage_key.into(),
            self.proof_type.into(),
            self.new_root.into(),
            self.old_root.into(),
            self.new_value.into(),
            self.old_value.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("q_enable"),
            String::from("address"),
            String::from("storage_key"),
            String::from("proof_type"),
            String::from("new_root"),
            String::from("old_root"),
            String::from("new_value"),
            String::from("old_value"),
        ]
    }
}

impl MptTable {
    /// Construct a new MptTable
    pub(crate) fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            q_enable: meta.fixed_column(),
            address: meta.advice_column(),
            storage_key: meta.advice_column_in(SecondPhase),
            proof_type: meta.advice_column(),
            new_root: meta.advice_column_in(SecondPhase),
            old_root: meta.advice_column_in(SecondPhase),
            new_value: meta.advice_column_in(SecondPhase),
            old_value: meta.advice_column_in(SecondPhase),
        }
    }

    pub(crate) fn assign<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &MptUpdateRow<Value<F>>,
    ) -> Result<(), Error> {
        region.assign_fixed(
            || "assign mpt table row value",
            self.q_enable,
            offset,
            || Value::known(F::one()),
        )?;
        let mpt_table_columns = <MptTable as LookupTable<F>>::advice_columns(self);
        for (column, value) in mpt_table_columns.iter().zip_eq(row.values()) {
            region.assign_advice(|| "assign mpt table row value", *column, offset, || *value)?;
        }
        Ok(())
    }

    pub(crate) fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        updates: &MptUpdates,
        max_mpt_rows: usize,
        randomness: Value<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "mpt table zkevm",
            |mut region| self.load_with_region(&mut region, updates, max_mpt_rows, randomness),
        )
    }

    pub(crate) fn load_par<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        updates: &MptUpdates,
        max_mpt_rows: usize,
        randomness: Value<F>,
    ) -> Result<(), Error> {
        let num_threads = std::thread::available_parallelism().unwrap().get();
        let chunk_size = (max_mpt_rows + num_threads - 1) / num_threads;
        let mpt_update_rows = updates
            .table_assignments(randomness)
            .into_iter()
            .chain(repeat(MptUpdateRow::padding()))
            .take(max_mpt_rows)
            .collect_vec();
        let mut is_first_passes = vec![true; num_threads];
        let assignments = mpt_update_rows
            .chunks(chunk_size)
            .zip(is_first_passes.iter_mut())
            .map(|(mpt_update_rows, is_first_pass)| {
                |mut region: Region<'_, F>| -> Result<(), Error> {
                    if *is_first_pass {
                        *is_first_pass = false;
                        let last_off = mpt_update_rows.len() - 1;
                        self.assign(&mut region, last_off, &mpt_update_rows[last_off])?;
                        return Ok(());
                    }
                    for (offset, row) in mpt_update_rows.iter().enumerate() {
                        self.assign(&mut region, offset, row)?;
                    }
                    Ok(())
                }
            })
            .collect_vec();

        layouter.assign_regions(|| "mpt table zkevm", assignments)?;

        Ok(())
    }

    pub(crate) fn load_with_region<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        updates: &MptUpdates,
        max_mpt_rows: usize,
        randomness: Value<F>,
    ) -> Result<(), Error> {
        let mpt_update_rows = updates.table_assignments(randomness);
        for (offset, row) in mpt_update_rows
            .into_iter()
            .chain(repeat(MptUpdateRow::padding()))
            .take(max_mpt_rows)
            .enumerate()
        {
            self.assign(region, offset, &row)?;
        }
        Ok(())
    }
}

/// The Poseidon hash table shared between Hash Circuit, Mpt Circuit and
/// Bytecode Circuit
/// the 5 cols represent [index(final hash of inputs), input0, input1, control,
/// heading mark]
#[derive(Clone, Copy, Debug)]
pub struct PoseidonTable {
    /// Is Enabled
    pub q_enable: Column<Fixed>,
    /// Hash id
    pub hash_id: Column<Advice>,
    /// input0
    pub input0: Column<Advice>,
    /// input1
    pub input1: Column<Advice>,
    /// control
    pub control: Column<Advice>,
    /// domain spec
    pub domain_spec: Column<Advice>,
    /// heading_mark
    pub heading_mark: Column<Advice>,
}

impl<F: Field> LookupTable<F> for PoseidonTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.q_enable.into(),
            self.hash_id.into(),
            self.input0.into(),
            self.input1.into(),
            self.control.into(),
            self.domain_spec.into(),
            self.heading_mark.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("q_enable"),
            String::from("hash_id"),
            String::from("input0"),
            String::from("input1"),
            String::from("control"),
            String::from("domain spec"),
            String::from("heading_mark"),
        ]
    }
}

impl PoseidonTable {
    /// the permutation width of current poseidon table
    pub(crate) const WIDTH: usize = 3;

    /// the input width of current poseidon table
    pub(crate) const INPUT_WIDTH: usize = Self::WIDTH - 1;

    /// Construct a new PoseidonTable
    pub(crate) fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            q_enable: meta.fixed_column(),
            hash_id: meta.advice_column(),
            input0: meta.advice_column(),
            input1: meta.advice_column(),
            control: meta.advice_column(),
            domain_spec: meta.advice_column(),
            heading_mark: meta.advice_column(),
        }
    }

    /// Load mpt hashes (without the poseidon circuit) for testing purposes.
    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        hashes: &[[Value<F>; 6]],
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "poseidon table",
            |mut region| {
                self.assign(&mut region, 0, [Value::known(F::zero()); 6])?;
                for (offset, row) in hashes.iter().enumerate() {
                    self.assign(&mut region, offset + 1, *row)?;
                }
                Ok(())
            },
        )
    }

    /// Provide this function for the case that we want to consume a poseidon
    /// table but without running the full poseidon circuit
    pub fn dev_load<'a, F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        inputs: impl IntoIterator<Item = &'a Vec<u8>> + Clone,
    ) -> Result<(), Error> {
        use crate::bytecode_circuit::bytecode_unroller::{
            unroll_to_hash_input_default, HASHBLOCK_BYTES_IN_FIELD,
        };
        use bus_mapping::state_db::CodeDB;
        use hash_circuit::hash::HASHABLE_DOMAIN_SPEC;

        layouter.assign_region(
            || "poseidon codehash table",
            |mut region| {
                let mut offset = 0;
                let poseidon_table_columns =
                    <PoseidonTable as LookupTable<F>>::advice_columns(self);

                region.assign_fixed(
                    || "poseidon table all-zero row",
                    self.q_enable,
                    offset,
                    || Value::known(F::zero()),
                )?;
                for column in poseidon_table_columns.iter().copied() {
                    region.assign_advice(
                        || "poseidon table all-zero row",
                        column,
                        offset,
                        || Value::known(F::zero()),
                    )?;
                }
                offset += 1;
                // let nil_hash =
                //     Value::known(CodeDB::empty_code_hash().to_word().to_scalar().unwrap());
                // region.assign_fixed(
                //     || "poseidon table nil input row",
                //     self.q_enable,
                //     offset,
                //     || Value::known(F::one()),
                // )?;
                // for (column, value) in poseidon_table_columns
                //     .iter()
                //     .copied()
                //     .zip(once(nil_hash).chain(repeat(Value::known(F::zero()))))
                // {
                //     region.assign_advice(
                //         || "poseidon table nil input row",
                //         column,
                //         offset,
                //         || value,
                //     )?;
                // }
                offset += 1;

                for input in inputs.clone() {
                    let mut control_len = input.len();
                    let mut first_row = true;
                    let ref_hash = Value::known(
                        CodeDB::hash(input.as_slice())
                            .to_word()
                            .to_scalar()
                            .unwrap(),
                    );
                    for row in unroll_to_hash_input_default::<F>(input.iter().copied()) {
                        assert_ne!(
                            control_len,
                            0,
                            "must have enough len left (original size {})",
                            input.len()
                        );
                        let block_size = HASHBLOCK_BYTES_IN_FIELD * row.len();
                        let control_len_as_flag =
                            F::from_u128(HASHABLE_DOMAIN_SPEC * control_len as u128);

                        region.assign_fixed(
                            || format!("poseidon table row {offset}"),
                            self.q_enable,
                            offset,
                            || Value::known(F::one()),
                        )?;
                        for (column, value) in poseidon_table_columns.iter().zip_eq(
                            once(ref_hash)
                                .chain(row.map(Value::known))
                                .chain(once(Value::known(control_len_as_flag)))
                                .chain(once(Value::known(F::zero()))) // always use domain 0 in codehash
                                .chain(once(Value::known(if first_row {
                                    F::one()
                                } else {
                                    F::zero()
                                }))),
                        ) {
                            region.assign_advice(
                                || format!("poseidon table row {offset}"),
                                *column,
                                offset,
                                || value,
                            )?;
                        }
                        first_row = false;
                        offset += 1;
                        control_len = if control_len > block_size {
                            control_len - block_size
                        } else {
                            0
                        };
                    }
                    assert_eq!(
                        control_len,
                        0,
                        "should have exhaust all bytes (original size {})",
                        input.len()
                    );
                }
                Ok(())
            },
        )
    }

    fn assign<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: [Value<F>; 6],
    ) -> Result<(), Error> {
        region.assign_fixed(
            || "assign poseidon table row value",
            self.q_enable,
            offset,
            || Value::known(F::one()),
        )?;
        let poseidon_table_columns = <PoseidonTable as LookupTable<F>>::advice_columns(self);
        for (column, value) in poseidon_table_columns.iter().zip_eq(row) {
            region.assign_advice(
                || "assign poseidon table row value",
                *column,
                offset,
                || value,
            )?;
        }
        Ok(())
    }
}

/// Tag to identify the field in a Bytecode Table row
#[derive(Clone, Copy, Debug)]
pub enum BytecodeFieldTag {
    /// Header field
    Header,
    /// Byte field
    Byte,
}
impl_expr!(BytecodeFieldTag);

/// Table with Bytecode indexed by its Code Hash
#[derive(Clone, Debug)]
pub struct BytecodeTable {
    /// Is Enabled
    pub q_enable: Column<Fixed>,
    /// Code Hash
    pub code_hash: Column<Advice>,
    /// Tag
    pub tag: Column<Advice>,
    /// Index
    pub index: Column<Advice>,
    /// Is Code is true when the byte is not an argument to a PUSH* instruction.
    pub is_code: Column<Advice>,
    /// Value
    pub value: Column<Advice>,
    /// The RLC of the PUSH data (LE order), or 0.
    /// Warning: If the bytecode is truncated, this is the actual data, without zero-padding.
    pub push_rlc: Column<Advice>,
}

impl BytecodeTable {
    /// Construct a new BytecodeTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let [tag, index, is_code, value] = array::from_fn(|_| meta.advice_column());
        let code_hash = meta.advice_column_in(SecondPhase);
        let push_rlc = meta.advice_column_in(SecondPhase);
        Self {
            q_enable: meta.fixed_column(),
            code_hash,
            tag,
            index,
            is_code,
            value,
            push_rlc,
        }
    }

    /// Assign the `BytecodeTable` from a list of bytecodes, following the same
    /// table layout that the Bytecode Circuit uses.
    pub fn dev_load<'a, F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        bytecodes: impl IntoIterator<Item = &'a Bytecode> + Clone,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "bytecode table",
            |mut region| {
                let mut offset = 0;
                let bytecode_table_columns =
                    <BytecodeTable as LookupTable<F>>::advice_columns(self);
                for bytecode in bytecodes.clone() {
                    for row in bytecode.table_assignments(challenges) {
                        region.assign_fixed(
                            || format!("bytecode table row {offset}"),
                            self.q_enable,
                            offset,
                            || Value::known(F::one()),
                        )?;
                        for (&column, value) in bytecode_table_columns.iter().zip_eq(row) {
                            region.assign_advice(
                                || format!("bytecode table row {offset}"),
                                column,
                                offset,
                                || value,
                            )?;
                        }
                        offset += 1;
                    }
                }
                Ok(())
            },
        )
    }

    /// A sub-table of bytecode without is_code nor push_rlc.
    fn columns_mini(&self) -> Vec<Column<Any>> {
        vec![
            self.q_enable.into(),
            self.code_hash.into(),
            self.tag.into(),
            self.index.into(),
            self.value.into(),
        ]
    }

    /// The expressions of the sub-table of bytecode without is_code nor push_rlc.
    pub fn table_exprs_mini<F: Field>(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        self.columns_mini()
            .iter()
            .map(|&column| meta.query_any(column, Rotation::cur()))
            .collect()
    }
}

impl<F: Field> LookupTable<F> for BytecodeTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.q_enable.into(),
            self.code_hash.into(),
            self.tag.into(),
            self.index.into(),
            self.is_code.into(),
            self.value.into(),
            self.push_rlc.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("q_enable"),
            String::from("code_hash"),
            String::from("tag"),
            String::from("index"),
            String::from("is_code"),
            String::from("value"),
            String::from("push_rlc"),
        ]
    }
}

/// Tag to identify the field in a Block Table row
// Keep the sequence consistent with OpcodeId for scalar
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter)]
pub enum BlockContextFieldTag {
    /// Null
    Null = 0,
    /// Coinbase field
    Coinbase = 1,
    /// Timestamp field
    Timestamp,
    /// Number field
    Number,
    /// Difficulty field
    Difficulty,
    /// Gas Limit field
    GasLimit,
    /// Base Fee field
    BaseFee = 8,
    /// Block Hash field
    BlockHash,
    /// Chain ID field.  Although this is not a field in the block header, we
    /// add it here for convenience.
    ChainId,
    /// In a multi-block setup, this variant represents the total number of txs
    /// included (executed) in this block.
    NumTxs,
    /// In a multi-block setup, this variant represents the cumulative number of
    /// txs included up to this block, including the txs in this block.
    CumNumTxs,
    /// In a multi-block setup, this variant represents the total number of txs
    /// included in this block which also taking skipped l1 msgs into account.
    /// This could possibly be larger than NumTxs.
    NumAllTxs,
}
impl_expr!(BlockContextFieldTag);

impl From<BlockContextFieldTag> for usize {
    fn from(value: BlockContextFieldTag) -> Self {
        value as usize
    }
}

/// Table with Block header fields
#[derive(Clone, Debug)]
pub struct BlockTable {
    /// Tag
    pub tag: Column<Fixed>,
    /// Index
    pub index: Column<Advice>,
    /// Value
    pub value: Column<Advice>,
}

impl BlockTable {
    /// Construct a new BlockTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            tag: meta.fixed_column(),
            index: meta.advice_column(),
            value: meta.advice_column_in(SecondPhase),
        }
    }

    /// Assign the `BlockTable` from a `BlockContext`.
    pub fn dev_load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        block_ctxs: &BlockContexts,
        txs: &[Transaction],
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "block table",
            |mut region| {
                let mut offset = 0;
                let block_table_columns = <BlockTable as LookupTable<F>>::advice_columns(self);
                for column in block_table_columns.iter() {
                    region.assign_advice(
                        || "block table all-zero row",
                        *column,
                        offset,
                        || Value::known(F::zero()),
                    )?;
                }
                offset += 1;

                let mut cum_num_txs = 0usize;
                for block_ctx in block_ctxs.ctxs.values() {
                    let num_txs = txs
                        .iter()
                        .filter(|tx| tx.block_number == block_ctx.number.as_u64())
                        .count();
                    cum_num_txs += num_txs;
                    for row in block_ctx.table_assignments(num_txs, cum_num_txs, 0, challenges) {
                        region.assign_fixed(
                            || format!("block table row {offset}"),
                            self.tag,
                            offset,
                            || row[0],
                        )?;
                        for (column, value) in block_table_columns.iter().zip_eq(&row[1..]) {
                            region.assign_advice(
                                || format!("block table row {offset}"),
                                *column,
                                offset,
                                || *value,
                            )?;
                        }
                        offset += 1;
                    }
                }

                Ok(())
            },
        )
    }
}

impl<F: Field> LookupTable<F> for BlockTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![self.tag.into(), self.index.into(), self.value.into()]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("tag"),
            String::from("index"),
            String::from("value"),
        ]
    }
}

/// Keccak Table, used to verify keccak hashing from RLC'ed input.
#[derive(Clone, Debug)]
pub struct KeccakTable {
    /// True when the row is enabled
    pub q_enable: Column<Fixed>,
    /// True when the row is final
    pub is_final: Column<Advice>,
    /// Byte array input as `RLC(reversed(input))`
    pub input_rlc: Column<Advice>, // RLC of input bytes
    /// Byte array input length
    pub input_len: Column<Advice>,
    /// RLC of the hash result
    pub output_rlc: Column<Advice>, // RLC of hash of input bytes
}

impl<F: Field> LookupTable<F> for KeccakTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.q_enable.into(),
            self.is_final.into(),
            self.input_rlc.into(),
            self.input_len.into(),
            self.output_rlc.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("q_enable"),
            String::from("is_final"),
            String::from("input_rlc"),
            String::from("input_len"),
            String::from("output_rlc"),
        ]
    }
}

impl KeccakTable {
    /// Construct a new KeccakTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            q_enable: meta.fixed_column(),
            is_final: meta.advice_column(),
            input_rlc: meta.advice_column_in(SecondPhase),
            input_len: meta.advice_column(),
            output_rlc: meta.advice_column_in(SecondPhase),
        }
    }

    /// Generate the keccak table assignments from a byte array input.
    /// Used only for dev_load
    pub fn assignments<F: Field>(
        input: &[u8],
        challenges: &Challenges<Value<F>>,
    ) -> Vec<[Value<F>; 4]> {
        let input_rlc = challenges
            .keccak_input()
            .map(|challenge| rlc::value(input.iter().rev(), challenge));
        let input_len = F::from(input.len() as u64);
        let mut keccak = Keccak::default();
        keccak.update(input);
        let output = keccak.digest();
        let output_rlc = challenges.evm_word().map(|challenge| {
            rlc::value(
                &Word::from_big_endian(output.as_slice()).to_le_bytes(),
                challenge,
            )
        });

        vec![[
            Value::known(F::one()),
            input_rlc,
            Value::known(input_len),
            output_rlc,
        ]]
    }

    /// Assign a table row for keccak table
    /// Used inside keccak circuit
    /// q_enable assigned inside keccak circuit
    pub fn assign_row<F: Field>(
        &self,
        region: &mut Region<F>,
        offset: usize,
        values: [Value<F>; 4],
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let mut res = vec![];
        for (&column, value) in <KeccakTable as LookupTable<F>>::advice_columns(self)
            .iter()
            .zip(values.iter())
        {
            res.push(region.assign_advice(
                || format!("assign {offset}"),
                column,
                offset,
                || *value,
            )?);
        }
        Ok(res)
    }
    /// Provide this function for the case that we want to consume a keccak
    /// table but without running the full keccak circuit
    pub fn dev_load<'a, F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        inputs: impl IntoIterator<Item = &'a Vec<u8>> + Clone,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "keccak table",
            |mut region| {
                let mut offset = 0;
                for column in <KeccakTable as LookupTable<F>>::advice_columns(self) {
                    region.assign_fixed(
                        || "keccak table all-zero row",
                        self.q_enable,
                        offset,
                        || Value::known(F::one()),
                    )?;
                    region.assign_advice(
                        || "keccak table all-zero row",
                        column,
                        offset,
                        || Value::known(F::zero()),
                    )?;
                }
                offset += 1;

                let keccak_table_columns = <KeccakTable as LookupTable<F>>::advice_columns(self);
                for input in inputs.clone() {
                    for row in Self::assignments(input, challenges) {
                        region.assign_fixed(
                            || format!("keccak table row {offset}"),
                            self.q_enable,
                            offset,
                            || Value::known(F::one()),
                        )?;
                        for (&column, value) in keccak_table_columns.iter().zip_eq(row) {
                            region.assign_advice(
                                || format!("keccak table row {offset}"),
                                column,
                                offset,
                                || value,
                            )?;
                        }
                        offset += 1;
                    }
                }
                Ok(())
            },
        )
    }

    /// returns matchings between the circuit columns passed as parameters and
    /// the table columns
    pub fn match_columns(
        &self,
        value_rlc: Column<Advice>,
        length: Column<Advice>,
        code_hash: Column<Advice>,
    ) -> Vec<(Column<Advice>, Column<Advice>)> {
        vec![
            (value_rlc, self.input_rlc),
            (length, self.input_len),
            (code_hash, self.output_rlc),
        ]
    }
}

/// SHA256 Table, used to verify SHA256 hashing from RLC'ed input in precompile.
#[derive(Clone, Debug)]
pub struct SHA256Table {
    /// True when the row is enabled
    pub q_enable: Column<Fixed>,
    /// True when the row is final
    pub is_final: Column<Advice>,
    /// Byte array input as `RLC(reversed(input))`
    pub input_rlc: Column<Advice>, // RLC of input bytes
    /// Byte array input length
    pub input_len: Column<Advice>,
    /// RLC of the hash result
    pub output_rlc: Column<Advice>, // RLC of hash of input bytes
}

impl<F: Field> LookupTable<F> for SHA256Table {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.q_enable.into(),
            self.is_final.into(),
            self.input_rlc.into(),
            self.input_len.into(),
            self.output_rlc.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("q_enable"),
            String::from("is_final"),
            String::from("input_rlc"),
            String::from("input_len"),
            String::from("output_rlc"),
        ]
    }
}

impl SHA256Table {
    /// Construct a new KeccakTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            q_enable: meta.fixed_column(),
            is_final: meta.advice_column(),
            input_len: meta.advice_column(),
            input_rlc: meta.advice_column_in(SecondPhase),
            output_rlc: meta.advice_column_in(SecondPhase),
        }
    }

    /// Generate the sha256 table assignments from a byte array pair of input/output.
    /// Used only for dev_load
    pub fn assignments<F: Field>(
        entry: (&[u8], &[u8; 32]),
        challenges: &Challenges<Value<F>>,
    ) -> Vec<[Value<F>; 4]> {
        let (input, output) = entry;
        let input_len = Value::known(F::from(input.len() as u64));
        let input_rlc = challenges
            .keccak_input()
            .map(|challenge| rlc::value(input.iter().rev(), challenge));
        let output_rlc = challenges
            .keccak_input()
            .map(|challenge| rlc::value(&Word::from_big_endian(output).to_le_bytes(), challenge));

        vec![[Value::known(F::one()), input_rlc, input_len, output_rlc]]
    }

    /// Provide this function for the case that we want to consume a sha256
    /// table but without running the full sha256 circuit
    pub fn dev_load<'a, F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        entries: impl IntoIterator<Item = (&'a Vec<u8>, &'a [u8; 32])> + Clone,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "sha256 table dev",
            |mut region| {
                let mut offset = 0;
                for column in <Self as LookupTable<F>>::advice_columns(self) {
                    region.assign_fixed(
                        || "sha256 table all-zero row",
                        self.q_enable,
                        offset,
                        || Value::known(F::one()),
                    )?;
                    region.assign_advice(
                        || "sha256 table all-zero row",
                        column,
                        offset,
                        || Value::known(F::zero()),
                    )?;
                }
                offset += 1;

                let table_columns = <Self as LookupTable<F>>::advice_columns(self);
                for (input, digest) in entries.clone() {
                    for row in Self::assignments((input, digest), challenges) {
                        region.assign_fixed(
                            || format!("table row {offset}"),
                            self.q_enable,
                            offset,
                            || Value::known(F::one()),
                        )?;
                        for (&column, value) in table_columns.iter().zip_eq(row) {
                            region.assign_advice(
                                || format!("table row {offset}"),
                                column,
                                offset,
                                || value,
                            )?;
                        }
                        offset += 1;
                    }
                }
                Ok(())
            },
        )
    }
}

/// Copy Table, used to verify copies of byte chunks between Memory, Bytecode,
/// TxLogs and TxCallData.
#[derive(Clone, Copy, Debug)]
pub struct CopyTable {
    /// Is enable
    pub q_enable: Column<Fixed>,
    /// Whether the row is the first read-write pair for a copy event.
    pub is_first: Column<Advice>,
    /// The relevant ID for the read-write row, represented as a random linear
    /// combination. The ID may be one of the below:
    /// 1. Call ID/Caller ID for CopyDataType::Memory
    /// 2. RLC encoding of bytecode hash for CopyDataType::Bytecode
    /// 3. Transaction ID for CopyDataType::TxCalldata, CopyDataType::TxLog
    pub id: Column<Advice>,
    /// The source/destination address for this copy step.  Can be memory
    /// address, byte index in the bytecode, tx call data, and tx log data.
    pub addr: Column<Advice>,
    /// The end of the source buffer for the copy event.  Any data read from an
    /// address greater than or equal to this value will be 0.
    pub src_addr_end: Column<Advice>,
    /// The number of non-masked bytes left to be copied.
    pub real_bytes_left: Column<Advice>,
    /// mask indicates the byte is actual coped or padding to memory word
    pub value_wrod_rlc: Column<Advice>, // TODO: rm
    /// mask indicates the byte is actual coped or padding to memory word
    //pub mask: Column<Advice>,
    /// An accumulator value in the RLC representation. This is used for
    /// specific purposes, for instance, when `tag == CopyDataType::RlcAcc`.
    /// Having an additional column for the `rlc_acc` simplifies the lookup
    /// to copy table.
    pub rlc_acc: Column<Advice>,
    /// The associated read-write counter for this row.
    pub rw_counter: Column<Advice>,
    /// Decrementing counter denoting reverse read-write counter.
    pub rwc_inc_left: Column<Advice>,
    /// Binary chip to constrain the copy table conditionally depending on the
    /// current row's tag, whether it is Bytecode, Memory, TxCalldata or
    /// TxLog. This also now includes various precompile calls, hence will take up more cells.
    pub tag: BinaryNumberConfig<CopyDataType, { CopyDataType::N_BITS }>,
}

type CopyTableRow<F> = [(Value<F>, &'static str); 8];
type CopyCircuitRow<F> = [(Value<F>, &'static str); 10];

/// CopyThread is the state used while generating rows of the copy table.
struct CopyThread<F: Field> {
    tag: CopyDataType,
    is_rw: bool,
    id: Value<F>,
    front_mask: bool,
    addr: u64,
    addr_end: u64,
    bytes_left: u64,
    value_acc: Value<F>,
    word_rlc: Value<F>,
    word_rlc_prev: Value<F>,
}

impl CopyTable {
    /// Construct a new CopyTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>, q_enable: Column<Fixed>) -> Self {
        Self {
            q_enable,
            is_first: meta.advice_column(),
            id: meta.advice_column_in(SecondPhase),
            tag: BinaryNumberChip::configure(meta, q_enable, None),
            addr: meta.advice_column(),
            src_addr_end: meta.advice_column(),
            real_bytes_left: meta.advice_column(),
            value_wrod_rlc: meta.advice_column(), // TODO: rm
            rlc_acc: meta.advice_column_in(SecondPhase),
            rw_counter: meta.advice_column(),
            rwc_inc_left: meta.advice_column(),
        }
    }

    /// Generate the copy table and copy circuit assignments from a copy event.
    pub fn assignments<F: Field>(
        copy_event: &CopyEvent,
        challenges: Challenges<Value<F>>,
    ) -> Vec<(CopyDataType, CopyTableRow<F>, CopyCircuitRow<F>)> {
        assert!(copy_event.src_addr_end >= copy_event.src_addr);
        assert!(
            copy_event.src_type != CopyDataType::Padding
                && copy_event.dst_type != CopyDataType::Padding,
            "Padding is an internal type"
        );

        let mut assignments = Vec::new();
        // rlc_acc
        let rlc_acc = if copy_event.has_rlc() {
            let values = copy_event
                .copy_bytes
                .bytes
                .iter()
                .filter(|(_, _, mask)| !mask)
                .map(|(value, _, _)| *value)
                .collect::<Vec<u8>>();

            challenges
                .keccak_input()
                .map(|keccak_input| rlc::value(values.iter().rev(), keccak_input))
        } else {
            Value::known(F::zero())
        };

        let read_steps = copy_event.copy_bytes.bytes.iter();
        let copy_steps = if let Some(ref write_steps) = copy_event.copy_bytes.aux_bytes {
            read_steps.zip(write_steps.iter())
        } else {
            read_steps.zip(copy_event.copy_bytes.bytes.iter())
        };

        let prev_write_bytes: Vec<u8> = copy_event
            .copy_bytes
            .bytes_write_prev
            .clone()
            .unwrap_or_default();

        let mut rw_counter = copy_event.rw_counter_start();
        let mut rwc_inc_left = copy_event.rw_counter_delta();

        let mut reader = CopyThread {
            tag: copy_event.src_type,
            is_rw: copy_event.is_source_rw(),
            id: number_or_hash_to_field(&copy_event.src_id, challenges.evm_word()),
            front_mask: true,
            addr: copy_event.src_addr,
            addr_end: copy_event.src_addr_end,
            bytes_left: copy_event.copy_length(),
            value_acc: Value::known(F::zero()),
            word_rlc: Value::known(F::zero()),
            word_rlc_prev: Value::known(F::zero()),
        };

        let mut writer = CopyThread {
            tag: copy_event.dst_type,
            is_rw: copy_event.is_destination_rw(),
            id: number_or_hash_to_field(&copy_event.dst_id, challenges.evm_word()),
            front_mask: true,
            addr: copy_event.dst_addr,
            addr_end: copy_event.dst_addr + copy_event.full_length(),
            bytes_left: reader.bytes_left,
            value_acc: Value::known(F::zero()),
            word_rlc: Value::known(F::zero()),
            word_rlc_prev: Value::known(F::zero()),
        };

        let is_access_list = copy_event.src_type == CopyDataType::AccessListAddresses
            || copy_event.src_type == CopyDataType::AccessListStorageKeys;
        for (step_idx, (is_read_step, mut copy_step)) in copy_steps
            .flat_map(|(read_step, write_step)| {
                let read_step = CopyStep {
                    value: read_step.0,
                    prev_value: read_step.0,
                    mask: read_step.2,
                };
                let write_step = CopyStep {
                    value: write_step.0,
                    // Will overwrite if previous values are given.
                    prev_value: write_step.0,
                    mask: write_step.2,
                };
                once((true, read_step)).chain(once((false, write_step)))
            })
            .enumerate()
        {
            // re-assign with correct `prev_value` in copy_step
            if !is_read_step && !prev_write_bytes.is_empty() {
                copy_step.prev_value = *prev_write_bytes.get(step_idx / 2).unwrap();
            }
            let copy_step = copy_step;

            let thread = if is_read_step {
                &mut reader
            } else {
                &mut writer
            };

            let is_first = step_idx == 0;
            let is_last = step_idx as u64 == copy_event.full_length() * 2 - 1;

            let is_pad = is_read_step && thread.addr >= thread.addr_end;

            let [value, value_prev] = if is_access_list {
                // Save address, storage_key, storage_key_index and is_warm_prev
                // to column value_word_rlc, value_word_rlc_prev, value and
                // value_prev in copy circuit.
                let access_list = &copy_event.access_list[step_idx / 2];

                [
                    F::from(access_list.storage_key_index),
                    F::from(access_list.is_warm_prev),
                ]
            } else {
                [
                    F::from(copy_step.value as u64),
                    F::from(copy_step.prev_value as u64),
                ]
            }
            .map(Value::known);

            let value_or_pad = if is_pad {
                Value::known(F::zero())
            } else {
                value
            };

            if !copy_step.mask {
                thread.front_mask = false;
                thread.value_acc = thread.value_acc * challenges.keccak_input() + value_or_pad;
            }
            if (step_idx / 2) % 32 == 0 {
                // reset
                thread.word_rlc = Value::known(F::zero());
                thread.word_rlc_prev = Value::known(F::zero());
            }
            thread.word_rlc = thread.word_rlc * challenges.evm_word() + value;
            thread.word_rlc_prev = if is_read_step {
                thread.word_rlc // Reader does not change the word.
            } else {
                thread.word_rlc_prev * challenges.evm_word() + value_prev
            };

            if is_access_list {
                // Save address, storage_key, storage_key_index and is_warm_prev
                // to column value_word_rlc, value_word_rlc_prev, value and
                // value_prev in copy circuit.
                let access_list = &copy_event.access_list[step_idx / 2];

                thread.word_rlc = Value::known(access_list.address.to_scalar().unwrap());
                thread.word_rlc_prev = challenges
                    .evm_word()
                    .map(|challenge| rlc::value(&access_list.storage_key.to_le_bytes(), challenge));
            }

            let word_index = (step_idx as u64 / 2) % 32;

            // For LOG, format the address including the log_id.
            let addr = if thread.tag == CopyDataType::TxLog {
                build_tx_log_address(thread.addr, TxLogFieldTag::Data, copy_event.log_id.unwrap())
                    .to_scalar()
                    .unwrap()
            } else {
                F::from(thread.addr)
            };

            assignments.push((
                thread.tag,
                [
                    (Value::known(F::from(is_first)), "is_first"),
                    (thread.id, "id"),
                    (Value::known(addr), "addr"),
                    (Value::known(F::from(thread.addr_end)), "src_addr_end"),
                    (Value::known(F::from(thread.bytes_left)), "real_bytes_left"),
                    (rlc_acc, "rlc_acc"),
                    (Value::known(F::from(rw_counter)), "rw_counter"),
                    (Value::known(F::from(rwc_inc_left)), "rwc_inc_left"),
                ],
                [
                    (Value::known(F::from(is_last)), "is_last"),
                    (value, "value"),
                    (value_prev, "value_prev"),
                    (thread.word_rlc, "value_word_rlc"),
                    (thread.word_rlc_prev, "value_word_rlc_prev"),
                    (thread.value_acc, "value_acc"),
                    (Value::known(F::from(is_pad)), "is_pad"),
                    (Value::known(F::from(copy_step.mask)), "mask"),
                    (Value::known(F::from(thread.front_mask)), "front_mask"),
                    (Value::known(F::from(word_index)), "word_index"),
                ],
            ));

            // Increment the address.
            if !thread.front_mask {
                thread.addr += 1;
            }
            // Decrement the number of steps left.
            if !copy_step.mask {
                thread.bytes_left -= 1;
            }
            // No word operation for access list data types.
            let is_row_end = is_access_list || (step_idx / 2) % 32 == 31;
            // Update the RW counter.
            if is_row_end && thread.is_rw {
                rw_counter += 1;
                rwc_inc_left -= 1;
            }
        }
        assignments
    }

    /// Assign the `CopyTable` from a `Block`.
    pub fn dev_load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        block: &Block<F>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "copy table",
            |mut region| {
                let mut offset = 0;
                region.assign_fixed(
                    || "copy table all-zero row",
                    self.q_enable,
                    offset,
                    || Value::known(F::one()),
                )?;
                for column in <CopyTable as LookupTable<F>>::advice_columns(self) {
                    region.assign_advice(
                        || "copy table all-zero row",
                        column,
                        offset,
                        || Value::known(F::zero()),
                    )?;
                }
                offset += 1;

                let tag_chip = BinaryNumberChip::construct(self.tag);
                let copy_table_columns = <CopyTable as LookupTable<F>>::advice_columns(self);
                for copy_event in block.copy_events.iter() {
                    for (tag, row, _) in Self::assignments(copy_event, *challenges) {
                        region.assign_fixed(
                            || format!("q_enable at row: {offset}"),
                            self.q_enable,
                            offset,
                            || Value::known(F::one()),
                        )?;
                        for (&column, (value, label)) in copy_table_columns.iter().zip_eq(row) {
                            region.assign_advice(
                                || format!("{label} at row: {offset}"),
                                column,
                                offset,
                                || value,
                            )?;
                        }
                        tag_chip.assign(&mut region, offset, &tag)?;
                        offset += 1;
                    }
                }

                Ok(())
            },
        )
    }
}

impl<F: Field> LookupTable<F> for CopyTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.q_enable.into(),
            self.is_first.into(),
            self.id.into(),
            self.addr.into(),
            self.src_addr_end.into(),
            self.real_bytes_left.into(),
            self.rlc_acc.into(),
            self.rw_counter.into(),
            self.rwc_inc_left.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("q_enable"),
            String::from("is_first"),
            String::from("id"),
            String::from("addr"),
            String::from("src_addr_end"),
            String::from("real_bytes_left"),
            String::from("rlc_acc"),
            String::from("rw_counter"),
            String::from("rwc_inc_left"),
        ]
    }

    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        vec![
            meta.query_fixed(self.q_enable, Rotation::cur()),
            meta.query_advice(self.is_first, Rotation::cur()),
            meta.query_advice(self.id, Rotation::cur()), // src_id
            self.tag.value(Rotation::cur())(meta),       // src_tag
            meta.query_advice(self.id, Rotation::next()), // dst_id
            self.tag.value(Rotation::next())(meta),      // dst_tag
            meta.query_advice(self.addr, Rotation::cur()), // src_addr
            meta.query_advice(self.src_addr_end, Rotation::cur()), // src_addr_end
            meta.query_advice(self.addr, Rotation::next()), // dst_addr
            meta.query_advice(self.real_bytes_left, Rotation::cur()), // real_length
            meta.query_advice(self.rlc_acc, Rotation::cur()), // rlc_acc
            meta.query_advice(self.rw_counter, Rotation::cur()), // rw_counter
            meta.query_advice(self.rwc_inc_left, Rotation::cur()), // rwc_inc_left
        ]
    }
}

/// Lookup table within the Exponentiation circuit.
#[derive(Clone, Copy, Debug)]
pub struct ExpTable {
    /// Whether the row is enabled.
    pub q_enable: Column<Fixed>,
    /// Whether the row is the start of a step.
    pub is_step: Column<Fixed>,
    /// Whether this row is the last row in the exponentiation operation's
    /// trace.
    pub is_last: Column<Advice>,
    /// The integer base of the exponentiation.
    pub base_limb: Column<Advice>,
    /// The integer exponent of the exponentiation.
    pub exponent_lo_hi: Column<Advice>,
    /// The intermediate result of exponentiation by squaring.
    pub exponentiation_lo_hi: Column<Advice>,
}

impl ExpTable {
    /// Construct the Exponentiation table.
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            q_enable: meta.fixed_column(),
            is_step: meta.fixed_column(),
            is_last: meta.advice_column(),
            base_limb: meta.advice_column(),
            exponent_lo_hi: meta.advice_column(),
            exponentiation_lo_hi: meta.advice_column(),
        }
    }

    /// Given an exponentiation event and randomness, get assignments to the
    /// exponentiation table.
    pub fn assignments<F: Field>(exp_event: &ExpEvent) -> Vec<[F; 4]> {
        let mut assignments = Vec::new();
        let base_limbs = split_u256_limb64(&exp_event.base);
        let mut exponent = exp_event.exponent;
        for (step_idx, exp_step) in exp_event.steps.iter().rev().enumerate() {
            let is_last = if step_idx == exp_event.steps.len() - 1 {
                F::one()
            } else {
                F::zero()
            };
            let (exp_lo, exp_hi) = split_u256(&exp_step.d);
            let (exponent_lo, exponent_hi) = split_u256(&exponent);

            // row 1
            assignments.push([
                is_last,
                base_limbs[0].as_u64().into(),
                exponent_lo
                    .to_scalar()
                    .expect("exponent should fit to scalar"),
                exp_lo
                    .to_scalar()
                    .expect("exponentiation lo should fit to scalar"),
            ]);
            // row 2
            assignments.push([
                F::zero(),
                base_limbs[1].as_u64().into(),
                exponent_hi
                    .to_scalar()
                    .expect("exponent hi should fit to scalar"),
                exp_hi
                    .to_scalar()
                    .expect("exponentiation hi should fit to scalar"),
            ]);
            // row 3
            assignments.push([
                F::zero(),
                base_limbs[2].as_u64().into(),
                F::zero(),
                F::zero(),
            ]);
            // row 4
            assignments.push([
                F::zero(),
                base_limbs[3].as_u64().into(),
                F::zero(),
                F::zero(),
            ]);
            for _ in ROWS_PER_STEP..OFFSET_INCREMENT {
                assignments.push([F::zero(), F::zero(), F::zero(), F::zero()]);
            }

            // update intermediate exponent.
            let (exponent_div2, remainder) = exponent.div_mod(U256::from(2));
            if remainder.is_zero() {
                // exponent is even
                exponent = exponent_div2;
            } else {
                // exponent is odd
                exponent = exponent - 1;
            }
        }
        assignments
    }

    /// Assign witness data from a block to the exponentiation table.
    pub fn dev_load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        block: &Block<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "exponentiation table",
            |mut region| {
                let mut offset = 0;
                let exp_table_columns = <ExpTable as LookupTable<F>>::advice_columns(self);
                for exp_event in block.exp_events.iter() {
                    for row in Self::assignments::<F>(exp_event) {
                        region.assign_fixed(
                            || format!("exponentiation table row {offset}"),
                            self.q_enable,
                            offset,
                            || Value::known(F::one()),
                        )?;
                        for (&column, value) in exp_table_columns.iter().zip_eq(row) {
                            region.assign_advice(
                                || format!("exponentiation table row {offset}"),
                                column,
                                offset,
                                || Value::known(value),
                            )?;
                        }
                        let is_step = if offset % OFFSET_INCREMENT == 0 {
                            F::one()
                        } else {
                            F::zero()
                        };
                        region.assign_fixed(
                            || format!("exponentiation table row {offset}"),
                            self.is_step,
                            offset,
                            || Value::known(is_step),
                        )?;
                        offset += 1;
                    }
                }

                // pad an empty row
                let row = [F::from_u128(0); 4];
                region.assign_fixed(
                    || format!("exponentiation table row {offset}"),
                    self.q_enable,
                    offset,
                    || Value::known(F::one()),
                )?;
                for (column, value) in exp_table_columns.iter().zip_eq(row) {
                    region.assign_advice(
                        || format!("exponentiation table row {offset}"),
                        *column,
                        offset,
                        || Value::known(value),
                    )?;
                }

                Ok(())
            },
        )
    }
}

impl<F: Field> LookupTable<F> for ExpTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.q_enable.into(),
            self.is_step.into(),
            self.is_last.into(),
            self.base_limb.into(),
            self.exponent_lo_hi.into(),
            self.exponentiation_lo_hi.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("q_enable"),
            String::from("is_step"),
            String::from("is_last"),
            String::from("base_limb"),
            String::from("exponent_lo_hi"),
            String::from("exponentiation_lo_hi"),
        ]
    }

    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        vec![
            meta.query_fixed(self.q_enable, Rotation::cur()),
            meta.query_fixed(self.is_step, Rotation::cur()),
            meta.query_advice(self.base_limb, Rotation::cur()),
            meta.query_advice(self.base_limb, Rotation::next()),
            meta.query_advice(self.base_limb, Rotation(2)),
            meta.query_advice(self.base_limb, Rotation(3)),
            meta.query_advice(self.exponent_lo_hi, Rotation::cur()),
            meta.query_advice(self.exponent_lo_hi, Rotation::next()),
            meta.query_advice(self.exponentiation_lo_hi, Rotation::cur()),
            meta.query_advice(self.exponentiation_lo_hi, Rotation::next()),
        ]
    }
}

/// The RLP table connected to the RLP state machine circuit.
#[derive(Clone, Copy, Debug)]
pub struct RlpFsmRlpTable {
    /// Whether the row is enabled.
    pub q_enable: Column<Fixed>,
    /// The transaction's index in the chunk.
    pub tx_id: Column<Advice>,
    /// The format of the tx being decoded.
    pub format: Column<Advice>,
    /// The RLP-Tag assigned at the current row.
    pub rlp_tag: Column<Advice>,
    /// The actual value of the current tag being decoded.
    pub tag_value: Column<Advice>,
    /// RLC of the tag's big-endian bytes
    pub tag_bytes_rlc: Column<Advice>,
    /// The actual length of bytes of the current tag being decoded.
    pub tag_length: Column<Advice>,
    /// Whether or not the row emits an output value.
    pub is_output: Column<Advice>,
    /// Whether or not the current tag's value was nil.
    pub is_none: Column<Advice>,
    /// Index of access list address
    pub access_list_idx: Column<Advice>,
    /// Index of storage key in an access list item
    pub storage_key_idx: Column<Advice>,
}

impl<F: Field> LookupTable<F> for RlpFsmRlpTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.q_enable.into(),
            self.tx_id.into(),
            self.format.into(),
            self.rlp_tag.into(),
            self.tag_value.into(),
            self.tag_bytes_rlc.into(),
            self.tag_length.into(),
            self.is_output.into(),
            self.is_none.into(),
            self.access_list_idx.into(),
            self.storage_key_idx.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("q_enable"),
            String::from("tx_id"),
            String::from("format"),
            String::from("rlp_tag"),
            String::from("tag_value_acc"),
            String::from("tag_bytes_rlc"),
            String::from("tag_length"),
            String::from("is_output"),
            String::from("is_none"),
            String::from("access_list_idx"),
            String::from("storage_key_idx"),
        ]
    }
}

impl RlpFsmRlpTable {
    /// Construct the RLP table.
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            q_enable: meta.fixed_column(),
            tx_id: meta.advice_column(),
            format: meta.advice_column(),
            rlp_tag: meta.advice_column(),
            tag_value: meta.advice_column_in(SecondPhase),
            tag_bytes_rlc: meta.advice_column_in(SecondPhase),
            tag_length: meta.advice_column(),
            is_output: meta.advice_column(),
            is_none: meta.advice_column(),
            access_list_idx: meta.advice_column(),
            storage_key_idx: meta.advice_column(),
        }
    }

    /// Load the RLP table (only for dev).
    pub fn dev_load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        txs: Vec<Transaction>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        let rows = txs
            .into_iter()
            .flat_map(|tx| tx.gen_sm_witness(challenges))
            .filter(|row| row.rlp_table.is_output)
            .map(|row| row.rlp_table)
            .collect::<Vec<_>>();

        let assign_any = |region: &mut Region<'_, F>,
                          annotation: &'static str,
                          col: Column<Any>,
                          row: usize,
                          value: Value<F>| {
            match *(col.column_type()) {
                Any::Fixed => {
                    region.assign_fixed(|| annotation, col.try_into().unwrap(), row, || value)
                }
                Any::Advice(_) => {
                    region.assign_advice(|| annotation, col.try_into().unwrap(), row, || value)
                }
                Any::Instance => unreachable!("we do not assign to instance column"),
            }
        };

        layouter.assign_region(
            || "RLP dev table",
            |mut region| {
                for (i, row) in rows.iter().enumerate() {
                    let cells: Vec<(&'static str, Column<Any>, Value<F>)> = vec![
                        ("q_enable", self.q_enable.into(), Value::known(F::one())),
                        ("tx_id", self.tx_id.into(), Value::known(F::from(row.tx_id))),
                        (
                            "format",
                            self.format.into(),
                            Value::known(F::from(usize::from(row.format) as u64)),
                        ),
                        (
                            "rlp_tag",
                            self.rlp_tag.into(),
                            Value::known(F::from(usize::from(row.rlp_tag) as u64)),
                        ),
                        ("tag_value", self.tag_value.into(), row.tag_value),
                        (
                            "tag_bytes_rlc",
                            self.tag_bytes_rlc.into(),
                            row.tag_bytes_rlc,
                        ),
                        (
                            "tag_length",
                            self.tag_length.into(),
                            Value::known(F::from(row.tag_length as u64)),
                        ),
                        ("is_output", self.is_output.into(), Value::known(F::one())),
                        (
                            "is_none",
                            self.is_none.into(),
                            Value::known(F::from(row.is_none as u64)),
                        ),
                        (
                            "access_list_idx",
                            self.access_list_idx.into(),
                            Value::known(F::from(row.access_list_idx)),
                        ),
                        (
                            "storage_key_idx",
                            self.storage_key_idx.into(),
                            Value::known(F::from(row.storage_key_idx)),
                        ),
                    ];

                    for cell in cells.into_iter() {
                        assign_any(&mut region, cell.0, cell.1, i, cell.2)?;
                    }
                }
                Ok(())
            },
        )?;

        Ok(())
    }
}

/// The sig table is used to verify signatures, used in tx circuit and ecrecover precompile.
#[derive(Clone, Copy, Debug)]
pub struct SigTable {
    /// Indicates whether or not the gates are enabled on the current row.
    pub q_enable: Column<Fixed>,
    /// Random-linear combination of the Keccak256 hash of the message that's signed.
    pub msg_hash_rlc: Column<Advice>,
    /// should be in range [0, 1]
    pub sig_v: Column<Advice>,
    /// Random-linear combination of the signature's `r` component.
    pub sig_r_rlc: Column<Advice>,
    /// Random-linear combination of the signature's `s` component.
    pub sig_s_rlc: Column<Advice>,
    /// The recovered address, i.e. the 20-bytes address that must have signed the message.
    pub recovered_addr: Column<Advice>,
    /// Indicates whether or not the signature is valid or not upon signature verification.
    pub is_valid: Column<Advice>,
}

impl SigTable {
    /// Construct the SigTable.
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            q_enable: meta.fixed_column(),
            msg_hash_rlc: meta.advice_column_in(SecondPhase),
            sig_v: meta.advice_column(),
            sig_s_rlc: meta.advice_column_in(SecondPhase),
            sig_r_rlc: meta.advice_column_in(SecondPhase),
            recovered_addr: meta.advice_column(),
            is_valid: meta.advice_column(),
        }
    }

    /// Assign witness data from a block to the verification table.
    pub fn dev_load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        block: &Block<F>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "sig table (dev load)",
            |mut region| {
                let signatures: Vec<SignData> = block.get_sign_data(false);

                let evm_word = challenges.evm_word();
                for (offset, sign_data) in signatures.iter().enumerate() {
                    let msg_hash_rlc = evm_word.map(|challenge| {
                        rlc::value(
                            sign_data.msg_hash.to_bytes().iter().collect_vec(),
                            challenge,
                        )
                    });
                    let sig_r_rlc = evm_word.map(|challenge| {
                        rlc::value(
                            sign_data.signature.0.to_bytes().iter().collect_vec(),
                            challenge,
                        )
                    });
                    let sig_s_rlc = evm_word.map(|challenge| {
                        rlc::value(
                            sign_data.signature.1.to_bytes().iter().collect_vec(),
                            challenge,
                        )
                    });
                    let sig_v = Value::known(F::from(sign_data.signature.2 as u64));
                    let recovered_addr = Value::known(sign_data.get_addr().to_scalar().unwrap());
                    region.assign_fixed(
                        || format!("sig table q_enable {offset}"),
                        self.q_enable,
                        offset,
                        || Value::known(F::one()),
                    )?;
                    for (column_name, column, value) in [
                        ("msg_hash_rlc", self.msg_hash_rlc, msg_hash_rlc),
                        ("sig_v", self.sig_v, sig_v),
                        ("sig_r_rlc", self.sig_r_rlc, sig_r_rlc),
                        ("sig_s_rlc", self.sig_s_rlc, sig_s_rlc),
                        ("recovered_addr", self.recovered_addr, recovered_addr),
                        (
                            "is_valid",
                            self.is_valid,
                            Value::known(F::from(!sign_data.get_addr().is_zero())),
                        ),
                    ] {
                        region.assign_advice(
                            || format!("sig table {column_name} {offset}"),
                            column,
                            offset,
                            || value,
                        )?;
                    }
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}

impl<F: Field> LookupTable<F> for SigTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.q_enable.into(),
            self.msg_hash_rlc.into(),
            self.sig_v.into(),
            self.sig_r_rlc.into(),
            self.sig_s_rlc.into(),
            self.recovered_addr.into(),
            self.is_valid.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("q_enable"),
            String::from("msg_hash_rlc"),
            String::from("sig_v"),
            String::from("sig_r_rlc"),
            String::from("sig_s_rlc"),
            String::from("recovered_addr"),
            String::from("is_valid"),
        ]
    }
}

/// 1. if EcAdd(P, Q) == R then: (arg1_rlc, arg2_rlc, arg3_rlc, arg4_rlc) \mapsto (output1_rlc,
///    output2_rlc).
///
///     where arg1_rlc = rlc(P.x), arg2_rlc = rlc(P.y),
///           arg3_rlc = rlc(Q.x), arg4_rlc = rlc(Q.x),
///           output1_rlc = rlc(R.x), output2_rlc = rlc(R.y),
///
/// 2. if EcMul(P, s) == R then: (arg1_rlc, arg2_rlc, arg3_rlc) \mapsto (output1_rlc, output2_rlc).
///
///     where arg1_rlc = rlc(P.x), arg2_rlc = rlc(P.y),
///           arg3_rlc = s
///           output1_rlc = rlc(R.x), output2_rlc = rlc(R.y),
///
/// 3. EcPairing:
///    - arg*_rlc <- 0
///    - input_rlc <- RLC over all input bytes
///    - output1_rlc <- success {0, 1}
#[derive(Clone, Copy, Debug)]
pub struct EccTable {
    /// Since the current design of the ECC circuit reserves fixed number of rows for EcAdd, EcMul
    /// and EcPairing ops respectively, we already know the `op_type` for each row.
    pub op_type: Column<Fixed>,
    /// Indicates whether or not the EVM inputs were valid.
    pub is_valid: Column<Advice>,
    /// Advice column for input argument 1= RLC(input_bytes[0..32]).
    pub arg1_rlc: Column<Advice>,
    /// Advice column for input argument 2= RLC(input_bytes[32..64]).
    pub arg2_rlc: Column<Advice>,
    /// Advice column for input argument 3= RLC(input_bytes[64..96]).
    pub arg3_rlc: Column<Advice>,
    /// Advice column for input argument 4= RLC(input_bytes[96..128]).
    pub arg4_rlc: Column<Advice>,
    /// Advice column for RLC of all input bytes= RLC(input_bytes).
    pub input_rlc: Column<Advice>,
    /// Advice column for output 1= RLC(output_bytes[0..32]).
    pub output1_rlc: Column<Advice>,
    /// Advice column for output 2= RLC(output_bytes[32..64]).
    pub output2_rlc: Column<Advice>,
}

impl<F: Field> LookupTable<F> for EccTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.op_type.into(),
            self.is_valid.into(),
            self.arg1_rlc.into(),
            self.arg2_rlc.into(),
            self.arg3_rlc.into(),
            self.arg4_rlc.into(),
            self.input_rlc.into(),
            self.output1_rlc.into(),
            self.output2_rlc.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("op_type"),
            String::from("is_valid"),
            String::from("arg1_rlc"),
            String::from("arg2_rlc"),
            String::from("arg3_rlc"),
            String::from("arg4_rlc"),
            String::from("input_rlc"),
            String::from("output1_rlc"),
            String::from("output2_rlc"),
        ]
    }

    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        vec![
            meta.query_fixed(self.op_type, Rotation::cur()),
            meta.query_advice(self.is_valid, Rotation::cur()),
            meta.query_advice(self.arg1_rlc, Rotation::cur()),
            meta.query_advice(self.arg2_rlc, Rotation::cur()),
            meta.query_advice(self.arg3_rlc, Rotation::cur()),
            meta.query_advice(self.arg4_rlc, Rotation::cur()),
            meta.query_advice(self.input_rlc, Rotation::cur()),
            meta.query_advice(self.output1_rlc, Rotation::cur()),
            meta.query_advice(self.output2_rlc, Rotation::cur()),
        ]
    }
}

impl EccTable {
    /// Construct the ECC table.
    pub(crate) fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            op_type: meta.fixed_column(),
            is_valid: meta.advice_column(),
            arg1_rlc: meta.advice_column_in(SecondPhase),
            arg2_rlc: meta.advice_column_in(SecondPhase),
            arg3_rlc: meta.advice_column_in(SecondPhase),
            arg4_rlc: meta.advice_column_in(SecondPhase),
            input_rlc: meta.advice_column_in(SecondPhase),
            output1_rlc: meta.advice_column_in(SecondPhase),
            output2_rlc: meta.advice_column_in(SecondPhase),
        }
    }

    /// Load witness in the ECC table. Note: for dev purposes.
    pub fn dev_load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        params: PrecompileEcParams,
        add_ops: &[EcAddOp],
        mul_ops: &[EcMulOp],
        pairing_ops: &[EcPairingOp],
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        let mut assignments = Vec::with_capacity(params.ec_add + params.ec_mul + params.ec_pairing);
        let u256_to_value = |u256: U256, randomness: Value<F>| -> Value<F> {
            randomness.map(|r| rlc::value(u256.to_le_bytes().iter(), r))
        };
        let fq_to_value = |fq: Fq, randomness: Value<F>| -> Value<F> {
            randomness.map(|r| rlc::value(fq.to_bytes().iter(), r))
        };

        let keccak_rand = challenges.keccak_input();

        // assign EcAdd
        for add_op in add_ops
            .iter()
            .filter(|add_op| !add_op.skip_by_ecc_circuit())
            .chain(std::iter::repeat(&EcAddOp::default()))
            .take(params.ec_add)
        {
            assignments.push([
                Value::known(F::from(u64::from(PrecompileCalls::Bn128Add))),
                Value::known(F::from(add_op.is_valid() as u64)),
                u256_to_value(add_op.p.0, keccak_rand),
                u256_to_value(add_op.p.1, keccak_rand),
                u256_to_value(add_op.q.0, keccak_rand),
                u256_to_value(add_op.q.1, keccak_rand),
                Value::known(F::zero()),
                fq_to_value(add_op.r.unwrap_or(G1Affine::identity()).x, keccak_rand),
                fq_to_value(add_op.r.unwrap_or(G1Affine::identity()).y, keccak_rand),
            ]);
        }

        // assign EcMul
        for mul_op in mul_ops
            .iter()
            .filter(|mul_op| !mul_op.skip_by_ecc_circuit())
            .chain(std::iter::repeat(&EcMulOp::default()))
            .take(params.ec_mul)
        {
            assignments.push([
                Value::known(F::from(u64::from(PrecompileCalls::Bn128Mul))),
                Value::known(F::from(mul_op.is_valid() as u64)),
                u256_to_value(mul_op.p.0, keccak_rand),
                u256_to_value(mul_op.p.1, keccak_rand),
                // no need to RLC the scalar s, since it will fit within the scalar field.
                Value::known(mul_op.s.into()),
                Value::known(F::zero()),
                Value::known(F::zero()),
                fq_to_value(mul_op.r.unwrap_or(G1Affine::identity()).x, keccak_rand),
                fq_to_value(mul_op.r.unwrap_or(G1Affine::identity()).y, keccak_rand),
            ]);
        }

        // assign EcPairing
        for pairing_op in pairing_ops
            .iter()
            .filter(|pairing_op| !pairing_op.skip_by_ecc_circuit())
            .chain(std::iter::repeat(&EcPairingOp::default()))
            .take(params.ec_pairing)
        {
            assignments.push([
                Value::known(F::from(u64::from(PrecompileCalls::Bn128Pairing))),
                Value::known(F::from(pairing_op.is_valid() as u64)),
                Value::known(F::zero()),
                Value::known(F::zero()),
                Value::known(F::zero()),
                Value::known(F::zero()),
                keccak_rand.map(|r| rlc::value(pairing_op.to_bytes_be().iter().rev(), r)),
                Value::known(
                    pairing_op
                        .output
                        .to_scalar()
                        .expect("EcPairing output = {0, 1}"),
                ),
                Value::known(F::zero()),
            ]);
        }

        layouter.assign_region(
            || "ecc table dev load",
            |mut region| {
                for (i, row) in assignments.iter().enumerate() {
                    region.assign_fixed(
                        || format!("ecc table row = {i}, op_type"),
                        self.op_type,
                        i,
                        || row[0],
                    )?;
                    for (&column, &value) in <EccTable as LookupTable<F>>::advice_columns(self)
                        .iter()
                        .zip_eq(row.iter().skip(1))
                    {
                        region.assign_advice(
                            || format!("ecc table row = {i}, column = {column:?}"),
                            column,
                            i,
                            || value,
                        )?;
                    }
                }

                Ok(())
            },
        )
    }
}

/// Lookup table embedded in the modexp circuit for precompile.
#[derive(Clone, Copy, Debug)]
pub struct ModExpTable {
    /// Use for indicate beginning of a limbs group
    pub q_head: Column<Fixed>,
    /// base represented by limbs
    pub base: Column<Advice>,
    /// exp represented by limbs
    pub exp: Column<Advice>,
    /// modulus represented by limbs
    pub modulus: Column<Advice>,
    /// result represented by limbs
    pub result: Column<Advice>,
}

impl ModExpTable {
    /// Construct the modexp table.
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let ret = Self {
            q_head: meta.fixed_column(),
            base: meta.advice_column(),
            exp: meta.advice_column(),
            modulus: meta.advice_column(),
            result: meta.advice_column(),
        };
        meta.enable_equality(ret.base);
        meta.enable_equality(ret.exp);
        meta.enable_equality(ret.modulus);
        meta.enable_equality(ret.result);
        ret
    }

    /// helper for devide a U256 into 3 108bit limbs
    pub fn split_u256_108bit_limbs(word: &Word) -> [u128; 3] {
        let bit108 = 1u128 << 108;
        let (next, limb0) = word.div_mod(U256::from(bit108));
        let (limb2, limb1) = next.div_mod(U256::from(bit108));
        [limb0.as_u128(), limb1.as_u128(), limb2.as_u128()]
    }

    /// helper for obtain the modulus of a U256 in Fr
    pub fn native_u256<F: Field>(word: &Word) -> F {
        let minus1 = -F::one();
        let div = Word::from_little_endian(minus1.to_repr().as_ref()) + Word::from(1u64);
        let (_, remainder) = word.div_mod(div);

        let mut bytes = [0u8; 64];
        remainder.to_little_endian(&mut bytes[..32]);
        F::from_uniform_bytes(&bytes)
    }

    /// fill a blank 4-row region start from offset for empty lookup
    pub fn fill_blank<F: Field>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(
            || "modexp table blank region",
            |mut region| {
                for i in 0..4 {
                    // fill last totally 0 row
                    region.assign_fixed(
                        || "modexp table blank head row",
                        self.q_head,
                        i,
                        || Value::known(F::zero()),
                    )?;
                    for &col in [&self.base, &self.exp, &self.modulus, &self.result] {
                        region.assign_advice(
                            || "modexp table blank limb row",
                            col,
                            i,
                            || Value::known(F::zero()),
                        )?;
                    }
                }
                Ok(())
            },
        )
    }

    /// Get assignments to the modexp table. Meant to be used for dev purposes.
    pub fn dev_load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        events: &[BigModExp],
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "modexp table",
            |mut region| {
                let mut offset = 0usize;

                for event in events {
                    for i in 0..4 {
                        region.assign_fixed(
                            || format!("modexp table head {}", offset + i),
                            self.q_head,
                            offset + i,
                            || Value::known(if i == 0 { F::one() } else { F::zero() }),
                        )?;
                    }

                    let base_limbs = Self::split_u256_108bit_limbs(&event.base);
                    let exp_limbs = Self::split_u256_108bit_limbs(&event.exponent);
                    let modulus_limbs = Self::split_u256_108bit_limbs(&event.modulus);
                    let result_limbs = Self::split_u256_108bit_limbs(&event.result);

                    for i in 0..3 {
                        for (limbs, &col) in [base_limbs, exp_limbs, modulus_limbs, result_limbs]
                            .iter()
                            .zip([&self.base, &self.exp, &self.modulus, &self.result])
                        {
                            region.assign_advice(
                                || format!("modexp table limb row {}", offset + i),
                                col,
                                offset + i,
                                || Value::known(F::from_u128(limbs[i])),
                            )?;
                        }
                    }

                    // native is not used by lookup (and in fact it can be omitted in dev)
                    for (word, &col) in
                        [&event.base, &event.exponent, &event.modulus, &event.result]
                            .iter()
                            .zip([&self.base, &self.exp, &self.modulus, &self.result])
                    {
                        region.assign_advice(
                            || format!("modexp table native row {}", offset + 3),
                            col,
                            offset + 3,
                            || Value::<F>::known(Self::native_u256(word)),
                        )?;
                    }

                    offset += 4;
                }

                Ok(())
            },
        )?;
        self.fill_blank(layouter)
    }
}

impl<F: Field> LookupTable<F> for ModExpTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.q_head.into(),
            self.base.into(),
            self.exp.into(),
            self.modulus.into(),
            self.result.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("is_head"),
            String::from("base"),
            String::from("exp"),
            String::from("modulus"),
            String::from("result"),
        ]
    }

    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        vec![
            // ignore the is_valid field as the EVM circuit's use-case (Ecrecover precompile) does
            // not care whether the signature is valid or not. It only cares about the recovered
            // address.
            meta.query_fixed(self.q_head, Rotation::cur()),
            meta.query_advice(self.base, Rotation::cur()),
            meta.query_advice(self.exp, Rotation::cur()),
            meta.query_advice(self.modulus, Rotation::cur()),
            meta.query_advice(self.result, Rotation::cur()),
            meta.query_advice(self.base, Rotation::next()),
            meta.query_advice(self.exp, Rotation::next()),
            meta.query_advice(self.modulus, Rotation::next()),
            meta.query_advice(self.result, Rotation::next()),
            meta.query_advice(self.base, Rotation(2)),
            meta.query_advice(self.exp, Rotation(2)),
            meta.query_advice(self.modulus, Rotation(2)),
            meta.query_advice(self.result, Rotation(2)),
        ]
    }
}

/// Lookup table for powers of keccak randomness up to exponent in [0, 128)
#[derive(Clone, Copy, Debug)]
pub struct PowOfRandTable {
    /// Whether the row is enabled.
    pub q_enable: Column<Fixed>,
    /// Whether the row is the first enabled row.
    pub is_first: Column<Fixed>,
    /// exponent = [0, 1, 2, ..., 126, 127] for enabled rows.
    /// exponent = 0 for all other rows (disabled).
    pub exponent: Column<Fixed>,
    /// power of keccak randomness.
    pub pow_of_rand: Column<Advice>,
}

impl PowOfRandTable {
    /// Construct the powers of randomness table.
    pub fn construct<F: Field>(
        meta: &mut ConstraintSystem<F>,
        challenges: &Challenges<Expression<F>>,
    ) -> Self {
        let table = Self {
            q_enable: meta.fixed_column(),
            is_first: meta.fixed_column(),
            exponent: meta.fixed_column(),
            pow_of_rand: meta.advice_column_in(SecondPhase),
        };

        meta.create_gate("pow_of_rand_table: first row", |meta| {
            let mut cb = BaseConstraintBuilder::default();
            cb.require_equal(
                "first row: rand ^ 0 == 1",
                meta.query_advice(table.pow_of_rand, Rotation::cur()),
                1.expr(),
            );
            cb.gate(and::expr([
                meta.query_fixed(table.q_enable, Rotation::cur()),
                meta.query_fixed(table.is_first, Rotation::cur()),
            ]))
        });

        meta.create_gate("pow_of_rand_table: all other enabled rows", |meta| {
            let mut cb = BaseConstraintBuilder::default();
            cb.require_equal(
                "pow_of_rand::cur == pow_of_rand::prev * rand",
                meta.query_advice(table.pow_of_rand, Rotation::cur()),
                meta.query_advice(table.pow_of_rand, Rotation::prev()) * challenges.keccak_input(),
            );
            cb.gate(and::expr([
                meta.query_fixed(table.q_enable, Rotation::cur()),
                not::expr(meta.query_fixed(table.is_first, Rotation::cur())),
            ]))
        });

        table
    }

    /// Assign values to the table.
    pub fn assign<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        let r = challenges.keccak_input();
        layouter.assign_region(
            || "power of randomness table",
            |mut region| {
                let pows_of_rand =
                    std::iter::successors(Some(Value::known(F::one())), |&v| Some(v * r))
                        .take(N_PAIRING_PER_OP * N_BYTES_PER_PAIR);

                for (idx, pow_of_rand) in pows_of_rand.enumerate() {
                    region.assign_fixed(
                        || format!("q_enable at offset = {idx}"),
                        self.q_enable,
                        idx,
                        || Value::known(F::one()),
                    )?;
                    region.assign_fixed(
                        || format!("is_first at offset = {idx}"),
                        self.is_first,
                        idx,
                        || Value::known(if idx == 0 { F::one() } else { F::zero() }),
                    )?;
                    region.assign_fixed(
                        || format!("exponent at offset = {idx}"),
                        self.exponent,
                        idx,
                        || Value::known(F::from(idx as u64)),
                    )?;
                    region.assign_advice(
                        || format!("pow_of_rand at offset = {idx}"),
                        self.pow_of_rand,
                        idx,
                        || pow_of_rand,
                    )?;
                }

                Ok(())
            },
        )
    }
}

impl<F: Field> LookupTable<F> for PowOfRandTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.q_enable.into(),
            self.is_first.into(),
            self.exponent.into(),
            self.pow_of_rand.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("q_enable"),
            String::from("is_first"),
            String::from("exponent"),
            String::from("pow_of_rand"),
        ]
    }

    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        vec![
            meta.query_fixed(self.q_enable, Rotation::cur()),
            meta.query_fixed(self.exponent, Rotation::cur()),
            meta.query_advice(self.pow_of_rand, Rotation::cur()),
        ]
    }
}

/// Lookup table for [0, MAX) range
#[derive(Clone, Copy, Debug)]
pub struct RangeTable<const MAX: usize>(TableColumn);

/// Type Alias of u8 table, [0, 1 << 8)
pub type U8Table = RangeTable<{ 1 << 8 }>;
/// Type Alias of u16 table, [0, 1 << 16)
pub type U16Table = RangeTable<{ 1 << 16 }>;

impl<const MAX: usize> RangeTable<MAX> {
    /// Construct the range table.
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let inner = meta.lookup_table_column();
        meta.annotate_lookup_column(inner, || format!("range table [0, {MAX})"));
        Self(inner)
    }

    /// Assign values to the table.
    pub fn load<F: Field>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || format!("range table [0, {MAX})"),
            |mut table| {
                for i in 0..MAX {
                    table.assign_cell(
                        || format!("range at offset = {i}"),
                        self.0,
                        i,
                        || Value::known(F::from(i as u64)),
                    )?;
                }

                Ok(())
            },
        )
    }
}

impl<const MAX: usize> From<RangeTable<MAX>> for TableColumn {
    fn from(table: RangeTable<MAX>) -> TableColumn {
        table.0
    }
}
