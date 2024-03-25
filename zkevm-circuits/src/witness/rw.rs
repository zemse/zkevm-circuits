#![allow(missing_docs)]
use std::collections::HashMap;

use bus_mapping::{
    operation::{self, AccountField, CallContextField, TxLogField, TxReceiptField},
    Error,
};
use eth_types::{Address, Field, ToLittleEndian, ToScalar, Word, U256};

use halo2_proofs::{circuit::Value, halo2curves::bn256::Fr};
use itertools::Itertools;
use rayon::prelude::{ParallelBridge, ParallelIterator};

use crate::{
    evm_circuit::util::rlc,
    table::{AccountFieldTag, CallContextFieldTag, RwTableTag, TxLogFieldTag, TxReceiptFieldTag},
    util::build_tx_log_address,
};

use super::MptUpdates;

const ERR_MSG_FIRST: &str = "first access reads don't change value";
const ERR_MSG_NON_FIRST: &str = "non-first access reads don't change value";

/// Rw constainer for a witness block
#[derive(Debug, Default, Clone)]
pub struct RwMap(pub HashMap<RwTableTag, Vec<Rw>>);

impl std::ops::Index<(RwTableTag, usize)> for RwMap {
    type Output = Rw;

    fn index(&self, (tag, idx): (RwTableTag, usize)) -> &Self::Output {
        &self.0.get(&tag).unwrap()[idx]
    }
}
impl RwMap {
    /// Check rw_counter is continuous and starting from 1
    pub fn check_rw_counter_sanity(&self) {
        for (idx, rw_counter) in self
            .0
            .iter()
            .filter(|(tag, _rs)| !matches!(tag, RwTableTag::Start))
            .flat_map(|(_tag, rs)| rs)
            .map(|r| r.rw_counter())
            .sorted()
            .enumerate()
        {
            debug_assert_eq!(idx, rw_counter - 1);
        }
    }

    /// Check value but don't construct mpt
    pub fn check_value(&self) -> Result<(), Error> {
        let rows = self.table_assignments_with_idx();
        let errs = rows
            .into_values()
            .par_bridge()
            .flat_map(|group| {
                // assumption: errs is mostly empty, Vec::new won't do heap allocation
                let mut errs = Vec::new();
                debug_assert!(!group.is_empty(), "group cannot be empty");
                let mut group = group.into_iter();
                let (idx, first) = group.next().unwrap();
                let mut prev = first;
                if !first.is_write() {
                    // first access reads don't change value
                    if first.value_word() != U256::zero()
                        && !(first.tag() == RwTableTag::TxAccessListAccountStorage
                            || first.tag() == RwTableTag::Account
                            || first.tag() == RwTableTag::AccountStorage)
                    {
                        errs.push((idx, ERR_MSG_FIRST, first, None));
                    }
                }
                for (idx, rw) in group {
                    if !rw.is_write() {
                        // non-first access reads don't change value
                        if rw.value_word() != prev.value_word() {
                            errs.push((idx, ERR_MSG_NON_FIRST, rw, Some(prev)));
                        }
                    }
                    prev = rw;
                }
                errs
            })
            .collect::<Vec<_>>();
        if !errs.is_empty() {
            log::error!("rw value check err num: {}", errs.len());
            for e in errs {
                log::error!("err is {:?}", e);
            }
            Err(Error::InternalError("check rw failed"))
        } else {
            log::debug!("rw value check err num: {}", errs.len());
            Ok(())
        }
    }

    /// Check value in the same way like StateCircuit
    pub fn check_value_strict(&self) {
        let mock_rand = Fr::from(0x1000u64);
        let rows = self.table_assignments();
        let updates = MptUpdates::from_rws_with_mock_state_roots(
            &rows,
            0xcafeu64.into(),
            0xdeadbeefu64.into(),
        );
        let mut errs = Vec::new();
        for idx in 1..rows.len() {
            let row = &rows[idx];
            let prev_row = &rows[idx - 1];
            let is_first = {
                let key = |row: &Rw| {
                    (
                        row.tag() as u64,
                        row.id().unwrap_or_default(),
                        row.address().unwrap_or_default(),
                        row.field_tag().unwrap_or_default(),
                        row.storage_key().unwrap_or_default(),
                    )
                };
                key(prev_row) != key(row)
            };
            if !row.is_write() {
                let value = row.value_assignment::<Fr>(mock_rand);
                if is_first {
                    // value == init_value
                    let init_value = updates
                        .get(row)
                        .map(|u| u.value_assignments(mock_rand).1)
                        .unwrap_or_default();
                    if value != init_value {
                        // EIP2930
                        if row.tag() != RwTableTag::TxAccessListAccountStorage {
                            errs.push((idx, ERR_MSG_FIRST, *row, None));
                        }
                    }
                } else {
                    // value == prev_value
                    let prev_value = prev_row.value_assignment::<Fr>(mock_rand);
                    if value != prev_value {
                        errs.push((idx, ERR_MSG_NON_FIRST, *row, Some(*prev_row)));
                    }
                }
            }
        }
        if !errs.is_empty() {
            log::error!("rw value check err num: {}", errs.len());
            for e in errs {
                log::error!("err is {:?}", e);
            }
        } else {
            log::debug!("rw value check err num: {}", errs.len());
        }
    }
    /// Calculates the number of Rw::Start rows needed.
    /// `target_len` is allowed to be 0 as an "auto" mode,
    /// then only 1 Rw::Start row will be prepadded.
    pub(crate) fn padding_len(rows_len: usize, target_len: usize) -> usize {
        if target_len > rows_len {
            target_len - rows_len
        } else {
            if target_len != 0 {
                log::error!(
                    "RwMap::padding_len overflow, target_len: {}, rows_len: {}",
                    target_len,
                    rows_len
                );
            }
            1
        }
    }
    /// Prepad Rw::Start rows to target length
    pub fn table_assignments_prepad(rows: &[Rw], target_len: usize) -> (Vec<Rw>, usize) {
        // Remove Start rows as we will add them from scratch.
        let rows: Vec<Rw> = rows
            .iter()
            .skip_while(|rw| matches!(rw, Rw::Start { .. }))
            .cloned()
            .collect();
        let padding_length = Self::padding_len(rows.len(), target_len);
        let padding = (1..=padding_length).map(|rw_counter| Rw::Start { rw_counter });
        (padding.chain(rows).collect(), padding_length)
    }
    /// Build Rws for assignment
    #[inline(always)]
    pub fn table_assignments_unsorted(&self) -> Vec<Rw> {
        self.0.values().flatten().cloned().collect()
    }

    /// Build Rws for assignment
    pub fn table_assignments(&self) -> Vec<Rw> {
        let mut rows = self.table_assignments_unsorted();
        rows.sort_by_cached_key(Rw::as_key);
        rows
    }

    /// Build Rws for assignment
    pub fn table_assignments_with_idx(&self) -> HashMap<RwKey, Vec<(usize, Rw)>> {
        // key/value ratio is about 23-24
        // each key has about ~250 rows
        // each Rw has size of 168 bytes
        // so each array has size of ~42KB
        let total_len = self.0.values().map(|v| v.len()).sum::<usize>();
        // take roughly estimated capacity
        let mut map = HashMap::<RwKey, Vec<(usize, Rw)>>::with_capacity(total_len / 22);
        for (idx, row) in self.0.values().flatten().copied().enumerate() {
            map.entry(row.as_key()).or_default().push((idx, row));
        }
        map
    }

    /// Return rw number for the specified tag.
    pub fn rw_num(&self, tag: RwTableTag) -> usize {
        self.0.get(&tag).map(|v| v.len()).unwrap_or_default()
    }
}

/// Rw key
pub type RwKey = (u64, usize, Address, u64, Word);

/// Read-write records in execution. Rws are used for connecting evm circuit and
/// state circuits.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Rw {
    /// Start
    Start { rw_counter: usize },
    /// TxAccessListAccount
    TxAccessListAccount {
        rw_counter: usize,
        is_write: bool,
        tx_id: usize,
        account_address: Address,
        is_warm: bool,
        is_warm_prev: bool,
    },
    /// TxAccessListAccountStorage
    TxAccessListAccountStorage {
        rw_counter: usize,
        is_write: bool,
        tx_id: usize,
        account_address: Address,
        storage_key: Word,
        is_warm: bool,
        is_warm_prev: bool,
    },
    /// TxRefund
    TxRefund {
        rw_counter: usize,
        is_write: bool,
        tx_id: usize,
        value: u64,
        value_prev: u64,
    },
    /// Account
    Account {
        rw_counter: usize,
        is_write: bool,
        account_address: Address,
        field_tag: AccountFieldTag,
        value: Word,
        value_prev: Word,
    },
    /// AccountStorage
    AccountStorage {
        rw_counter: usize,
        is_write: bool,
        account_address: Address,
        storage_key: Word,
        value: Word,
        value_prev: Word,
        tx_id: usize,
        committed_value: Word,
    },
    /// CallContext
    CallContext {
        rw_counter: usize,
        is_write: bool,
        call_id: usize,
        field_tag: CallContextFieldTag,
        value: Word,
    },
    /// Stack
    Stack {
        rw_counter: usize,
        is_write: bool,
        call_id: usize,
        stack_pointer: usize,
        value: Word,
    },
    /// Memory
    Memory {
        rw_counter: usize,
        is_write: bool,
        call_id: usize,
        memory_address: u64,
        value: Word,
        value_prev: Word,
    },
    /// TxLog
    TxLog {
        rw_counter: usize,
        is_write: bool,
        tx_id: usize,
        log_id: u64, // pack this can index together into address?
        field_tag: TxLogFieldTag,
        // topic index (0..4) if field_tag is TxLogFieldTag:Topic
        // byte index if field_tag is TxLogFieldTag:Data
        // 0 for other field tags
        index: usize,
        // when it is topic field, value can be word type
        value: Word,
    },
    /// TxReceipt
    TxReceipt {
        rw_counter: usize,
        is_write: bool,
        tx_id: usize,
        field_tag: TxReceiptFieldTag,
        value: u64,
    },
}

/// Rw table row assignment
#[derive(Default, Clone, Copy, Debug)]
pub struct RwRow<F> {
    pub(crate) rw_counter: F,
    pub(crate) is_write: F,
    pub(crate) tag: F,
    pub(crate) id: F,
    pub(crate) address: F,
    pub(crate) field_tag: F,
    pub(crate) storage_key: F,
    pub(crate) value: F,
    pub(crate) value_prev: F,
    pub(crate) aux1: F,
    pub(crate) aux2: F,
    pub(crate) is_state: F,
}

impl<F: Field> RwRow<F> {
    pub(crate) fn values(&self) -> [F; 11] {
        [
            self.rw_counter,
            self.is_write,
            self.tag,
            self.id,
            self.address,
            self.field_tag,
            self.storage_key,
            self.value,
            self.value_prev,
            self.aux1,
            self.aux2,
        ]
    }
    pub(crate) fn rlc(&self, randomness: F) -> F {
        let values = self.values();
        std::iter::once(&F::one())
            .chain(values.iter())
            .rev()
            .fold(F::zero(), |acc, value| acc * randomness + value)
    }

    pub(crate) fn rlc_value(&self, randomness: Value<F>) -> Value<F> {
        randomness.map(|randomness| self.rlc(randomness))
    }
}

impl Rw {
    pub fn tx_access_list_value_pair(&self) -> (bool, bool) {
        match self {
            Self::TxAccessListAccount {
                is_warm,
                is_warm_prev,
                ..
            } => (*is_warm, *is_warm_prev),
            Self::TxAccessListAccountStorage {
                is_warm,
                is_warm_prev,
                ..
            } => (*is_warm, *is_warm_prev),
            _ => unreachable!("{:?}", self),
        }
    }

    pub fn tx_refund_value_pair(&self) -> (u64, u64) {
        match self {
            Self::TxRefund {
                value, value_prev, ..
            } => (*value, *value_prev),
            _ => unreachable!("{:?}", self),
        }
    }

    pub fn account_value_pair(&self) -> (Word, Word) {
        match self {
            Self::Account {
                value, value_prev, ..
            } => (*value, *value_prev),
            _ => unreachable!("{:?}", self),
        }
    }

    pub fn account_balance_pair(&self) -> (Word, Word) {
        self.account_value_pair_field_tag(AccountFieldTag::Balance)
    }
    pub fn account_codehash_pair(&self) -> (Word, Word) {
        self.account_value_pair_field_tag(AccountFieldTag::CodeHash)
    }
    pub fn account_keccak_codehash_pair(&self) -> (Word, Word) {
        self.account_value_pair_field_tag(AccountFieldTag::KeccakCodeHash)
    }
    pub fn account_nonce_pair(&self) -> (Word, Word) {
        self.account_value_pair_field_tag(AccountFieldTag::Nonce)
    }

    pub fn account_value_pair_field_tag(
        &self,
        required_field_tag: AccountFieldTag,
    ) -> (Word, Word) {
        match self {
            Self::Account {
                value,
                value_prev,
                field_tag,
                ..
            } => {
                debug_assert_eq!(*field_tag, required_field_tag, "invalid rw {:?}", &self);
                (*value, *value_prev)
            }
            _ => unreachable!("{:?}", self),
        }
    }

    pub fn aux_pair(&self) -> (usize, Word) {
        match self {
            Self::AccountStorage {
                tx_id,
                committed_value,
                ..
            } => (*tx_id, *committed_value),
            _ => unreachable!("{:?}", self),
        }
    }

    pub fn storage_value_aux(&self) -> (Word, Word, usize, Word) {
        match self {
            Self::AccountStorage {
                value,
                value_prev,
                tx_id,
                committed_value,
                ..
            } => (*value, *value_prev, *tx_id, *committed_value),
            _ => unreachable!("{:?}", self),
        }
    }

    pub fn call_context_value(&self) -> Word {
        match self {
            Self::CallContext { value, .. } => *value,
            _ => unreachable!("{:?}", self),
        }
    }

    pub fn stack_value(&self) -> Word {
        match self {
            Self::Stack { value, .. } => *value,
            _ => unreachable!("{:?}", self),
        }
    }

    pub fn log_value(&self) -> Word {
        match self {
            Self::TxLog { value, .. } => *value,
            _ => unreachable!("{:?}", self),
        }
    }

    pub fn receipt_value(&self) -> u64 {
        match self {
            Self::TxReceipt { value, .. } => *value,
            _ => unreachable!("{:?}", self),
        }
    }

    /// Return the memory word read or written, and its value before the operation.
    pub fn memory_word_pair(&self) -> (Word, Word) {
        match self {
            Self::Memory {
                value, value_prev, ..
            } => (*value, *value_prev),
            _ => unreachable!("{:?}", self),
        }
    }

    // At this moment is a helper for the EVM circuit until EVM challange API is
    // applied
    pub(crate) fn table_assignment_aux<F: Field>(&self, randomness: F) -> RwRow<F> {
        RwRow {
            rw_counter: F::from(self.rw_counter() as u64),
            is_write: F::from(self.is_write() as u64),
            tag: F::from(self.tag() as u64),
            id: F::from(self.id().unwrap_or_default() as u64),
            address: self.address().unwrap_or_default().to_scalar().unwrap(),
            field_tag: F::from(self.field_tag().unwrap_or_default()),
            storage_key: rlc::value(
                &self.storage_key().unwrap_or_default().to_le_bytes(),
                randomness,
            ),
            value: self.value_assignment(randomness),
            value_prev: self.value_prev_assignment(randomness).unwrap_or_default(),
            aux1: F::zero(), // only used for AccountStorage::tx_id, which moved to key1.
            aux2: self
                .committed_value_assignment(randomness)
                .unwrap_or_default(),
            is_state: if self.tag() == RwTableTag::Account
                || self.tag() == RwTableTag::AccountStorage
            {
                F::ONE
            } else {
                F::ZERO
            },
        }
    }

    pub(crate) fn table_assignment<F: Field>(&self, randomness: Value<F>) -> RwRow<Value<F>> {
        RwRow {
            rw_counter: Value::known(F::from(self.rw_counter() as u64)),
            is_write: Value::known(F::from(self.is_write() as u64)),
            tag: Value::known(F::from(self.tag() as u64)),
            id: Value::known(F::from(self.id().unwrap_or_default() as u64)),
            address: Value::known(self.address().unwrap_or_default().to_scalar().unwrap()),
            field_tag: Value::known(F::from(self.field_tag().unwrap_or_default())),
            storage_key: randomness.map(|randomness| {
                rlc::value(
                    &self.storage_key().unwrap_or_default().to_le_bytes(),
                    randomness,
                )
            }),
            value: randomness.map(|randomness| self.value_assignment(randomness)),
            value_prev: randomness
                .map(|randomness| self.value_prev_assignment(randomness).unwrap_or_default()),
            aux1: Value::known(F::zero()), /* only used for AccountStorage::tx_id, which moved to
                                            * key1. */
            aux2: randomness.map(|randomness| {
                self.committed_value_assignment(randomness)
                    .unwrap_or_default()
            }),
            is_state: if self.tag() == RwTableTag::Account
                || self.tag() == RwTableTag::AccountStorage
            {
                Value::known(F::ONE)
            } else {
                Value::known(F::ZERO)
            },
        }
    }

    pub fn rw_counter(&self) -> usize {
        match self {
            Self::Start { rw_counter }
            | Self::Memory { rw_counter, .. }
            | Self::Stack { rw_counter, .. }
            | Self::AccountStorage { rw_counter, .. }
            | Self::TxAccessListAccount { rw_counter, .. }
            | Self::TxAccessListAccountStorage { rw_counter, .. }
            | Self::TxRefund { rw_counter, .. }
            | Self::Account { rw_counter, .. }
            | Self::CallContext { rw_counter, .. }
            | Self::TxLog { rw_counter, .. }
            | Self::TxReceipt { rw_counter, .. } => *rw_counter,
        }
    }

    pub fn is_write(&self) -> bool {
        match self {
            Self::Start { .. } => false,
            Self::Memory { is_write, .. }
            | Self::Stack { is_write, .. }
            | Self::AccountStorage { is_write, .. }
            | Self::TxAccessListAccount { is_write, .. }
            | Self::TxAccessListAccountStorage { is_write, .. }
            | Self::TxRefund { is_write, .. }
            | Self::Account { is_write, .. }
            | Self::CallContext { is_write, .. }
            | Self::TxLog { is_write, .. }
            | Self::TxReceipt { is_write, .. } => *is_write,
        }
    }

    pub fn tag(&self) -> RwTableTag {
        match self {
            Self::Start { .. } => RwTableTag::Start,
            Self::Memory { .. } => RwTableTag::Memory,
            Self::Stack { .. } => RwTableTag::Stack,
            Self::AccountStorage { .. } => RwTableTag::AccountStorage,
            Self::TxAccessListAccount { .. } => RwTableTag::TxAccessListAccount,
            Self::TxAccessListAccountStorage { .. } => RwTableTag::TxAccessListAccountStorage,
            Self::TxRefund { .. } => RwTableTag::TxRefund,
            Self::Account { .. } => RwTableTag::Account,
            Self::CallContext { .. } => RwTableTag::CallContext,
            Self::TxLog { .. } => RwTableTag::TxLog,
            Self::TxReceipt { .. } => RwTableTag::TxReceipt,
        }
    }

    #[inline(always)]
    pub fn id(&self) -> Option<usize> {
        match self {
            Self::AccountStorage { tx_id, .. }
            | Self::TxAccessListAccount { tx_id, .. }
            | Self::TxAccessListAccountStorage { tx_id, .. }
            | Self::TxRefund { tx_id, .. }
            | Self::TxLog { tx_id, .. }
            | Self::TxReceipt { tx_id, .. } => Some(*tx_id),
            Self::CallContext { call_id, .. }
            | Self::Stack { call_id, .. }
            | Self::Memory { call_id, .. } => Some(*call_id),
            Self::Start { .. } | Self::Account { .. } => None,
        }
    }

    #[inline(always)]
    pub fn address(&self) -> Option<Address> {
        match self {
            Self::TxAccessListAccount {
                account_address, ..
            }
            | Self::TxAccessListAccountStorage {
                account_address, ..
            }
            | Self::Account {
                account_address, ..
            }
            | Self::AccountStorage {
                account_address, ..
            } => Some(*account_address),
            Self::Memory { memory_address, .. } => Some(Address::from_low_u64_be(*memory_address)),
            Self::Stack { stack_pointer, .. } => {
                Some(Address::from_low_u64_be(*stack_pointer as u64))
            }
            Self::TxLog {
                log_id,
                field_tag,
                index,
                ..
            } => {
                // make field_tag fit into one limb (16 bits)
                Some(build_tx_log_address(*index as u64, *field_tag, *log_id))
            }
            Self::Start { .. }
            | Self::CallContext { .. }
            | Self::TxRefund { .. }
            | Self::TxReceipt { .. } => None,
        }
    }

    #[inline(always)]
    pub fn field_tag(&self) -> Option<u64> {
        match self {
            Self::Account { field_tag, .. } => Some(*field_tag as u64),
            Self::CallContext { field_tag, .. } => Some(*field_tag as u64),
            Self::TxReceipt { field_tag, .. } => Some(*field_tag as u64),
            // See comment above configure for is_non_exist in state_circuit.rs for the explanation
            // for why the field tag for AccountStorage is CodeHash instead of None.
            Self::AccountStorage { .. } => Some(AccountFieldTag::CodeHash as u64),
            Self::Start { .. }
            | Self::Memory { .. }
            | Self::Stack { .. }
            | Self::TxAccessListAccount { .. }
            | Self::TxAccessListAccountStorage { .. }
            | Self::TxRefund { .. }
            | Self::TxLog { .. } => None,
        }
    }

    #[inline(always)]
    pub fn storage_key(&self) -> Option<Word> {
        match self {
            Self::AccountStorage { storage_key, .. }
            | Self::TxAccessListAccountStorage { storage_key, .. } => Some(*storage_key),
            Self::Start { .. }
            | Self::CallContext { .. }
            | Self::Stack { .. }
            | Self::Memory { .. }
            | Self::TxRefund { .. }
            | Self::Account { .. }
            | Self::TxAccessListAccount { .. }
            | Self::TxLog { .. }
            | Self::TxReceipt { .. } => None,
        }
    }

    pub fn value_assignment<F: Field>(&self, randomness: F) -> F {
        match self {
            Self::Start { .. } => F::zero(),
            Self::CallContext {
                field_tag, value, ..
            } => {
                match field_tag {
                    // Only these two tags have values that may not fit into a scalar, so we need to
                    // RLC. (for poseidon hash feature, CodeHash not need rlc)
                    CallContextFieldTag::CodeHash => {
                        if cfg!(feature = "poseidon-codehash") {
                            value.to_scalar().unwrap()
                        } else {
                            rlc::value(&value.to_le_bytes(), randomness)
                        }
                    }
                    CallContextFieldTag::Value => rlc::value(&value.to_le_bytes(), randomness),
                    _ => value.to_scalar().unwrap(),
                }
            }
            Self::Account {
                value, field_tag, ..
            } => match field_tag {
                AccountFieldTag::KeccakCodeHash | AccountFieldTag::Balance => {
                    rlc::value(&value.to_le_bytes(), randomness)
                }
                AccountFieldTag::CodeHash => {
                    if cfg!(feature = "poseidon-codehash") {
                        value.to_scalar().unwrap()
                    } else {
                        rlc::value(&value.to_le_bytes(), randomness)
                    }
                }
                AccountFieldTag::Nonce
                | AccountFieldTag::NonExisting
                | AccountFieldTag::CodeSize => value.to_scalar().unwrap(),
            },
            Self::AccountStorage { value, .. } | Self::Stack { value, .. } => {
                rlc::value(&value.to_le_bytes(), randomness)
            }

            Self::TxLog {
                field_tag, value, ..
            } => match field_tag {
                TxLogFieldTag::Topic => rlc::value(&value.to_le_bytes(), randomness),
                TxLogFieldTag::Data => rlc::value(&value.to_le_bytes(), randomness),
                _ => value.to_scalar().unwrap(),
            },

            Self::TxAccessListAccount { is_warm, .. }
            | Self::TxAccessListAccountStorage { is_warm, .. } => F::from(*is_warm as u64),
            Self::Memory { value, .. } => rlc::value(&value.to_le_bytes(), randomness),
            Self::TxRefund { value, .. } | Self::TxReceipt { value, .. } => F::from(*value),
        }
    }

    pub fn value_word(&self) -> U256 {
        match self {
            Self::Start { .. } => U256::zero(),
            Self::CallContext { value, .. } => *value,
            Self::Account { value, .. }
            | Self::AccountStorage { value, .. }
            | Self::Stack { value, .. }
            | Self::Memory { value, .. }
            | Self::TxLog { value, .. } => *value,
            Self::TxAccessListAccount { is_warm, .. }
            | Self::TxAccessListAccountStorage { is_warm, .. } => U256::from(*is_warm as u64),
            Self::TxRefund { value, .. } | Self::TxReceipt { value, .. } => U256::from(*value),
        }
    }

    pub(crate) fn value_prev_assignment<F: Field>(&self, randomness: F) -> Option<F> {
        match self {
            Self::Account {
                value_prev,
                field_tag,
                ..
            } => Some(match field_tag {
                AccountFieldTag::KeccakCodeHash | AccountFieldTag::Balance => {
                    rlc::value(&value_prev.to_le_bytes(), randomness)
                }
                AccountFieldTag::CodeHash => {
                    if cfg!(feature = "poseidon-codehash") {
                        value_prev.to_scalar().unwrap()
                    } else {
                        rlc::value(&value_prev.to_le_bytes(), randomness)
                    }
                }
                AccountFieldTag::Nonce
                | AccountFieldTag::NonExisting
                | AccountFieldTag::CodeSize => value_prev.to_scalar().unwrap(),
            }),
            Self::AccountStorage { value_prev, .. } => {
                Some(rlc::value(&value_prev.to_le_bytes(), randomness))
            }
            Self::Memory { value_prev, .. } => {
                Some(rlc::value(&value_prev.to_le_bytes(), randomness))
            }
            Self::TxAccessListAccount { is_warm_prev, .. }
            | Self::TxAccessListAccountStorage { is_warm_prev, .. } => {
                Some(F::from(*is_warm_prev as u64))
            }
            Self::TxRefund { value_prev, .. } => Some(F::from(*value_prev)),
            Self::Start { .. }
            | Self::Stack { .. }
            | Self::CallContext { .. }
            | Self::TxLog { .. }
            | Self::TxReceipt { .. } => None,
        }
    }

    fn committed_value_assignment<F: Field>(&self, randomness: F) -> Option<F> {
        match self {
            Self::AccountStorage {
                committed_value, ..
            } => Some(rlc::value(&committed_value.to_le_bytes(), randomness)),
            _ => None,
        }
    }

    #[inline(always)]
    pub(crate) fn as_key(&self) -> RwKey {
        (
            self.tag() as u64,
            self.id().unwrap_or_default(),
            self.address().unwrap_or_default(),
            self.field_tag().unwrap_or_default(),
            self.storage_key().unwrap_or_default(),
        )
    }
}

impl From<&operation::OperationContainer> for RwMap {
    fn from(container: &operation::OperationContainer) -> Self {
        let mut rws = HashMap::default();

        rws.insert(
            RwTableTag::Start,
            container
                .start
                .iter()
                .map(|op| Rw::Start {
                    rw_counter: op.rwc().into(),
                })
                .collect(),
        );
        rws.insert(
            RwTableTag::TxAccessListAccount,
            container
                .tx_access_list_account
                .iter()
                .map(|op| Rw::TxAccessListAccount {
                    rw_counter: op.rwc().into(),
                    is_write: op.rw().is_write(),
                    tx_id: op.op().tx_id,
                    account_address: op.op().address,
                    is_warm: op.op().is_warm,
                    is_warm_prev: op.op().is_warm_prev,
                })
                .collect(),
        );
        rws.insert(
            RwTableTag::TxAccessListAccountStorage,
            container
                .tx_access_list_account_storage
                .iter()
                .map(|op| Rw::TxAccessListAccountStorage {
                    rw_counter: op.rwc().into(),
                    is_write: op.rw().is_write(),
                    tx_id: op.op().tx_id,
                    account_address: op.op().address,
                    storage_key: op.op().key,
                    is_warm: op.op().is_warm,
                    is_warm_prev: op.op().is_warm_prev,
                })
                .collect(),
        );
        rws.insert(
            RwTableTag::TxRefund,
            container
                .tx_refund
                .iter()
                .map(|op| Rw::TxRefund {
                    rw_counter: op.rwc().into(),
                    is_write: op.rw().is_write(),
                    tx_id: op.op().tx_id,
                    value: op.op().value,
                    value_prev: op.op().value_prev,
                })
                .collect(),
        );
        rws.insert(
            RwTableTag::Account,
            container
                .account
                .iter()
                .map(|op| Rw::Account {
                    rw_counter: op.rwc().into(),
                    is_write: op.rw().is_write(),
                    account_address: op.op().address,
                    field_tag: match op.op().field {
                        AccountField::Nonce => AccountFieldTag::Nonce,
                        AccountField::Balance => AccountFieldTag::Balance,
                        AccountField::CodeHash => AccountFieldTag::CodeHash,
                        AccountField::KeccakCodeHash => AccountFieldTag::KeccakCodeHash,
                        AccountField::CodeSize => AccountFieldTag::CodeSize,
                    },
                    value: op.op().value,
                    value_prev: op.op().value_prev,
                })
                .collect(),
        );
        rws.insert(
            RwTableTag::AccountStorage,
            container
                .storage
                .iter()
                .map(|op| Rw::AccountStorage {
                    rw_counter: op.rwc().into(),
                    is_write: op.rw().is_write(),
                    account_address: op.op().address,
                    storage_key: op.op().key,
                    value: op.op().value,
                    value_prev: op.op().value_prev,
                    tx_id: op.op().tx_id,
                    committed_value: op.op().committed_value,
                })
                .collect(),
        );
        rws.insert(
            RwTableTag::CallContext,
            container
                .call_context
                .iter()
                .map(|op| Rw::CallContext {
                    rw_counter: op.rwc().into(),
                    is_write: op.rw().is_write(),
                    call_id: op.op().call_id,
                    field_tag: match op.op().field {
                        CallContextField::RwCounterEndOfReversion => {
                            CallContextFieldTag::RwCounterEndOfReversion
                        }
                        CallContextField::CallerId => CallContextFieldTag::CallerId,
                        CallContextField::TxId => CallContextFieldTag::TxId,
                        CallContextField::Depth => CallContextFieldTag::Depth,
                        CallContextField::CallerAddress => CallContextFieldTag::CallerAddress,
                        CallContextField::CalleeAddress => CallContextFieldTag::CalleeAddress,
                        CallContextField::CallDataOffset => CallContextFieldTag::CallDataOffset,
                        CallContextField::CallDataLength => CallContextFieldTag::CallDataLength,
                        CallContextField::ReturnDataOffset => CallContextFieldTag::ReturnDataOffset,
                        CallContextField::ReturnDataLength => CallContextFieldTag::ReturnDataLength,
                        CallContextField::Value => CallContextFieldTag::Value,
                        CallContextField::IsSuccess => CallContextFieldTag::IsSuccess,
                        CallContextField::IsPersistent => CallContextFieldTag::IsPersistent,
                        CallContextField::IsStatic => CallContextFieldTag::IsStatic,
                        CallContextField::LastCalleeId => CallContextFieldTag::LastCalleeId,
                        CallContextField::LastCalleeReturnDataOffset => {
                            CallContextFieldTag::LastCalleeReturnDataOffset
                        }
                        CallContextField::LastCalleeReturnDataLength => {
                            CallContextFieldTag::LastCalleeReturnDataLength
                        }
                        CallContextField::IsRoot => CallContextFieldTag::IsRoot,
                        CallContextField::IsCreate => CallContextFieldTag::IsCreate,
                        CallContextField::CodeHash => CallContextFieldTag::CodeHash,
                        CallContextField::ProgramCounter => CallContextFieldTag::ProgramCounter,
                        CallContextField::StackPointer => CallContextFieldTag::StackPointer,
                        CallContextField::GasLeft => CallContextFieldTag::GasLeft,
                        CallContextField::MemorySize => CallContextFieldTag::MemorySize,
                        CallContextField::ReversibleWriteCounter => {
                            CallContextFieldTag::ReversibleWriteCounter
                        }
                        CallContextField::L1Fee => CallContextFieldTag::L1Fee,
                    },
                    value: op.op().value,
                })
                .collect(),
        );
        rws.insert(
            RwTableTag::Stack,
            container
                .stack
                .iter()
                .map(|op| Rw::Stack {
                    rw_counter: op.rwc().into(),
                    is_write: op.rw().is_write(),
                    call_id: op.op().call_id(),
                    stack_pointer: usize::from(*op.op().address()),
                    value: *op.op().value(),
                })
                .collect(),
        );
        rws.insert(
            RwTableTag::Memory,
            container
                .memory
                .iter()
                .map(|op| Rw::Memory {
                    rw_counter: op.rwc().into(),
                    is_write: op.rw().is_write(),
                    call_id: op.op().call_id(),
                    memory_address: u64::from_le_bytes(
                        op.op().address().to_le_bytes()[..8].try_into().unwrap(),
                    ),
                    value: op.op().value(),
                    value_prev: op.op().value_prev(),
                })
                .collect(),
        );
        rws.insert(
            RwTableTag::TxLog,
            container
                .tx_log
                .iter()
                .map(|op| Rw::TxLog {
                    rw_counter: op.rwc().into(),
                    is_write: op.rw().is_write(),
                    tx_id: op.op().tx_id,
                    log_id: op.op().log_id as u64,
                    field_tag: match op.op().field {
                        TxLogField::Address => TxLogFieldTag::Address,
                        TxLogField::Topic => TxLogFieldTag::Topic,
                        TxLogField::Data => TxLogFieldTag::Data,
                    },
                    index: op.op().index,
                    value: op.op().value,
                })
                .collect(),
        );
        rws.insert(
            RwTableTag::TxReceipt,
            container
                .tx_receipt
                .iter()
                .map(|op| Rw::TxReceipt {
                    rw_counter: op.rwc().into(),
                    is_write: op.rw().is_write(),
                    tx_id: op.op().tx_id,
                    field_tag: match op.op().field {
                        TxReceiptField::PostStateOrStatus => TxReceiptFieldTag::PostStateOrStatus,
                        TxReceiptField::LogLength => TxReceiptFieldTag::LogLength,
                        TxReceiptField::CumulativeGasUsed => TxReceiptFieldTag::CumulativeGasUsed,
                    },
                    value: op.op().value,
                })
                .collect(),
        );

        Self(rws)
    }
}
