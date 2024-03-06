use eth_types::{Address, Field, ToLittleEndian, ToScalar, Word};
use gadgets::util::{and, expr_from_bytes, not, select, sum, Expr};
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

use crate::evm_circuit::{
    param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_U64, N_BYTES_WORD},
    util::{
        constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
        CachedRegion, Cell, RandomLinearCombination,
    },
};

use super::IsZeroGadget;

#[derive(Clone, Debug)]
pub struct RlpU64Gadget<F> {
    /// Byte representation of the U64 value.
    value_rlc: RandomLinearCombination<F, N_BYTES_U64>,
    /// Flag to mark the most significant byte in the U64's byte representation.
    is_most_significant_byte: [Cell<F>; N_BYTES_U64],
    /// Whether the most significant byte is zero, to check for zero value.
    most_significant_byte_is_zero: IsZeroGadget<F>,
    /// Boolean flag to mark whether or not the U64 value is less than 128.
    is_lt_128: Cell<F>,
}

impl<F: Field> RlpU64Gadget<F> {
    /// Configure and construct a gadget for RLP-encoding of a U64 value.
    fn construct(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let value_rlc = cb.query_keccak_rlc();

        let is_most_significant_byte = array_init::array_init(|_| cb.query_bool());
        cb.require_boolean(
            "at most one of is_most_significant_byte is one",
            sum::expr(&is_most_significant_byte),
        );

        let most_significant_byte = sum::expr(
            value_rlc
                .cells
                .iter()
                .zip(&is_most_significant_byte)
                .map(|(byte, indicator)| byte.expr() * indicator.expr()),
        );
        let most_significant_byte_is_zero = IsZeroGadget::construct(cb, most_significant_byte);
        let is_lt_128 = cb.query_bool();

        let value = expr_from_bytes(&value_rlc.cells);
        cb.condition(most_significant_byte_is_zero.expr(), |cb| {
            cb.require_zero("if most significant byte is 0, value is 0", value.clone());
            cb.require_zero(
                "if most significant byte is 0, value is less than 128",
                1.expr() - is_lt_128.expr(),
            );
        });

        for (i, is_most_significant) in is_most_significant_byte.iter().enumerate() {
            cb.condition(is_most_significant.expr(), |cb| {
                cb.require_equal(
                    "most significant byte is non-zero",
                    most_significant_byte_is_zero.expr(),
                    0.expr(),
                );
                cb.require_equal(
                    "higher bytes are 0",
                    expr_from_bytes(&value_rlc.cells[0..(i + 1)]),
                    value.clone(),
                );
            });
        }

        // If is_lt_128, then value < 128, checked by a lookup.

        // Otherwise, then value >= 128, checked as follows:
        // - Either the first byte is not the most significant, and there is a more significant one;
        // - Or the first byte is the most significant, and it is >= 128. value ∈ [128, 256) (value
        //   - 128) ∈ [0, 128)
        let byte_128 = value_rlc.cells[0].expr() - 128.expr();
        let is_first = is_most_significant_byte[0].expr();
        let byte_128_or_zero = byte_128 * is_first;

        let value_lt_128 = select::expr(is_lt_128.expr(), value, byte_128_or_zero);
        cb.range_lookup(value_lt_128, 128);

        Self {
            value_rlc,
            is_most_significant_byte,
            most_significant_byte_is_zero,
            is_lt_128,
        }
    }

    /// Assign witness data to the RlpU64 gadget.
    fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: u64,
    ) -> Result<(), Error> {
        let value_bytes = value.to_le_bytes();

        let most_significant_byte_index = value_bytes
            .iter()
            .rev()
            .position(|&byte| byte != 0)
            .map(|i| N_BYTES_U64 - i - 1);
        self.most_significant_byte_is_zero.assign(
            region,
            offset,
            most_significant_byte_index
                .map(|i| F::from(value_bytes[i] as u64))
                .unwrap_or_default(),
        )?;

        self.value_rlc.assign(region, offset, Some(value_bytes))?;

        for i in 0..N_BYTES_U64 {
            self.is_most_significant_byte[i].assign(
                region,
                offset,
                Value::known(
                    (Some(i) == most_significant_byte_index)
                        .to_scalar()
                        .unwrap(),
                ),
            )?;
        }

        self.is_lt_128.assign(
            region,
            offset,
            Value::known((value < 128).to_scalar().unwrap()),
        )?;

        Ok(())
    }

    /// Value of the U64 as an expression.
    fn value(&self) -> Expression<F> {
        expr_from_bytes(&self.value_rlc.cells)
    }

    /// Minimum number of bytes it takes to represent the U64 value.
    fn n_bytes(&self) -> Expression<F> {
        sum::expr(
            self.is_most_significant_byte
                .iter()
                .enumerate()
                .map(|(i, indicator)| (1 + i).expr() * indicator.expr()),
        )
    }

    /// Length of the RLP-encoding of the U64 value.
    fn rlp_length(&self) -> Expression<F> {
        1.expr() + (not::expr(self.is_lt_128.expr()) * self.n_bytes())
    }

    /// RLC for the RLP-encoding of the U64 value.
    fn rlp_rlc(&self, cb: &EVMConstraintBuilder<F>) -> Expression<F> {
        select::expr(
            and::expr([
                self.is_lt_128.expr(),
                not::expr(self.most_significant_byte_is_zero.expr()),
            ]),
            self.value(),
            (0x80.expr() + self.n_bytes()) * self.challenge_power_n_bytes(cb)
                + self.value_rlc.expr(),
        )
    }

    fn challenge_power_rlp_length(&self, cb: &EVMConstraintBuilder<F>) -> Expression<F> {
        cb.challenges().keccak_input()
            * select::expr(
                self.is_lt_128.expr(),
                1.expr(),
                self.challenge_power_n_bytes(cb),
            )
    }

    fn challenge_power_n_bytes(&self, cb: &EVMConstraintBuilder<F>) -> Expression<F> {
        select::expr(
            self.most_significant_byte_is_zero.expr(),
            1.expr(),
            sum::expr(
                self.is_most_significant_byte
                    .iter()
                    .zip(cb.challenges().keccak_powers_of_randomness::<N_BYTES_U64>())
                    .map(|(indicator, power)| indicator.expr() * power.expr()),
            ),
        )
    }
}

#[derive(Clone, Debug)]
pub struct ContractCreateGadget<F, const IS_CREATE2: bool> {
    /// Sender address of the contract creation tx.
    caller_address: RandomLinearCombination<F, N_BYTES_ACCOUNT_ADDRESS>,
    /// Sender nonce of the contract creation tx.
    nonce: RlpU64Gadget<F>,
    /// Keccak256 hash of init code, used for CREATE2. We don't use a
    /// RandomLinearCombination here since we require both keccak and word
    /// RLC in the case of init code hash, for BeginTx and
    /// CREATE2 respectively. Instead, we store just the bytes and calculate the
    /// appropriate RLC wherever needed.
    keccak_code_hash: [Cell<F>; N_BYTES_WORD],
    /// RLC of the init code's hash. The value of this field is feature gated and can be the keccak
    /// or the poseidon hash.
    code_hash_rlc: Cell<F>,
    /// Random salt for CREATE2.
    salt: [Cell<F>; N_BYTES_WORD],
}

impl<F: Field, const IS_CREATE2: bool> ContractCreateGadget<F, IS_CREATE2> {
    /// Configure and construct the gadget.
    pub(crate) fn construct(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let caller_address = cb.query_keccak_rlc();
        let nonce = RlpU64Gadget::construct(cb);
        let keccak_code_hash = array_init::array_init(|_| cb.query_byte());
        let code_hash_rlc = cb.query_cell_phase2();
        let salt = array_init::array_init(|_| cb.query_byte());

        #[cfg(not(feature = "poseidon-codehash"))]
        {
            let word_rlc = cb.word_rlc::<N_BYTES_WORD>(
                keccak_code_hash
                    .iter()
                    .map(Expr::expr)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
            );
            cb.require_zero(
                "keccak_code_hash == 0 or keccak_code_hash == code_hash",
                word_rlc.expr() * (word_rlc.expr() - code_hash_rlc.expr()),
            );
        }

        Self {
            caller_address,
            nonce,
            keccak_code_hash,
            code_hash_rlc,
            salt,
        }
    }

    /// Assign witness data to the ContractCreate gadget.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        caller_address: Address,
        caller_nonce: u64,
        keccak_code_hash: Option<Word>,
        code_hash: Option<Word>,
        salt: Option<Word>,
    ) -> Result<(), Error> {
        let mut caller_address_bytes = caller_address.to_fixed_bytes();
        caller_address_bytes.reverse();
        self.caller_address
            .assign(region, offset, Some(caller_address_bytes))?;

        self.nonce.assign(region, offset, caller_nonce)?;

        #[cfg(feature = "poseidon-codehash")]
        if code_hash.is_some() && keccak_code_hash.is_some() {
            debug_assert_ne!(code_hash, keccak_code_hash);
        }
        #[cfg(not(feature = "poseidon-codehash"))]
        if code_hash.is_some() && keccak_code_hash.is_some() {
            debug_assert_eq!(code_hash, keccak_code_hash);
        }

        for (c, v) in self.keccak_code_hash.iter().zip(
            keccak_code_hash
                .map(|v| v.to_le_bytes())
                .unwrap_or_default(),
        ) {
            c.assign(region, offset, Value::known(F::from(v as u64)))?;
        }
        self.code_hash_rlc.assign(
            region,
            offset,
            region.code_hash(code_hash.unwrap_or_default()),
        )?;
        for (c, v) in self
            .salt
            .iter()
            .zip(salt.map(|v| v.to_le_bytes()).unwrap_or_default())
        {
            c.assign(region, offset, Value::known(F::from(v as u64)))?;
        }

        Ok(())
    }

    /// Caller address' value.
    pub(crate) fn caller_address(&self) -> Expression<F> {
        expr_from_bytes(&self.caller_address.cells)
    }

    /// Caller nonce's value.
    pub(crate) fn caller_nonce(&self) -> Expression<F> {
        self.nonce.value()
    }

    /// Dynamic code hash in RLC form.
    pub(crate) fn code_hash_word_rlc(&self) -> Expression<F> {
        self.code_hash_rlc.expr()
    }

    /// Init Code's keccak hash word RLC.
    pub(crate) fn keccak_code_hash_word_rlc(&self, cb: &EVMConstraintBuilder<F>) -> Expression<F> {
        cb.word_rlc::<N_BYTES_WORD>(
            self.keccak_code_hash
                .iter()
                .map(Expr::expr)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        )
    }

    /// Init Code's keccak hash keccak RLC.
    pub(crate) fn keccak_code_hash_keccak_rlc(
        &self,
        cb: &EVMConstraintBuilder<F>,
    ) -> Expression<F> {
        cb.keccak_rlc::<N_BYTES_WORD>(
            self.keccak_code_hash
                .iter()
                .map(Expr::expr)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        )
    }

    /// Salt EVM word RLC.
    pub(crate) fn salt_word_rlc(&self, cb: &EVMConstraintBuilder<F>) -> Expression<F> {
        cb.word_rlc::<N_BYTES_WORD>(
            self.salt
                .iter()
                .map(Expr::expr)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        )
    }

    /// Salt keccak RLC.
    pub(crate) fn salt_keccak_rlc(&self, cb: &EVMConstraintBuilder<F>) -> Expression<F> {
        cb.keccak_rlc::<N_BYTES_WORD>(
            self.salt
                .iter()
                .map(Expr::expr)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        )
    }

    /// Caller address' RLC value.
    pub(crate) fn caller_address_rlc(&self) -> Expression<F> {
        self.caller_address.expr()
    }

    /// Caller nonce's RLC value.
    pub(crate) fn caller_nonce_rlc(&self) -> Expression<F> {
        self.nonce.value_rlc.expr()
    }

    /// Length of the input data to the keccak hash function.
    pub(crate) fn input_length(&self) -> Expression<F> {
        if IS_CREATE2 {
            // | 0xff | caller_address | salt | code_hash |
            // |------|----------------|------|-----------|
            // | 1    | 20             | 32   | 32        |
            (1 + 20 + 32 + 32).expr()
        } else {
            // | prefix | addr-prefix | addr | nonce-bytes       |
            // |--------|-------------|------|-------------------|
            // | 1      | 1           | 20   | rlp_length(nonce) |
            22.expr() + self.nonce.rlp_length()
        }
    }

    /// RLC for the input data.
    pub(crate) fn input_rlc(&self, cb: &EVMConstraintBuilder<F>) -> Expression<F> {
        let challenges = cb.challenges().keccak_powers_of_randomness::<21>();
        let challenge_power_20 = challenges[19].clone();
        if IS_CREATE2 {
            // RLC(le-bytes([0xff | caller_address | salt | code_hash]))
            //
            // | 0xff | caller address | salt | init code hash |
            // |------|----------------|------|----------------|
            // | 1    | 20             | 32   | 32             |
            let challenge_power_16 = challenges[15].clone();
            let challenge_power_32 = challenge_power_16.square();
            let challenge_power_64 = challenge_power_32.clone().square();
            let challenge_power_84 = challenge_power_64.clone() * challenge_power_20;
            (0xff.expr() * challenge_power_84)
                + (self.caller_address_rlc() * challenge_power_64)
                + (self.salt_keccak_rlc(cb) * challenge_power_32)
                + self.keccak_code_hash_keccak_rlc(cb)
        } else {
            // RLC(RLP([caller_address, caller_nonce]))
            let challenge_power_21 = challenges[20].clone();
            ((self.caller_address_rlc()
                + (148.expr() * challenge_power_20)
                + ((213.expr() + self.nonce.rlp_length()) * challenge_power_21))
                * self.nonce.challenge_power_rlp_length(cb))
                + self.nonce.rlp_rlc(cb)
        }
    }
}

#[cfg(test)]
mod test {
    use super::{super::test_util::*, ContractCreateGadget};
    use bus_mapping::state_db::CodeDB;
    use eth_types::{Field, ToAddress, ToLittleEndian, ToWord, Word};
    use ethers_core::utils::keccak256;
    use gadgets::util::{not, Expr};
    use halo2_proofs::halo2curves::bn256::Fr;

    use crate::evm_circuit::util::{
        constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
        CachedRegion, Cell,
    };

    #[derive(Clone)]
    struct ContractCreateGadgetContainer<F, const IS_CREATE2: bool> {
        create_gadget: ContractCreateGadget<F, IS_CREATE2>,
        input_len_expected: Cell<F>,
        create_input_rlc_expected: [Cell<F>; 32],
        create2_input_rlc_expected: [Cell<F>; 85],
    }

    impl<F: Field, const IS_CREATE2: bool> MathGadgetContainer<F>
        for ContractCreateGadgetContainer<F, IS_CREATE2>
    {
        fn configure_gadget_container(cb: &mut EVMConstraintBuilder<F>) -> Self {
            let create_gadget = ContractCreateGadget::construct(cb);
            let input_len_expected = cb.query_cell();
            let create_input_rlc_expected = array_init::array_init(|_| cb.query_byte());
            let create2_input_rlc_expected = array_init::array_init(|_| cb.query_byte());
            cb.require_equal(
                "RLP length correct",
                input_len_expected.expr(),
                create_gadget.input_length(),
            );
            cb.condition(IS_CREATE2.expr(), |cb| {
                cb.require_equal(
                    "CREATE2 RLP-encoding correct",
                    cb.keccak_rlc::<85>(
                        create2_input_rlc_expected
                            .iter()
                            .map(Expr::expr)
                            .collect::<Vec<_>>()
                            .try_into()
                            .unwrap(),
                    ),
                    create_gadget.input_rlc(cb),
                );
            });
            cb.condition(not::expr(IS_CREATE2.expr()), |cb| {
                cb.require_equal(
                    "CREATE RLP-encoding correct",
                    cb.keccak_rlc::<32>(
                        create_input_rlc_expected
                            .iter()
                            .map(Expr::expr)
                            .collect::<Vec<_>>()
                            .try_into()
                            .unwrap(),
                    ),
                    create_gadget.input_rlc(cb),
                );
            });

            Self {
                create_gadget,
                input_len_expected,
                create_input_rlc_expected,
                create2_input_rlc_expected,
            }
        }

        fn assign_gadget_container(
            &self,
            witnesses: &[Word],
            region: &mut CachedRegion<'_, '_, F>,
        ) -> Result<(), halo2_proofs::plonk::Error> {
            let offset = 0;
            let caller_address = witnesses[0].to_address();
            let caller_nonce = witnesses[1].as_u64();
            let input_len = witnesses[2].as_u64();
            let (salt, init_code_keccak_hash, init_code_hash) = if IS_CREATE2 {
                (Some(witnesses[5]), Some(witnesses[6]), Some(witnesses[7]))
            } else {
                (None, None, None)
            };

            self.create_gadget.assign(
                region,
                offset,
                caller_address,
                caller_nonce,
                init_code_keccak_hash,
                init_code_hash,
                salt,
            )?;
            self.input_len_expected
                .assign(region, offset, Value::known(F::from(input_len)))?;
            if IS_CREATE2 {
                for c in self.create_input_rlc_expected.iter() {
                    c.assign(region, offset, Value::known(F::ZERO))?;
                }
                for (c, v) in self.create2_input_rlc_expected.iter().zip(
                    [
                        witnesses[6].to_le_bytes().as_ref(), // 32-byte init code's keccak hash
                        witnesses[5].to_le_bytes().as_ref(), // 32-byte salt
                        witnesses[4].to_le_bytes()[0..20].as_ref(), // 20-byte address
                        witnesses[3].to_le_bytes()[0..1].as_ref(), // 0xff
                    ]
                    .concat(),
                ) {
                    c.assign(region, offset, Value::known(F::from(v as u64)))?;
                }
            } else {
                for (c, v) in self
                    .create_input_rlc_expected
                    .iter()
                    .zip(witnesses[3].to_le_bytes())
                {
                    c.assign(region, offset, Value::known(F::from(v as u64)))?;
                }
                for c in self.create2_input_rlc_expected.iter() {
                    c.assign(region, offset, Value::known(F::ZERO))?;
                }
            }

            Ok(())
        }
    }

    #[test]
    fn create_address() {
        for (caller_address, caller_nonce) in [
            (mock::MOCK_ACCOUNTS[0], 0x00u64),
            (mock::MOCK_ACCOUNTS[1], 0x01u64),
            (mock::MOCK_ACCOUNTS[2], 0x7fu64),
            (mock::MOCK_ACCOUNTS[3], 0x80u64),
            (mock::MOCK_ACCOUNTS[4], 0xffu64),
            (mock::MOCK_ACCOUNTS[0], 0xffffu64),
            (mock::MOCK_ACCOUNTS[1], 0xffffffu64),
            (mock::MOCK_ACCOUNTS[2], 0xffffffffu64),
            (mock::MOCK_ACCOUNTS[3], 0xffffffffffu64),
            (mock::MOCK_ACCOUNTS[4], 0xffffffffffffu64),
            (mock::MOCK_ACCOUNTS[0], 0xffffffffffffffu64),
            (mock::MOCK_ACCOUNTS[1], 0xffffffffffffffffu64),
        ] {
            let (rlp_word, rlp_len) = {
                let mut stream = ethers_core::utils::rlp::RlpStream::new();
                stream.begin_list(2);
                stream.append(&caller_address);
                stream.append(&caller_nonce);
                let rlp_encoded = stream.out().to_vec();
                (
                    Word::from_big_endian(&rlp_encoded),
                    Word::from(rlp_encoded.len()),
                )
            };
            try_test!(
                ContractCreateGadgetContainer<Fr, false>,
                [
                    caller_address.to_word(),
                    Word::from(caller_nonce),
                    rlp_len,
                    rlp_word,
                ],
                true
            );
        }
    }

    #[test]
    fn create2_address() {
        let caller_address = mock::MOCK_ACCOUNTS[0];
        let salt = Word::from(0xbeefcafedeadu64);
        let code = [1, 2, 3, 4, 5, 6, 7, 8];
        let code_hash = Word::from(CodeDB::hash(&code).to_fixed_bytes());
        let keccak_code_hash = Word::from(keccak256(code));
        try_test!(
            ContractCreateGadgetContainer<Fr, true>,
            [
                caller_address.to_word(),
                Word::default(),
                85u64.into(),
                Word::from(0xffu64),
                caller_address.to_word(),
                salt,
                keccak_code_hash,
                code_hash,
            ],
            true
        )
    }
}
