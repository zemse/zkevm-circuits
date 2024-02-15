//! Testing utilities

use crate::{
    evm_circuit::{cached::EvmCircuitCached, EvmCircuit},
    state_circuit::StateCircuit,
    util::SubCircuit,
    witness::{Block, Rw},
};
use bus_mapping::{
    circuit_input_builder::{FeatureConfig, FixedCParams},
    mock::BlockData,
};
use eth_types::geth_types::GethData;
use itertools::all;
use std::cmp;
use thiserror::Error;

use crate::util::log2_ceil;
use halo2_proofs::{
    dev::{MockProver, VerifyFailure},
    halo2curves::bn256::Fr,
};
use mock::TestContext;

#[cfg(test)]
#[ctor::ctor]
fn init_env_logger() {
    // Enable RUST_LOG during tests
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("error")).init();
}

const NUM_BLINDING_ROWS: usize = 64;

#[allow(clippy::type_complexity)]
/// Struct used to easily generate tests for EVM &| State circuits being able to
/// customize all of the steps involved in the testing itself.
///
/// By default, the tests run through `prover.assert_satisfied()` but the
/// builder pattern provides functions that allow to pass different functions
/// that the prover should execute when verifying the CTB correctness.
///
/// The CTB also includes a mechanism to receive calls that will modify the
/// block produced from the [`TestContext`] and apply them before starting to
/// compute the proof.
///
/// ## Example:
/// ```rust, no_run
/// use eth_types::geth_types::Account;
/// use eth_types::{address, bytecode, Address, Bytecode, ToWord, Word, U256, word};
/// use mock::{TestContext, MOCK_ACCOUNTS, gwei, eth};
/// use zkevm_circuits::test_util::CircuitTestBuilder;
///     let code = bytecode! {
/// // [ADDRESS, STOP]
///     PUSH32(word!("
/// 3000000000000000000000000000000000000000000000000000000000000000"))
///     PUSH1(0)
///     MSTORE
///
///     PUSH1(2)
///     PUSH1(0)
///     RETURN
/// };
/// let ctx = TestContext::<1, 1>::new(
///     None,
///     |accs| {
///         accs[0].address(MOCK_ACCOUNTS[0]).balance(eth(20));
///     },
///     |mut txs, _accs| {
///         txs[0]
///             .from(MOCK_ACCOUNTS[0])
///             .gas_price(gwei(2))
///             .gas(Word::from(0x10000))
///             .value(eth(2))
///             .input(code.into());
///     },
///     |block, _tx| block.number(0xcafeu64),
/// )
/// .unwrap();
///
/// CircuitTestBuilder::new_from_test_ctx(ctx)
///     .block_modifier(Box::new(|block| block.circuits_params.max_evm_rows = (1 << 18) - 100))
///     .run();
/// ```
pub struct CircuitTestBuilder<const NACC: usize, const NTX: usize> {
    test_ctx: Option<TestContext<NACC, NTX>>,
    circuits_params: Option<FixedCParams>,
    feature_config: Option<FeatureConfig>,
    block: Option<Block<Fr>>,
    block_modifiers: Vec<Box<dyn Fn(&mut Block<Fr>)>>,
}

impl<const NACC: usize, const NTX: usize> CircuitTestBuilder<NACC, NTX> {
    /// Generates an empty/set to default `CircuitTestBuilder`.
    fn empty() -> Self {
        CircuitTestBuilder {
            test_ctx: None,
            circuits_params: None,
            feature_config: None,
            block: None,
            block_modifiers: vec![],
        }
    }

    /// Generates a CTBC from a [`TestContext`] passed with all the other fields
    /// set to [`Default`].
    pub fn new_from_test_ctx(ctx: TestContext<NACC, NTX>) -> Self {
        Self::empty().test_ctx(ctx)
    }

    /// Generates a CTBC from a [`Block`] passed with all the other fields
    /// set to [`Default`].
    pub fn new_from_block(block: Block<Fr>) -> Self {
        Self::empty().block(block)
    }

    /// Allows to produce a [`TestContext`] which will serve as the generator of
    /// the Block.
    pub fn test_ctx(mut self, ctx: TestContext<NACC, NTX>) -> Self {
        self.test_ctx = Some(ctx);
        self
    }

    /// Allows to pass a non-default [`FixedCParams`] to the builder.
    /// This means that we can increase for example, the `max_rws` or `max_txs`.
    pub fn params(mut self, params: FixedCParams) -> Self {
        assert!(
            self.block.is_none(),
            "circuit_params already provided in the block"
        );
        self.circuits_params = Some(params);
        self
    }

    /// Configure [`FeatureConfig`]
    pub fn feature(mut self, feature_config: FeatureConfig) -> Self {
        assert!(self.feature_config.is_none(), "Already configured");
        self.feature_config = Some(feature_config);
        self
    }

    /// Allows to pass a [`Block`] already built to the constructor.
    pub fn block(mut self, block: Block<Fr>) -> Self {
        self.block = Some(block);
        self
    }

    #[allow(clippy::type_complexity)]
    /// Allows to provide modifier functions for the [`Block`] that will be
    /// generated within this builder.
    ///
    /// That removes the need in a lot of tests to build the block outside of
    /// the builder because they need to modify something particular.
    pub fn block_modifier(mut self, modifier: Box<dyn Fn(&mut Block<Fr>)>) -> Self {
        self.block_modifiers.push(modifier);
        self
    }
}

impl<const NACC: usize, const NTX: usize> CircuitTestBuilder<NACC, NTX> {
    /// build block
    pub fn build_block(&self) -> Result<Block<Fr>, CircuitTestError> {
        if let Some(block) = &self.block {
            // If a block is specified, no need to modify the block
            return Ok(block.clone());
        }
        let block = self
            .test_ctx
            .as_ref()
            .ok_or(CircuitTestError::NotEnoughAttributes)?;
        let block: GethData = block.clone().into();
        let builder = BlockData::new_from_geth_data(block.clone())
            .new_circuit_input_builder_with_feature(self.feature_config.unwrap_or_default());
        let builder = builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .map_err(|err| CircuitTestError::CannotHandleBlock(err.to_string()))?;
        // Build a witness block from trace result.
        let mut block = crate::witness::block_convert(&builder)
            .map_err(|err| CircuitTestError::CannotConvertBlock(err.to_string()))?;

        for modifier_fn in &self.block_modifiers {
            modifier_fn.as_ref()(&mut block);
        }
        Ok(block)
    }

    fn run_evm_circuit_test(&self, block: Block<Fr>) -> Result<(), CircuitTestError> {
        let k = block.get_test_degree();

        let (active_gate_rows, active_lookup_rows) = EvmCircuit::<Fr>::get_active_rows(&block);

        // Mainnet EVM circuit constraints can be cached for test performance.
        // No cache for EVM circuit with customized features
        let prover = if block.feature_config.is_mainnet() {
            let circuit = EvmCircuitCached::get_test_circuit_from_block(block);
            MockProver::<Fr>::run(k, &circuit, vec![])
        } else {
            let circuit = EvmCircuit::get_test_circuit_from_block(block);
            MockProver::<Fr>::run(k, &circuit, vec![])
        };

        let prover = prover.map_err(|err| CircuitTestError::SynthesisFailure {
            circuit: Circuit::EVM,
            reason: err,
        })?;

        prover
            .verify_at_rows(
                active_gate_rows.iter().cloned(),
                active_lookup_rows.iter().cloned(),
            )
            .map_err(|err| CircuitTestError::VerificationFailed {
                circuit: Circuit::EVM,
                reasons: err,
            })
    }
    // TODO: use randomness as one of the circuit public input, since randomness in
    // state circuit and evm circuit must be same
    fn run_state_circuit_test(&self, block: Block<Fr>) -> Result<(), CircuitTestError> {
        let rows_needed = StateCircuit::<Fr>::min_num_rows_block(&block).1;
        let k = cmp::max(log2_ceil(rows_needed + NUM_BLINDING_ROWS), 18);
        let max_rws = block.circuits_params.max_rws;
        let state_circuit = StateCircuit::<Fr>::new(block.rws, max_rws);
        let instance = state_circuit.instance();
        let prover = MockProver::<Fr>::run(k, &state_circuit, instance).map_err(|err| {
            CircuitTestError::SynthesisFailure {
                circuit: Circuit::State,
                reason: err,
            }
        })?;
        // Skip verification of Start rows to accelerate testing
        let non_start_rows_len = state_circuit
            .rows
            .iter()
            .filter(|rw| !matches!(rw, Rw::Start { .. }))
            .count();
        let rows = max_rws - non_start_rows_len..max_rws;
        prover.verify_at_rows(rows.clone(), rows).map_err(|err| {
            CircuitTestError::VerificationFailed {
                circuit: Circuit::EVM,
                reasons: err,
            }
        })
    }
    /// Triggers the `CircuitTestBuilder` to convert the [`TestContext`] if any,
    /// into a [`Block`] and apply the default or provided block_modifiers or
    /// circuit checks to the provers generated for the State and EVM circuits.
    pub fn run_with_result(self) -> Result<(), CircuitTestError> {
        let block = self.build_block()?;

        self.run_evm_circuit_test(block.clone())?;
        self.run_state_circuit_test(block)
    }

    /// Convenient method to run in test cases that error handling is not required.
    pub fn run(self) {
        self.run_with_result().unwrap()
    }
}

#[derive(Debug)]
/// Circuits to test in [`CircuitTestBuilder`]
pub enum Circuit {
    /// EVM circuit
    EVM,
    /// State circuit
    State,
}

#[derive(Debug, Error)]
/// Errors for Circuit test
pub enum CircuitTestError {
    /// We didn't specify enough attibutes to define a block for the circuit test
    #[error("NotEnoughAttributes")]
    NotEnoughAttributes,
    /// Something wrong in the handle_block
    #[error("CannotHandleBlock({0})")]
    CannotHandleBlock(String),
    /// Something worng in the block_convert
    #[error("CannotConvertBlock({0})")]
    CannotConvertBlock(String),
    /// Problem constructing MockProver
    #[error("SynthesisFailure({circuit:?}, reason: {reason:?})")]
    SynthesisFailure {
        /// The circuit that causes the failure
        circuit: Circuit,
        /// The MockProver error that causes the failure
        reason: halo2_proofs::plonk::Error,
    },
    /// Failed to verify a circuit in the MockProver
    #[error("VerificationFailed({circuit:?}, reasons: {reasons:?})")]
    VerificationFailed {
        /// The circuit that causes the failure
        circuit: Circuit,
        /// The list of verification failure
        reasons: Vec<VerifyFailure>,
    },
}

impl CircuitTestError {
    /// Filter out EVM circuit failures
    ///
    /// Errors must come from EVM circuit and must be unsatisifed constraints or lookup failure
    pub fn assert_evm_failure(&self) {
        match self {
            Self::VerificationFailed { circuit, reasons } => {
                assert!(matches!(circuit, Circuit::EVM));
                assert!(!reasons.is_empty());

                assert!(all(reasons, |reason| matches!(
                    reason,
                    VerifyFailure::ConstraintNotSatisfied { .. } | VerifyFailure::Lookup { .. }
                )));
            }
            _ => panic!("Not a EVM circuit failure {self:?}"),
        }
    }
}
