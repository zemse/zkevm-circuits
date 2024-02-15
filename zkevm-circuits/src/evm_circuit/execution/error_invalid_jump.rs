use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_PROGRAM_COUNTER,
        step::ExecutionState,
        util::{
            common_gadget::{CommonErrorGadget, WordByteCapGadget},
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::{IsEqualGadget, IsZeroWordGadget},
            CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::{
        word::{WordExpr, WordLoHi, WordLoHiCell},
        Expr,
    },
};
use eth_types::{evm_types::OpcodeId, Field, U256};

use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ErrorInvalidJumpGadget<F> {
    opcode: Cell<F>,
    dest: WordByteCapGadget<F, N_BYTES_PROGRAM_COUNTER>,
    code_len: Cell<F>,
    value: Cell<F>,
    is_code: Cell<F>,
    is_jump_dest: IsEqualGadget<F>,
    is_jumpi: IsEqualGadget<F>,
    condition: WordLoHiCell<F>,
    is_condition_zero: IsZeroWordGadget<F, WordLoHiCell<F>>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorInvalidJumpGadget<F> {
    const NAME: &'static str = "ErrorInvalidJump";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorInvalidJump;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let code_len = cb.query_cell();
        let dest = WordByteCapGadget::construct(cb, code_len.expr());

        let opcode = cb.query_cell();
        let value = cb.query_cell();
        let is_code = cb.query_cell();
        let condition = cb.query_word_unchecked();

        cb.require_in_set(
            "ErrorInvalidJump only happened in JUMP or JUMPI",
            opcode.expr(),
            vec![OpcodeId::JUMP.expr(), OpcodeId::JUMPI.expr()],
        );

        let is_jumpi = cb.is_eq(opcode.expr(), OpcodeId::JUMPI.expr());

        // initialize is_jump_dest
        let is_jump_dest = cb.is_eq(value.expr(), OpcodeId::JUMPDEST.expr());

        // first default this condition, if use will re-construct with real condition
        // value
        let is_condition_zero = cb.is_zero_word(&condition);

        // Pop the value from the stack
        cb.stack_pop(dest.original_word().to_word());

        cb.condition(is_jumpi.expr(), |cb| {
            cb.stack_pop(condition.to_word());
            // if condition is zero, jump will not happen, so constrain condition not zero
            cb.require_zero("condition is not zero", is_condition_zero.expr());
        });

        // Look up bytecode length
        cb.bytecode_length(cb.curr.state.code_hash.to_word(), code_len.expr());

        // If destination is in valid range, lookup for the value.
        cb.condition(dest.lt_cap(), |cb| {
            cb.bytecode_lookup(
                cb.curr.state.code_hash.to_word(),
                dest.valid_value(),
                is_code.expr(),
                value.expr(),
            );
            cb.require_zero(
                "is_code is false or not JUMPDEST",
                is_code.expr() * is_jump_dest.expr(),
            );
        });

        let common_error_gadget =
            CommonErrorGadget::construct(cb, opcode.expr(), cb.rw_counter_offset());

        Self {
            opcode,
            dest,
            code_len,
            value,
            is_code,
            is_jump_dest,
            is_jumpi,
            condition,
            is_condition_zero,
            common_error_gadget,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let opcode = step.opcode().unwrap();
        let is_jumpi = opcode == OpcodeId::JUMPI;
        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;

        let condition = if is_jumpi {
            block.get_rws(step, 1).stack_value()
        } else {
            U256::zero()
        };

        let code = block
            .bytecodes
            .get_from_h256(&call.code_hash)
            .expect("could not find current environment's bytecode");
        let code_len = code.codesize() as u64;
        self.code_len
            .assign(region, offset, Value::known(F::from(code_len)))?;

        let dest = block.get_rws(step, 0).stack_value();
        self.dest.assign(region, offset, dest, F::from(code_len))?;

        // set default value in case can not find value, is_code from bytecode table
        let dest = usize::try_from(dest).unwrap_or(code.codesize());
        let (value, is_code) = code.get(dest).unwrap_or((0, false));

        self.value
            .assign(region, offset, Value::known(F::from(value as u64)))?;
        self.is_code
            .assign(region, offset, Value::known(F::from(is_code as u64)))?;
        self.is_jump_dest.assign(
            region,
            offset,
            F::from(value as u64),
            F::from(OpcodeId::JUMPDEST.as_u64()),
        )?;

        self.is_jumpi.assign(
            region,
            offset,
            F::from(opcode.as_u64()),
            F::from(OpcodeId::JUMPI.as_u64()),
        )?;

        self.condition.assign_u256(region, offset, condition)?;
        self.is_condition_zero.assign_value(
            region,
            offset,
            Value::known(WordLoHi::from(condition)),
        )?;

        self.common_error_gadget.assign(
            region,
            offset,
            block,
            call,
            step,
            3 + is_jumpi as usize,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {

    use crate::test_util::CircuitTestBuilder;
    use eth_types::{
        address, bytecode, bytecode::Bytecode, evm_types::OpcodeId, geth_types::Account, Address,
        ToWord, Word,
    };

    use mock::TestContext;

    fn test_invalid_jump(destination: usize, out_of_range: bool) {
        let mut bytecode = bytecode! {
            PUSH32(if out_of_range { destination + 10} else { destination })
            JUMP
        };

        // incorrect assigning for invalid jump
        for _ in 0..(destination - 33) {
            bytecode.write(0, false);
        }
        bytecode.append(&bytecode! {
            JUMPDEST
            STOP
        });

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }

    #[test]
    fn invalid_jump_err() {
        test_invalid_jump(34, false);
    }

    #[test]
    fn invalid_jump_outofrange() {
        test_invalid_jump(40, true);
    }

    #[test]
    fn invalid_jump_internal() {
        // test jump error in internal call
        test_internal_jump_error(false);
        // test jumpi error in internal call
        test_internal_jump_error(true);
    }

    #[test]
    fn invalid_jump_dest_overflow() {
        let bytecode = bytecode! {
            PUSH32(Word::MAX)
            JUMP
        };

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }

    fn callee(code: Bytecode) -> Account {
        Account::mock_code_balance(code)
    }

    // jump or jumpi error happen in internal call
    fn test_internal_jump_error(is_jumpi: bool) {
        let mut caller_bytecode = bytecode! {
            PUSH1(0)
            PUSH1(0)
            PUSH1(0)
            PUSH1(0)
            PUSH1(0)
        };

        caller_bytecode.append(&bytecode! {
            PUSH32(Address::repeat_byte(0xff).to_word())
            PUSH2(10000)
            CALL
            STOP
        });

        let opcode = if is_jumpi {
            OpcodeId::JUMPI
        } else {
            OpcodeId::JUMP
        };

        let mut callee_bytecode = bytecode! {
            PUSH1(1) //  work as condition if is_jumpi
            PUSH1(42) // jump dest 45
            .write_op(opcode)

            PUSH1(0)
            PUSH1(0)
            PUSH1(0)
            PUSH1(0)
            PUSH1(0)
        };

        callee_bytecode.append(&bytecode! {
            PUSH20(Address::repeat_byte(0xff).to_word())
            PUSH1(132) // gas

            JUMPDEST
            GAS
            PUSH1(1)
            AND
            PUSH1(56)
            JUMPI

            PUSH1(0)
            PUSH1(0)
            REVERT

            JUMPDEST
            STOP
        });
        test_ok(
            Account::mock_100_ether(caller_bytecode),
            callee(callee_bytecode),
        );
    }

    fn test_ok(caller: Account, callee: Account) {
        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x000000000000000000000000000000000000cafe"))
                    .balance(Word::from(10u64.pow(19)));
                accs[1].account(&caller);
                accs[2].account(&callee);
            },
            |mut txs, accs| {
                txs[0]
                    .from(accs[0].address)
                    .to(accs[1].address)
                    .gas(100000.into());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    fn test_invalid_jumpi(destination: usize) {
        let mut bytecode = bytecode! {
            PUSH32(destination)
            PUSH32(100) // condition
            JUMPI
        };

        // incorrect assigning for invalid jump
        for _ in 0..(destination - 33) {
            bytecode.write(0, false);
        }
        bytecode.append(&bytecode! {
            JUMPDEST
            STOP
        });

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }

    #[test]
    fn invalid_jumpi_err_root() {
        test_invalid_jumpi(34);
    }
}
