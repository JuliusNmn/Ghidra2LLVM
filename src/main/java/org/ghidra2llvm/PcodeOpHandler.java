package org.ghidra2llvm;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;

public abstract class PcodeOpHandler<T> {

	public T translateStatement( PcodeBlockBasic block, PcodeOp op, Address addr) {
		switch (op.getOpcode()) {
		case PcodeOp.UNIMPLEMENTED: // Place holder for unimplemented instruction
		    return UNIMPLEMENTED(block, op, addr);
		case PcodeOp.COPY: // Copy one operand to another
		    return COPY(block, op, addr);
		case PcodeOp.LOAD: // Dereference a pointer into specified space
		    return LOAD(block, op, addr);
		case PcodeOp.STORE: // Store at a pointer into specified space
		    return STORE(block, op, addr);
		case PcodeOp.BRANCH: // Always branch
		    return BRANCH(block, op, addr);
		case PcodeOp.CBRANCH: // Conditional branch
		    return CBRANCH(block, op, addr);
		case PcodeOp.BRANCHIND: // An indirect branch (jumptable)
		    return BRANCHIND(block, op, addr);
		case PcodeOp.CALL: // A call with absolute address
		    return CALL(block, op, addr);
		case PcodeOp.CALLIND: // An indirect call
		    return CALLIND(block, op, addr);
		case PcodeOp.CALLOTHER: // Other unusual subroutine calling conventions
		    return CALLOTHER(block, op, addr);
		case PcodeOp.RETURN: // A from subroutine
		    return RETURN(block, op, addr);
		case PcodeOp.INT_EQUAL: // TRUE if operand1 == operand2
		    return INT_EQUAL(block, op, addr);
		case PcodeOp.INT_NOTEQUAL: // TRUE if operand1 != operand2
		    return INT_NOTEQUAL(block, op, addr);
		case PcodeOp.INT_SLESS: // TRUE if signed op1 < signed op2
		    return INT_SLESS(block, op, addr);
		case PcodeOp.INT_SLESSEQUAL: // TRUE if signed op1 <= signed op2
		    return INT_SLESSEQUAL(block, op, addr);
		case PcodeOp.INT_LESS: // TRUE if unsigned op1 < unsigned op2 // Also indicates borrow on
		                         // unsigned substraction
		    return INT_LESS(block, op, addr);
		case PcodeOp.INT_LESSEQUAL: // TRUE if unsigned op1 <= unsigned op2
		    return INT_LESSEQUAL(block, op, addr);
		case PcodeOp.INT_ZEXT: // Zero extend operand
		    return INT_ZEXT(block, op, addr);
		case PcodeOp.INT_SEXT: // Sign extend operand
		    return INT_SEXT(block, op, addr);
		case PcodeOp.INT_ADD: // Unsigned addition of operands of same size
		    return INT_ADD(block, op, addr);
		case PcodeOp.INT_SUB: // Unsigned subtraction of operands of same size
		    return INT_SUB(block, op, addr);
		case PcodeOp.INT_CARRY: // TRUE if adding two operands has overflow (carry)
		    return INT_CARRY(block, op, addr);
		case PcodeOp.INT_SCARRY: // TRUE if carry in signed addition of 2 ops
		    return INT_SCARRY(block, op, addr);
		case PcodeOp.INT_SBORROW: // TRUE if borrow in signed subtraction of 2 ops
		    return INT_SBORROW(block, op, addr);
		case PcodeOp.INT_2COMP: // Twos complement (for subtracting) of operand
			return INT_2COMP(block, op, addr);
		case PcodeOp.INT_NEGATE:
		    return INT_NEGATE(block, op, addr);
		case PcodeOp.INT_XOR: // Exclusive OR of two operands of same size
		    return INT_XOR(block, op, addr);
		case PcodeOp.INT_AND:
		    return INT_AND(block, op, addr);
		case PcodeOp.INT_OR:
		    return INT_OR(block, op, addr);
		case PcodeOp.INT_LEFT: // Left shift
		    return INT_LEFT(block, op, addr);
		case PcodeOp.INT_RIGHT: // Right shift zero fill
		    return INT_RIGHT(block, op, addr);
		case PcodeOp.INT_SRIGHT: // Signed right shift
		    return INT_SRIGHT(block, op, addr);
		case PcodeOp.INT_MULT: // Integer multiplication
		    return INT_MULT(block, op, addr);
		case PcodeOp.INT_DIV: // Unsigned integer division
		    return INT_DIV(block, op, addr);
		case PcodeOp.INT_SDIV: // Signed integer division
		    return INT_SDIV(block, op, addr);
		case PcodeOp.INT_REM: // Unsigned mod (remainder)
		    return INT_REM(block, op, addr);
		case PcodeOp.INT_SREM: // Signed mod (remainder)
		    return INT_SREM(block, op, addr);
		case PcodeOp.BOOL_NEGATE: // Boolean negate or not
		    return BOOL_NEGATE(block, op, addr);
		case PcodeOp.BOOL_XOR: // Boolean xor
		    return BOOL_XOR(block, op, addr);
		case PcodeOp.BOOL_AND: // Boolean and (&&)
		    return BOOL_AND(block, op, addr);
		case PcodeOp.BOOL_OR: // Boolean or (||)
		    return BOOL_OR(block, op, addr);
		case PcodeOp.FLOAT_EQUAL: // TRUE if operand1 == operand2
		    return FLOAT_EQUAL(block, op, addr);
		case PcodeOp.FLOAT_NOTEQUAL: // TRUE if operand1 != operand2
		    return FLOAT_NOTEQUAL(block, op, addr);
		case PcodeOp.FLOAT_LESS: // TRUE if op1 < op2
		    return FLOAT_LESS(block, op, addr);
		case PcodeOp.FLOAT_LESSEQUAL: // TRUE if op1 <= op2
		    return FLOAT_LESSEQUAL(block, op, addr);
		case PcodeOp.FLOAT_NAN: // TRUE if neither op1 is NaN
		    return FLOAT_NAN(block, op, addr);
		case PcodeOp.FLOAT_ADD: // float addition
		    return FLOAT_ADD(block, op, addr);
		case PcodeOp.FLOAT_DIV: // float division
		    return FLOAT_DIV(block, op, addr);
		case PcodeOp.FLOAT_MULT: // float multiplication
		    return FLOAT_MULT(block, op, addr);
		case PcodeOp.FLOAT_SUB: // float subtraction
		    return FLOAT_SUB(block, op, addr);
		case PcodeOp.FLOAT_NEG: // float negation
		    return FLOAT_NEG(block, op, addr);
		case PcodeOp.FLOAT_ABS: // float absolute value
		    return FLOAT_ABS(block, op, addr);
		case PcodeOp.FLOAT_SQRT: // float square root
		    return FLOAT_SQRT(block, op, addr);
		case PcodeOp.FLOAT_INT2FLOAT: // convert int type to float type
			return FLOAT_INT2FLOAT(block, op, addr);
		case PcodeOp.FLOAT_FLOAT2FLOAT: // convert between float sizes
			return FLOAT_FLOAT2FLOAT(block, op, addr);
		case PcodeOp.FLOAT_TRUNC: // round towards zero
		    return FLOAT_TRUNC(block, op, addr);
		case PcodeOp.FLOAT_CEIL: // round towards +infinity
		    return FLOAT_CEIL(block, op, addr);
		case PcodeOp.FLOAT_FLOOR: // round towards -infinity
		    return FLOAT_FLOOR(block, op, addr);
		case PcodeOp.FLOAT_ROUND: // round towards nearest
		    return FLOAT_ROUND(block, op, addr);

		case PcodeOp.MULTIEQUAL: // Output equal to one of inputs, depending on execution
		    return MULTIEQUAL(block, op, addr);
		case PcodeOp.INDIRECT: // Output probably equals input, but may be indirectly affected
		    return INDIRECT(block, op, addr);
		case PcodeOp.PIECE: // Output is constructed from multiple peices
		    return PIECE(block, op, addr);
		case PcodeOp.SUBPIECE: // Output is a subpiece of input0, input1=offset into input0
		    return SUBPIECE(block, op, addr);
		case PcodeOp.CAST: // Cast from one type to another
		    return CAST(block, op, addr);
		case PcodeOp.PTRADD: // outptr = ptrbase,offset, (size multiplier)
		    return PTRADD(block, op, addr);
		case PcodeOp.PTRSUB: // outptr = &(ptr->subfield)
		    return PTRSUB(block, op, addr);
		case PcodeOp.SEGMENTOP:
		    return SEGMENTOP(block, op, addr);
		case PcodeOp.CPOOLREF:
		    return CPOOLREF(block, op, addr);
		case PcodeOp.NEW:
		    return NEW(block, op, addr);
		case PcodeOp.INSERT:
		    return INSERT(block, op, addr);
		case PcodeOp.EXTRACT:
		    return EXTRACT(block, op, addr);
		case PcodeOp.POPCOUNT:
		    return POPCOUNT(block, op, addr);
		case PcodeOp.PCODE_MAX:
		    return PCODE_MAX(block, op, addr);

		}
		return null;
	}

	/** Place holder for unimplemented instruction */
	public abstract T UNIMPLEMENTED(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Copy one operand to another */
	public abstract T COPY(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Dereference a pointer into specified space */
	public abstract T LOAD(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Store at a pointer into specified space */
	public abstract T STORE(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Always branch */
	public abstract T BRANCH(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Conditional branch */
	public abstract T CBRANCH(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** An indirect branch (jumptable) */
	public abstract T BRANCHIND(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** A call with absolute address */
	public abstract T CALL(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** An indirect call */
	public abstract T CALLIND(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Other unusual subroutine calling conventions */
	public abstract T CALLOTHER(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** A from subroutine */
	public abstract T RETURN(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** TRUE if operand1 == operand2 */
	public abstract T INT_EQUAL(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** TRUE if operand1 != operand2 */
	public abstract T INT_NOTEQUAL(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** TRUE if signed op1 < signed op2 */
	public abstract T INT_SLESS(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** TRUE if signed op1 <= signed op2 */
	public abstract T INT_SLESSEQUAL(PcodeBlockBasic block, PcodeOp op, Address addr);

	/**
	 * TRUE if unsigned op1 < unsigned op2 // Also indicates borrow on
	 * unsigned substraction
	 */
	public abstract T INT_LESS(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** TRUE if unsigned op1 <= unsigned op2 */
	public abstract T INT_LESSEQUAL(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Zero extend operand */
	public abstract T INT_ZEXT(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Sign extend operand */
	public abstract T INT_SEXT(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Unsigned addition of operands of same size */
	public abstract T INT_ADD(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Unsigned subtraction of operands of same size */
	public abstract T INT_SUB(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** TRUE if adding two operands has overflow (carry) */
	public abstract T INT_CARRY(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** TRUE if carry in signed addition of 2 ops */
	public abstract T INT_SCARRY(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** TRUE if borrow in signed subtraction of 2 ops */
	public abstract T INT_SBORROW(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Twos complement (for subtracting) of operand */
	public abstract T INT_2COMP(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** negate */
	public abstract T INT_NEGATE(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Exclusive OR of two operands of same size */
	public abstract T INT_XOR(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** and */
	public abstract T INT_AND(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** or */
	public abstract T INT_OR(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Left shift */
	public abstract T INT_LEFT(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Right shift zero fill */
	public abstract T INT_RIGHT(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Signed right shift */
	public abstract T INT_SRIGHT(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Integer multiplication */
	public abstract T INT_MULT(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Unsigned integer division */
	public abstract T INT_DIV(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Signed integer division */
	public abstract T INT_SDIV(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Unsigned mod (remainder) */
	public abstract T INT_REM(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Signed mod (remainder) */
	public abstract T INT_SREM(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Boolean negate or not */
	public abstract T BOOL_NEGATE(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Boolean xor */
	public abstract T BOOL_XOR(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Boolean and (&&) */
	public abstract T BOOL_AND(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Boolean or (||) */
	public abstract T BOOL_OR(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** TRUE if operand1 == operand2 */
	public abstract T FLOAT_EQUAL(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** TRUE if operand1 != operand2 */
	public abstract T FLOAT_NOTEQUAL(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** TRUE if op1 < op2 */
	public abstract T FLOAT_LESS(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** TRUE if op1 <= op2 */
	public abstract T FLOAT_LESSEQUAL(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** TRUE if neither op1 is NaN */
	public abstract T FLOAT_NAN(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** float addition */
	public abstract T FLOAT_ADD(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** float division */
	public abstract T FLOAT_DIV(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** float multiplication */
	public abstract T FLOAT_MULT(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** float subtraction */
	public abstract T FLOAT_SUB(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** float negation */
	public abstract T FLOAT_NEG(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** float absolute value */
	public abstract T FLOAT_ABS(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** float square root */
	public abstract T FLOAT_SQRT(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** convert int type to float type */
	public abstract T FLOAT_INT2FLOAT(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** convert between float sizes */
	public abstract T FLOAT_FLOAT2FLOAT(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** round towards zero */
	public abstract T FLOAT_TRUNC(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** round towards +infinity */
	public abstract T FLOAT_CEIL(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** round towards -infinity */
	public abstract T FLOAT_FLOOR(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** round towards nearest */
	public abstract T FLOAT_ROUND(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Output equal to one of inputs, depending on execution */
	public abstract T MULTIEQUAL(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Output probably equals input, but may be indirectly affected */
	public abstract T INDIRECT(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Output is constructed from multiple peices */
	public abstract T PIECE(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Output is a subpiece of input0, input1=offset into input0 */
	public abstract T SUBPIECE(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** Cast from one type to another */
	public abstract T CAST(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** outptr = ptrbase,offset, (size multiplier) */
	public abstract T PTRADD(PcodeBlockBasic block, PcodeOp op, Address addr);

	/** outptr = &(ptr->subfield) */
	public abstract T PTRSUB(PcodeBlockBasic block, PcodeOp op, Address addr);

	public abstract T SEGMENTOP(PcodeBlockBasic block, PcodeOp op, Address addr);

	public abstract T CPOOLREF(PcodeBlockBasic block, PcodeOp op, Address addr);

	public abstract T NEW(PcodeBlockBasic block, PcodeOp op, Address addr);

	public abstract T INSERT(PcodeBlockBasic block, PcodeOp op, Address addr);

	public abstract T EXTRACT(PcodeBlockBasic block, PcodeOp op, Address addr);

	public abstract T POPCOUNT(PcodeBlockBasic block, PcodeOp op, Address addr);

	public abstract T PCODE_MAX(PcodeBlockBasic block, PcodeOp op, Address addr);

}
