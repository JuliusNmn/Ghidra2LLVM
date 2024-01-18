package org.ghidra2llvm;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import org.bytedeco.javacpp.PointerPointer;
import org.bytedeco.llvm.LLVM.*;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

import static org.bytedeco.llvm.global.LLVM.*;
public class PcodeLLVMBuilder extends PcodeOpHandler<LLVMValueRef> {
    private final Function function;
    private final LLVMTranslationContext ctx;
    private final LLVMBuilderRef builder;
    private final DecompileResults decompileResults;
    private LLVMTypeRef functionType;
    private LLVMValueRef llvmFunction;
    // private LLVMBasicBlockRef entry;
    // public LLVMBasicBlockRef getEntry() {
    //     return entry;
    // }

    private final Field opcodeFieldPcodeBlockBasic;
    private final Field linkedListTerminal;
    private final Field nodeData;
    private final Field nodeNextNode;
    public LLVMValueRef getLlvmFunction() {
        return llvmFunction;
    }

    public PcodeLLVMBuilder(LLVMTranslationContext ctx, Function function, DecompileResults decompileResults) {
        this.ctx = ctx;
        this.function = function;
        this.builder = ctx.builder;
        this.decompileResults = decompileResults;

        try {
            opcodeFieldPcodeBlockBasic
                    = PcodeBlockBasic.class.getDeclaredField("oplist");
            opcodeFieldPcodeBlockBasic.setAccessible(true);
            Class<?> linkedIterator = Class.forName("ghidra.program.model.pcode.ListLinked$LinkedIterator");
            Class<?> linkedNode = Class.forName("ghidra.program.model.pcode.ListLinked$LinkedNode");
            linkedListTerminal = ListLinked.class.getDeclaredField("terminal");
            linkedListTerminal.setAccessible(true);

            nodeData = linkedNode.getDeclaredField("data");
            nodeData.setAccessible(true);

            nodeNextNode = linkedNode.getDeclaredField("nextNode");
            nodeNextNode.setAccessible(true);


        } catch (Exception e) {
            throw new RuntimeException();
        }
    }
    void buildLLVMFunction() {
        LLVMTypeRef retType = LLVMVoidType();
        functionType = LLVMFunctionType(retType, new PointerPointer(), 0, 0);
        llvmFunction = LLVMAddFunction(ctx.module, function.getName(), functionType);
        //entry = LLVMAppendBasicBlock(llvmFunction, "entry");

        HighFunction highFunction = decompileResults.getHighFunction();
        HighParamID highParamID = decompileResults.getHighParamID();
        ArrayList<ParamMeasure> inputs = null;
        if (false && ctx.program.getLanguage().getLanguageDescription().toString().equals("x86/little/64/default") ){
            // don't use highparamID for x86,
            // HighFunction is better for some reason...
            Parameter[] parameters = highFunction.getFunction().getParameters();
            ArrayList<ParamMeasure> betterInputs = new ArrayList<ParamMeasure>();
            // match function parameters, use order from Function instead of HighParamID.
            if (parameters.length == highParamID.getNumInputs()) {
                for (Parameter p : parameters) {
                    String varnode = null;
                    if (p.getFirstStorageVarnode() != null){
                        varnode = p.getFirstStorageVarnode().toString();
                    } else {
                        betterInputs = null;
                        break;
                    }
                    boolean match = false;
                    for (int j = 0; j < highParamID.getNumInputs(); j++){
                        if (varnode.equals(highParamID.getInput(j).getVarnode().toString())){
                            betterInputs.add(highParamID.getInput(j));
                            match = true; break;
                        }
                    }
                    if (!match) {
                        betterInputs = null;
                        break;
                    }
                }
            }

            if (betterInputs != null && betterInputs.size() == highParamID.getNumInputs()){
                inputs = betterInputs;
            }

        }
        if (false){
            inputs = new ArrayList<>();
            for (int i = 0; i < highParamID.getNumInputs(); i++){
                inputs.add(highParamID.getInput(i));
            }
        }
    }

    void translateInstructions() {
        // todo: use highfunction basic blocks?

        LLVMTypeRef retType = LLVMVoidType();
        functionType = LLVMFunctionType(retType, new PointerPointer(), 0, 0);
        this.llvmFunction = LLVMAddFunction(ctx.module, function.getName(), functionType);

        Address entry = function.getEntryPoint();
        FunctionPrototype functionPrototype = decompileResults.getHighFunction().getFunctionPrototype();
        for (int x = 0; x < function.getParameterCount(); x++) {
            Parameter parameter = function.getParameter(x);
            parameter.getDataType().getDisplayName();
        }

         InstructionIterator ii = ctx.program.getListing().getInstructions(entry, true);

         int y = 0;
         Long nextFunctionStart = ctx.addressOfNextFunction(function.getEntryPoint().getOffset());
         while (ii.hasNext()) {
             Instruction inst = ii.next();
             // only get code up to next function
             // if this is the last function, see how far we get...
             if (nextFunctionStart != null && inst.getAddress().getOffset() >= nextFunctionStart)
                 break;
             PcodeOp[] pcode = inst.getPcode();
             Address instAddress = inst.getAddress();
             LLVMBasicBlockRef basicBlock = ctx.getBasicBlock(instAddress);
             LLVMPositionBuilderAtEnd(builder, basicBlock);
             translate(null, pcode, instAddress);
             y++;
         }
        /*
        HighFunction highFunction = decompileResults.getHighFunction();

        for (PcodeBlockBasic bb : highFunction.getBasicBlocks()) {
            int added = 0;
            List<PcodeOp> ops = new ArrayList<>();
            try {
                ListLinked<PcodeOp> opcodes = (ListLinked<PcodeOp>) opcodeFieldPcodeBlockBasic.get(bb);
                final Object terminal = linkedListTerminal.get(opcodes);
                Object currentNode = terminal;
                do {

                    PcodeOp op = (PcodeOp) nodeData.get(currentNode);
                    if (op != null) {
                        ops.add(op);
                        added += 1;
                    }
                    currentNode = nodeNextNode.get(currentNode);
                } while (currentNode != terminal);
                if (added == 0){
                    System.out.println("no opcodes in basic block");

                }
            } catch (IllegalAccessException e) {
                throw new RuntimeException();
            }
            LLVMBasicBlockRef basicBlock = ctx.getBasicBlock(bb.getStart());
            LLVMPositionBuilderAtEnd(builder, basicBlock);
            for (PcodeOp op : ops) {
                translateStatement(null, op, null);
            }
        }
        */


    }


    void storeOutput(Varnode output, LLVMValueRef value) {
        if (output.isRegister()) {
            LLVMValueRef global = ctx.valueToRef(output);
            LLVMBuildStore(builder, global, value);
        } else if (output.isAddress()){
            LLVMValueRef addr = ctx.valueToRef(output);
            LLVMBuildStore(builder, addr, value);
        } else if (output.isUnique()) {

            LLVMValueRef globalRef = LLVMAddGlobal(ctx.module, LLVMIntType(8 * output.getSize()), ctx.getVarName(output));
            //LLVMSetInitializer(globalRef, value);
            LLVMBuildStore(builder, globalRef, value);
            ctx.uniques.put(output, globalRef);
        } else {
            throw new RuntimeException("aa");
        }
    }


    public void translate(PcodeBlockBasic block, PcodeOp[] ops, Address addr) {

        for (PcodeOp op : ops) {
            translateStatement(block, op, addr);
        }

    }
    @Override
    public LLVMValueRef UNIMPLEMENTED(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef COPY(PcodeBlockBasic block, PcodeOp op, Address addr) {
        LLVMValueRef in = ctx.valueToRef(op.getInput(0));
        storeOutput(op.getOutput(), in);
        return in;
    }

    @Override
    public LLVMValueRef LOAD(PcodeBlockBasic block, PcodeOp op, Address addr) {
        LLVMValueRef in = ctx.valueToRef(op.getInput(0));
        LLVMValueRef out = LLVMBuildLoad2(builder, LLVMIntType(8 * op.getInput(0).getSize()), in, op.toString());
        storeOutput(op.getOutput(), out);
        return out;
    }

    @Override
    public LLVMValueRef STORE(PcodeBlockBasic block, PcodeOp op, Address addr) {
        LLVMValueRef src = ctx.valueToRef(op.getInput(2));
        LLVMValueRef dest = ctx.valueToRef(op.getInput(1));
        LLVMBuildStore(builder, dest, src);
        return null;
    }

    @Override
    public LLVMValueRef BRANCH(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef CBRANCH(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef BRANCHIND(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef CALL(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef CALLIND(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef CALLOTHER(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef RETURN(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef INT_EQUAL(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef INT_NOTEQUAL(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef INT_SLESS(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef INT_SLESSEQUAL(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef INT_LESS(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef INT_LESSEQUAL(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef INT_ZEXT(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef INT_SEXT(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef INT_ADD(PcodeBlockBasic block, PcodeOp op, Address addr) {
        LLVMValueRef op1 = ctx.valueToRef(op.getInput(0));
        LLVMValueRef op2 = ctx.valueToRef(op.getInput(1));
        LLVMValueRef res = LLVMBuildAdd(builder, op1, op2, op.toString());
        storeOutput(op.getOutput(), res);
        return res;
    }

    @Override
    public LLVMValueRef INT_SUB(PcodeBlockBasic block, PcodeOp op, Address addr) {
        LLVMValueRef op1 = ctx.valueToRef(op.getInput(0));
        LLVMValueRef op2 = ctx.valueToRef(op.getInput(1));
        LLVMValueRef res = LLVMBuildSub(builder, op1, op2, op.toString());
        storeOutput(op.getOutput(), res);
        return res;
    }

    @Override
    public LLVMValueRef INT_CARRY(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef INT_SCARRY(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef INT_SBORROW(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef INT_2COMP(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef INT_NEGATE(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef INT_XOR(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef INT_AND(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef INT_OR(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef INT_LEFT(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef INT_RIGHT(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef INT_SRIGHT(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef INT_MULT(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef INT_DIV(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef INT_SDIV(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef INT_REM(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef INT_SREM(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef BOOL_NEGATE(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef BOOL_XOR(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef BOOL_AND(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef BOOL_OR(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef FLOAT_EQUAL(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef FLOAT_NOTEQUAL(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef FLOAT_LESS(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef FLOAT_LESSEQUAL(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef FLOAT_NAN(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef FLOAT_ADD(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef FLOAT_DIV(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef FLOAT_MULT(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef FLOAT_SUB(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef FLOAT_NEG(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef FLOAT_ABS(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef FLOAT_SQRT(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef FLOAT_INT2FLOAT(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef FLOAT_FLOAT2FLOAT(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef FLOAT_TRUNC(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef FLOAT_CEIL(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef FLOAT_FLOOR(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef FLOAT_ROUND(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef MULTIEQUAL(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef INDIRECT(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef PIECE(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef SUBPIECE(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef CAST(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef PTRADD(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef PTRSUB(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef SEGMENTOP(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef CPOOLREF(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef NEW(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef INSERT(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef EXTRACT(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef POPCOUNT(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

    @Override
    public LLVMValueRef PCODE_MAX(PcodeBlockBasic block, PcodeOp op, Address addr) {
        return null;
    }

}
