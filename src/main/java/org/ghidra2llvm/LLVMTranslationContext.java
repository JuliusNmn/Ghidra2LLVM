package org.ghidra2llvm;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.Varnode;
import org.bytedeco.llvm.LLVM.LLVMBasicBlockRef;
import org.bytedeco.llvm.LLVM.LLVMBuilderRef;
import org.bytedeco.llvm.LLVM.LLVMModuleRef;
import org.bytedeco.llvm.LLVM.LLVMValueRef;

import java.util.HashMap;
import java.util.TreeSet;

import static org.bytedeco.llvm.global.LLVM.*;
import static org.bytedeco.llvm.global.LLVM.LLVMIntType;

public class LLVMTranslationContext {
    LLVMBuilderRef builder;
    Program program;
    LLVMModuleRef module;
    HashMap<Varnode, LLVMValueRef> registers = new HashMap<>();
    HashMap<Address, LLVMValueRef> addresses = new HashMap<>();

    HashMap<Address, LLVMBasicBlockRef> basicBlocks = new HashMap<>();

    HashMap<Varnode, LLVMValueRef> uniques = new HashMap<>();

    public LLVMTranslationContext(LLVMBuilderRef builder, LLVMModuleRef module, Program program) {
        this.builder = builder;
        this.module = module;
        this.program = program;
    }

    LLVMValueRef valueToRef(Varnode var) {
        if (var.isRegister()) {
            return registers.computeIfAbsent(var, varnode -> {
                Register reg = program.getLanguage().getRegister(varnode.getAddress(), varnode.getSize());
                LLVMValueRef globalRef = LLVMAddGlobal(module, LLVMIntType(8 * var.getSize()), reg.getName());
                LLVMSetInitializer(globalRef, null);
                return globalRef;
            });
        } else if (var.isAddress()) {
            return getAddress(var.getAddress());
        } else if (var.isConstant()) {
            return LLVMConstInt(LLVMIntType(8 * var.getSize()), var.getOffset(), 0);
        } else if (var.isUnique()) {
            LLVMValueRef unique = uniques.get(var);
            if (unique == null) {
                System.err.println("usage of undefined unique!");
                LLVMValueRef globalRef = LLVMAddGlobal(module, LLVMIntType(8 * var.getSize()), getVarName(var) + "_undefined");
                LLVMSetInitializer(globalRef, LLVMConstNull(LLVMIntType(8 * var.getSize())));
                uniques.put(var, globalRef);
                return globalRef;
            }
            return unique;
        }
        return null;
    }

    LLVMValueRef getAddress(Address a) {
        return addresses.computeIfAbsent(a, varnode -> {
            LLVMValueRef addressGlobalRef = LLVMAddGlobal(module, LLVMIntType(8 * a.getSize()), getVarName(a));
            LLVMSetInitializer(addressGlobalRef, LLVMConstInt(LLVMIntType(8 * a.getSize()), a.getOffset(), 0));
            return addressGlobalRef;
        });
    }
    void setBasicBlock(Address a, LLVMBasicBlockRef bb) {
        basicBlocks.put(a, bb);
    }
    LLVMBasicBlockRef getBasicBlock(Address a) {
        return basicBlocks.get(a);
    }

    public String getVarName(Varnode var) {
        Register register = program.getLanguage().getRegister(var.getAddress(), var.getSize());

        //return String.format("%s%s_%s0x%x_id%d", var.getAddress().getAddressSpace().getName(), register == null ? "" : ("_" + register.getName()), var.getOffset() >= 0 ? "" : "N", Math.abs( var.getOffset()), System.identityHashCode(var));
        return String.format("%s%s_%s0x%x", var.getAddress().getAddressSpace().getName(), register == null ? "" : ("_" + register.getName()), var.getOffset() >= 0 ? "" : "N", Math.abs( var.getOffset()));
    }
    public String getVarName(Address var) {
        return String.format("ram_0x%x", var.getOffset());
    }
    TreeSet<Long> functionStarts = new TreeSet();
    public void addFunction(Address entryPoint, LLVMBuilderRef builder) {
        functionStarts.add(entryPoint.getOffset());
    }
    public Long addressOfNextFunction(long addr) {
        return functionStarts.higher(addr);
    }
}
