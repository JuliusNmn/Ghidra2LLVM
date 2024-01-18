package org.ghidra2llvm;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.ListLinked;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import org.bytedeco.llvm.LLVM.LLVMBasicBlockRef;
import org.bytedeco.llvm.LLVM.LLVMBuilderRef;
import org.bytedeco.llvm.LLVM.LLVMModuleRef;

import java.lang.reflect.Field;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.TreeSet;

import static org.bytedeco.llvm.global.LLVM.*;

public class BinaryTranslator {
	private final DecompInterface fullDecompiler;
	private Program program;
	private SymbolTable symbolTable;
	private FunctionManager functionManager;
	private DecompInterface normalizeDecompiler;

	private TaskMonitor taskMonitor;

	// stores boundaries of typeinfo and vtable memory regions
	private TreeSet<Long> typeInfoRegions = new TreeSet<Long>();

	Path outDir;
	final LLVMBuilderRef builder;

	LLVMModuleRef module;

	public BinaryTranslator(Program program, DecompInterface normalizeDecompiler, DecompInterface fullDecompiler) {
		this.program = program;
		symbolTable = program.getSymbolTable();
		functionManager = program.getFunctionManager();
		this.normalizeDecompiler = normalizeDecompiler;
		this.fullDecompiler = fullDecompiler;

		this.taskMonitor = new ConsoleTaskMonitor();
		builder  = LLVMCreateBuilder();
		module = LLVMModuleCreateWithName("mymodule");


	}


	public void translateAllClasses() throws Exception {


		for (Symbol vtableSymbol : symbolTable.getSymbols("vtable")) {
			typeInfoRegions.add(vtableSymbol.getAddress().getOffset());

			MemoryBlock block = program.getMemory().getBlock(vtableSymbol.getAddress());
			typeInfoRegions.add(block.getStart().getOffset());
			typeInfoRegions.add(block.getEnd().getOffset());
		}
		for (Symbol vtableSymbol : symbolTable.getSymbols("typeinfo")) {
			typeInfoRegions.add(vtableSymbol.getAddress().getOffset());
			MemoryBlock block = program.getMemory().getBlock(vtableSymbol.getAddress());
			typeInfoRegions.add(block.getStart().getOffset());
			typeInfoRegions.add(block.getEnd().getOffset());
		}
		LLVMTranslationContext ctx = new LLVMTranslationContext(builder, module, program);
		HashMap<Function, PcodeLLVMBuilder> builders = new HashMap<>();
		Listing listing = program.getListing();
		FunctionIterator fi = listing.getFunctions(true);

		while (fi.hasNext()) {
			Function function1 = fi.next();
			DecompileResults decompileResults = fullDecompiler.decompileFunction(function1, 60, taskMonitor);
			HighFunction highFunction = decompileResults.getHighFunction();
			PcodeLLVMBuilder llvmBuilder = new PcodeLLVMBuilder(ctx, function1, decompileResults);
			builders.put(function1, llvmBuilder);
			llvmBuilder.buildLLVMFunction();
			//ctx.setBasicBlock(function1.getEntryPoint(), llvmBuilder.getEntry());
			//LLVMPositionBuilderAtEnd(builder, llvmBuilder.getEntry());
			InstructionIterator ii = ctx.program.getListing().getInstructions(function1.getEntryPoint(), true);
			ctx.addFunction(function1.getEntryPoint(), builder);
			ctx.program.getListing().getInstructionAt(function1.getEntryPoint());
			while (ii.hasNext()) {
				Instruction inst = ii.next();
				Address instAddress = inst.getAddress();
				LLVMBasicBlockRef llvmBasicBlockRef = LLVMAppendBasicBlock(llvmBuilder.getLlvmFunction(), instAddress.toString());
				ctx.setBasicBlock(instAddress, llvmBasicBlockRef);
				LLVMPositionBuilderAtEnd(builder, llvmBasicBlockRef);
			}
			/*
			for (PcodeBlockBasic bb : highFunction.getBasicBlocks()) {
				LLVMBasicBlockRef llvmBasicBlockRef = LLVMAppendBasicBlock(llvmBuilder.getLlvmFunction(), bb.getStart().toString());
				ctx.setBasicBlock(bb.getStart(), llvmBasicBlockRef);
				LLVMPositionBuilderAtEnd(builder, llvmBasicBlockRef);
			}*/

		}

		program.getFunctionManager().getFunctions(true).forEach((function) -> {
			PcodeLLVMBuilder llvmBuilder = builders.get(function);
			llvmBuilder.translateInstructions();
		});

		LLVMDumpModule(module);
		// LLVMVerifyModule()
		// LLVMVerifyFunction()
		LLVMDisposeBuilder(builder);
	}



}
