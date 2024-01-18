package org.ghidra2llvm;

import generic.stl.Pair;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import org.bytedeco.javacpp.PointerPointer;

import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.logging.Logger;

import static org.bytedeco.llvm.global.LLVM.LLVMParseCommandLineOptions;
/**
 * Interace for Ghidra headless
 * 
 * @author naeumann
 *
 */
public class GhidraInterface {

	private Logger logger;

	public File importBinary(File binary) throws Exception {
		String binaryName = binary.getName();
		File projectDir = new File(getTempDir(), binaryName);
		int i = 1;
		while (projectDir.exists()) {
			projectDir = new File(getTempDir(), binaryName + i);
			i++;
		}
		projectDir.mkdirs();

		System.setProperty("log4j.configuration", "debug.log4jdev.xml");

		ApplicationConfiguration configuration = new HeadlessGhidraApplicationConfiguration();
		configuration.setApplicationLogFile(new File("ghidra.log"));
		configuration.setInitializeLogging(true);
		Application.initializeApplication(new GhidraApplicationLayout(), configuration);
		DecompileResults reests = null;
		Function f = null;
		MessageLog m = new MessageLog();
		TaskMonitor tm = new ConsoleTaskMonitor();
		ArrayList<Pair<String, String>> options = new ArrayList<Pair<String, String>>();

		Program program = AutoImporter.importByUsingBestGuess(binary, null, this, m, tm);


		int tx = program.startTransaction("Analysis");

		Options analysisOptions = program.getOptions(Program.ANALYSIS_PROPERTIES);

		for (Entry<String, Object> kv : getOptions().entrySet()) {
			analysisOptions.putObject(kv.getKey(), kv.getValue());
		}
		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
		mgr.initializeOptions();

		int txId = program.startTransaction("Analysis");
		try {
			// analyze all memory and code
			mgr.reAnalyzeAll(null);
			// TaskMonitorAdapter mainTaskMonitor = new TaskMonitorAdapter(true);

			mgr.startAnalysis(tm); // blocks

		} finally {
			program.endTransaction(txId, true);
		}

		DecompInterface fullDecompiler = new DecompInterface();

		fullDecompiler.toggleCCode(true);
		fullDecompiler.toggleSyntaxTree(true);
		fullDecompiler.toggleParamMeasures(true);
		fullDecompiler.setSimplificationStyle("decompile");
		fullDecompiler.setOptions(new DecompileOptions());
		if (!fullDecompiler.openProgram(program)) {
			fullDecompiler.dispose();
			throw new RuntimeException(fullDecompiler.getLastMessage());
		}



		DecompInterface normalizeDecompiler = new DecompInterface();
		
		normalizeDecompiler.toggleCCode(true);
		normalizeDecompiler.toggleSyntaxTree(true);
		normalizeDecompiler.toggleParamMeasures(true);
		// https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html#setSimplificationStyle(java.lang.String)
		normalizeDecompiler.setSimplificationStyle("normalize");

		if (!normalizeDecompiler.openProgram(program)) {
			normalizeDecompiler.dispose();
			throw new RuntimeException(normalizeDecompiler.getLastMessage());
		}

		//Path outdir = new File(binary.getParent(), binaryName + ".output" ).toPath();
		//outdir.toFile().mkdirs();
		//System.out.println(outdir);

		BinaryTranslator translator = new BinaryTranslator(program, normalizeDecompiler, fullDecompiler);
		String[] llvmOptions = new String[] {"-o", binaryName + ".ll"};
		LLVMParseCommandLineOptions(llvmOptions.length, new PointerPointer(llvmOptions), null);
		translator.translateAllClasses();
		return projectDir;
	}

	private static String getTempDir() {
		return System.getProperty("java.io.tmpdir");
	}


	private Map<String, Object> getOptions() {
		Map<String, Object> options = new HashMap<>();

		// two analyses required
		options.put("Demangler GNU", true);
		options.put("Function Start Search", true); // required
		/*
		options.put("Scalar Operand References", false);
		options.put("Objective-C 2 Message", false);
		options.put("Embedded Media", false);
		options.put("Non-Returning Functions - Discovered", false);
		options.put("Basic Constant Reference Analyzer", false);
		options.put("ASCII Strings", true);
		options.put("CFStrings", true);
		options.put("DWARF Line Number", false);
		options.put("Apply Data Archives", false);
		options.put("Objective-C 2 Decompiler Message", false);
		options.put("Function Start Search After Data", false);
		options.put("Create Address Tables", false);
		options.put("External Entry References", true);
		options.put("Function Start Search After Code", false);
		options.put("Decompiler Switch Analysis", false);
		options.put("Aggressive Instruction Finder", false);
		options.put("Shared Return Calls", false);
		options.put("Data Reference", true);
		options.put("Condense Filler Bytes", false);
		options.put("Reference", true);
		options.put("Subroutine References", true);
		options.put("Disassemble Entry Points", false);
		options.put("Non-Returning Functions - Known", false);
		options.put("Stack", true);

		options.put("Call Convention ID", true);
		options.put("Call-Fixup Installer", true);
		options.put("Objective-C 2 Class", false);
		options.put("Decompiler Parameter ID", true);
		options.put("AARCH64 ELF PLT Thunks", false);
		*/
		return options;
	}
}
