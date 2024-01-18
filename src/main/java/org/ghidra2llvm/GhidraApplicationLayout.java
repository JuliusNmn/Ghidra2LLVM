package org.ghidra2llvm;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import generic.jar.ResourceFile;
import ghidra.GhidraJarApplicationLayout;
import utility.application.ApplicationLayout;

public class GhidraApplicationLayout extends GhidraJarApplicationLayout{

	
	private static final String PLUGIN = "us.nsa.ghidra";
	private static final String JAR;
	static {
		String jar = null;
		try {
			jar = new File(ApplicationLayout.class.getProtectionDomain().getCodeSource().getLocation().toURI())
					.toString();
		} catch (URISyntaxException e) {
			e.printStackTrace();
		}
		JAR = jar;
	}

	
	public GhidraApplicationLayout() throws FileNotFoundException, IOException {
		super();
	}
	

	@Override
	protected Collection<ResourceFile> findGhidraApplicationRootDirs() {
		// return Collections.singletonList(new ResourceFile("/Users/julius/Developer/llvm/BinaryTranslator/res/_Root/Ghidra"));
		return Collections.singletonList(new ResourceFile("jar:file:" + JAR + "!/_Root/Ghidra/"));
	}

	@Override
	protected List<ResourceFile> findExtensionInstallationDirectories() {
		//	return Collections.singletonList(new ResourceFile("/Users/julius/Developer/llvm/BinaryTranslator/res/_Root/Ghidra/Extensions"));
		return Collections.singletonList(new ResourceFile("jar:file:" + JAR + "!/_Root/Ghidra/Extensions/"));
	}

}
