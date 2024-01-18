package org.ghidra2llvm;

import java.io.File;
import java.io.IOException;


public class Main {
    public static void main(String[] args) throws Exception {
        if (args.length < 1)
            throw new IllegalArgumentException("please pass executable path as argument. -Dexec.args=\"/path.to.file.o\"");
        System.out.println(args);
        String file = args[0];
        GhidraInterface ghidraInterface = new GhidraInterface();
        ghidraInterface.importBinary(new File(file));
        System.exit(0);
    }
}
