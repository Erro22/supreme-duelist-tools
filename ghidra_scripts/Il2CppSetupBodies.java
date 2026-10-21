// Il2CppSetupBodies: minimal-listing setup. Disassembles ONLY the exact byte ranges of
// Assembly-CSharp method bodies (no linear fill of the whole region), so the decompiler
// cannot follow tail calls into engine code that is undefined.
// Args: <input-dir with labels.tsv, strings.tsv, methods.tsv>
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;

import java.io.*;
import java.util.*;

public class Il2CppSetupBodies extends GhidraScript {

	private static String[] readLines(File f) throws IOException {
		List<String> out = new ArrayList<>();
		try (BufferedReader br = new BufferedReader(new InputStreamReader(
				new FileInputStream(f), "UTF-8"))) {
			String l;
			while ((l = br.readLine()) != null) {
				if (!l.isEmpty()) {
					out.add(l);
				}
			}
		}
		return out.toArray(new String[0]);
	}

	private static String makeName(String type, String decl) {
		String t = type.replace('/', '_');
		int paren = decl.indexOf('(');
		String head = paren < 0 ? decl : decl.substring(0, paren);
		String[] parts = head.trim().split("\\s+");
		String method = parts[parts.length - 1];
		int lt = method.indexOf('<');
		if (lt > 0) {
			method = method.substring(0, lt);
		}
		method = method.replace("::", ".");
		return t + "$$" + method;
	}

	@Override
	public void run() throws Exception {
		String[] a = getScriptArgs();
		File inDir = new File(a[0]);
		Address base = currentProgram.getImageBase();
		println("[setup] image base = " + base);

		// 1. labels (all assemblies)
		String[] labels = readLines(new File(inDir, "labels.tsv"));
		int lab = 0;
		for (String l : labels) {
			if (monitor.isCancelled()) {
				break;
			}
			String[] p = l.split("\t", 3);
			if (p.length < 2) {
				continue;
			}
			try {
				Address ad = base.add(Long.parseLong(p[0], 16));
				String nm = p.length > 2 ? p[2] : ("sub_" + p[0]);
				currentProgram.getSymbolTable().createLabel(ad, nm, SourceType.USER_DEFINED);
				lab++;
			}
			catch (Exception e) {
				// ignore duplicates/invalid
			}
		}
		println("[setup] labels: " + lab + "/" + labels.length);

		// 2. string literals as comments
		File sf = new File(inDir, "strings.tsv");
		int str = 0;
		if (sf.exists()) {
			for (String l : readLines(sf)) {
				String[] p = l.split("\t", 2);
				if (p.length < 2) {
					continue;
				}
				try {
					Address ad = base.add(Long.parseLong(p[0], 16));
					currentProgram.getListing().setComment(ad, ghidra.program.model.listing.CommentType.EOL,
						"\"" + p[1].replace("\\", "\\\\").replace("\"", "'") + "\"");
					str++;
				}
				catch (Exception e) {
					// ignore
				}
			}
		}
		println("[setup] strings labeled: " + str);

		// 3. per-method limited disassembly: only [entry, end)
		String[] rows = readLines(new File(inDir, "methods.tsv"));
		println("[setup] methods: " + rows.length);
		int dis = 0, disFail = 0;
		for (String l : rows) {
			if (monitor.isCancelled()) {
				break;
			}
			String[] r = l.split("\t", 6);
			if (r.length < 5 || r[4].isEmpty()) {
				continue;
			}
			long s = Long.parseLong(r[0], 16);
			long e = Long.parseLong(r[4], 16);
			if (e <= s) {
				continue;
			}
			Address start = base.add(s);
			Address last = base.add(e).subtract(1);
			try {
				new DisassembleCommand(start, new AddressSet(start, last), true)
					.applyTo(currentProgram, monitor);
				dis++;
			}
			catch (Exception ex) {
				disFail++;
			}
			if ((dis % 5000) == 0) {
				println("[setup]   disassembled " + dis + " bodies");
			}
		}
		println("[setup] bodies disassembled: " + dis + " failed: " + disFail);

		// 4. functions with exact bodies
		FunctionManager fm = currentProgram.getFunctionManager();
		int created = 0, failed = 0;
		for (String l : rows) {
			String[] r = l.split("\t", 6);
			if (r.length < 5 || r[4].isEmpty()) {
				continue;
			}
			Address entry = base.add(Long.parseLong(r[0], 16));
			Address end = base.add(Long.parseLong(r[4], 16)).subtract(1);
			if (end.compareTo(entry) < 0) {
				end = entry;
			}
			if (fm.getFunctionAt(entry) != null) {
				continue;
			}
			String name = makeName(r[1], r[2]);
			try {
				Function f = fm.createFunction(name, entry, new AddressSet(entry, end),
					SourceType.USER_DEFINED);
				if (f != null) {
					created++;
				}
				else {
					failed++;
				}
			}
			catch (Exception e1) {
				failed++;
			}
		}
		println("[setup] functions created: " + created + " failed: " + failed);
	}
}
