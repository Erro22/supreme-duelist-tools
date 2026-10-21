// Il2CppSetup: labels + string comments + linear disassembly of the Assembly-CSharp
// region + creation of functions at known IL2CPP method boundaries.
// Args: <input-dir with region.txt, labels.tsv, strings.tsv, methods.tsv>
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;

import java.io.*;
import java.util.*;

public class Il2CppSetup extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] a = getScriptArgs();
		File inDir = new File(a[0]);
		Address base = currentProgram.getImageBase();
		println("[setup] image base = " + base);

		String[] reg = readLines(new File(inDir, "region.txt"));
		Address rStart = base.add(Long.parseLong(reg[0].trim(), 16));
		Address rEnd = base.add(Long.parseLong(reg[1].trim(), 16));
		println("[setup] region " + rStart + " .. " + rEnd);

		int tx = currentProgram.startTransaction("il2cpp setup");
		try {
			// 1. labels for every IL2CPP method (call targets readable in decompilation)
			List<String[]> labels = readTsv(new File(inDir, "labels.tsv"), 2);
			println("[setup] labels: " + labels.size());
			int i = 0;
			for (String[] r : labels) {
				if (monitor.isCancelled()) {
					break;
				}
				try {
					createLabel(base.add(Long.parseLong(r[0], 16)), r[1], false,
						SourceType.USER_DEFINED);
				} catch (Exception e) {
					// invalid name / duplicate - skip, non critical
				}
				if ((++i % 50000) == 0) {
					println("[setup]   labels " + i);
				}
			}

			// 2. string literals: label + EOL comment
			for (String[] r : readTsv(new File(inDir, "strings.tsv"), 3)) {
				try {
					Address ad = base.add(Long.parseLong(r[0], 16));
					createLabel(ad, "StringLiteral_" + r[1], true, SourceType.USER_DEFINED);
					setEOLComment(ad, r[2]);
				} catch (Exception e) {
					// skip
				}
			}
			println("[setup] strings labeled");

			// 3. linear disassembly over the region (4-byte steps, flow fills gaps)
			println("[setup] disassembling region ...");
			Address p = rStart;
			long steps = 0;
			while (p.compareTo(rEnd) <= 0) {
				if (monitor.isCancelled()) {
					break;
				}
				if (currentProgram.getListing().getInstructionAt(p) == null) {
					new DisassembleCommand(p, null, true).applyTo(currentProgram, monitor);
				}
				p = p.add(4);
				if ((++steps % 500000) == 0) {
					println("[setup]   at " + p);
				}
			}
			// coverage report
			long expected = (rEnd.subtract(rStart)) / 4 + 1;
			long have = 0;
			for (ghidra.program.model.listing.InstructionIterator it =
					currentProgram.getListing().getInstructions(new AddressSet(rStart, rEnd), true); it.hasNext();) {
				it.next();
				have++;
			}
			println("[setup] instructions in region: " + have + " / expected ~" + expected);

			// 4. functions with exact bodies: col0 = entry, col4 = end (exclusive),
			// boundaries computed from the address list of ALL assemblies
			List<String[]> rows = readTsv(new File(inDir, "methods.tsv"), 5);
			println("[setup] methods: " + rows.size());
			FunctionManager fm = currentProgram.getFunctionManager();
			// drop functions from a previous run (bodies were computed wrongly)
			int dropped = 0;
			java.util.Iterator<Function> fit = fm.getFunctions(true);
			while (fit.hasNext()) {
				Function old = fit.next();
				try {
					fm.removeFunction(old.getEntryPoint());
					dropped++;
				}
				catch (Exception ignore) {
				}
			}
			println("[setup] old functions dropped: " + dropped);
			int created = 0, failed = 0, renamed = 0;
			for (int k = 0; k < rows.size(); k++) {
				if (monitor.isCancelled()) {
					break;
				}
				String[] r = rows.get(k);
				Address entry = base.add(Long.parseLong(r[0], 16));
				Address end = (r.length > 4 && !r[4].isEmpty())
						? base.add(Long.parseLong(r[4], 16)).subtract(1)
						: rEnd;
				if (end.compareTo(entry) < 0) {
					end = entry;
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
					// duplicate/overlapping: retry with unique suffix, then bodyless
					try {
						Function f = fm.createFunction(name + "$" + r[0], entry,
							new AddressSet(entry, end), SourceType.USER_DEFINED);
						if (f != null) {
							created++;
							renamed++;
						}
					}
					catch (Exception e2) {
						try {
							fm.createFunction(name + "$" + r[0], entry, null,
								SourceType.USER_DEFINED);
							created++;
							renamed++;
						}
						catch (Exception e3) {
							failed++;
							if (failed < 20) {
								println("[setup] FAIL " + r[0] + " " + name + " : " + e3);
							}
						}
					}
				}
				if ((k + 1) % 5000 == 0) {
					println("[setup]   functions " + (k + 1) + "/" + rows.size());
				}
			}
			println("[setup] functions created=" + created + " renamed=" + renamed +
				" failed=" + failed);
		}
		finally {
			currentProgram.endTransaction(tx, true);
		}
		println("[setup] done");
	}

	private static String makeName(String type, String decl) {
		String mname;
		int p = decl.indexOf('(');
		String head = (p > 0 ? decl.substring(0, p) : decl).trim();
		int sp = head.lastIndexOf(' ');
		mname = sp >= 0 ? head.substring(sp + 1) : head;
		if (mname.isEmpty()) {
			mname = "m";
		}
		return sanitize(type) + "$$" + sanitize(mname);
	}

	private static String sanitize(String s) {
		StringBuilder sb = new StringBuilder(s.length() + 2);
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			sb.append((Character.isLetterOrDigit(c) || c == '_' || c == '$' || c == '.') ? c : '_');
		}
		if (sb.length() == 0 || Character.isDigit(sb.charAt(0))) {
			sb.insert(0, '_');
		}
		return sb.toString();
	}

	private static String[] readLines(File f) throws IOException {
		List<String> out = new ArrayList<>();
		try (BufferedReader br = new BufferedReader(new FileReader(f))) {
			String l;
			while ((l = br.readLine()) != null) {
				if (!l.trim().isEmpty()) {
					out.add(l);
				}
			}
		}
		return out.toArray(new String[0]);
	}

	private static List<String[]> readTsv(File f, int cols) throws IOException {
		List<String[]> out = new ArrayList<>();
		try (BufferedReader br = new BufferedReader(
				new InputStreamReader(new FileInputStream(f), "UTF-8"))) {
			String l;
			while ((l = br.readLine()) != null) {
				if (l.isEmpty()) {
					continue;
				}
				String[] p = l.split("\t", cols);
				if (p.length >= 2) {
					out.add(p);
				}
			}
		}
		return out;
	}
}
