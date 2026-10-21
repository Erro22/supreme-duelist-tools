// Il2CppExport (parallel): decompile every Assembly-CSharp function with K
// decompiler threads, write per-type files into outDir/partK/, then merge parts.
// Reads addresses/names from labels.tsv, methods (addr, type, decl, sig) from methods.tsv.
// Args: <input-dir> <output-dir> [threads=4]
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Il2CppExport extends GhidraScript {

	private static final Pattern PTR_P =
		Pattern.compile("0x0*([0-9a-fA-F]{6,16})");
	private static final Pattern PRE_P =
		Pattern.compile("\\b(?:FUN_|DAT_|SUB_|LBL_|PTR_|uav_|thunk_)([0-9a-fA-F]{6,16})");

	private static final Object LOG_LOCK = new Object();

	// таймаут декомпиляции на метод: IL2CPP_TIMEOUT (сек), по умолчанию 3
	private static final int TMO = readTimeout();

	private static int readTimeout() {
		try {
			String e = System.getenv("IL2CPP_TIMEOUT");
			if (e != null && e.trim().length() > 0)
				return Integer.parseInt(e.trim());
		}
		catch (Exception ignored) {}
		return 3;
	}

	@Override
	public void run() throws Exception {
		String[] a = getScriptArgs();
		File inDir = new File(a[0]);
		File outDir = new File(a[1]);
		int nThreads = a.length > 2 ? Integer.parseInt(a[2]) : 4;
		if (!outDir.exists() && !outDir.mkdirs()) {
			println("[export] cannot create " + outDir);
			return;
		}
		Address base = currentProgram.getImageBase();

		// addr -> symbol name (from labels.tsv: all IL2CPP methods)
		Map<Long, String> names = new HashMap<>(200_000);
		try (BufferedReader br = new BufferedReader(new InputStreamReader(
				new FileInputStream(new File(inDir, "labels.tsv")), StandardCharsets.UTF_8))) {
			String l;
			while ((l = br.readLine()) != null) {
				int t = l.indexOf('\t');
				if (t > 0) {
					names.put(Long.parseLong(l.substring(0, t), 16), l.substring(t + 1));
				}
			}
		}
		println("[export] name map: " + names.size());

		// methods: addr, type, decl, sig
		List<String[]> rows = new ArrayList<>();
		try (BufferedReader br = new BufferedReader(new InputStreamReader(
				new FileInputStream(new File(inDir, "methods.tsv")), StandardCharsets.UTF_8))) {
			String l;
			while ((l = br.readLine()) != null) {
				String[] p = l.split("\t", 6);
				if (p.length >= 3) {
					rows.add(p);
				}
			}
		}
		println("[export] methods: " + rows.size() + " threads: " + nThreads);

		long t0 = System.currentTimeMillis();
		AtomicInteger totalDone = new AtomicInteger();
		AtomicInteger totalFailed = new AtomicInteger();
		AtomicInteger totalNoFunc = new AtomicInteger();

		// contiguous chunks keep per-type files mostly in one part
		Thread[] workers = new Thread[nThreads];
		int chunk = (rows.size() + nThreads - 1) / nThreads;
		for (int k = 0; k < nThreads; k++) {
			int from = k * chunk;
			int to = Math.min(rows.size(), from + chunk);
			if (from >= to) {
				workers[k] = null;
				continue;
			}
			final int partIdx = k;
			final List<String[]> slice = rows.subList(from, to);
			final File partDir = new File(outDir, "part" + k);
			workers[k] = new Thread(() -> {
				try {
					work(partIdx, slice, partDir, base, names, totalDone, totalFailed,
						totalNoFunc, t0);
				}
				catch (Throwable t2) {
					synchronized (LOG_LOCK) {
						println("[export] part" + partIdx + " died: " + t2);
					}
				}
			}, "il2cpp-export-" + k);
			workers[k].start();
		}
		for (Thread w : workers) {
			if (w != null) {
				w.join();
			}
		}
		long sec = (System.currentTimeMillis() - t0) / 1000;

		// merge INDEX.txt across parts
		Map<String, Integer> counts = new TreeMap<>();
		for (int k = 0; k < nThreads; k++) {
			File idx = new File(outDir, "part" + k + File.separator + "INDEX.txt");
			try (BufferedReader br = new BufferedReader(new InputStreamReader(
					new FileInputStream(idx), StandardCharsets.UTF_8))) {
				String l;
				while ((l = br.readLine()) != null) {
					String[] p = l.split("\t", 2);
					if (p.length == 2) {
						counts.merge(p[0], Integer.parseInt(p[1]), Integer::sum);
					}
				}
			}
			catch (IOException ignore) {
			}
		}
		try (BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
				new FileOutputStream(new File(outDir, "INDEX.txt")), StandardCharsets.UTF_8))) {
			for (Map.Entry<String, Integer> e : counts.entrySet()) {
				w.write(e.getKey() + "\t" + e.getValue() + "\n");
			}
		}
		println("[export] finished: types=" + counts.size() + " methods=" + totalDone.get() +
			" failed=" + totalFailed.get() + " nofunc=" + totalNoFunc.get() + " time=" + sec +
			"s");
	}

	private void work(int partIdx, List<String[]> slice, File partDir, Address base,
			Map<Long, String> names, AtomicInteger totalDone, AtomicInteger totalFailed,
			AtomicInteger totalNoFunc, long t0) throws Exception {
		if (!partDir.exists() && !partDir.mkdirs()) {
			println("[export] cannot create " + partDir);
			return;
		}
		DecompInterface di = startDecompiler();
		Map<String, BufferedWriter> writers = new HashMap<>();
		BufferedWriter index = new BufferedWriter(new OutputStreamWriter(
			new FileOutputStream(new File(partDir, "INDEX.txt")), StandardCharsets.UTF_8));
		Map<String, Integer> counts = new TreeMap<>();
		int failed = 0, noFunc = 0, done = 0;
		int lastPct = -1;
		try {
			for (String[] r : slice) {
				if (monitor.isCancelled()) {
					break;
				}
				long addr = Long.parseLong(r[0], 16);
				Address ad = base.add(addr);
				Function f = currentProgram.getFunctionManager().getFunctionAt(ad);
				if (f == null) {
					f = currentProgram.getFunctionManager().getFunctionContaining(ad);
				}

				String body;
				if (f == null) {
					noFunc++;
					body = "// [no function created]\n";
				}
				else {
					DecompileResults res = di.decompileFunction(f, TMO, monitor);
					if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
						body = clean(res.getDecompiledFunction().getC(), names);
					}
					else {
						failed++;
						String err = res == null ? "null result" : res.getErrorMessage();
						body = "// [decompile failed: " + err + "]\n";
					}
				}

				String type = r[1];
				BufferedWriter w = writers.get(type);
				if (w == null) {
					File f2 = new File(partDir, fileName(type));
					w = new BufferedWriter(new OutputStreamWriter(
						new FileOutputStream(f2), StandardCharsets.UTF_8));
					writers.put(type, w);
					w.write("// ================= " + type + " =================\n");
					counts.put(type, 0);
				}
				w.write("// RVA: 0x" + r[0] + "\n");
				w.write("// C#: " + r[2] + "\n");
				if (r.length > 3 && !r[3].isEmpty()) {
					w.write("// il2cpp: " + r[3] + "\n");
				}
				w.write(body);
				if (!body.endsWith("\n")) {
					w.write("\n");
				}
				w.write("\n");
				counts.merge(type, 1, Integer::sum);

				done++;
				totalDone.incrementAndGet();
				totalFailed.addAndGet(0);
				int pct = done * 100 / slice.size();
				if (pct / 10 != lastPct / 10) {
					lastPct = pct;
					long sec = (System.currentTimeMillis() - t0) / 1000;
					synchronized (LOG_LOCK) {
						println("[export] part" + partIdx + " " + pct + "% (" + done + "/" +
							slice.size() + ", failed=" + failed + ", nofunc=" + noFunc +
							", " + sec + "s)");
					}
					// keep decompiler fresh
					di.dispose();
					di = startDecompiler();
					System.gc();
				}
			}
		}
		finally {
			for (BufferedWriter w : writers.values()) {
				try {
					w.close();
				}
				catch (IOException ignore) {
				}
			}
			for (Map.Entry<String, Integer> e : counts.entrySet()) {
				try {
					index.write(e.getKey() + "\t" + e.getValue() + "\n");
				}
				catch (IOException ignore) {
				}
			}
			index.close();
			di.dispose();
		}
		totalFailed.addAndGet(failed);
		totalNoFunc.addAndGet(noFunc);
		synchronized (LOG_LOCK) {
			println("[export] part" + partIdx + " done: methods=" + done + " failed=" + failed +
				" nofunc=" + noFunc);
		}
	}

	private DecompInterface startDecompiler() {
		DecompileOptions opt = new DecompileOptions();
		// cap the decompiler payload so explosive control-flow graphs fail fast
		opt.setMaxPayloadMBytes(8);
		opt.setWARNCommentIncluded(false);
		opt.setEliminateUnreachable(true);
		DecompInterface di = new DecompInterface();
		di.setOptions(opt);
		di.setSimplificationStyle("decompile");
		di.toggleCCode(true);
		di.toggleSyntaxTree(false);
		if (!di.openProgram(currentProgram)) {
			println("[export] WARNING: decompiler failed to open program");
		}
		return di;
	}

	/** Drops Ghidra inline WARNING noise and substitutes names. */
	private static String clean(String text, Map<Long, String> names) {
		if (text == null || text.isEmpty()) {
			return text;
		}
		StringBuilder sb = new StringBuilder(text.length());
		for (String line : text.split("\n", -1)) {
			String t = line.trim();
			if (t.startsWith("/* WARNING:") || t.startsWith("// WARNING:")) {
				continue;
			}
			sb.append(line).append('\n');
		}
		return substitute(sb.toString(), names);
	}

	private static String substitute(String text, Map<Long, String> names) {
		if (text == null || text.isEmpty()) {
			return text;
		}
		Matcher m = PTR_P.matcher(text);
		StringBuffer sb = new StringBuffer(text.length());
		while (m.find()) {
			long v;
			try {
				v = Long.parseUnsignedLong(m.group(1), 16);
			}
			catch (NumberFormatException e) {
				m.appendReplacement(sb, Matcher.quoteReplacement(m.group()));
				continue;
			}
			String nm = names.get(v);
			if (nm != null) {
				m.appendReplacement(sb, Matcher.quoteReplacement(nm));
			}
			else {
				m.appendReplacement(sb, Matcher.quoteReplacement(m.group()));
			}
		}
		m.appendTail(sb);

		String s = sb.toString();
		Matcher m2 = PRE_P.matcher(s);
		sb = new StringBuffer(s.length());
		while (m2.find()) {
			long v;
			try {
				v = Long.parseUnsignedLong(m2.group(1), 16);
			}
			catch (NumberFormatException e) {
				m2.appendReplacement(sb, Matcher.quoteReplacement(m2.group()));
				continue;
			}
			String nm = names.get(v);
			m2.appendReplacement(sb,
				Matcher.quoteReplacement(nm != null ? nm : m2.group()));
		}
		m2.appendTail(sb);
		return sb.toString();
	}

	private static String fileName(String type) {
		StringBuilder sb = new StringBuilder(type.length() + 3);
		for (int i = 0; i < type.length(); i++) {
			char c = type.charAt(i);
			sb.append((Character.isLetterOrDigit(c) || c == '_' || c == '.' || c == '$') ? c : '_');
		}
		if (sb.length() == 0) {
			sb.append("unknown");
		}
		if (Character.isDigit(sb.charAt(0))) {
			sb.insert(0, '_');
		}
		return sb.toString() + ".cs";
	}
}
