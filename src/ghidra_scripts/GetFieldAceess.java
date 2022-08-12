//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;

import org.json.JSONException;
import org.json.JSONObject;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;

public class GetFieldAceess extends GhidraScript {

	HashSet<Long> myMethodAddresses = new HashSet<Long>();

	public void loadJson(String jsPath) throws JSONException, IOException {
		JSONObject js = new JSONObject(Files.readString(Paths.get(jsPath)));
		long baseOffset = currentProgram.getImageBase().getOffset();

		js.getJSONArray("ScriptMethod").forEach(item -> {
			JSONObject tmpJs = (JSONObject) item;
			String tmpStr = tmpJs.getString("Image");
			if (tmpStr.equals("Assembly-CSharp-firstpass.dll") || tmpStr.equals("Assembly-CSharp.dll")) {
				myMethodAddresses.add(tmpJs.getLong("Address") + baseOffset);
			}
		});
		println("[*] myMethodAddresses len:" + myMethodAddresses.size());
	}

	public void run() throws Exception {

		Utility.setUpDecompiler(this, this.currentProgram);

		GCT.getInstance().initialzeSymbols(this, "~/Documents/tmpGameApks/1.1.0/");

		ArrayList<MyInst> source = TaintSourceIdentification.findAll(this);

		for (MyInst accnode : source) {
			println("          accnode:" + accnode.getFunc().getName());
			println("          accnode:" + accnode.op.getOutput());
		}

	}

	public static ArrayList<MyInst> LocateClassFieldAccess(GhidraScript gs, HighFunction fHigh, Varnode clsVarnod,
			int fieldOffset) {

		ArrayList<MyInst> accessed = new ArrayList<MyInst>();

		for (PcodeOp usenode : Utility.iterator2List(clsVarnod.getDescendants())) {

			if (usenode.getOpcode() == PcodeOp.INT_ADD) {
				if (usenode.getInput(1).getOffset() == fieldOffset) {

					PcodeOpAST tt = Utility.getNextPCodeASTinSameAddress(fHigh, usenode);

					if (tt != null && tt.getOpcode() == PcodeOp.LOAD && tt.getOutput() != null) {
						accessed.add(new MyInst(fHigh.getFunction(), fHigh, tt));
					}

				}
			}
		}
		return accessed;
	}

	public static ArrayList<MyInst> LocateClassFieldAccess(GhidraScript gs, String functionName, int paramIndex,
			int offset) {

		ArrayList<MyInst> accessed = new ArrayList<MyInst>();

		@SuppressWarnings("deprecation")
		Function f = gs.getFunction(functionName);
		if (f == null) {
			gs.println("[-] function not found:" + functionName);
		} else {
			HighFunction fHigh = Utility.decompileFunction(gs, f);
			if (fHigh == null) {
				gs.println("[-] Hfunction not found:" + functionName);
			} else {
				if (fHigh.getFunctionPrototype().getNumParams() > paramIndex) {
					HighParam hp = (HighParam) fHigh.getFunctionPrototype().getParam(paramIndex).getHighVariable();
					if (hp != null) {
						for (Varnode node : hp.getInstances()) {

							ArrayList<MyInst> taccessed = LocateClassFieldAccess(gs, fHigh, node, offset);
							accessed.addAll(taccessed);
						}
					}
				}
			}
		}

		return accessed;
	}
}
