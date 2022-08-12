//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import java.util.ArrayList;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;

public class TaintSourceIdentification {

	public static String getReceiptMthodStr = null;
	public static HighFunction getReceiptMthodHigh = null;

	public static ArrayList<MyInst> findAll(GhidraScript gs) {

		ArrayList<MyInst> source = new ArrayList<MyInst>();

		ArrayList<MyInst> sourceA = findGetReceiptCalls(gs);
		source.addAll(sourceA);

		return source;
	}

	private static ArrayList<MyInst> findGetReceiptCalls(GhidraScript gs) {
		ArrayList<MyInst> targets = new ArrayList<MyInst>();

		TaintRules.getInstance().getSources().forEach(x->{
			targets.addAll(findGetReceiptCalls(gs, x));
		});

		return targets;
	}
	
	private static ArrayList<MyInst> findGetReceiptCalls(GhidraScript gs, String functionName) {
		ArrayList<MyInst> targets = new ArrayList<MyInst>();

		@SuppressWarnings("deprecation")
		Function getReceiptMthod = gs.getFunction(functionName);

		gs.println("[*] targetMthod:" + getReceiptMthod);
		getReceiptMthodHigh = Utility.decompileFunction(gs, getReceiptMthod);
		getReceiptMthodStr = functionName;

		ArrayList<MyInst> callers = Utility.getAllCaller(gs, getReceiptMthod);
		gs.println("[*]   CallerCount:" + callers.size());

		for (MyInst inst : callers) {

			targets.add(inst);

		}

		return targets;
	}


}
