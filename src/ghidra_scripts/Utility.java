import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.symbol.Reference;

public class Utility {

	public static void main(String[] args) {

	}

	public static <T> List<T> iterator2List(Iterator<T> iter) {
		List<T> copy = new ArrayList<T>();
		while (iter.hasNext())
			copy.add(iter.next());
		return copy;
	}

	/////////////
	static DecompInterface decompiler = null;

	public static DecompInterface setUpDecompiler(GhidraScript gs, Program program) {
		decompiler = new DecompInterface();

		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		decompiler.setSimplificationStyle("decompile");

		decompiler.openProgram(program);

		return decompiler;
	}

	public static HighFunction decompileFunction(GhidraScript gs, Function f) {
		
		//gs.println(f+"");
		if (decompiler == null) {
			setUpDecompiler(gs, gs.getCurrentProgram());
		}

		HighFunction highFunc = null;
		
		// try {
		DecompileResults dRes = decompiler.
				decompileFunction(f, 30, gs.
						getMonitor());
		highFunc = dRes.getHighFunction();
		// } catch (Exception exc) {
		// printf("exception in decompilation\n" + exc.getMessage());
		// exc.printStackTrace();
		// }

		return highFunc;
	}
	/////////////

	public List<PcodeOpAST> getPCodeAST(HighFunction calleeHighFunction, Address callSite) {
		Iterator<PcodeOpAST> pcodeOps = calleeHighFunction.getPcodeOps(callSite);
		return iterator2List(pcodeOps);
	}

	public static PcodeOpAST getNextPCodeASTinSameAddress(HighFunction calleeHighFunction, PcodeOp pcode) {

		Iterator<PcodeOpAST> pcodeOps = calleeHighFunction.getPcodeOps(pcode.getSeqnum().getTarget());
		while (pcodeOps.hasNext()) {
			if (pcodeOps.next().equals(pcode)) {
				if (pcodeOps.hasNext())
					return pcodeOps.next();
				break;
			}
		}
		return null;
	}

	public static int getPCodeASTID(HighFunction calleeHighFunction, PcodeOpAST pcode) {

		Iterator<PcodeOpAST> pcodeOps = calleeHighFunction.getPcodeOps(pcode.getSeqnum().getTarget());
		int id = 0;
		while (pcodeOps.hasNext()) {
			id++;
			if (pcodeOps.next().equals(pcode)) {
				return id;
			}
		}
		return -1;
	}

	public static ArrayList<MyInst> getAllCaller(GhidraScript gs, Function func) {
		return getAllCaller(gs, decompileFunction(gs, func));
	}

	public static ArrayList<MyInst> getAllCaller(GhidraScript gs, HighFunction highFunc) {
		// gs.println(highFunc+"");
		Function func = highFunc.getFunction();
		Reference[] callers = gs.getReferencesTo(highFunc.getFunction().getEntryPoint());

		ArrayList<MyInst> callerInsts = new ArrayList<MyInst>();

		Function callerMethod;
		HighFunction callerHighMethod;
		Iterator<PcodeOpAST> ops;
		PcodeOpAST op;
		MyInst inst;
		for (Reference ref : callers) {
			if (!ref.getReferenceType().isCall())
				continue;

			callerMethod = gs.getFunctionContaining(ref.getFromAddress());
			callerHighMethod = decompileFunction(gs, callerMethod);
			ops = callerHighMethod.getPcodeOps(ref.getFromAddress());// error
			while (ops.hasNext()) {
				op = ops.next();
				if (op.getOpcode() == PcodeOp.CALL) {
					if (gs.getFunctionContaining(op.getInput(0).getAddress()).equals(func)) {
						inst = new MyInst(callerMethod, callerHighMethod, op);

						callerInsts.add(inst);
						break;
					}
				}
			}
		}
		return callerInsts;
	}

	public static boolean isUnityClasses(String methodName) {
		if (methodName.startsWith("IAPDemoProductUI$$") || methodName.startsWith("IAPDemo$$")
				|| methodName.startsWith("UnityEngine.Purchasing.")) {
			return true;
		}
		return false;
	}

	public static boolean isSamePCode(MyInst instA, MyInst instB) {
		if (instA.getOp().getSeqnum().getTarget().getOffset() == instB.getOp().getSeqnum().getTarget().getOffset()) {
			if (getPCodeASTID(instA.getHighFunc(), instA.getOp()) == getPCodeASTID(instB.getHighFunc(), instB.getOp()))
				return true;
		}
		return false;
	}

	public static void error(String str) {

	}
}
