//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;

import org.json.JSONObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;

public class TaintAnalysisPayment extends GhidraScript {

	private int MAX_DEPTH = 50;
	private int MAX_ID = 1000;
	private DecompInterface decomplib;
	private GCT gct;
	private TaintGCT taintGCT;
	private TaintRules taintRules;

	private String pname = "";
	private String focusonSpecificOne = null;

	List<TaintTraceNode> leafes = new ArrayList<TaintTraceNode>();
	/*
	 * HashSet<Long> myMethodAddresses = new HashSet<Long>();
	 * 
	 * public void loadJson(String jsPath) throws JSONException, IOException {
	 * JSONObject js = new JSONObject(Files.readString(Paths.get(jsPath))); long
	 * baseOffset = currentProgram.getImageBase().getOffset();
	 * 
	 * js.getJSONArray("ScriptMethod").forEach(item -> { JSONObject tmpJs =
	 * (JSONObject) item; String tmpStr = tmpJs.getString("Image"); if
	 * (tmpStr.equals("Assembly-CSharp-firstpass.dll") ||
	 * tmpStr.equals("Assembly-CSharp.dll")) {
	 * myMethodAddresses.add(tmpJs.getLong("Address") + baseOffset); } });
	 * println("[*] myMethodAddresses len:" + myMethodAddresses.size()); }
	 */

	public void run() throws Exception {

		// AnalysisManager am = new AnalysisManager(this.currentProgram);
		// am.runAnalysis(new AddressSet(this.toAddr(0x540A44)));

		gct = GCT.getInstance();
		taintGCT = new TaintGCT(this);
		taintRules = TaintRules.getInstance();
		taintRules.initialze(this);

		List<TaintTraceNode> rootNodes = new ArrayList<TaintTraceNode>();
		JSONObject result = new JSONObject();

		pname = "test";

		String folder = null;
		if (this.isRunningHeadless()) {
			pname = this.askString("pname", "pname");
			folder = this.askString("folder", "folder");
			// loadJson(this.askString("json", "json"));
			gct.initialzeSymbols(this, folder);
		} else {
			//folder = "tmp/lib/arm64-v8a/il2cppdumper";
			// pname = this.askString("pname", "pname");
			// fold = this.askString("fold", "fold");

			//gct.initialzeSymbols(this, folder);

		}

		result.put("pname", pname);
		result.put("executablePath", currentProgram.getExecutablePath());
		try {

			println("[*] ExecutablePath: " + currentProgram.getExecutablePath());
			println("[*] ImageBase: " + currentProgram.getImageBase());
			println("[*] focusonSpecificOne: " + focusonSpecificOne);

			decomplib = setUpDecompiler(this.currentProgram);
			if (decomplib == null) {
				println("[-] Decompile Error: " + decomplib.getLastMessage());
				return;
			}
			this.println("[+] Decompile created!");

			this.println("[*] Pre analyzing!");
			TaintTraceNode rootNode = preAnalysis();
			rootNodes.add(rootNode);

			this.println("[*] Start analyzing!");
			performTaintAnalysis(rootNodes);

			this.println("[*] Post analysis!");
			postAnalysis(rootNodes, result);

			this.println("[*] Done!");

		} catch (Exception e) {
			StringWriter sw = new StringWriter();
			PrintWriter pw = new PrintWriter(sw);
			e.printStackTrace(pw);
			result.put("error", sw.toString());
			this.println("[-] Error:" + sw.toString());
		}
		result.put("isVulnerable", this.decideVulnerability(result));
		this.println(result.toString(4));

		String resPath = folder + "/analysisRes.json";
		Files.write(Paths.get(resPath), (result.toString(4)).getBytes(), StandardOpenOption.CREATE,
				StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
	}

	static HashSet<String> vulnerableKeys = new HashSet<String>();
	static String localVerifySig = "UnityEngine.Purchasing.Security.CrossPlatformValidator$$Validate";
	static {
		vulnerableKeys.add("Ending_OPCode");
		vulnerableKeys.add("Ending_API");
		vulnerableKeys.add("Unused_Parameter");
		vulnerableKeys.add("Unused_Node");
		vulnerableKeys.add("Missing_Target_Node");
		vulnerableKeys.add("No_Callser");
	}

	private String decideVulnerability(JSONObject result) {
		// removed implementation for ethical reason, and return "None"
		return "None";
	}

	public TaintTraceNode preAnalysis() {

		ArrayList<MyInst> source = TaintSourceIdentification.findAll(this);

		String getReceiptMthodStr = TaintSourceIdentification.getReceiptMthodHigh.getFunction().getName();
		TaintTraceNode rootNode = new TaintTraceNode(TaintSourceIdentification.getReceiptMthodHigh, null, null, 0);

		TaintTraceNode son = null;
		for (MyInst inst : source) {

			son = createChild(rootNode, inst.highFunc, inst.op, inst.op.getOutput());
			son.setAdditionalInfo(getReceiptMthodStr);

			if (Utility.isUnityClasses(inst.func.getName(true))) {
				son.setUnityBuildInClasseDerived(true);
			}

			println("[*]    Add source:" + inst.func.getName(true));
			println("[*]        Inst:" + inst.op);

		}

		if (rootNode.getChidren().size() == 0)
			rootNode.setAsLeaf(LeafNodeType.Unused_Node, "");

		return rootNode;
	}

	public void postAnalysis(List<TaintTraceNode> trootNodes, JSONObject result) {

		List<TaintTraceNode> untaggedLeafes = new ArrayList<TaintTraceNode>();
		for (TaintTraceNode rootNode : trootNodes)
			findUntaggedLeaf(rootNode, untaggedLeafes);
		printf("UntaggedLeaf (%s) start:\n", untaggedLeafes.size());
		for (TaintTraceNode untagged : untaggedLeafes) {
			printf("%s\n", untagged.toString());
			result.append("untaggedLeaf", untagged.getnID());
		}
		printf("UntaggedLeaf end\n\n");

		getLeafNodeInfor(result);
		for (TaintTraceNode ln : leafes) {
			result.append("leafes", ln.getnID());
		}

		JSONObject nodes = new JSONObject();
		result.put("nodes", nodes);

		for (TaintTraceNode node : trootNodes) {
			dumpNodes(node, nodes);
		}

	}

	public void dumpNodes(TaintTraceNode rootNode, JSONObject nodes) {

		String mid = rootNode.getnID() + "";
		if (!nodes.has(mid)) {
			nodes.put(mid, rootNode.toJson());
			for (TaintTraceNode node : rootNode.getChidren()) {
				dumpNodes(node, nodes);
			}
		}
	}

	public void findUntaggedLeaf(TaintTraceNode rootNode, List<TaintTraceNode> untaggedLeafes) {
		if (rootNode.leafType == null && rootNode.getChidren().size() == 0)
			untaggedLeafes.add(rootNode);

		for (TaintTraceNode node : rootNode.getChidren()) {
			findUntaggedLeaf(node, untaggedLeafes);
		}

	}

	public void getLeafNodeInfor(JSONObject result) {

		JSONObject leafInfo = new JSONObject();
		result.put("leafInfo", leafInfo);

		for (TaintTraceNode ln : leafes) {
			if (!ln.isUnityBuildInClasseDerived()) {

				if (ln.leafType.name().equals(LeafNodeType.Unkown_API.name())
						&& (ln.leafNote.startsWith("FUN_") || ln.leafNote.startsWith("thunk_FUN_"))) {
					// IL2CPP internal functions
					continue;
				}

				printf("[%s] %s: %s\n", ln.getnID(), ln.leafType.name(), ln.leafNote);
				leafInfo.append(ln.leafType.name(), String.format("%s [%s]", ln.leafNote, ln.getnID()));
			}
		}
	}

	private void performTaintAnalysis(List<TaintTraceNode> trootNodes) {
		Queue<TaintTraceNode> waiting = new LinkedList<TaintTraceNode>();

		for (TaintTraceNode rootNode : trootNodes)
			waiting.addAll(rootNode.getChidren());

		TaintTraceNode workingNode;
		while (waiting.size() != 0) {
			workingNode = waiting.remove();
			List<TaintTraceNode> nextHops = moveOn(workingNode);
			for (TaintTraceNode ttn : nextHops)
				waiting.add(ttn);
		}
	}

	private List<TaintTraceNode> moveOn(TaintTraceNode currentNode) {

		println("\n\nWoring on node:" + currentNode);
		List<TaintTraceNode> nextHops = new ArrayList<TaintTraceNode>();

		if (currentNode.getTargetVarnode() == null) { // not safe
			println("[+] Null TargetVarnode!");
			currentNode.setAsLeaf(LeafNodeType.Missing_Target_Node, "");
			return nextHops;
		}

		if (currentNode.getDepth() >= MAX_DEPTH) {
			println("[+] MAX_DEPTH!");
			currentNode.setAsLeaf(LeafNodeType.MAX_DEPTH, "");
			return nextHops;
		}

		if (currentNode.getnID() >= MAX_ID) {
			println("[+] MAX_ID!");
			currentNode.setAsLeaf(LeafNodeType.MAX_ID, "");
			return nextHops;
		}

		HighFunction contextMethod = currentNode.getContextMethod();
		// PcodeOp currentPcode = currentNode.getCurrentPcode();
		Varnode targetVarnode = currentNode.getTargetVarnode();

		Iterator<PcodeOp> varnodeUses = targetVarnode.getDescendants(); // error
		if (varnodeUses == null || !varnodeUses.hasNext()) {
			println("[+] didn't use!");
			currentNode.setAsLeaf(LeafNodeType.Unused_Node, "");
			return nextHops;
		}
		PcodeOp varnodeUse;
		TaintTraceNode nextHop;
		while (varnodeUses.hasNext() && !monitor.isCancelled()) {
			varnodeUse = varnodeUses.next();
			println("[+] varnodeUse:" + varnodeUse.getSeqnum().getTarget() + ":" + varnodeUse);

			int opcode = varnodeUse.getOpcode();
			switch (opcode) {
			case PcodeOp.CALL:

				println("[*]   CALL:" + varnodeUse);
				Iterator<PcodeOpAST> ggg = contextMethod.getPcodeOps(varnodeUse.getSeqnum().getTarget());
				while (ggg.hasNext()) {
					println("[*]     " + ggg.next());
				}

				Address calleeAddr = varnodeUse.getInput(0).getAddress();
				Function callee = this.getFunctionAt(calleeAddr);
				HighFunction calleeHigh = decompileFunction(callee);
				println("[*]   CALL:" + callee);

				if (isSystemAPI(calleeAddr)) {
					if (taintRules.propagate2Ret(callee.toString())) {
						nextHop = createChild(currentNode, contextMethod, varnodeUse, varnodeUse.getOutput());
						nextHop.setAdditionalInfo(callee.getName(true));
						if (nextHop.getTargetVarnode() != null)
							nextHops.add(nextHop);
						else
							nextHop.setAsLeaf(LeafNodeType.Missing_Target_Node, callee.getName(true));
					} else if (taintRules.propagate2End(callee.toString())) {
						nextHop = createChild(currentNode, contextMethod, varnodeUse, varnodeUse.getOutput());
						nextHop.setAdditionalInfo(callee.getName(true));
						nextHop.setAsLeaf(LeafNodeType.Ending_API, callee.getName(true));
					} else {
						println("[-]   Unsupported SystemAPI:" + callee + "|");
						nextHop = createChild(currentNode, contextMethod, varnodeUse, null);
						nextHop.setAdditionalInfo(callee.getName(true));
						nextHop.setAsLeaf(LeafNodeType.Unkown_API, callee.getName(true));
					}
					break;
				}

				// println("[*] paramCount:" + callee.getParameterCount());
				println("[*]   paramCount:" + calleeHigh.getFunctionPrototype().getNumParams());

				HighParam hp;
				Iterator<PcodeOp> ops;
				int paramIndex;
				boolean paramUsed = false;
				for (int i = 1; i < varnodeUse.getInputs().length; i++) {
					paramIndex = i - 1;
					if (varnodeUse.getInputs()[i].equals(targetVarnode)) {
						println("[*]   targetParamIndex:" + paramIndex);

						hp = (HighParam) calleeHigh.getFunctionPrototype().getParam(paramIndex).getHighVariable();
						if (hp != null) {
							for (Varnode node : hp.getInstances()) {
								ops = node.getDescendants();
								if (ops == null || !ops.hasNext())
									continue;
								println("[*]   targetParamVarnode:" + node);
								nextHop = createChild(currentNode, contextMethod, varnodeUse, targetVarnode);
								nextHop.setAdditionalInfo(callee.getName(true));

								nextHop = createChild(nextHop, calleeHigh, null, node);
								nextHops.add(nextHop);
								nextHop.callStackPush(nextHop.getParent());

								paramUsed = true;
							}
						}
					}
				}
				if (!paramUsed) {
					nextHop = createChild(currentNode, contextMethod, varnodeUse, targetVarnode);
					nextHop.setAdditionalInfo(callee.getName(true));
					nextHop.setAsLeaf(LeafNodeType.Unused_Parameter, callee.getName(true));
				}

				break;
			case PcodeOp.RETURN:
				println("[*]   RETURN:" + varnodeUse);

				// return instruction
				TaintTraceNode nextHopReturn = createChild(currentNode, contextMethod, varnodeUse,
						varnodeUse.getOutput());

				TaintTraceNode callStackItem = nextHopReturn.callStackPop();
				if (callStackItem != null) {
					nextHop = createChild(nextHopReturn, callStackItem.getContextMethod(),
							callStackItem.getCurrentPcode(), callStackItem.getCurrentPcode().getOutput());
					nextHop.setAdditionalInfo(contextMethod.getFunction().getName(true));

					if (nextHop.getTargetVarnode() != null)
						nextHops.add(nextHop);
					else
						nextHop.setAsLeaf(LeafNodeType.Missing_Target_Node,
								currentNode.getContextMethod().getFunction().getName(true));

				} else {
					ArrayList<MyInst> insts = Utility.getAllCaller(this, contextMethod);

					if (insts.size() == 0) {
						nextHopReturn.setAsLeaf(LeafNodeType.No_Callser,
								currentNode.getContextMethod().getFunction().getName(true));
					}

					for (MyInst inst : insts) {
						nextHop = createChild(nextHopReturn, inst.highFunc, inst.op, inst.op.getOutput());
						nextHop.setAdditionalInfo(contextMethod.getFunction().getName(true));

						if (nextHop.getTargetVarnode() != null)
							nextHops.add(nextHop);
						else
							nextHop.setAsLeaf(LeafNodeType.Missing_Target_Node,
									currentNode.getContextMethod().getFunction().getName(true));
					}
				}
				break;
			case PcodeOp.LOAD:
			case PcodeOp.INT_ADD:
			case PcodeOp.COPY:
			case PcodeOp.CAST:
			case PcodeOp.MULTIEQUAL:
			case PcodeOp.INT_ZEXT:
			case PcodeOp.SUBPIECE:
			case PcodeOp.INT_AND:
			case PcodeOp.INT_SUB:
			case PcodeOp.INDIRECT:

				println("[*]   LOAD/ADD/COPY/CAST/MULTIEQUAL:" + varnodeUse);
				nextHop = createChild(currentNode, contextMethod, varnodeUse, varnodeUse.getOutput());
				nextHops.add(nextHop);
				// println("[*] " + targetVarnode + " -> " +
				// varnodeUse.getOutput());

				break;

			case PcodeOp.INT_EQUAL:
			case PcodeOp.INT_NOTEQUAL:
			case PcodeOp.INT_LESS:
			case PcodeOp.INT_LESSEQUAL:
			case PcodeOp.INT_SLESS:
				println("[*]   Ignore! " + PcodeOp.getMnemonic(opcode));
				nextHop = createChild(currentNode, contextMethod, varnodeUse, null);
				nextHop.setAsLeaf(LeafNodeType.Ending_OPCode, PcodeOp.getMnemonic(opcode));
				break;

			case PcodeOp.STORE:
				println("[*]   Handling STORE! " + varnodeUse);
				FieldResolutionReport resReport = taintGCT.findMoveTarget(contextMethod, varnodeUse);
				if (resReport.errorMsg != null) {
					nextHop = createChild(currentNode, contextMethod, varnodeUse, varnodeUse.getInput(1));
					nextHop.setAsLeaf(LeafNodeType.Unhandlable_OPCode, "STORE:" + resReport.toString());
				} else {

					nextHop = createChild(currentNode, contextMethod, varnodeUse, varnodeUse.getInput(1));
					nextHop.setAdditionalInfo(resReport.toString());

					if (gct.addNewClassFeild(resReport)) {

						TaintTraceNode nextNextHop;
						ArrayList<MyInst> accessedTarget = taintGCT.processFunctionWithTaintedClasses(resReport);

						if (accessedTarget.size() > 0) {
							for (MyInst inst : accessedTarget) {

								nextNextHop = createChild(nextHop, inst.getHighFunc(), inst.getOp(),
										inst.getOp().getOutput());
								nextHops.add(nextNextHop);
								nextNextHop.callStackClear();
							}
						} else {
							nextHop.setAsLeaf(LeafNodeType.Unused_Node, "STORE:" + resReport.toString());
						}
					} else {
						nextHop.setAsLeaf(LeafNodeType.Unused_Node, "STORE:handled:" + resReport.toString());
					}

				}
				break;

			case PcodeOp.CALLIND:

				println("[*]   Canc't handle! " + PcodeOp.getMnemonic(opcode));
				nextHop = createChild(currentNode, contextMethod, varnodeUse, null);
				nextHop.setAsLeaf(LeafNodeType.Unhandlable_OPCode, PcodeOp.getMnemonic(opcode));
				break;

			default:
				nextHop = createChild(currentNode, contextMethod, varnodeUse, varnodeUse.getOutput());
				nextHop.setAsLeaf(LeafNodeType.Unkown_OPCode, PcodeOp.getMnemonic(opcode));
				println("[-]   Unsupported OP:" + varnodeUse);
			}
		}

		return nextHops;
	}

	private boolean isSystemAPI(Address functionAddr) {
		println("[*] isSystemAPI:" + functionAddr.getOffset());
		// if (systemAPIOffset != -1)
		// return functionAddr.getOffset() < systemAPIOffset;
		boolean ret = !gct.isDeveloperFunction(functionAddr);
		println("[*] isSystemAPI:" + ret);
		return ret;
	}

	private DecompInterface setUpDecompiler(Program program) {
		DecompInterface decompiler = new DecompInterface();

		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		decompiler.setSimplificationStyle("decompile");

		decompiler.openProgram(program);

		return decompiler;
	}

	public HighFunction decompileFunction(Function f) {
		HighFunction highFunc = null;

		// try {
		DecompileResults dRes = decomplib.decompileFunction(f, 30, getMonitor());
		highFunc = dRes.getHighFunction();
		// } catch (Exception exc) {
		// printf("exception in decompilation\n" + exc.getMessage());
		// exc.printStackTrace();
		// }

		return highFunc;
	}

	static int counter = 0;

	class TaintTraceNode {

		int nID;

		int depth;

		HighFunction contextMethod;

		PcodeOp currentPcode;

		Varnode targetVarnode;

		TaintTraceNode parent;

		List<TaintTraceNode> chidren = new ArrayList<TaintTraceNode>();

		LinkedList<TaintTraceNode> callStack = null;// new
													// LinkedList<TaintTraceNode>();
		String additionalInfo = null;

		LeafNodeType leafType = null;
		String leafNote = null;

		boolean unityBuildInClasseDerived = false;

		public JSONObject toJson() {

			JSONObject ret = new JSONObject();
			ret.put("id", this.getnID());
			ret.put("depth", this.getDepth());
			ret.put("contextMethod", contextMethod.getFunction().getName(true));
			ret.put("currentPcode", currentPcode);
			ret.put("unityBuildin", unityBuildInClasseDerived);
			if (currentPcode != null)
				ret.put("pcodeOffset", currentPcode.getSeqnum().getTarget());

			ret.put("targetVarnode", targetVarnode);
			if (parent != null)
				ret.put("parentID", parent.getnID());
			if (leafType != null)
				ret.put("leafType", leafType.name());
			if (leafNote != null)
				ret.put("leafNote", leafNote);

			if (this.getAdditionalInfo() != null)
				ret.put("additionalInfo", this.getAdditionalInfo());

			for (TaintTraceNode child : chidren)
				ret.append("children", child.getnID());
			return ret;
		}

		public String toString() {
			return "ID\t" + nID + "\ndepth\t" + depth + "\ncMethod\t" + contextMethod.getFunction().getName(true)
					+ "\ncPcode\t" + currentPcode + "\ntVNode\t" + targetVarnode;

		}

		public void setAsLeaf(LeafNodeType leafType, String leafNote) {
			this.leafType = leafType;
			this.leafNote = leafNote;
			leafes.add(this);
		}

		public TaintTraceNode(HighFunction contextMethod, PcodeOp currentPcode, Varnode targetVarnode, int depth) {
			this.setContextMethod(contextMethod);
			this.setCurrentPcode(currentPcode);
			this.setTargetVarnode(targetVarnode);
			this.setDepth(depth);

			nID = counter++;
		}

		public HighFunction getContextMethod() {
			return contextMethod;
		}

		public void setContextMethod(HighFunction contextMethod) {
			this.contextMethod = contextMethod;
		}

		public PcodeOp getCurrentPcode() {
			return currentPcode;
		}

		public void setCurrentPcode(PcodeOp currentPcode) {
			this.currentPcode = currentPcode;
		}

		public Varnode getTargetVarnode() {
			return targetVarnode;
		}

		public void setTargetVarnode(Varnode targetVarnode) {
			this.targetVarnode = targetVarnode;
		}

		public TaintTraceNode getParent() {
			return parent;
		}

		@SuppressWarnings("unchecked")
		public void setParent(TaintTraceNode parent) {
			this.parent = parent;
			parent.chidren.add(this);
			this.setUnityBuildInClasseDerived(parent.isUnityBuildInClasseDerived());
			if (parent.callStack != null && parent.callStack.size() > 0)
				this.callStack = (LinkedList<TaintTraceNode>) parent.callStack.clone();
			println("[*]   flow " + this.parent.getnID() + " -> " + this.getnID());
			println("[*]       vnode " + this.parent.getTargetVarnode() + " -> " + this.getTargetVarnode());
			if (this.parent.getCurrentPcode() != null && this.getCurrentPcode() != null)
				println("[*]       vnode " + this.parent.getCurrentPcode().getSeqnum().getTarget() + " -> "
						+ this.getCurrentPcode().getSeqnum().getTarget());
		}

		public List<TaintTraceNode> getChidren() {
			return chidren;
		}

		// private void addChidren(TaintTraceNode child) {
		// this.chidren.add(child);
		// }

		public int getnID() {
			return nID;
		}

		public void callStackPush(TaintTraceNode item) {
			if (callStack == null)
				callStack = new LinkedList<TaintTraceNode>();
			callStack.add(item);
		}

		public TaintTraceNode callStackPop() {
			if (callStack != null && callStack.size() > 0)
				return callStack.remove(0);
			return null;
		}

		public void callStackClear() {
			if (callStack != null && callStack.size() > 0)
				callStack.clear();
		}

		public int getDepth() {
			return depth;
		}

		public void setDepth(int depth) {
			this.depth = depth;
		}

		public String getAdditionalInfo() {
			return additionalInfo;
		}

		public void setAdditionalInfo(String additionalInfo) {
			this.additionalInfo = additionalInfo;
		}

		public boolean isUnityBuildInClasseDerived() {
			return unityBuildInClasseDerived;
		}

		public void setUnityBuildInClasseDerived(boolean unityBuildInClasseDerived) {
			this.unityBuildInClasseDerived = unityBuildInClasseDerived;
		}

	}

	public TaintTraceNode createChild(TaintTraceNode parent, HighFunction contextMethod, PcodeOp currentPcode,
			Varnode targetVarnode) {
		TaintTraceNode nextHop = new TaintTraceNode(contextMethod, currentPcode, targetVarnode, parent.getDepth() + 1);
		nextHop.setParent(parent);
		return nextHop;
	}
}
