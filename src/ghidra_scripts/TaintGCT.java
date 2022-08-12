import java.util.ArrayList;
import java.util.Map.Entry;

import org.json.JSONObject;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class TaintGCT {

	GhidraScript gs;
	GCT gct;

	public TaintGCT(GhidraScript gs) {
		this.gs = gs;
		gct = GCT.getInstance();
	}

	// PROCESSFUNCTIONWITHTAINTEDCLASSES
	public ArrayList<MyInst> processFunctionWithTaintedClasses(FieldResolutionReport report) {
		ArrayList<MyInst> accessed = new ArrayList<MyInst>();
		JSONObject jsObj, param;
		long address;
		for (Entry<Long, JSONObject> ent : gct.methodAddresses.entrySet()) {
			address = ent.getKey();
			jsObj = ent.getValue();

			for (Object obj : jsObj.getJSONArray("ScriptParameters")) {
				param = (JSONObject) obj;
				if (param.getString("ClassType").equals(report.hostClass)) {
					accessed.addAll(taintNewUsages(report, jsObj, address, param.getInt("Index")));
				}
			}
		}

		ArrayList<MyInst> distinctAccessed = new ArrayList<MyInst>();

		for (MyInst tinst : accessed) {

			boolean duplicated = false;
			for (MyInst inst : distinctAccessed) {
				// gs.println("[*] cmp:" + inst.getOp() +" - " + tinst.getOp());
				// gs.println("[*] :" + inst.getOp().getSeqnum().getTarget() +" - " +
				// tinst.getOp().getSeqnum().getTarget());
				if (Utility.isSamePCode(inst, tinst)) {
					duplicated = true;
					gs.println("[*]     duplicated:" + inst + " - " + tinst);
					break;
				}
			}
			if (!duplicated) {
				distinctAccessed.add(tinst);
			}
		}

		return distinctAccessed;
	}

	private ArrayList<MyInst> taintNewUsages(FieldResolutionReport report, JSONObject jsObj,
			long address, int paramIndex) {
		// gs.println(jsObj.toString());

		ArrayList<MyInst> accessed = GetFieldAceess.LocateClassFieldAccess(gs, jsObj.getString("Name"), paramIndex,
				report.offset);

		@SuppressWarnings("deprecation")
		Function function = gs.getFunction(jsObj.getString("Name"));
		gs.println("[*]   function:" + jsObj.getString("Name"));

		ArrayList<MyInst> callers = Utility.getAllCaller(gs, function);
		for (MyInst inst : callers) {

			if (inst.op.getInput(paramIndex + 1) != null) { // Ghidra may miss some parameters
				ArrayList<MyInst> callerAccess = GetFieldAceess.LocateClassFieldAccess(gs, inst.highFunc,
						inst.op.getInput(paramIndex + 1), report.offset);

				for (MyInst tinst : callerAccess) {
					gs.println("[*]   callerAccess:----------------------------------");
					gs.println("[*]   callerAccess:" + tinst.func);
					gs.println("[*]   callerAccess:" + tinst.op);
					gs.println("[*]   callerAccess:" + tinst.op.getSeqnum().getTarget());
				}
				accessed.addAll(callerAccess);
			}
		}

		if (accessed.size() > 0) {
			gs.println("[*]   access:");
			for (MyInst inst : accessed) {
				gs.println("[*]   access:" + inst.func);
				gs.println("[*]   access:" + inst.op);
				gs.println("[*]   access:" + inst.op.getSeqnum().getTarget());
			}
		}

		return accessed;
	}

	public FieldResolutionReport findMoveTarget(HighFunction contextMethod, PcodeOp varnodeUse) {
		Varnode outputVarnode = varnodeUse.getInput(1);
		this.gs.println("[*]   findMoveTarget:def:" + outputVarnode.getDef() + ":"
				+ outputVarnode.getDef().getSeqnum().getTarget());

		FieldResolutionReport report = fieldBaseAddressResolution(contextMethod, outputVarnode);
		gs.println("[*]   report.hostClass:" + report.hostClass);
		gs.println("[*]   report.offset:" + report.offset);
		gs.println("[*]   report.errorMsg:" + report.errorMsg);
		return report;

	}

	public FieldResolutionReport fieldBaseAddressResolution(HighFunction contextMethod, Varnode varnode) {

		FieldResolutionReport report = new FieldResolutionReport();

		boolean stop = false;
		PcodeOp define;
		while (!stop) {

			define = varnode.getDef();
			if (define == null) {
				report.errorMsg = "fieldBaseAddressResolution:def not found";
				break;

			}

			// this.gs.println("[*] " +define + ":" + define.getSeqnum().getTarget());

			switch (define.getOpcode()) {

			case PcodeOp.COPY:
			case PcodeOp.CAST:

				varnode = define.getInput(0);
				break;

			case PcodeOp.INT_ADD:
				stop = true;

				Varnode baseClass = define.getInput(0);
				Varnode offset = define.getInput(1);
				this.gs.println("[*]   fieldBaseAddressResolution:bacccseClass:" + baseClass);
				this.gs.println("[*]   fieldBaseAddressResolution:baseClass:offset:" + offset);
				try {
					String hostClass = baseClassResolution(contextMethod, baseClass);
					if (hostClass == null) {
						report.errorMsg = "fieldBaseAddressResolution:baseClassResolution return null";
					} else {
						report.hostClass = hostClass;
						report.offset = (int) offset.getOffset();
					}
				} catch (Exception e) {
					report.errorMsg = e.getMessage();
				}

				break;

			default:
				stop = true;
				report.errorMsg = "fieldBaseAddressResolution:unknow Opcode:" + define;
			}

		}
		return report;

	}

	public String baseClassResolution(HighFunction contextMethod, Varnode baseClass) throws Exception {

		PcodeOp define = baseClass.getDef();
		this.gs.println("[*]   baseClassResolution:define:" + define);

		if (define != null) {
			// if opcode(vde f ) is COPY or CAST then
			if (define.getOpcode() == PcodeOp.COPY || define.getOpcode() == PcodeOp.CAST)
				return baseClassResolution(contextMethod, define.getInput(0));

			// if opcode(vde f ) is CALL then
			if (define.getOpcode() == PcodeOp.CALL) {
				Address calleeAddr = define.getInput(0).getAddress();
				String type = gct.getFunctionReturnType(calleeAddr.getOffset());

				if (type == null) {
					throw new Exception("baseClassResolution:return type not found:" + calleeAddr.getOffset());
				}

				return type;
			}
			// if opcode(vde f ) is LOAD
			if (define.getOpcode() == PcodeOp.LOAD) {
				FieldResolutionReport subReport = fieldBaseAddressResolution(contextMethod, define.getInput(1));
				if (subReport.errorMsg != null) {
					throw new Exception("baseClassResolution:LOAD target not found:" + subReport.errorMsg);
				}

				String type = gct.getFieldType(subReport);
				if (type == null) {
					throw new Exception("baseClassResolution:LOAD target field not found");
				}

				return type;

			}

		}

		int paramIndex = getParameterIndex(contextMethod, baseClass);

		// isParameter(vde f )
		if (paramIndex != -1) {
			long address = contextMethod.getFunction().getEntryPoint().getOffset();

			String type = gct.getFunctionParameterType(address, paramIndex);

			this.gs.println("[*]   baseClassResolution:" + address + ":" + paramIndex + ":" + type);
			this.gs.println("[*]   baseClassResolution:getParameterType:" + type);
			if (type == null) {
				throw new Exception("baseClassResolution:parameter not found:" + address + ":" + paramIndex);
			}

			return type;
		}

		throw new Exception("baseClassResolution:unrecognized baseclass");
	}

	private int getParameterIndex(HighFunction contextMethod, Varnode baseClass) {

		int paramCount = contextMethod.getFunctionPrototype().getNumParams();
		this.gs.println("[*]   baseClass:paramCount:" + paramCount);
		for (int paramIndex = 0; paramIndex < paramCount; paramIndex++) {

			HighParam hp = (HighParam) contextMethod.getFunctionPrototype().getParam(paramIndex).getHighVariable();

			for (Varnode node : hp.getInstances()) {
				if (node.equals(baseClass))
					return paramIndex;
			}
		}
		return -1;
	}

}
