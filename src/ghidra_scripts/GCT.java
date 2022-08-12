import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

import org.json.JSONException;
import org.json.JSONObject;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class GCT {

	private GCT() {

	}

	static GCT symbo = new GCT();

	public static GCT getInstance() {
		return symbo;
	}

	public static ArrayList<String> unityBuildinPurchaseFunctionNames = new ArrayList<String>();
	static {
		unityBuildinPurchaseFunctionNames.add("UnityEngine.Purchasing.IAPListener$$ProcessPurchase");
		unityBuildinPurchaseFunctionNames.add("UnityEngine.Purchasing.IAPButton$$ProcessPurchase");
		unityBuildinPurchaseFunctionNames.add("UnityEngine.Purchasing.CodelessIAPStoreListener$$ProcessPurchase");
		unityBuildinPurchaseFunctionNames.add("IAPDemo$$ProcessPurchase");
	}

	GhidraScript gs;
	JSONObject scriptJs;
	JSONObject csharpClasses;
	// HashSet<Long> methodAddresses = new HashSet<Long>();
	HashMap<Long, JSONObject> methodAddresses = new HashMap<Long, JSONObject>();

	HashSet<Long> myMethodAddresses = new HashSet<Long>();
	ArrayList<String> purchaseFunctionNames = new ArrayList<String>();
	HashSet<String> taintedClassFeild = new HashSet<String>();

	int productOffset;
	int receiptOffset;

	boolean inited = false;

	// UnityEngine_Purchasing_PurchaseEventArgs_o* e, const MethodInfo* method);"
	// UnityEngine_Purchasing_PurchaseEventArgs_o* e, const MethodInfo* method);
	// UnityEngine_Purchasing_PurchaseEventArgs_o* args, const MethodInfo* method);
	public void initialzeSymbols(GhidraScript tgs, String symbFolder) throws JSONException, IOException {
		if (inited)
			return;
		inited = true;

		this.gs = tgs;

		loadJson(symbFolder + "/script.json");
		loadCS(symbFolder + "/dump.cs");
		csharpClasses = new JSONObject(Files.readString(Paths.get(symbFolder + "/classes.json")));
	}

	private void loadJson(String jsPath) throws JSONException, IOException {
		scriptJs = new JSONObject(Files.readString(Paths.get(jsPath)));
		long baseOffset = gs.getCurrentProgram().getImageBase().getOffset();

		scriptJs.getJSONArray("ScriptMethod").forEach(item -> {
			JSONObject tmpJs = (JSONObject) item;
			// this.gs.println(tmpJs + "");
			if (tmpJs.has("Image") && tmpJs.get("Image") instanceof String) {
				String tmpStr = tmpJs.getString("Image");
				if (tmpStr.equals("Assembly-CSharp-firstpass.dll") || tmpStr.equals("Assembly-CSharp.dll")) {
					myMethodAddresses.add(tmpJs.getLong("Address") + baseOffset);
				}
				methodAddresses.put((tmpJs.getLong("Address") + baseOffset), tmpJs);
			}
		});
		gs.println("[*] myMethodAddresses len:" + myMethodAddresses.size());
	}

	private void loadCS(String csPath) throws JSONException, IOException {
		String cs = Files.readString(Paths.get(csPath));

		getProductReceiptOffsets(cs);

		findPurchaseFunctions(cs);

		for (String str : purchaseFunctionNames) {
			this.gs.println("purchaseFunctionNames:" + str);
		}
	}

	private void getProductReceiptOffsets(String cs) {

		String tmp = cs.split("Namespace: UnityEngine.Purchasing\npublic class PurchaseEventArgs ")[1];
		tmp = tmp.split(" Product <purchasedProduct>")[1].split("\n")[0].split("//")[1].strip();
		productOffset = Integer.decode(tmp);

		tmp = cs.split("Namespace: UnityEngine.Purchasing\npublic class Product ")[1];
		tmp = tmp.split(" string <receipt>")[1].split("\n")[0].split("//")[1].strip();
		receiptOffset = Integer.decode(tmp);

		this.gs.println("" + productOffset + ":" + receiptOffset);

	}

	private ArrayList<String> findPurchaseFunctions(String cs) {

		String nameSpaceMark = "// Namespace:";
		String nameSpace = "";
		String className = "";
		boolean interested = false;
		String[] tmpsps;
		String tmps;
		// int count = 0;
		for (String str : cs.split("\n")) {
			// this.gs.println("str:" + str);
			// count ++;
			// if(count>100)break;

			if (str.startsWith(nameSpaceMark)) {
				// this.gs.println(str);
				if (str.strip().equals(nameSpaceMark))
					nameSpace = "";
				else
					nameSpace = str.strip().substring(nameSpaceMark.length()).strip();
			} else if (str.contains("// TypeDefIndex:")) {
				// this.gs.println(str);
				tmpsps = str.split(":")[0].split(" ");
				className = tmpsps[tmpsps.length - 1];
				interested = true;
			} else if (str.startsWith("}")) {
				interested = false;
			} else if (str.strip().startsWith("public PurchaseProcessingResult ProcessPurchase(PurchaseEventArgs ")) {

				if (interested) {
					if (nameSpace.length() > 0)
						tmps = nameSpace + "." + className;
					else
						tmps = className;
					purchaseFunctionNames.add(tmps + "$$ProcessPurchase");
					this.gs.println(tmps);
				}
			}

		}
		return purchaseFunctionNames;
	}

	public ArrayList<String> getCustomizedPurchaseFunctionNames() {
		ArrayList<String> customizedPurchaseFunctionNames = new ArrayList<String>();

		for (String str : purchaseFunctionNames) {
			if (!unityBuildinPurchaseFunctionNames.contains(str)) {

				if (!customizedPurchaseFunctionNames.contains(str)) {
					customizedPurchaseFunctionNames.add(str);
				}
			}
		}

		return customizedPurchaseFunctionNames;

	}

	public int getProductOffset() {
		return productOffset;
	}

	public int getReceiptOffset() {
		return receiptOffset;
	}

	public boolean isDeveloperFunction(Address functionAddr) {
		return myMethodAddresses.contains(functionAddr.getOffset());
	}

	/*
	 * { "Image": "Assembly-CSharp.dll", "Address": 19043216, "Name":
	 * "unityInAppPurchase_LS$$ProcessPurchase", "Signature":
	 * "int32_t unityInAppPurchase_LS__ProcessPurchase (unityInAppPurchase_LS_o* __this, UnityEngine_Purchasing_PurchaseEventArgs_o* e, const MethodInfo* method);"
	 * , "TypeSignature": "iiii", "ReturnType": "int32_t", "ScriptParameters": [ {
	 * "Index": 0, "Name": "", "ClassType": "unityInAppPurchase_LS_o*" }, { "Index":
	 * 1, "Name": "", "ClassType": "UnityEngine_Purchasing_PurchaseEventArgs_o*" },
	 * { "Index": 2, "Name": "", "ClassType": "MethodInfo" } ] }
	 */
	public String getFunctionParameterType(long address, int parameterIndex) {
		if (methodAddresses.containsKey(address)) {
			JSONObject method = methodAddresses.get(address);
			JSONObject param;

			for (Object obj : method.getJSONArray("ScriptParameters")) {
				param = (JSONObject) obj;
				if (param.getInt("Index") == parameterIndex)
					return param.getString("ClassType");
			}
		}

		return null;
	}

	public String getFunctionReturnType(long address) {
		if (methodAddresses.containsKey(address)) {
			JSONObject method = methodAddresses.get(address);
			return method.getString("ReturnType");

		}
		return null;
	}

	public String getFieldType(FieldResolutionReport report) {
		JSONObject jsObj;
		JSONObject jsObjSub;
		String tname;
		for (Object obj : csharpClasses.getJSONArray("ScriptClassess")) {
			jsObj = (JSONObject) obj;

			if (!jsObj.has("Il2cppName")) {
				if (jsObj.getString("NameSpace").length() > 0)
					tname = jsObj.getString("NameSpace") + "." + jsObj.getString("Name");
				else
					tname = jsObj.getString("Name");
				tname = tname.replace(".", "_") + "_o*";
				jsObj.put("Il2cppName", tname);
			}
			tname = jsObj.getString("Il2cppName");

			if (tname.equals(report.hostClass)) {
				for (Object tobj : jsObj.getJSONArray("ScriptFields")) {
					jsObjSub = (JSONObject) tobj;
					if (jsObjSub.getInt("Offset") == report.offset)
						return jsObjSub.getString("Class") + "_o*";
				}
			}
		}
		return null;
	}
	

	public boolean addNewClassFeild(FieldResolutionReport report) {
		String sig = report.hostClass + ":" + report.offset;
		if(taintedClassFeild.contains(sig)) {
			return false;
		}
		taintedClassFeild.add(sig);
		return true;
	}

	public static void main(String[] args) throws JSONException, IOException {
		FieldResolutionReport subReport = new FieldResolutionReport();
		subReport.hostClass = "MyPurchase_o*";
		subReport.offset = 24;
		GCT gct = GCT.getInstance();
		gct.initialzeSymbols(null, "/tmp/il2cppdumper/");
		System.out.println(gct.getFieldType(subReport));
	}
}
