
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptUtil;

public class TaintRules {
	private TaintRules() {

	}

	static TaintRules taintRules = new TaintRules();

	public static TaintRules getInstance() {
		return taintRules;
	}

	JSONArray rulesJs;

	public void initialze(GhidraScript tgs) throws JSONException, IOException {
		tgs.println("getUserScriptDirectory:" + GhidraScriptUtil.getUserScriptDirectory().getAbsolutePath());
		String rulePath = GhidraScriptUtil.getUserScriptDirectory().getAbsolutePath() + "/rules.json";
		rulesJs = new JSONArray(Files.readString(Paths.get(rulePath)));
	}

	public ArrayList<String> getSources() {
		ArrayList<String> sources = new ArrayList<String>();
		rulesJs.forEach(x -> {
			JSONObject jobj = (JSONObject) x;
			if (jobj.getString("type").equals("source")) {
				sources.add(jobj.getString("function_name"));
			}
		});
		return sources;
	}

	private boolean matchFunctionName(JSONObject jobj, String functionName) {
		if (jobj.has("function_name") && jobj.getString("function_name").equals(functionName)) {
			return true;
		}

		if (jobj.has("function_name_start") && functionName.startsWith(jobj.getString("function_name_start"))) {
			
			if(jobj.has("function_name_end")) {
				
				if(functionName.endsWith(jobj.getString("function_name_end"))) {
					return true;
				}
				
			}else {
				return true;
			}
		}
		return false;
	}
	
	public boolean propagate2End(String functionName) {

		JSONObject jobj;
		for (Object x : rulesJs) {
			jobj = (JSONObject) x;
			if (jobj.getString("type").equals("sink")) {

				if(matchFunctionName(jobj, functionName))
					return true;

			}
		}

		return false;
	}
	
	public boolean propagate2Ret(String functionName) {

		JSONObject jobj;
		for (Object x : rulesJs) {
			jobj = (JSONObject) x;
			if (jobj.getString("type").equals("propagate2return")) {

				if(matchFunctionName(jobj, functionName))
					return true;

			}
		}

		return false;
	}
}
