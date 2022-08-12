import java.util.Map;

import ghidra.app.script.GhidraScript;

public class PaymentAnalysisSetOptions extends GhidraScript {

	
	public void run() throws Exception {
		
		
		Map<String, String> options = this.getCurrentAnalysisOptionsAndValues(currentProgram);
		
		for(String key :options.keySet()) {
			printf("%s -- %s\n", key, options.get(key));
		}
		
		options.put("ARM Constant Reference Analyzer", "true");
		options.put("Create Address Tables - One Time", "true");
		options.put("Decompiler Switch Analysis", "true");
		options.put("Disassemble", "true");
		options.put("Non-Returning Functions - Discovered", "true");
		options.put("Reference", "true");
		options.put("Disassemble Entry Points", "true");
		options.put("Embedded Media", "true");
		
		
		options.put("ASCII Strings", "true");

		options.put("Non-Returning Functions - Discovered", "false");
		options.put("GCC Exception Handlers", "false");
		
		
		this.setAnalysisOptions(currentProgram, options);
		println("\n\n\nOption setup done!\n Start analyzing\n\n\n");
		
	}

}
