
import subprocess
import io, sys, os

ghidra_path = None
options_script = None
il2cpp_script = None
analysis_script = None

def setup(tool_folder, script_option, script_il2cpp, script_analysis):
    global ghidra_path, options_script, il2cpp_script, analysis_script
    ghidra_path = "%s/ghidra_10.0.3_PUBLIC/support/analyzeHeadless" % tool_folder
    options_script = script_option
    il2cpp_script = script_il2cpp
    analysis_script = script_analysis


def analysis(ghidra_proj_folder, ghidra_proj_name, so_file, symbol_path, pn):

    command =   [ghidra_path, ghidra_proj_folder, ghidra_proj_name, 
                    "-import", so_file, 
                    "-preScript", options_script, 
                    "-preScript", il2cpp_script, "%s/script.json" % symbol_path, 
                    "-postScript", analysis_script, pn, symbol_path,
                    "-log", "%s/%s.log.txt" % (ghidra_proj_folder, pn), 
                    #"-deleteProject"
                ]

    result = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in io.TextIOWrapper(result.stdout, encoding="utf-8"):
        print(line.strip())

def analysisExist(ghidra_proj_folder, ghidra_proj_name, symbol_path, pn):

    command =   [ghidra_path, ghidra_proj_folder, ghidra_proj_name, 
                    "-process", 
                    "-postScript", analysis_script, pn, symbol_path,
                    "-log", "%s/%s.log.txt" % (ghidra_proj_folder, pn), 
                    "-noanalysis",
                    #"-readOnly"
                ]

    result = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in io.TextIOWrapper(result.stdout, encoding="utf-8"):
        print(line.strip())