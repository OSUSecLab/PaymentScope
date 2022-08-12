#!/usr/bin/env python3

import os
import sys 
from os.path import abspath, dirname 
sys.path.insert(0, dirname(abspath(__file__)))

import il2cppdumperHelper as i2c
import ghidraHelper as ghidra
import argparse
import sys
import json

SCRIPT_SETOPTIONS = "PaymentAnalysisSetOptions"
SCRIPT_IL2CPPSYMBOL = "IL2CPPDumper.py"
SCRIPT_PAYMENTSCOPE = "TaintAnalysisPayment"

def setup(tool_folder):
    i2c.setup(tool_folder)
    ghidra.setup(tool_folder, SCRIPT_SETOPTIONS, SCRIPT_IL2CPPSYMBOL, SCRIPT_PAYMENTSCOPE)

def dumpSymbols(target_so_folder, target_symbol_folder, apk_path, prefix):
    target_so_path, target_mt_path = i2c.extractSoMetadata(apk_path, target_so_folder, prefix)

    if None in [target_so_path, target_mt_path]:
        return None, None

    dumped = i2c.extractSymbols(target_so_path, target_mt_path, target_symbol_folder)
    if not dumped:
        return None, None
    
    return target_so_path, target_mt_path

def run(pn, apk_path, target_folder):

    target_so_path, target_mt_path = dumpSymbols(target_folder, target_folder, apk_path, pn)
    if None in [target_so_path, target_mt_path]:
        print("[-] symbol dumper error, libil2cpp.so not found or the files are protected (e.g., encrypted)")
        return None, None
    
    if not os.path.exists("%s/DummyDll/UnityEngine.Purchasing.dll" % (target_folder)):
        print("[-] the app does not have Unity IAP")
        return None, None

    ghidra_proj_folder = "%s/ghidra" % target_folder
    ghidra_proj_name = pn
    os.mkdir(ghidra_proj_folder)

    ghidra.analysis(ghidra_proj_folder, ghidra_proj_name, target_so_path, target_folder, pn)

def runOnCacheProject(pn, target_folder):
    ghidra_proj_folder = "%s/ghidra" % target_folder
    ghidra_proj_name = pn
    ghidra.analysisExist(ghidra_proj_folder, ghidra_proj_name, target_folder, pn)

if __name__ == "__main__":

    with open(os.path.dirname(os.path.abspath(__file__)) +"/config.json") as f:
        tools_folder = json.load(f)["tools_folder"]
        setup(tools_folder)

    parser = argparse.ArgumentParser()
    parser.add_argument('-n','--new_process_mode',  help='The path of the target APK')
    parser.add_argument('-c','--cached_mode',       help='Run the script on an existing output folder (cached)')
    parser.add_argument('-o','--output',            help='The output folder where the project will be store')
    parser.add_argument('-p','--package_name',      help='The package name of the target game')
    args = parser.parse_args()


    if args.new_process_mode and args.cached_mode:
        parser.error("only one of --new_process_mode and --cached_mode can be used")

    if args.new_process_mode is None and args.cached_mode is None:
        parser.error("at least one of --new_process_mode and --cached_mode required")
    
    if args.new_process_mode and args.output is None:
        parser.error("output folder is required in new process mode")

    if args.package_name is None:
        parser.error("package_name is required")
    
    pn = args.package_name
    if args.new_process_mode:
        apk_path = args.new_process_mode
        target_folder = args.output

        if not os.path.exists(target_folder): 
            os.makedirs(target_folder)

        run(pn, apk_path, target_folder)
    else:
        target_folder = args.cached_mode
        runOnCacheProject(pn, target_folder)


