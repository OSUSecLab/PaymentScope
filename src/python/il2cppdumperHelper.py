import zipfile
import shutil
import subprocess

dumper_path = ""
metadata_path = "assets/bin/Data/Managed/Metadata/global-metadata.dat"

def setup(tool_folder):
    global dumper_path
    dumper_path = "%s/Il2CppDumper-Customized/Il2CppDumper.dll" % tool_folder

def extractSoMetadata(apk_path, target_folder, prefix):

    with zipfile.ZipFile(apk_path, 'r') as zip_ref:
        so_path = None
        for i in zip_ref.namelist():
            if(i.startswith("lib/arm64") and i.endswith("/libil2cpp.so")):
                so_path = i
                break

        if so_path == None:
            for i in zip_ref.namelist():
                if(i.startswith("lib/arm") and i.endswith("/libil2cpp.so")):
                    so_path = i
                    break
        
        if so_path == None or metadata_path not in zip_ref.namelist(): return None, None

        target_so_path = "%s/%s_libil2cpp.so" % (target_folder, prefix)
        target_mt_path = "%s/%s_global-metadata.dat" % (target_folder, prefix)

        for memb, target_path in [(so_path, target_so_path), (metadata_path, target_mt_path)]:
            with zip_ref.open(memb) as source, open(target_path, "wb") as target:
                shutil.copyfileobj(source, target)

        return target_so_path, target_mt_path

def extractSymbols(target_so_path, target_mt_path, target_folder):

    completedProc = subprocess.run(["dotnet", dumper_path, target_so_path, target_mt_path, target_folder], input=b"\n\n\n")
    print(completedProc.returncode)

    if completedProc.returncode != 0:
        with open("error_Il2CppDumper.txt",'a+') as f:
            f.write('%s:ret:%s\n' % (target_so_path, completedProc.returncode) )
        return False
    return True


if __name__ == "__main__":
    setup("~/Tools")

    apk_path = "~/Documents/rocketsky.apk"
    target_folder = "~/Documents/rocketsky.apk.out"
    prefix = "my"
    target_so_path, target_mt_path = extractSoMetadata(apk_path, target_folder, prefix)
    extractSymbols(target_so_path, target_mt_path, target_folder)