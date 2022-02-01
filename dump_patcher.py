from lief import PE
import lief
import json
from keystone import *
import sys


def get_f(binary, lib, name):
    for imp in binary.imports:
        if imp.name == lib:
            print(lib, name)
            return imp.get_entry(name).iat_value
    return 0


def add_imports(binary, imports):
    data = list()
    for import_ in imports:
        data.append({import_["original_module"]: import_["original_name"]})

    data = [dict(t) for t in {tuple(d.items()) for d in data}]
    for import_ in data:
        for lib, function in import_.items():
            try:
                binary.add_import_function(lib, function)
            except:
                binary.add_library(lib)
                binary.add_import_function(lib, function)
    return binary


binary = lief.parse(sys.argv[1])
binary.remove_all_libraries()

binary.optional_header.dll_characteristics &= ~lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE

ks = Ks(KS_ARCH_X86, KS_MODE_64)
imports = json.load(open("functions.json"))
binary = add_imports(binary, imports)
for _import in imports:

    f_address = binary.predict_function_rva(_import["original_module"], _import["original_name"])\
                + binary.optional_header.imagebase
    asm = "%s [%s]" % (_import["type"], hex(f_address))
    print(asm)
    encoding, count = ks.asm(asm, binary.optional_header.imagebase+_import["call"]) #
    print(encoding)
    binary.patch_address(_import["call"], encoding, lief.Binary.VA_TYPES.RVA)


builder = lief.PE.Builder(binary)
builder.build_imports(True)
# builder.build_relocations(True)
builder.build()
builder.write("fix.exe")
