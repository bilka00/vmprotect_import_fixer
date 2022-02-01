from x64dbgpy import pluginsdk
import capstone
from unicorn import *
from unicorn.x86_const import *
import json


def find_all(start, size, pattern):
    local_start = start
    while True:
        found = pluginsdk.FindMem(local_start, size, pattern)
        local_start = found + 1
        if not (found != 0 and size > 0 and found < start + size):
            break
        yield found


def get_image_size(module_name):
    size = 0
    for section in pluginsdk.SectionListFromName(module_name):
        size += section.size
    return size


def check_address_to_sections(address, module_name, sect):
    for section in pluginsdk.SectionListFromName(module_name):
        if section.name in sect:
            section_end = section.addr + section.size
            if section.addr < address < section_end:
                return True

    return False


class MyGlobals:
    prev_address = 0
    this_address = 0


def hook_code(mu, address, size, user_data):
    MyGlobals.prev_address = MyGlobals.this_address
    MyGlobals.this_address = address


def unic(addr, image_size, next_instruction):
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    stack_addr = 0
    STACK_SIZE = 1024
    base = pluginsdk.GetMainModuleBase()

    mu.mem_map(base, 1024 * 1024 * 1024)  # edit this
    mu.mem_write(base, pluginsdk.Read(pluginsdk.GetMainModuleBase(), image_size))
    mu.mem_map(stack_addr, 1024 * 4)
    mu.reg_write(UC_X86_REG_RSP, stack_addr + (STACK_SIZE / 2))
    original_stack = mu.reg_read(UC_X86_REG_RSP)
    mu.hook_add(UC_HOOK_CODE, hook_code)
    try:
        mu.emu_start(addr, addr + next_instruction)
    except:
        mu.emu_stop()
        # print("0x%0.2X" % MyGlobals.this_address)
        return mu.reg_read(UC_X86_REG_RIP), original_stack-mu.reg_read(UC_X86_REG_RSP), mu.mem_read(MyGlobals.this_address, 1)
    return False, False, False


function_name_cache = dict()


def get_function_name(address):
    if address in function_name_cache.keys():
        return function_name_cache[address]
    for symbol in pluginsdk.symbol.GetList():
        if symbol.type == pluginsdk.symbol.SymbolType.Export:
            function_name_cache[address] = (symbol.mod, symbol.name)
            if address == (symbol.rva + pluginsdk.module.BaseFromName(symbol.mod)):
                return symbol.mod, symbol.name
    return None, None


functions = []


def script_main(target_module, target_section, protector_sections):
    target_module_base = pluginsdk.module.BaseFromName(target_module)
    modules = pluginsdk.module.GetList()
    for module in modules:
        if module.name == target_module:
            for section in pluginsdk.SectionListFromName(module.name):
                if section.name == target_section:
                    all_call = find_all(section.addr, section.size, "E8 ?? ?? ?? ??")
                    for call in all_call:
                        disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                        data = pluginsdk.Read(call, 6)
                        dis = disassembler.disasm(data, call)
                        ints = next(dis)
                        call_addr = int(ints.op_str, 16)

                        if pluginsdk.IsValidPtr(call_addr):
                            if check_address_to_sections(call_addr, target_module, protector_sections):
                                # print("%s: %s %s" % (hex(ints.address), ints.mnemonic, ints.op_str))
                                original, stack_position, ret_mem = unic(call, get_image_size(target_module), ints.size)
                                # newbase = 0x14000000000
                                # print(stack_position, "0x%0.2X 0x%0.2X" %(call, call+newbase-target_module_base))
                                if not original:
                                    print("Error(not work on unicorn): 0x%0.2X" % call)
                                    continue
                                module, name = get_function_name(original)
                                if not name:
                                    print("Error(not find export): 0x%0.2X" % call)
                                    continue
                                print(module, name)

                                type_ = ""

                                if ret_mem == "\xC2":
                                    type_ = "jmp"
                                elif ret_mem == "\xC3":
                                    type_ = "call"
                                else:
                                    print("ERROR", ret_mem)

                                if int(stack_position) == 0:
                                    call -= 1

                                if int(stack_position) == 8:
                                    pass

                                if int(stack_position) == -8:
                                    call -= 2

                                functions.append({"call": call-target_module_base,
                                                  "original_name": name,
                                                  "original_module": module,
                                                  "type": type_})

    with open('functions.json', 'w') as f:
        json.dump(functions, f)

    print("ok")


script_main(
    "helloworld.vmp.exe",
    ".text",
    [".vmp0", ".vmp1"]
)
