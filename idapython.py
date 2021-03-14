#!/usr/bin/env python
# coding=utf-8
import idc
import idaapi
import idautils

dangerous_functions = [
    "strcpy", 
    "strcat",  
    "sprintf",
    "read", 
    "getenv"    
]

attention_functions = [
    "memcpy",
    "strncpy",
    "sscanf", 
    "strncat", 
    "snprintf",
    "vprintf", 
    "printf"
]

command_execution_functions = [
    "system", 
    "execve",
    "popen",
    "unlink"
]

print("\n")
for func in idautils.Functions():
    flags = idc.get_func_attr(func, FUNCATTR_FLAGS)
    if flags & FUNC_LIB or flags & FUNC_THUNK:
        continue
    dism_addr = list(idautils.FuncItems(func))
    for line in dism_addr:
        m = idc.print_insn_mnem(line)
        if m == 'call' or m == 'jmp':
            op = idc.print_operand(line, 0)
            for cnt in range(len(dangerous_functions)):
                if dangerous_functions[cnt] in op[-9:] and len(op) < 10:
                    print("dangerous_functions:\n0x%x %s\n" % (line, idc.generate_disasm_line(line, 0)))
            for cnt in range(len(attention_functions)):
                if attention_functions[cnt] in op[-9:] and len(op) < 10:
                    print("attention_functions:\n0x%x %s\n" % (line, idc.generate_disasm_line(line, 0)))
            for cnt in range(len(command_execution_functions)):
                if command_execution_functions[cnt] in op[-9:] and len(op) < 10:
                    print("command_execution_functions:\n0x%x %s\n" % (line, idc.generate_disasm_line(line, 0)))
