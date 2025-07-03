# -*- coding: utf-8 -*-
"""
Classe de Registradores MIPS para o simulador GUI.
- Exibe todos os 32 registradores sempre
- Mantém compatibilidade com o datapath
- Suporta acesso por nome ou número
"""

class MIPS_Registers:
    def __init__(self):
        self.reg_map = {
            0: "$zero", 1: "$at", 2: "$v0", 3: "$v1",
            4: "$a0", 5: "$a1", 6: "$a2", 7: "$a3",
            8: "$t0", 9: "$t1", 10: "$t2", 11: "$t3",
            12: "$t4", 13: "$t5", 14: "$t6", 15: "$t7",
            16: "$s0", 17: "$s1", 18: "$s2", 19: "$s3",
            20: "$s4", 21: "$s5", 22: "$s6", 23: "$s7",
            24: "$t8", 25: "$t9", 26: "$k0", 27: "$k1",
            28: "$gp", 29: "$sp", 30: "$fp", 31: "$ra"
        }
        self.registers = {num: 0 for num in range(32)}
        self.registers[29] = 0x10000000  # $sp

    def get_register(self, reg):
        if isinstance(reg, str):
            reg = next((num for num, name in self.reg_map.items() if name == reg), None)
            if reg is None:
                raise ValueError(f"Registrador inválido: {reg}")
        return self.registers.get(reg, 0)

    def set_register(self, reg, value):
        if isinstance(reg, str):
            reg = next((num for num, name in self.reg_map.items() if name == reg), None)
            if reg is None:
                raise ValueError(f"Registrador inválido: {reg}")
        if reg == 0:
            return
        self.registers[reg] = value & 0xFFFFFFFF

    def get_all_registers(self):
        return [
            (self.reg_map[num], f"0x{self.registers[num]:08X}") 
            for num in sorted(self.registers.keys())
        ]

    def __str__(self):
        return "\n".join([f"{name}: {hex(val)}" for name, val in self.get_all_registers()])

    def reset(self):
        self.registers = {num: 0 for num in range(32)}
        self.registers[29] = 0x10000000

if __name__ == "__main__":
    regs = MIPS_Registers()
    print("=== Estado Inicial dos Registradores ===")
    print(regs)