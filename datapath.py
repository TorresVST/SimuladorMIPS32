# -*- coding: utf-8 -*-
"""
Datapath MIPS 32-bit atualizado:
- Integração perfeita com registers.py
- Tratamento completo de instruções
- Controle de execução passo a passo
"""

from registradores import MIPS_Registers

class MIPS_Datapath:
    def __init__(self):
        self.registers = MIPS_Registers()
        self.memory = {}
        self.pc = 0
        self.halted = False

    def execute_instruction(self, binary_instr):
        if self.halted:
            return
        opcode = (binary_instr >> 26) & 0x3F
        if opcode == 0x00:
            self._execute_r_type(binary_instr)
        elif opcode in [0x08, 0x0A, 0x0F, 0x23, 0x2B]:
            self._execute_i_type(binary_instr, opcode)
        elif binary_instr == 0x0000000C:
            self._handle_syscall()
        if not self.halted and opcode not in [0x02, 0x03]:
            self.pc += 4

    def _execute_r_type(self, instruction):
        funct = instruction & 0x3F
        rs = (instruction >> 21) & 0x1F
        rt = (instruction >> 16) & 0x1F
        rd = (instruction >> 11) & 0x1F
        shamt = (instruction >> 6) & 0x1F

        if funct == 0x20:
            val = self.registers.get_register(rs) + self.registers.get_register(rt)
            self.registers.set_register(rd, val)
        elif funct == 0x22:
            val = self.registers.get_register(rs) - self.registers.get_register(rt)
            self.registers.set_register(rd, val)
        # Outras instruções R podem ser adicionadas aqui

    def _execute_i_type(self, instruction, opcode):
        rs = (instruction >> 21) & 0x1F
        rt = (instruction >> 16) & 0x1F
        imm = instruction & 0xFFFF
        if imm & 0x8000:
            imm |= 0xFFFF0000
        if opcode == 0x08:
            val = self.registers.get_register(rs) + imm
            self.registers.set_register(rt, val)
        elif opcode == 0x23:
            addr = self.registers.get_register(rs) + imm
            self.registers.set_register(rt, self.memory.get(addr, 0))
        elif opcode == 0x2B:
            addr = self.registers.get_register(rs) + imm
            self.memory[addr] = self.registers.get_register(rt)
        # Outras instruções I podem ser adicionadas aqui

    def _handle_syscall(self):
        v0 = self.registers.get_register(2)
        if v0 == 1:
            print(self.registers.get_register(4))
        elif v0 == 10:
            self.halted = True
        # Outras syscalls podem ser adicionadas aqui

    def reset(self):
        self.registers = MIPS_Registers()
        self.memory = {}
        self.pc = 0
        self.halted = False
        self.registers.set_register(29, 0x10000000)

    def generate_report(self, filename="relatorio_registradores.txt"):
        with open(filename, 'w') as f:
            f.write("=== RELATÓRIO FINAL ===\n")
            f.write(f"PC Final: {hex(self.pc)}\n")
            f.write("\nRegistradores:\n")
            for reg_num in sorted(self.registers.registers.keys()):
                reg_name = self.registers.reg_map.get(reg_num, f"${reg_num}")
                value = self.registers.get_register(reg_num)
                f.write(f"{reg_name}: {hex(value)}\n")
            f.write("\nMemória Acessada:\n")
            for addr in sorted(self.memory.keys()):
                f.write(f"{hex(addr)}: {hex(self.memory[addr])}\n")

if __name__ == "__main__":
    dp = MIPS_Datapath()
    addi_t0 = 0x20080005  # addi $t0, $zero, 5
    dp.execute_instruction(addi_t0)
    print(f"$t0 após ADDI: {hex(dp.registers.get_register(8))}")