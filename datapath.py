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
        self.registers = MIPS_Registers()  # Usa a classe de registradores
        self.memory = {}                   # Memória simulada (endereço -> valor)
        self.pc = 0                        # Program Counter
        self.halted = False                # Flag para programa encerrado

    def execute_instruction(self, binary_instr):
        """Executa uma única instrução binária"""
        if self.halted:
            return

        opcode = (binary_instr >> 26) & 0x3F  # Extrai opcode (6 bits)

        # Instruções Tipo R (opcode 0x00)
        if opcode == 0x00:
            self._execute_r_type(binary_instr)
        
        # Instruções Tipo I
        elif opcode in [0x08, 0x0A, 0x0F, 0x23, 0x2B]:  # ADDI, SLTI, LUI, LW, SW
            self._execute_i_type(binary_instr, opcode)
        
        # Syscall
        elif binary_instr == 0x0000000C:
            self._handle_syscall()
        
        # Atualiza PC (exceto para jumps)
        if not self.halted and opcode not in [0x02, 0x03]:  # Não incrementa PC para J/JAL
            self.pc += 4

    def _execute_r_type(self, instruction):
        """Executa instruções tipo R (ADD, SUB, etc.)"""
        funct = instruction & 0x3F       # 6 bits
        rs = (instruction >> 21) & 0x1F  # 5 bits
        rt = (instruction >> 16) & 0x1F  # 5 bits
        rd = (instruction >> 11) & 0x1F  # 5 bits
        shamt = (instruction >> 6) & 0x1F # 5 bits

        if funct == 0x20:   # ADD
            val = self.registers.get_register(rs) + self.registers.get_register(rt)
            self.registers.set_register(rd, val)
        elif funct == 0x22:  # SUB
            val = self.registers.get_register(rs) - self.registers.get_register(rt)
            self.registers.set_register(rd, val)
        # Adicione outras instruções R aqui...

    def _execute_i_type(self, instruction, opcode):
        """Executa instruções tipo I (ADDI, LW, etc.)"""
        rs = (instruction >> 21) & 0x1F
        rt = (instruction >> 16) & 0x1F
        imm = instruction & 0xFFFF

        # Extensão de sinal para imediatos
        if imm & 0x8000:
            imm |= 0xFFFF0000

        if opcode == 0x08:    # ADDI
            val = self.registers.get_register(rs) + imm
            self.registers.set_register(rt, val)
        elif opcode == 0x23:  # LW
            addr = self.registers.get_register(rs) + imm
            self.registers.set_register(rt, self.memory.get(addr, 0))
        elif opcode == 0x2B:  # SW
            addr = self.registers.get_register(rs) + imm
            self.memory[addr] = self.registers.get_register(rt)
        # Adicione outras instruções I aqui...

    def _handle_syscall(self):
        """Trata chamadas de sistema"""
        v0 = self.registers.get_register(2)  # $v0 contém o código

        if v0 == 1:    # Print integer ($a0)
            print(self.registers.get_register(4))
        elif v0 == 10:  # Exit
            self.halted = True
        # Adicione outras syscalls aqui...

    def reset(self):
        """Reset completo do datapath"""
        self.registers = MIPS_Registers()  # Cria nova instância
        self.memory = {}
        self.pc = 0
        self.halted = False
        # Garante valores iniciais corretos
        self.registers.set_register(29, 0x10000000)  # $sp

    def generate_report(self, filename="relatorio_registradores.txt"):
        """Gera um arquivo com o estado final dos registradores"""
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

# Teste rápido
if __name__ == "__main__":
    dp = MIPS_Datapath()
    
    # Teste ADDI
    addi_t0 = 0x20080005  # addi $t0, $zero, 5
    dp.execute_instruction(addi_t0)
    print(f"$t0 após ADDI: {hex(dp.registers.get_register(8))}")  # $t0 = 8
