# -*- coding: utf-8 -*-
"""
Assembler MIPS integrado ao simulador GUI.
- Converte assembly diretamente para instruções binárias (sem arquivo .bin intermediário).
- Suporta as instruções do seu projeto.
"""

# Mapeamento de registradores e instruções (igual ao anterior)
REGISTERS = {
    "$zero": 0, "$at": 1, "$v0": 2, "$v1": 3,
    "$a0": 4, "$a1": 5, "$a2": 6, "$a3": 7,
    "$t0": 8, "$t1": 9, "$t2": 10, "$t3": 11,
    "$t4": 12, "$t5": 13, "$t6": 14, "$t7": 15,
    "$s0": 16, "$s1": 17, "$s2": 18, "$s3": 19,
    "$s4": 20, "$s5": 21, "$s6": 22, "$s7": 23,
    "$t8": 24, "$t9": 25, "$k0": 26, "$k1": 27,
    "$gp": 28, "$sp": 29, "$fp": 30, "$ra": 31
}

INSTRUCTIONS = {
    # Tipo R (opcode 0x00)
    "add": {"type": "R", "opcode": 0x00, "funct": 0x20},
    "sub": {"type": "R", "opcode": 0x00, "funct": 0x22},
    "and": {"type": "R", "opcode": 0x00, "funct": 0x24},
    "or": {"type": "R", "opcode": 0x00, "funct": 0x25},
    "sll": {"type": "R", "opcode": 0x00, "funct": 0x00},
    "mult": {"type": "R", "opcode": 0x00, "funct": 0x18},
    "slt": {"type": "R", "opcode": 0x00, "funct": 0x2A},
    # Tipo I
    "addi": {"type": "I", "opcode": 0x08},
    "slti": {"type": "I", "opcode": 0x0A},
    "lui": {"type": "I", "opcode": 0x0F},
    "lw": {"type": "I", "opcode": 0x23},
    "sw": {"type": "I", "opcode": 0x2B},
    # Syscalls
    "IMPRIMIR INTEIRO": {"type": "S", "opcode": 0x00, "funct": 0x01},
    "IMPRIMIR STRING": {"type": "S", "opcode": 0x00, "funct": 0x04},
    "SAIR": {"type": "S", "opcode": 0x00, "funct": 0x0A}
}

def assemble_instruction(line):
    """Converte UMA linha de assembly para binário (32 bits). Retorna None se for linha vazia/comentário."""
    line = line.strip().split('#')[0]  # Remove comentários
    if not line:
        return None

    parts = [p.strip() for p in line.replace(",", " ").split()]
    op = parts[0]
    
    if op not in INSTRUCTIONS:
        raise ValueError(f"Instrução não suportada: {op}")

    instr_info = INSTRUCTIONS[op]
    binary = 0

    # Tipo R: add, sub, and, or, sll, mult, slt
    if instr_info["type"] == "R":
        rd, rs, rt = parts[1], parts[2], parts[3]
        shamt = 0 if op != "sll" else int(parts[4])  # shamt só é usado em sll
        binary = (instr_info["opcode"] << 26) | (REGISTERS[rs] << 21) | (REGISTERS[rt] << 16) | (REGISTERS[rd] << 11) | (shamt << 6) | instr_info["funct"]

    # Tipo I: addi, slti, lui, lw, sw
    elif instr_info["type"] == "I":
        rt = parts[1]
        if op in ["lw", "sw"]:  # Formato: op rt, offset(rs)
            offset_rs = parts[2]
            offset, rs = offset_rs.split("(")
            rs = rs.replace(")", "")
            imm = int(offset)
        else:  # Formato: op rt, rs, immediate
            rs, imm = parts[2], int(parts[3])
        binary = (instr_info["opcode"] << 26) | (REGISTERS[rs] << 21) | (REGISTERS[rt] << 16) | (imm & 0xFFFF)

    # Syscall (IMPRIMIR INTEIRO, IMPRIMIR STRING, SAIR)
    elif instr_info["type"] == "S":
        binary = 0x0000000C  # Código de syscall

    return binary

def assemble_program(asm_code):
    """
    Converte um programa assembly (string) para uma lista de instruções binárias.
    - asm_code: String contendo o código assembly (uma instrução por linha).
    - Retorna: Lista de inteiros (instruções em binário) ou None em caso de erro.
    """
    binary_instructions = []
    for line in asm_code.split('\n'):
        try:
            binary = assemble_instruction(line)
            if binary is not None:
                binary_instructions.append(binary)
        except Exception as e:
            print(f"Erro na linha '{line}': {str(e)}")
            return None
    return binary_instructions

def assemble_file(input_path):
    """
    Lê um arquivo .asm e retorna as instruções binárias.
    - input_path: Caminho do arquivo .asm.
    - Retorna: Lista de instruções binárias ou None se falhar.
    """
    try:
        with open(input_path, 'r') as f:
            asm_code = f.read()
        return assemble_program(asm_code)
    except Exception as e:
        print(f"Erro ao ler arquivo: {str(e)}")
        return None