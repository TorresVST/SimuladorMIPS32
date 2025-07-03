import sys
from tkinter import messagebox

# ===================== TABELAS DE DADOS =====================
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
    # Tipo R
    "add":  {"type": "R", "opcode": 0x00, "funct": 0x20},
    "sub":  {"type": "R", "opcode": 0x00, "funct": 0x22},
    "and":  {"type": "R", "opcode": 0x00, "funct": 0x24},
    "or":   {"type": "R", "opcode": 0x00, "funct": 0x25},
    "sll":  {"type": "R", "opcode": 0x00, "funct": 0x00},
    "mult": {"type": "R", "opcode": 0x00, "funct": 0x18, "format": "rs,rt"},
    "slt":  {"type": "R", "opcode": 0x00, "funct": 0x2A},
    
    # Tipo I
    "addi": {"type": "I", "opcode": 0x08},
    "slti": {"type": "I", "opcode": 0x0A},
    "lui":  {"type": "I", "opcode": 0x0F},
    "ori":  {"type": "I", "opcode": 0x0D},
    "lw":   {"type": "I", "opcode": 0x23},
    "sw":   {"type": "I", "opcode": 0x2B},
    
    # Pseudo-instruções e syscall
    "li":      {"type": "P", "opcode": None},
    "syscall": {"type": "S", "opcode": 0x00, "funct": 0x0C},
    "move":    {"type": "P", "opcode": None}
}

DATA_DIRECTIVES = ['.asciiz', '.word', '.byte', '.space']

# ===================== FUNÇÕES AUXILIARES =====================
def parse_immediate(value_str):
    """Converte valores imediatos para inteiro com sinal"""
    try:
        if isinstance(value_str, int):
            return value_str
        
        value_str = str(value_str).lower().replace("_", "")
        
        if value_str.startswith(('0x', '0X')):
            val = int(value_str, 16)
        elif value_str.startswith(('0b', '0B')):
            val = int(value_str, 2)
        else:
            val = int(value_str)
        
        return ((val + 0x8000) & 0xFFFF) - 0x8000
        
    except ValueError:
        raise ValueError(f"Valor imediato inválido: '{value_str}'")

def normalize_instruction(op):
    """Padroniza o nome da instrução e trata aliases"""
    op = op.lower().strip()
    aliases = {
        "imprimir": "li $v0, 1",
        "sair": "li $v0, 10\nsyscall",
        "print": "li $v0, 1",
        "exit": "li $v0, 10\nsyscall"
    }
    return aliases.get(op, op)

def parse_data_directive(line, data_section):
    """Processa diretivas de dados (.asciiz, .word, etc.)"""
    parts = [p.strip() for p in line.split(maxsplit=1)]
    if len(parts) < 2:
        raise ValueError("Diretiva de dados incompleta")
    
    label, rest = parts[0], parts[1]
    if ':' not in label:
        raise ValueError("Formato inválido para rótulo de dados")
    
    label = label.replace(':', '')
    
    if rest.startswith('.asciiz'):
        string = rest.split('.asciiz')[1].strip().strip('"')
        data_section[label] = {'type': 'asciiz', 'value': string}
    elif rest.startswith('.word'):
        values = [parse_immediate(v.strip()) for v in rest.split('.word')[1].split(',')]
        data_section[label] = {'type': 'word', 'values': values}
    else:
        raise ValueError(f"Diretiva de dados não suportada: {rest.split()[0]}")
    
    return data_section

# ===================== FUNÇÃO PRINCIPAL =====================
def parse_instruction(line):
    """Converte uma linha de assembly para código binário"""
    original_line = line
    line = line.split('#')[0].strip()
    if not line:
        return None

    parts = [p.strip() for p in line.replace(",", " ").split()]
    if not parts:
        return None

    op = normalize_instruction(parts[0])
    if '\n' in op:
        return [parse_instruction(l) for l in op.split('\n') if l.strip()]

    if op not in INSTRUCTIONS:
        suggestions = [i for i in INSTRUCTIONS if i.startswith(op[:2])]
        suggestion_msg = f" Talvez você quis dizer: {suggestions[0]}" if suggestions else ""
        raise ValueError(f"Instrução não suportada: '{parts[0]}'.{suggestion_msg}")

    instr_info = INSTRUCTIONS[op]

    # Tipo R (add, sub, mult, etc.)
    if instr_info["type"] == "R":
        # Instruções especiais (mult, div, etc.)
        if op in ["mult", "multu"]:
            if len(parts) != 3:
                raise ValueError(f"Formato inválido para {op}. Esperado: {op} rs, rt")
            
            try:
                rs, rt = parts[1], parts[2]
                return (0x00 << 26 |
                        REGISTERS[rs] << 21 |
                        REGISTERS[rt] << 16 |
                        0 << 11 |  # rd não usado
                        0 << 6 |   # shamt não usado
                        instr_info["funct"])
            except KeyError as e:
                raise ValueError(f"Registrador inválido: {str(e)}")

        # Instruções R padrão (add, sub, etc.)
        elif len(parts) != 4 and not (op == "sll" and len(parts) == 5):
            raise ValueError(f"Formato inválido para {op}. Esperado: {op} rd, rs, rt" + 
                           (" ou sll rd, rt, shamt" if op == "sll" else ""))

        try:
            if op == "sll":
                rd, rt, shamt = parts[1], parts[2], parse_immediate(parts[3])
                return (0x00 << 26 |
                        REGISTERS["$zero"] << 21 |
                        REGISTERS[rt] << 16 |
                        REGISTERS[rd] << 11 |
                        (shamt & 0x1F) << 6 |
                        instr_info["funct"])
            else:
                rd, rs, rt = parts[1], parts[2], parts[3]
                return (0x00 << 26 |
                        REGISTERS[rs] << 21 |
                        REGISTERS[rt] << 16 |
                        REGISTERS[rd] << 11 |
                        0 << 6 |
                        instr_info["funct"])
        except KeyError as e:
            raise ValueError(f"Registrador inválido: {str(e)}")
        except ValueError as e:
            raise ValueError(str(e))

    # Tipo I (addi, lw, sw, lui, etc.)
    elif instr_info["type"] == "I":
        if op == "lui":
            if len(parts) != 3:
                raise ValueError("Formato inválido para lui. Use: lui rt, immediate")
            
            try:
                rt = parts[1]
                imm = parse_immediate(parts[2])
                if not (0 <= imm <= 0xFFFF):
                    raise ValueError
                return (0x0F << 26) | (REGISTERS[rt] << 16) | (imm & 0xFFFF)
            except:
                raise ValueError("Valor imediato inválido em lui. Range: 0-65535")

        elif op in ["lw", "sw"]:
            if len(parts) != 3 or '(' not in parts[2] or not parts[2].endswith(')'):
                raise ValueError(f"Formato inválido para {op}. Use: {op} rt, offset(base)")
            
            rt, mem_part = parts[1], parts[2]
            offset_str, base = mem_part.split('(')
            base = base[:-1]  # Remove ')'
            
            try:
                offset = parse_immediate(offset_str)
                return (instr_info["opcode"] << 26 |
                        REGISTERS[base] << 21 |
                        REGISTERS[rt] << 16 |
                        (offset & 0xFFFF))
            except Exception as e:
                raise ValueError(f"Erro em {op}: {str(e)}")

        else:  # addi, slti, ori
            if len(parts) != 4:
                raise ValueError(f"Formato inválido para {op}. Use: {op} rt, rs, immediate")
            
            try:
                rt, rs, imm = parts[1], parts[2], parse_immediate(parts[3])
                return (instr_info["opcode"] << 26 |
                        REGISTERS[rs] << 21 |
                        REGISTERS[rt] << 16 |
                        (imm & 0xFFFF))
            except Exception as e:
                raise ValueError(f"Erro em {op}: {str(e)}")

    # Pseudo-instruções
    elif instr_info["type"] == "P":
        if op == "li":
            if len(parts) != 3:
                raise ValueError("Formato inválido para li. Use: li rt, immediate")
            
            rt = parts[1]
            imm = parse_immediate(parts[2])
            upper = (imm >> 16) & 0xFFFF
            lower = imm & 0xFFFF
            
            instructions = []
            if upper != 0:
                instructions.append((0x0F << 26) | (REGISTERS[rt] << 16) | upper)
            if lower != 0:
                instructions.append((0x0D << 26) | (REGISTERS[rt] << 21) | (REGISTERS[rt] << 16) | lower)
            return instructions or [(0x0F << 26) | (REGISTERS[rt] << 16)]
            
        elif op == "move":
            if len(parts) != 3:
                raise ValueError("Formato inválido para move. Use: move rd, rs")
            return (0x00 << 26 |
                    REGISTERS[parts[2]] << 21 |
                    REGISTERS["$zero"] << 16 |
                    REGISTERS[parts[1]] << 11 |
                    0x20)

    # Syscall
    elif instr_info["type"] == "S":
        return 0x0000000C


def assemble_file(filepath):
    """Monta um arquivo .asm para código binário e dados"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip()]
        
        binary_instructions = []
        data_section = {}
        current_section = None
        
        for line_num, line in enumerate(lines, 1):
            try:
                # Remove comentários
                line = line.split('#')[0].strip()
                if not line:
                    continue
                
                # Verifica se é uma diretiva de seção
                if line.startswith('.'):
                    section = line.lower()
                    if section in ['.text', '.main']:
                        current_section = '.text'
                    elif section == '.data':
                        current_section = '.data'
                    continue
                
                # Verifica se é um rótulo (termina com :)
                if line.endswith(':'):
                    continue  # Ignora rótulos, apenas processa instruções
                
                # Processa de acordo com a seção atual
                if current_section == '.text':
                    binary = parse_instruction(line)
                    if binary is None:
                        continue
                        
                    if isinstance(binary, list):
                        binary_instructions.extend(binary)
                    else:
                        binary_instructions.append(binary)
                
                elif current_section == '.data':
                    if any(line.startswith(d) for d in DATA_DIRECTIVES):
                        data_section = parse_data_directive(line, data_section)
                    elif ':' in line:
                        label = line.split(':')[0].strip()
                        data_section[label] = {'type': 'raw', 'value': line.split(':')[1].strip()}
                    
            except ValueError as e:
                raise ValueError(f"Linha {line_num}: {str(e)}\n>>> {line}")
        
        if not binary_instructions and current_section != '.data':
            raise ValueError("Arquivo vazio ou sem instruções válidas na seção .text/.main")
        
        return {
            'instructions': binary_instructions,
            'data': data_section
        }
        
    except FileNotFoundError:
        raise ValueError(f"Arquivo não encontrado: {filepath}")
    except Exception as e:
        raise ValueError(f"Erro durante a montagem: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python assembler.py arquivo.asm")
        sys.exit(1)
    
    try:
        result = assemble_file(sys.argv[1])
        print("Montagem bem-sucedida!")
        print("\nInstruções:")
        for i, instr in enumerate(result['instructions']):
            print(f"{i*4:04X}: {instr:08X}  {instr:032b}")
        
        print("\nSeção de dados:")
        for label, data in result['data'].items():
            print(f"{label}: {data}")
            
    except ValueError as e:
        print(f"ERRO: {str(e)}", file=sys.stderr)
        sys.exit(1)