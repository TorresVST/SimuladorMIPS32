import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from datapath import MIPS_Datapath
from assembler import assemble_file
import os
from datetime import datetime

class MIPS_Simulator_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Simulador MIPS")
        self.root.geometry("1000x700")
        
        # Estado do simulador
        self.datapath = MIPS_Datapath()
        self.binary_instructions = []
        self.current_file = None
        self.program_loaded = False
        self.last_reg_values = {}
        self.generating_report = False
        
        # Configuração da interface
        self.setup_ui()
        self.setup_styles()
        self.update_display()
        
    def setup_styles(self):
        """Configura os estilos visuais"""
        style = ttk.Style()
        style.configure("TFrame", background="#f0f0f0")
        style.configure("TLabel", background="#f0f0f0", font=('Consolas', 10))
        style.configure("TButton", font=('Consolas', 10), padding=5)
        style.configure("Status.TLabel", background="#e0e0e0", font=('Consolas', 9))

    def setup_ui(self):
        """Configura todos os componentes da interface"""
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Painel de controle superior
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=5)

        ttk.Button(
            control_frame, 
            text="Carregar Programa",
            command=self.load_program
        ).pack(side=tk.LEFT, padx=5)

        self.step_btn = ttk.Button(
            control_frame,
            text="Executar Passo",
            command=self.execute_step,
            state=tk.DISABLED
        )
        self.step_btn.pack(side=tk.LEFT, padx=5)

        self.run_btn = ttk.Button(
            control_frame,
            text="Executar Tudo",
            command=self.run_all,
            state=tk.DISABLED
        )
        self.run_btn.pack(side=tk.LEFT, padx=5)

        self.reset_btn = ttk.Button(
            control_frame,
            text="Resetar",
            command=self.reset_simulator,
            state=tk.DISABLED
        )
        self.reset_btn.pack(side=tk.LEFT, padx=5)

        ttk.Button(
            control_frame,
            text="Gerar Relatório",
            command=self.generate_report
        ).pack(side=tk.RIGHT, padx=5)

        # Painel de exibição principal
        display_frame = ttk.Frame(main_frame)
        display_frame.pack(fill=tk.BOTH, expand=True)

        # Painel esquerdo (registradores)
        left_frame = ttk.Frame(display_frame, width=300)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5)

        ttk.Label(left_frame, text="Registradores", font=('Consolas', 11, 'bold')).pack(pady=5)
        
        # Container para scrollbar e canvas
        reg_container = ttk.Frame(left_frame)
        reg_container.pack(fill=tk.BOTH, expand=True)
        
        # Canvas e scrollbar
        self.reg_canvas = tk.Canvas(reg_container, bg="white")
        reg_scroll = ttk.Scrollbar(reg_container, orient="vertical", command=self.reg_canvas.yview)
        self.reg_canvas.configure(yscrollcommand=reg_scroll.set)
        
        # Empacotamento
        reg_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.reg_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Frame interno para os registradores
        self.reg_frame = ttk.Frame(self.reg_canvas)
        self.reg_canvas.create_window((0, 0), window=self.reg_frame, anchor="nw")
        
        # Configuração do scroll
        self.reg_frame.bind("<Configure>", lambda e: self.reg_canvas.configure(
            scrollregion=self.reg_canvas.bbox("all"),
            width=e.width  # Ajusta a largura do canvas ao frame interno
        ))

        # Painel direito (instruções e syscalls)
        right_frame = ttk.Frame(display_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Painel de instrução
        instr_frame = ttk.LabelFrame(right_frame, text="Instrução Atual", padding=10)
        instr_frame.pack(fill=tk.X, pady=5)

        self.instr_text = scrolledtext.ScrolledText(
            instr_frame,
            height=5,
            wrap=tk.WORD,
            state=tk.DISABLED,
            font=('Consolas', 10),
            bg="black",
            fg="white"
        )
        self.instr_text.pack(fill=tk.X)

        # Painel de informações de syscall
        syscall_info_frame = ttk.LabelFrame(right_frame, text="Informações de Syscall", padding=10)
        syscall_info_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.syscall_info_text = scrolledtext.ScrolledText(
            syscall_info_frame,
            wrap=tk.WORD,
            state=tk.DISABLED,
            font=('Consolas', 10),
            bg="#222222",
            fg="#FFFFFF"
        )
        self.syscall_info_text.pack(fill=tk.BOTH, expand=True)

        # Painel de saída do sistema
        syscall_frame = ttk.LabelFrame(right_frame, text="Saída do Sistema", padding=10)
        syscall_frame.pack(fill=tk.BOTH, pady=5)

        self.syscall_text = scrolledtext.ScrolledText(
            syscall_frame,
            height=4,
            wrap=tk.WORD,
            state=tk.DISABLED,
            font=('Consolas', 10),
            bg="black",
            fg="white"
        )
        self.syscall_text.pack(fill=tk.BOTH)

        # Barra de status
        self.status_var = tk.StringVar(value="Pronto. Carregue um programa para começar.")
        status_bar = ttk.Label(
            main_frame,
            textvariable=self.status_var,
            style="Status.TLabel",
            relief=tk.SUNKEN
        )
        status_bar.pack(fill=tk.X, pady=(5, 0))

    def load_program(self):
        """Carrega um programa .asm ou .bin"""
        filepath = filedialog.askopenfilename(
            filetypes=[("Assembly MIPS", "*.asm"), ("Binário MIPS", "*.bin")]
        )
        
        if not filepath:
            return

        try:
            self.reset_simulator(full=True)
            
            if filepath.endswith(".asm"):
                result = assemble_file(filepath)
                self.binary_instructions = result['instructions']
                self.load_data_to_memory(result.get('data', {}))
            elif filepath.endswith(".bin"):
                with open(filepath, 'r') as f:
                    self.binary_instructions = [int(line.strip(), 2) for line in f if line.strip()]
            
            self.current_file = os.path.basename(filepath)
            self.program_loaded = True
            self.toggle_controls(True)
            self.status_var.set(f"Programa carregado: {self.current_file}")
            self.update_display()
            
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao carregar arquivo:\n{str(e)}")
            self.reset_simulator(full=True)

    def load_data_to_memory(self, data_section):
        """Carrega dados da seção .data na memória"""
        data_address = 0x10000000  # Endereço base para dados
        
        for label, data in data_section.items():
            if data['type'] == 'asciiz':
                for i, char in enumerate(data['value']):
                    self.datapath.memory[data_address + i] = ord(char)
                self.datapath.memory[data_address + len(data['value'])] = 0  # Null terminator
                data_address += len(data['value']) + 1
                
            elif data['type'] == 'word':
                for value in data['values']:
                    self.datapath.memory[data_address] = value & 0xFFFFFFFF
                    data_address += 4

    def execute_step(self):
        """Executa uma única instrução"""
        if not self.program_loaded or self.datapath.halted or self.generating_report:
            return

        if self.datapath.pc >= len(self.binary_instructions) * 4:
            self.status_var.set("Execução concluída")
            if not self.generating_report:
                self.generating_report = True
                self.generate_report()
                self.generating_report = False
            return

        try:
            # Salva estado anterior dos registradores
            self.last_reg_values = {
                name: self.datapath.registers.get_register(num)
                for num, name in self.datapath.registers.reg_map.items()
            }

            # Executa instrução
            instr_index = self.datapath.pc // 4
            binary_instr = self.binary_instructions[instr_index]
            self.datapath.execute_instruction(binary_instr)

            # Trata syscalls
            if binary_instr == 0x0000000C:  # Syscall
                self.handle_syscall()

            self.update_display()
            self.status_var.set(
                f"Executando PC={hex(self.datapath.pc)} | "
                f"Instrução {instr_index+1}/{len(self.binary_instructions)}"
            )

        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao executar instrução:\n{str(e)}")
            self.reset_simulator(full=False)

    def handle_syscall(self):
        """Processa chamadas de sistema"""
        v0 = self.datapath.registers.get_register("$v0")
        a0 = self.datapath.registers.get_register("$a0")
        a1 = self.datapath.registers.get_register("$a1")

        # Atualiza o painel de informações
        self.syscall_info_text.config(state=tk.NORMAL)
        self.syscall_info_text.delete(1.0, tk.END)
        
        self.syscall_info_text.insert(tk.END, f"Syscall identificado: v0 = {v0}\n", "header")
        self.syscall_info_text.insert(tk.END, f"Parâmetros:\n", "header")
        self.syscall_info_text.insert(tk.END, f"  a0 = {a0} (0x{a0:08X})\n")
        self.syscall_info_text.insert(tk.END, f"  a1 = {a1} (0x{a1:08X})\n\n")

        # Processa a syscall e atualiza a saída
        self.syscall_text.config(state=tk.NORMAL)
        
        if v0 == 1:  # Imprimir inteiro
            self.syscall_info_text.insert(tk.END, "Tipo: print_int\n", "info")
            self.syscall_info_text.insert(tk.END, f"Valor a imprimir: {a0}\n")
            self.syscall_text.insert(tk.END, f"{a0}\n", "output")
            
        elif v0 == 4:  # Imprimir string
            self.syscall_info_text.insert(tk.END, "Tipo: print_string\n", "info")
            addr = a0
            result = ""
            while True:
                char = self.datapath.memory.get(addr, 0)
                if char == 0:
                    break
                result += chr(char)
                addr += 1
            self.syscall_info_text.insert(tk.END, f"Endereço da string: 0x{a0:08X}\n")
            self.syscall_info_text.insert(tk.END, f"Conteúdo: \"{result}\"\n")
            self.syscall_text.insert(tk.END, f"{result}\n", "output")
            
        elif v0 == 10:  # Sair
            self.syscall_info_text.insert(tk.END, "Tipo: exit\n", "info")
            self.syscall_text.insert(tk.END, "Programa encerrado.\n", "output")
            self.datapath.halted = True
            
        else:
            self.syscall_info_text.insert(tk.END, "Tipo: desconhecido\n", "warning")
            self.syscall_text.insert(tk.END, f"Syscall não implementada: {v0}\n", "error")

        # Configura as tags de estilo
        self.syscall_info_text.tag_config("header", foreground="#FF8888", font=('Consolas', 10, 'bold'))
        self.syscall_info_text.tag_config("info", foreground="#88FF88")
        self.syscall_info_text.tag_config("warning", foreground="#FFFF88")
        
        self.syscall_info_text.see(tk.END)
        self.syscall_info_text.config(state=tk.DISABLED)
        self.syscall_text.see(tk.END)
        self.syscall_text.config(state=tk.DISABLED)

    def run_all(self):
        """Executa todas as instruções até encontrar syscall de saída"""
        while (self.program_loaded and 
               not self.datapath.halted and 
               self.datapath.pc < len(self.binary_instructions) * 4):
            
            self.execute_step()
            self.root.update()
            
            if not self.datapath.halted:
                self.root.after(100)
        
        # Gera relatório apenas se o programa terminou naturalmente
        if (self.program_loaded and 
            not self.generating_report and 
            self.datapath.pc >= len(self.binary_instructions) * 4):
            
            self.status_var.set("Execução concluída - Gerando relatório...")
            self.generating_report = True
            self.generate_report()
            self.generating_report = False
            self.status_var.set("Execução concluída")

    def reset_simulator(self, full=False):
        """Reseta o simulador"""
        self.datapath = MIPS_Datapath()
        if full:
            self.binary_instructions = []
            self.current_file = None
            self.program_loaded = False
            self.syscall_text.config(state=tk.NORMAL)
            self.syscall_text.delete(1.0, tk.END)
            self.syscall_text.config(state=tk.DISABLED)
            self.syscall_info_text.config(state=tk.NORMAL)
            self.syscall_info_text.delete(1.0, tk.END)
            self.syscall_info_text.config(state=tk.DISABLED)
            self.status_var.set("Simulador resetado")
        else:
            self.status_var.set(f"Estado resetado | Programa: {self.current_file}")
        
        self.last_reg_values = {}
        self.toggle_controls(self.program_loaded)
        self.update_display()

    def toggle_controls(self, enable):
        """Ativa/desativa botões de controle"""
        state = tk.NORMAL if enable else tk.DISABLED
        self.step_btn.config(state=state)
        self.run_btn.config(state=state)
        self.reset_btn.config(state=state)

    def update_display(self):
        """Atualiza todos os elementos visuais"""
        self.update_instruction_display()
        self.update_registers_display()

    def update_instruction_display(self):
        """Atualiza o painel de instrução"""
        self.instr_text.config(state=tk.NORMAL)
        self.instr_text.delete(1.0, tk.END)
        
        if not self.program_loaded:
            self.instr_text.insert(tk.END, "Nenhum programa carregado", "info")
            self.instr_text.config(state=tk.DISABLED)
            return
        
        if self.datapath.pc >= len(self.binary_instructions) * 4:
            self.instr_text.insert(tk.END, "Execução concluída", "info")
            self.instr_text.config(state=tk.DISABLED)
            return
        
        instr_index = self.datapath.pc // 4
        binary_instr = self.binary_instructions[instr_index]
        
        # Formatação colorida
        self.instr_text.tag_config("address", foreground="#FF5555")
        self.instr_text.tag_config("binary", foreground="#AAAAFF")
        self.instr_text.tag_config("hex", foreground="#55FF55")
        self.instr_text.tag_config("instr", foreground="#FFFFFF")
        
        self.instr_text.insert(tk.END, f"PC: ", "info")
        self.instr_text.insert(tk.END, f"{hex(self.datapath.pc)}\n", "address")
        self.instr_text.insert(tk.END, "Binário: ", "info")
        self.instr_text.insert(tk.END, f"{binary_instr:032b}\n", "binary")
        self.instr_text.insert(tk.END, "Hexa: ", "info")
        self.instr_text.insert(tk.END, f"{binary_instr:08X}\n", "hex")
        
        self.instr_text.config(state=tk.DISABLED)

    def update_registers_display(self):
        """Atualiza a exibição dos registradores com cores"""
        # Limpa o frame anterior
        for widget in self.reg_frame.winfo_children():
            widget.destroy()
        
        if not hasattr(self.datapath, 'registers'):
            return
            
        # Configura tags de estilo
        style = ttk.Style()
        style.configure("Reg.TLabel", font=('Consolas', 10))
        style.configure("Modified.TLabel", font=('Consolas', 10, 'bold'), foreground='blue')
        
        # Organiza os registradores em uma única coluna
        for num, name in sorted(self.datapath.registers.reg_map.items()):
            value = self.datapath.registers.get_register(num)
            is_modified = self.last_reg_values.get(name, None) != value
            
            frame = ttk.Frame(self.reg_frame)
            frame.pack(fill=tk.X, padx=5, pady=1)
            
            ttk.Label(
                frame,
                text=f"{name}:",
                style="Modified.TLabel" if is_modified else "Reg.TLabel",
                width=8
            ).pack(side=tk.LEFT)
            
            ttk.Label(
                frame,
                text=f"0x{value:08X}",
                style="Modified.TLabel" if is_modified else "Reg.TLabel"
            ).pack(side=tk.LEFT)
        
        # Atualiza a região de scroll
        self.reg_canvas.update_idletasks()
        self.reg_canvas.config(scrollregion=self.reg_canvas.bbox("all"))

    def generate_report(self):
        """Gera e exibe um relatório completo"""
        if not self.program_loaded:
            messagebox.showwarning("Aviso", "Nenhum programa carregado para gerar relatório")
            return
            
        report = f"=== Relatório de Execução ===\n"
        report += f"Arquivo: {self.current_file}\n"
        report += f"Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"PC Final: {hex(self.datapath.pc)}\n"
        report += f"Instruções Executadas: {self.datapath.pc // 4}/{len(self.binary_instructions)}\n\n"
        
        report += "=== Estado Final dos Registradores ===\n"
        for num, name in sorted(self.datapath.registers.reg_map.items()):
            value = self.datapath.registers.get_register(num)
            report += f"{name}: 0x{value:08X} ({value})\n"
        
        report += "\n=== Saída do Sistema ===\n"
        report += self.syscall_text.get(1.0, tk.END)
        
        # Exibe em nova janela
        report_window = tk.Toplevel(self.root)
        report_window.title("Relatório de Execução")
        report_window.geometry("800x600")
        
        text_frame = ttk.Frame(report_window)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        text_scroll = ttk.Scrollbar(text_frame)
        text_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        report_text = tk.Text(
            text_frame,
            wrap=tk.WORD,
            yscrollcommand=text_scroll.set,
            font=('Consolas', 10)
        )
        report_text.pack(fill=tk.BOTH, expand=True)
        report_text.insert(tk.END, report)
        report_text.config(state=tk.DISABLED)
        
        text_scroll.config(command=report_text.yview)
        
        # Botões
        btn_frame = ttk.Frame(report_window)
        btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(
            btn_frame,
            text="Salvar Relatório",
            command=lambda: self.save_report(report)
        ).pack(side=tk.LEFT, padx=10)
        
        ttk.Button(
            btn_frame,
            text="Fechar",
            command=report_window.destroy
        ).pack(side=tk.RIGHT, padx=10)

    def save_report(self, report_text):
        """Salva o relatório em arquivo"""
        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Arquivos de Texto", "*.txt"), ("Todos os arquivos", "*.*")]
        )
        
        if filepath:
            try:
                with open(filepath, 'w') as f:
                    f.write(report_text)
                messagebox.showinfo("Sucesso", f"Relatório salvo em:\n{filepath}")
            except Exception as e:
                messagebox.showerror("Erro", f"Falha ao salvar relatório:\n{str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = MIPS_Simulator_GUI(root)
    root.mainloop()
