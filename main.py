import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datapath import MIPS_Datapath
from assembler import assemble_file
import os

class MIPS_Simulator_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Simulador MIPS 32-bit")
        self.root.geometry("800x600")
        
        # Estado do simulador
        self.datapath = MIPS_Datapath()
        self.binary_instructions = []
        self.current_file = None
        self.program_loaded = False
        
        # Configuração da interface
        self.setup_ui()
        self.update_display()
        
        # Configurações de estilo
        self.setup_styles()

    def setup_styles(self):
        """Configura estilos visuais"""
        style = ttk.Style()
        style.configure("TFrame", background="#f0f0f0")
        style.configure("TLabel", background="#f0f0f0", font=('Helvetica', 10))
        style.configure("TButton", font=('Helvetica', 10), padding=5)
        style.configure("Status.TLabel", background="#e0e0e0", font=('Helvetica', 9))

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
            command=self.step,
            state=tk.DISABLED
        )
        self.step_btn.pack(side=tk.LEFT, padx=5)
        
        self.reset_btn = ttk.Button(
            control_frame,
            text="Resetar",
            command=self.reset_simulator,
            state=tk.DISABLED
        )
        self.reset_btn.pack(side=tk.LEFT, padx=5)
        
        # Painel de exibição principal
        display_frame = ttk.Frame(main_frame)
        display_frame.pack(fill=tk.BOTH, expand=True)
        
        # Painel de instrução
        instr_frame = ttk.LabelFrame(display_frame, text="Instrução Atual", padding=10)
        instr_frame.pack(fill=tk.X, pady=5)
        
        self.instr_text = tk.Text(
            instr_frame,
            height=3,
            wrap=tk.WORD,
            state=tk.DISABLED,
            font=('Courier New', 10)
        )
        self.instr_text.pack(fill=tk.X)
        
        # Painel de registradores com scrollbar
        reg_frame = ttk.LabelFrame(display_frame, text="Registradores", padding=10)
        reg_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        reg_scroll = ttk.Scrollbar(reg_frame)
        reg_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.reg_text = tk.Text(
            reg_frame,
            wrap=tk.NONE,
            state=tk.DISABLED,
            yscrollcommand=reg_scroll.set,
            font=('Courier New', 10)
        )
        self.reg_text.pack(fill=tk.BOTH, expand=True)
        reg_scroll.config(command=self.reg_text.yview)
        
        # Barra de status
        self.status_var = tk.StringVar(value="Pronto. Carregue um programa para começar.")
        status_bar = ttk.Label(
            main_frame,
            textvariable=self.status_var,
            style="Status.TLabel",
            relief=tk.SUNKEN
        )
        status_bar.pack(fill=tk.X, pady=(5,0))

    def load_program(self):
        """Carrega um programa .asm ou .bin"""
        filepath = filedialog.askopenfilename(
            filetypes=[
                ("Assembly MIPS", "*.asm"),
                ("Binário MIPS", "*.bin"),
                ("Todos os arquivos", "*.*")
            ]
        )
        
        if not filepath:
            return
        
        try:
            # Reset antes de carregar novo programa
            self.datapath.reset()
            self.binary_instructions = []
            
            if filepath.endswith(".asm"):
                self.binary_instructions = assemble_file(filepath)
                if not self.binary_instructions:
                    raise ValueError("Erro ao montar o arquivo assembly")
                
            elif filepath.endswith(".bin"):
                with open(filepath, 'r') as f:
                    self.binary_instructions = [int(line.strip(), 2) for line in f if line.strip()]
            
            self.current_file = os.path.basename(filepath)
            self.program_loaded = True
            self.toggle_controls(True)
            self.status_var.set(f"Programa carregado: {self.current_file}")
            
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao carregar arquivo:\n{str(e)}")
            self.reset_simulator(full=True)

    def step(self):
        """Executa uma instrução por passo"""
        if not self.program_loaded:
            self.status_var.set("Erro: Nenhum programa carregado")
            return
        
        if self.datapath.pc >= len(self.binary_instructions) * 4:
            self.status_var.set("Execução concluída")
            self.generate_report()
            return
        
        try:
            # Obtém a instrução atual
            instr_index = self.datapath.pc // 4
            binary_instr = self.binary_instructions[instr_index]
            
            # Executa e atualiza a interface
            self.datapath.execute_instruction(binary_instr)
            self.update_display()
            
            self.status_var.set(
                f"Executando PC={hex(self.datapath.pc)} | "
                f"Instrução {instr_index+1}/{len(self.binary_instructions)}"
            )
            
        except Exception as e:
            messagebox.showerror("Erro de Execução", f"Falha ao executar instrução:\n{str(e)}")
            self.reset_simulator(full=False)

    def reset_simulator(self, full=False):
        """Reseta o simulador
        Args:
            full: Se True, faz reset completo (incluindo programa carregado)
        """
        self.datapath.reset()
        
        if full:
            self.binary_instructions = []
            self.current_file = None
            self.program_loaded = False
            self.status_var.set("Simulador resetado")
        else:
            self.status_var.set(f"Estado resetado | Programa: {self.current_file}")
        
        self.toggle_controls(self.program_loaded)
        self.update_display()

    def toggle_controls(self, enable):
        """Ativa/desativa botões de controle"""
        state = tk.NORMAL if enable else tk.DISABLED
        self.step_btn.config(state=state)
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
            self.instr_text.insert(tk.END, "Nenhuma instrução carregada")
            self.instr_text.config(state=tk.DISABLED)
            return
        
        if self.datapath.pc >= len(self.binary_instructions) * 4:
            self.instr_text.insert(tk.END, "Execução concluída")
            self.instr_text.config(state=tk.DISABLED)
            return
        
        instr_index = self.datapath.pc // 4
        binary_instr = self.binary_instructions[instr_index]
        
        # Formata a exibição
        self.instr_text.insert(tk.END, f"Endereço: {hex(self.datapath.pc)}\n")
        self.instr_text.insert(tk.END, f"Binário:  {format(binary_instr, '032b')}\n")
        self.instr_text.insert(tk.END, f"Hexa:     {hex(binary_instr)}")
        self.instr_text.config(state=tk.DISABLED)

    def update_registers_display(self):
        """Atualiza a exibição dos registradores com destaque para valores modificados"""
        self.reg_text.config(state=tk.NORMAL)
        self.reg_text.delete(1.0, tk.END)
        
        # Configuração das cores
        self.reg_text.tag_configure("modified", foreground="blue")
        self.reg_text.tag_configure("default", foreground="black")
        
        # Obtém todos os registradores ordenados por número
        registers = sorted(
            [(num, name) for num, name in self.datapath.registers.reg_map.items()],
            key=lambda x: x[0]
        )
        
        # Formata em 4 colunas
        for i in range(0, len(registers), 4):
            line = ""
            tags = []
            
            for num, name in registers[i:i+4]:
                current_value = self.datapath.registers.get_register(num)
                
                # Verifica se o valor foi modificado
                is_modified = hasattr(self, 'last_register_values') and \
                             (current_value != self.last_register_values.get(num, 0))
                
                tag = "modified" if is_modified else "default"
                entry = f"{name}: {hex(current_value)}".ljust(25)
                line += entry
                tags.append((tag, len(line)))  # Guarda a posição para aplicar a tag
            
            self.reg_text.insert(tk.END, line + "\n")
            
            # Aplica as tags de cor
            for (tag, pos), (num, _) in zip(tags, registers[i:i+4]):
                start_pos = f"{i//4 + 1}.{pos - 25}"
                end_pos = f"{i//4 + 1}.{pos}"
                self.reg_text.tag_add(tag, start_pos, end_pos)
        
        # Atualiza os valores para a próxima comparação
        self.last_register_values = {
            num: self.datapath.registers.get_register(num)
            for num in range(32)
        }
        
        self.reg_text.config(state=tk.DISABLED)

    def generate_report(self):
        """Gera relatório final da execução"""
        if not self.program_loaded:
            return
            
        report = (
            "=== RELATÓRIO DE EXECUÇÃO ===\n"
            f"Arquivo: {self.current_file}\n"
            f"PC Final: {hex(self.datapath.pc)}\n\n"
            "=== REGISTRADORES ===\n"
        )
        
        # Adiciona registradores ao relatório
        for num, name in sorted(self.datapath.registers.reg_map.items()):
            value = self.datapath.registers.get_register(num)
            report += f"{name}: {hex(value)}\n"
        
        # Exibe o relatório em nova janela
        self.show_report_window(report)

    def show_report_window(self, report_text):
        report_window = tk.Toplevel(self.root)
        report_window.title("Relatório de Execução")
        report_window.geometry("600x400")
    
        # Variável para controlar o estado da janela
        is_maximized = tk.BooleanVar(value=False)
    
        def toggle_maximize():
            if is_maximized.get():
                report_window.geometry("600x400")
            else:
                report_window.state('zoomed')  # Maximiza a janela
            is_maximized.set(not is_maximized.get())
            update_button_state()
    
        def update_button_state():
            if is_maximized.get():
                save_btn.pack(pady=5)
            else:
                save_btn.pack_forget()
    
        # Botão de maximizar
        ttk.Button(
            report_window,
            text="⛶ Maximizar",
            command=toggle_maximize
        ).pack(anchor=tk.NE, padx=5, pady=5)
    
        # Botão de salvar (inicialmente oculto)
        save_btn = ttk.Button(
            report_window,
            text="💾 Salvar Relatório",
            command=lambda: self.save_report(report_text)
        )

        # Configuração do texto
        text_frame = ttk.Frame(report_window)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
        text_scroll = ttk.Scrollbar(text_frame)
        text_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    
        report_display = tk.Text(
            text_frame,
            wrap=tk.WORD,
            yscrollcommand=text_scroll.set,
            font=('Courier New', 10)
        )
        report_display.pack(fill=tk.BOTH, expand=True)
        report_display.insert(tk.END, report_text)
        report_display.config(state=tk.DISABLED)
    
        text_scroll.config(command=report_display.yview)
    
        # Atualiza ao redimensionar
        report_window.bind("<Configure>", lambda e: update_button_state())

    def save_report(self, report_text):
        """Salva o relatório em arquivo"""
        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Arquivos de Texto", "*.txt")]
        )
        
        if filepath:
            with open(filepath, 'w') as f:
                f.write(report_text)
            messagebox.showinfo("Sucesso", f"Relatório salvo em:\n{filepath}")

if __name__ == "__main__":
    root = tk.Tk()
    app = MIPS_Simulator_GUI(root)
    root.mainloop()
