import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datapath import MIPS_Datapath
from assembler import assemble_file  # Importe seu assembler aqui

class MIPS_Simulator_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Simulador MIPS 32-bit")
        
        # Inicializa o datapath e a lista de instruções vazia
        self.datapath = MIPS_Datapath()
        self.binary_instructions = []
        
        # Configura a interface
        self.setup_ui()
        
        # Inicia com os controles desativados
        self.toggle_controls(False)
    
    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # === Botão para Carregar Arquivo ===
        load_frame = ttk.Frame(main_frame, padding="5")
        load_frame.grid(row=0, column=0, sticky="ew")
        
        self.load_btn = ttk.Button(
            load_frame, 
            text="Carregar Arquivo", 
            command=self.load_file
        )
        self.load_btn.pack(side="left", padx=5)
        
        # === Instrução Atual ===
        instr_frame = ttk.LabelFrame(main_frame, text="Instrução Atual", padding="10")
        instr_frame.grid(row=1, column=0, padx=5, pady=5, sticky="ew")
        
        self.instr_label = ttk.Label(instr_frame, text="Nenhum programa carregado.")
        self.instr_label.pack()
        
        self.binary_label = ttk.Label(instr_frame, text="Binário: -")
        self.binary_label.pack()
        
        # === Registradores ===
        reg_frame = ttk.LabelFrame(main_frame, text="Registradores", padding="10")
        reg_frame.grid(row=2, column=0, padx=5, pady=5, sticky="ew")
        
        self.reg_text = tk.Text(reg_frame, height=10, width=40, state="disabled")
        self.reg_text.pack()
        
        # === Memória ===
        mem_frame = ttk.LabelFrame(main_frame, text="Memória", padding="10")
        mem_frame.grid(row=3, column=0, padx=5, pady=5, sticky="ew")
        
        self.mem_text = tk.Text(mem_frame, height=10, width=40, state="disabled")
        self.mem_text.pack()
        
        # === Controles ===
        ctrl_frame = ttk.Frame(main_frame, padding="10")
        ctrl_frame.grid(row=4, column=0, sticky="ew")
        
        self.step_btn = ttk.Button(
            ctrl_frame, 
            text="Passo (Step)", 
            command=self.step,
            state="disabled"  # Inicia desativado
        )
        self.step_btn.pack(side="left", padx=5)
        
        self.reset_btn = ttk.Button(
            ctrl_frame, 
            text="Reset", 
            command=self.reset,
            state="disabled"  # Inicia desativado
        )
        self.reset_btn.pack(side="left", padx=5)
        
        # === Barra de Status ===
        self.status_var = tk.StringVar(value="Pronto. Carregue um arquivo para começar.")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var)
        status_bar.grid(row=5, column=0, sticky="ew")
    
    def toggle_controls(self, enable):
        """Ativa/desativa os botões de controle."""
        state = "normal" if enable else "disabled"
        self.step_btn.config(state=state)
        self.reset_btn.config(state=state)
    
    def load_file(self):
        filepath = filedialog.askopenfilename(
            title="Selecione um arquivo",
            filetypes=[("Assembly MIPS", "*.asm"), ("Binário MIPS", "*.bin")]
        )
        
        if not filepath:
            return
        
        try:
            if filepath.endswith(".asm"):
                # Usa o novo assembler (sem arquivo temporário)
                self.binary_instructions = assemble_file(filepath)
                if self.binary_instructions is None:
                    raise ValueError("Erro ao montar o assembly")
                    
            elif filepath.endswith(".bin"):
                with open(filepath, "r") as f:
                    self.binary_instructions = [int(line.strip(), 2) for line in f]
            
            self.reset()
            self.toggle_controls(True)
            messagebox.showinfo("Sucesso", f"Carregado: {len(self.binary_instructions)} instruções")
            
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao carregar:\n{str(e)}")
            self.binary_instructions = []
            self.toggle_controls(False)

    def step(self):
        """Executa uma instrução por vez e gera relatório ao final"""
        if self.datapath.halted:
            self.generate_report()
            return
        
        if self.datapath.pc >= len(self.binary_instructions) * 4:
            self.generate_report()
            self.status_var.set("Execução finalizada. Relatório gerado!")
            return
    
    def reset(self):
        """Reinicia o simulador"""
        self.datapath.reset()
        self.update_instruction_display(None)
        self.update_registers()
        self.update_memory()
        self.status_var.set("Simulador resetado. Carregue um programa para começar.")
        
        # Limpa relatórios anteriores (opcional)
        try:
            import os
            if os.path.exists("relatorio_final.txt"):
                os.remove("relatorio_final.txt")
        except:
            pass
    
    def update_instruction_display(self, binary_instr):
        """Exibe a instrução atual."""
        if binary_instr is None:
            self.instr_label.config(text="Nenhuma instrução em execução.")
            self.binary_label.config(text="Binário: -")
        else:
            self.instr_label.config(text=f"Instrução: {self.disassemble(binary_instr)}")
            self.binary_label.config(text=f"Binário: {format(binary_instr, '032b')}")
    
    def update_registers(self):
        self.reg_text.config(state="normal")
        self.reg_text.delete(1.0, tk.END)
    
        # Configura tags para cores
        self.reg_text.tag_config("modified", foreground="blue")
        self.reg_text.tag_config("default", foreground="black")
    
        for reg_name, reg_value in self.datapath.registers.get_all_registers():
            # Verifica se o valor foi modificado (exceto $zero)
            is_modified = (reg_name != "$zero") and (self.datapath.registers.get_register(reg_name) != 0)

            self.reg_text.insert(
                tk.END,
                f"{reg_name}: {reg_value}\n",
                "modified" if is_modified else "default"
            ) 
        self.reg_text.config(state="disabled")
    
    def update_memory(self):
        """Atualiza a exibição da memória."""
        self.mem_text.config(state="normal")
        self.mem_text.delete(1.0, tk.END)
        
        for addr, val in self.datapath.memory.items():
            self.mem_text.insert(tk.END, f"{hex(addr)}: {hex(val)}\n")
        
        self.mem_text.config(state="disabled")
    
    def disassemble(self, binary_instr):
        """Simplificação: retorna o binário como hexadecimal."""
        return hex(binary_instr)
    
    def generate_report(self):
        """Gera o relatório final e exibe confirmação"""
        report_file = "relatorio_final.txt"
        self.datapath.generate_report(report_file)
        
        # Mostra o conteúdo do relatório na interface
        with open(report_file, 'r') as f:
            report_content = f.read()
        
        # Cria uma nova janela para exibir o relatório
        report_window = tk.Toplevel(self.root)
        report_window.title("Relatório Final")
        
        text_frame = ttk.Frame(report_window)
        text_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        text_scroll = ttk.Scrollbar(text_frame)
        text_scroll.pack(side="right", fill="y")
        
        report_text = tk.Text(
            text_frame,
            wrap="word",
            yscrollcommand=text_scroll.set,
            font=("Courier New", 10)
        )
        report_text.pack(fill="both", expand=True)
        report_text.insert("1.0", report_content)
        report_text.config(state="disabled")
        
        text_scroll.config(command=report_text.yview)
        
        # Botão para salvar cópia
        save_btn = ttk.Button(
            report_window,
            text="Salvar Cópia",
            command=lambda: self.save_report_copy(report_content)
        )
        save_btn.pack(pady=5)

    def save_report_copy(self, content):
        """Permite salvar o relatório em outro local"""
        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Arquivos de Texto", "*.txt")]
        )
        if filepath:
            with open(filepath, 'w') as f:
                f.write(content)
            messagebox.showinfo("Sucesso", f"Relatório salvo em:\n{filepath}")

if __name__ == "__main__":
    root = tk.Tk()
    app = MIPS_Simulator_GUI(root)
    root.mainloop()