# teste.asm - Programa de teste completo para o simulador MIPS
# Testa: ADD, ADDI, SUB, MULT, AND, OR, SLL, SLT, SLTI, LW, SW, LUI
#        syscall (print_int, print_string, exit)

.data
    # Dados para teste
    msg1:   .asciiz "\nResultado: "
    msg2:   .asciiz "\nComparacao: "
    array:  .word 10, 20, 30, 40
    value:  .word 0xABCD1234

.text
main:
    # Teste de LUI (Load Upper Immediate)
    lui $t0, 0x1001      # Carrega endereço base de dados
    
    # Teste de operações aritméticas
    addi $t1, $zero, 15   # $t1 = 15
    addi $t2, $zero, 7    # $t2 = 7
    add  $t3, $t1, $t2    # $t3 = 22 (15 + 7)
    sub  $t4, $t1, $t2    # $t4 = 8 (15 - 7)
    mult $t1, $t2         # HI/LO = 105 (15 * 7)
    
    # Teste de operações lógicas
    and  $t5, $t1, $t2    # $t5 = 7 (15 AND 7)
    or   $t6, $t1, $t2    # $t6 = 15 (15 OR 7)
    sll  $t7, $t2, 2      # $t7 = 28 (7 << 2)
    
    # Teste de condicionais
    slt  $s0, $t2, $t1    # $s0 = 1 (7 < 15? TRUE)
    slti $s1, $t1, 20     # $s1 = 1 (15 < 20? TRUE)
    
    # Teste de Load/Store
    lw   $s2, 0($t0)      # Carrega primeiro valor do array (10)
    sw   $t3, 12($t0)     # Armazena 22 na posição array[3]
    
    # Teste de syscall print_string
    addi $v0, $zero, 4    # Código para print_string
    addi $a0, $t0, 16     # Endereço da string msg1
    syscall
    
    # Teste de syscall print_int (resultado do ADD)
    addi $v0, $zero, 1    # Código para print_int
    add  $a0, $zero, $t3  # Valor a imprimir (22)
    syscall
    
    # Teste de syscall print_string
    addi $v0, $zero, 4    # Código para print_string
    addi $a0, $t0, 28     # Endereço da string msg2
    syscall
    
    # Teste de syscall print_int (resultado da comparação SLT)
    addi $v0, $zero, 1    # Código para print_int
    add  $a0, $zero, $s0  # Valor a imprimir (1)
    syscall
    
    # Teste de syscall exit
    addi $v0, $zero, 10   # Código para exit
    syscall