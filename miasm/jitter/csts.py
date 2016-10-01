#-*- coding:utf-8 -*-


# VM Mngr Exceptions

EXCEPT_DO_NOT_UPDATE_PC = 1 << 25
EXCEPT_NUM_UPDT_EIP = (1<<11)

EXCEPT_CODE_AUTOMOD = (1 << 0)
EXCEPT_SOFT_BP = (1 << 1)
EXCEPT_INT_XX = (1 << 2)
EXCEPT_SPR_ACCESS = (1 << 3)
EXCEPT_BREAKPOINT_MEMORY = (1 << 10)
# Deprecated
EXCEPT_BREAKPOINT_INTERN = EXCEPT_BREAKPOINT_MEMORY

EXCEPT_ACCESS_VIOL = ((1 << 14) | EXCEPT_DO_NOT_UPDATE_PC)
EXCEPT_DIV_BY_ZERO = ((1 << 16) | EXCEPT_DO_NOT_UPDATE_PC)
EXCEPT_PRIV_INSN = ((1 << 17) | EXCEPT_DO_NOT_UPDATE_PC)
EXCEPT_ILLEGAL_INSN = ((1 << 18) | EXCEPT_DO_NOT_UPDATE_PC)
EXCEPT_UNK_MNEMO = ((1 << 19) | EXCEPT_DO_NOT_UPDATE_PC)
EXCEPT_INT_1 = ((1 << 20) | EXCEPT_DO_NOT_UPDATE_PC)

# Taint constants

EXCEPT_TAINT = (1 << 4)
EXCEPT_TAINT_ADD_REG = ((1 << 14) | EXCEPT_TAINT)
EXCEPT_TAINT_REMOVE_REG = ((1 << 15) | EXCEPT_TAINT)
EXCEPT_TAINT_ADD_MEM = ((1 << 16) | EXCEPT_TAINT)
EXCEPT_TAINT_REMOVE_MEM = ((1 << 17) | EXCEPT_TAINT)

# VM Mngr constants

PAGE_READ = 1
PAGE_WRITE = 2
PAGE_EXEC = 4

BREAKPOINT_READ = 1
BREAKPOINT_WRITE = 2

