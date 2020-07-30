import os
import tempfile

import miasm.jitter.csts as csts
from miasm.core.interval import interval
from miasm.analysis.taint_codegen import makeTaintGen
from miasm.jitter.jitcore_llvm import JitCore_LLVM
from llvmlite import ir as llvm_ir


def init_registers_index(jitter):
    """ Associate register names with an index (needed during JiT) """

    regs_index = dict()
    regs_name = dict()
    index = 0
    for reg in jitter.arch.regs.all_regs_ids_byname.keys():
        regs_index[reg] = index
        regs_name[index] = reg
        index += 1
    try:
        jitter.jit.codegen.regs_index = regs_index
        jitter.jit.codegen.regs_name = regs_name
    except:
        # codegen does not exit for llvm
        class Save_reg : pass
        jitter.jit.codegen = Save_reg()
        jitter.jit.codegen.regs_index = regs_index
        jitter.jit.codegen.regs_name = regs_name
        
    return len(regs_index)

def enable_taint_analysis(jitter, nb_colors=1):
    """ Init all component of the taint analysis engine """
    if isinstance(jitter.jit, JitCore_LLVM):
        jitter.jit.taint = True
        jitter.jit.context.nb_colors = nb_colors
    else:
        jitter.jit.codegen = makeTaintGen(jitter.C_Gen, jitter.ir_arch)
        jitter.nb_colors = nb_colors
    nb_regs = init_registers_index(jitter)
    # Allocate taint structures
    jitter.taint.init_taint_analysis(nb_colors, nb_regs)
    # Switch to taint cache
    jitter.jit.tempdir = os.path.join(tempfile.gettempdir(), "miasm_cache_taint")

def disable_taint_analysis(jitter):
    if isinstance(self.jit, JitCore_LLVM):
        jitter.jit.taint = False
    else:
        jitter.jit.codegen = jitter.C_Gen(jitter.ir_arch)
    jitter.jit.tempdir = os.path.join(tempfile.gettempdir(), "miasm_cache")

# API usage examples

def on_taint_register(jitter):
    try :
        nb_colors = jitter.nb_colors
    except:
        #attribute nb_color is not in jitter in llvm
        nb_colors = jitter.jit.context.nb_colors
    for color in range(nb_colors):
        last_regs = jitter.taint.last_tainted_registers(color)
        if last_regs:
            print("[Color:%s] Taint registers" % (color))

            for reg_id, intervals in last_regs:
                print("\t+ %s %s" % (jitter.jit.codegen.regs_name[reg_id], interval(intervals)))
            jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_REG))
    return True

def on_untaint_register(jitter):
    try :
        nb_colors = jitter.nb_colors
    except:
        #attribute nb_color is not in jitter in llvm
        nb_colors = jitter.jit.context.nb_colors
    for color in range(nb_colors):
        last_regs = jitter.taint.last_untainted_registers(color)
        if last_regs:
            print("[Color:%s] Untaint registers" % (color))

            for reg_id, intervals in last_regs:
                print("\t- %s %s" % (jitter.jit.codegen.regs_name[reg_id], interval(intervals)))
            jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_UNTAINT_REG))
    is_taint_vanished(jitter)
    return True

def on_taint_memory(jitter):
    try :
        nb_colors = jitter.nb_colors
    except:
        #attribute nb_color does not exist
        nb_colors = jitter.jit.context.nb_colors
    for color in range(nb_colors):
        last_mem = jitter.taint.last_tainted_memory(color)
        if last_mem:
            print("[Color:%s] Taint memory" % (color))
            print(interval(last_mem))
            jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_TAINT_MEM))
    return True

def on_untaint_memory(jitter):
    try :
        nb_colors = jitter.nb_colors
    except:
        #attribute nb_color does not exist
        nb_colors = jitter.jit.context.nb_colors
    for color in range(nb_colors):
        last_mem = jitter.taint.last_untainted_memory(color)
        if last_mem:
            print("[Color%s] Untaint memory" % (color))
            print(interval(last_mem))
            jitter.vm.set_exception(jitter.vm.get_exception() & (~csts.EXCEPT_UNTAINT_MEM))
    is_taint_vanished(jitter)
    return True

def display_all_taint(jitter):
    try :
        nb_colors = jitter.nb_colors
    except:
        #attribute nb_color is not in jitter in llvm
        nb_colors = jitter.jit.context.nb_colors
    for color in range(nb_colors):
        regs, mems = jitter.taint.get_all_taint(color)
        print("\n","_"*20)
        print("Color: %s" % (color))
        print("_"*20)
        print("Registers:")
        for reg_id, intervals in regs:
            print("\t* %s %s" % (jitter.jit.codegen.regs_name[reg_id], interval(intervals)))
        print("-"*20)
        print("Memory:")
        print(interval(mems))
        print("_"*20,"\n")

def is_taint_vanished(jitter):
    try :
        nb_colors = jitter.nb_colors
    except:
        #attribute nb_color is not in jitter in llvm
        nb_colors = jitter.jit.context.nb_colors
    for color in range(nb_colors):
        regs, mems = jitter.taint.get_all_taint(color)
        if regs or mems:
            return # There is still some taint
    print("\n\n/!\\ All taint is gone ! /!\\\n\n")

def pyt2llvm(size, value):
    """ Return an LLVM constant with a python integer
    Made to help writing LLVM IR code
    """
    return llvm_ir.Constant(LLVMType.IntType(size),value)

def externalCall(fc_ptr, args, builder,  var_name = ""):
    """ Save the pointer returned in an allocated space 
    This trick is often used in LLVM IR to avoid saving
    structures. We just use their pointer.
    """
    rb_root_pointer = builder.alloca(LLVMType.IntType(64))
    rb_root_u8 = builder.bitcast(rb_root_pointer, llvm_ir.IntType(8).as_pointer())
    args.append(rb_root_u8)
    ret = builder.call(fc_ptr, args, name = var_name )
    return ret
