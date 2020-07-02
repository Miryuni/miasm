from __future__ import print_function
import os
import importlib
import tempfile
import sysconfig

from miasm.analysis.taint_llvm_utils import LLVMFunction_Taint, LLVMContext_JIT_Taint
from miasm.jitter.llvmconvert import *
import miasm.jitter.jitcore as jitcore
from miasm.jitter import Jitllvm
import platform

is_win = platform.system() == "Windows"

class JitCore_LLVM(jitcore.JitCore):
    "JiT management, using LLVM as backend"

    # Architecture dependent libraries
    arch_dependent_libs = {
        "x86": "JitCore_x86",
        "arm": "JitCore_arm",
        "msp430": "JitCore_msp430",
        "mips32": "JitCore_mips32",
        "aarch64": "JitCore_aarch64",
        "ppc32": "JitCore_ppc32",
    }

    def __init__(self, ir_arch, bin_stream, taint=False):
        super(JitCore_LLVM, self).__init__(ir_arch, bin_stream)

        self.options.update(
            {
                "show_context": False,
                "safe_mode": True,   # Verify each function
                "optimise": True,     # Optimise functions
                "log_func": False,    # Print LLVM functions
                "log_assembly": False,  # Print assembly executed
            }
        )

        self.exec_wrapper = Jitllvm.llvm_exec_block
        self.ir_arch = ir_arch
        self.taint = taint
        # Cache temporary dir
        # TODO:Mighy create another cache temporary dir for taint?
        if self.taint:
            self.tempdir = os.path.join(tempfile.gettempdir(), "miasm_cache_taint")
        else:
            self.tempdir = os.path.join(tempfile.gettempdir(), "miasm_cache")
        try:
            os.mkdir(self.tempdir, 0o755)
        except OSError:
            pass
        if not os.access(self.tempdir, os.R_OK | os.W_OK):
            raise RuntimeError(
                'Cannot access cache directory %s ' % self.tempdir)

    def load(self):
        # Library to load within Jit context
        libs_to_load = []

        # Get architecture dependent Jitcore library (if any)
        lib_dir = os.path.dirname(os.path.realpath(__file__))
        ext = sysconfig.get_config_var('EXT_SUFFIX')
        if ext is None:
            ext = ".so" if not is_win else ".pyd"
        try:
            libname = self.arch_dependent_libs[self.ir_arch.arch.name] + ext
            jit_lib = os.path.join(lib_dir, "arch/" + libname)
            taint_lib = os.path.join(lib_dir, "../analysis/TaintMngr" + ext)
            libs_to_load.append(jit_lib)
            libs_to_load.append(taint_lib)
        except KeyError:
            pass
        
        # Create a context
        if self.taint:
            self.context = LLVMContext_JIT_Taint(libs_to_load, self.ir_arch)
        else:
            self.context = LLVMContext_JIT(libs_to_load, self.ir_arch)

        # Set the optimisation level
        self.context.optimise_level()

        # Save the current architecture parameters
        self.arch = self.ir_arch.arch

        # Get the correspondence between registers and vmcpu struct
        mod_name = "miasm.jitter.arch.JitCore_%s" % (self.ir_arch.arch.name)
        mod = importlib.import_module(mod_name)
        self.context.set_vmcpu(mod.get_gpreg_offset_all())
        # Enable caching
        self.context.enable_cache()

    def add_block(self, block):
        """Add a block to JiT and JiT it.
        @block: the block to add
        """
        block_hash = self.hash_block(block)
        fname_out = os.path.join(self.tempdir, "%s.bc" % block_hash)
        if not os.access(fname_out, os.R_OK):
            # Build a function in the context
            self.context.taint = self.taint
            if self.taint:  
                self.context.regs_index = self.codegen.regs_index
                self.context.regs_name = self.codegen.regs_name
                func = LLVMFunction_Taint(self.context, self.FUNCNAME)
            else:
                func = LLVMFunction(self.context, self.FUNCNAME)
            # Show the context created
            if self.options["show_context"] is True:
                print(func)

            # Set log level
            func.log_regs = self.log_regs
            func.log_mn = self.log_mn

            # Import asm block
            func.from_asmblock(block)
            # Verify
            if self.options["safe_mode"] is True:
                func.verify()

            # Optimise
            if self.options["optimise"] is True:
                func.optimise()

            # Log
            if self.options["log_func"] is True:
                print(func)
            if self.options["log_assembly"] is True:
                print(func.get_assembly())

            # Use propagate the cache filename
            self.context.set_cache_filename(func, fname_out)

            # Get a pointer on the function for JiT
            ptr = func.get_function_pointer()

        else:
            # The cache file exists: function can be loaded from cache
            ptr = self.context.get_ptr_from_cache(fname_out, self.FUNCNAME)

        # Store a pointer on the function jitted code
        loc_key = block.loc_key
        offset = self.ir_arch.loc_db.get_location_offset(loc_key)
        self.offset_to_jitted_func[offset] = ptr
