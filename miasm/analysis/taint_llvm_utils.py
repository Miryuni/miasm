import pdb, sys
from future.utils import viewitems, viewvalues
from miasm.jitter.llvmconvert import LLVMFunction, LLVMType, LLVMContext_JIT
from miasm.analysis.taint_codegen import get_detailed_read_elements
from miasm.expression.expression import ExprId, ExprSlice, ExprLoc
from miasm.expression.expression_helper import possible_values
from llvmlite import ir as llvm_ir

class LLVMFunction_Taint(LLVMFunction):
#TODO comments
    def __init__(self, llvm_context, name="fc", new_module=True):
        LLVMFunction.__init__(self, llvm_context, name, new_module)


    def init_fc(self):
        super(LLVMFunction_Taint, self).init_fc()

        builder = self.builder

        # Initialize the interval and get both the pointer of
        # interval.start and interval.last
        interval_ptr = builder.alloca(self.llvm_context.interval_type, name = "interval_taint")
        self.local_vars["interval_ptr"] = interval_ptr
        self.start_ptr = builder.gep(self.local_vars["interval_ptr"],[pyt2llvm(32, 0),pyt2llvm(32, 0)],name="interval.start") 
        self.stop_ptr = builder.gep(self.local_vars["interval_ptr"],[pyt2llvm(32, 0),pyt2llvm(32, 1)], name = "interval.stop")
        self.ptr_case_value = builder.alloca(LLVMType.IntType(64))
        self.ptr_current_color = builder.alloca(LLVMType.IntType(64))
        self.builder.store(pyt2llvm(64, 0), self.ptr_current_color)     


    def gen_get_taint_generic(self, name, color_index, get_type, start_check, stop_check, llvm_name = ""):
        """ Generation of llvm code, to get the intervals tainted with color_index of the register
            @param color_index the color that will be checked in the register, an i32
             @param reg_name the name of the register to checked, a string
             @param start_check start of the interval to check, an llvm value
             @param stop_check end of the interval to check, an llvm value
             @return A pointer to an rb_root containing all intervals tainted

             """

        builder = self.builder
        if get_type == "reg":
            reg_index = self.llvm_context.regs_index[name]
            get_type = 1
        elif get_type == "mem":
            reg_index = 0
            get_type = 2


        # Update the interval structure
        builder.store(start_check, self.start_ptr)
        builder.store(stop_check, self.stop_ptr)
        interval_struct = builder.load(self.local_vars["interval_ptr"])

        fc_ptr = self.mod.get_global("get_generic_structure")
        interval_tree = externalCall(fc_ptr,
                                    [
                                        self.local_vars["jitcpu"], 
                                        color_index, 
                                        pyt2llvm(64, reg_index), 
                                        interval_struct, 
                                        pyt2llvm(64, get_type)
                                    ], self.builder, var_name = llvm_name)
        return interval_tree

    def gen_jump(self, expr_loc):
        #TODO Comments
        """Generate the jump to the expr_loc

        """
        # In fact its not always an expr_loc?
        self.builder.store(pyt2llvm(64, 0), self.ptr_current_color)
        if isinstance(expr_loc, ExprLoc) : 
            try:
                # Making an internal jump
                label = str(expr_loc.loc_key) + "_taint_0"
                self.builder.branch(self.bb_list[str(expr_loc.loc_key)][label])
            except:
                # Exception : object doesnt exist on self.bb_list
                self.builder.branch(self.first_label)
            return
        else : 
            self.builder.branch(self.first_label)
            return 

                
    
    def gen_branch(self, src, current_block, label = ""):
        # We always come here if dst is an IRDst 
        # There is a special case where there might be IRDst = Expr(...)
        # In this case we dont know yet what to do

        # Evaluation of the IRDst = Expr(...) to know the branching
        
        # A jump to a specific assignblk, without needing to evaluate
        # XXX can be optimize by only computing the case2dst and not the evaluated
         
        case2dst, evaluated = self.expr2cases(src)

        next_color = self.builder.add(self.current_color, pyt2llvm(64, 1))
        self.builder.store(next_color, self.ptr_current_color)
        case_value = self.builder.sub(next_color, pyt2llvm(64, self.llvm_context.nb_colors))
        self.builder.store(case_value, self.ptr_case_value)

        current_bbl = self.builder.block
        label_loop = "switch_%s_loop" % label 
        label_continue = "switch_%s_continue" % label
        bbl_loop = self.append_basic_block(label_loop)
        bbl_continue = self.append_basic_block(label_continue)
        self.builder.position_at_start(bbl_loop)
        self.builder.branch(self.bb_list[current_block.name][current_block.name + "_taint_0"])
        self.builder.position_at_start(bbl_continue)
        if len(case2dst) ==1:
            self.gen_jump(next(iter(viewvalues(case2dst))))
            
        # A jump to multiple assignblk, must be handled to analyze only the code really executed, 
        else:
            self.builder.store(pyt2llvm(64, 0), self.ptr_current_color)
            self.builder.branch(self.first_label)

        self.builder.position_at_end(current_bbl)
        case_value = self.builder.load(self.ptr_case_value)
        switch = self.builder.switch(case_value, bbl_loop)
        switch.add_case(pyt2llvm(64, 0), bbl_continue)
             
        

    def add_ir_taint(self, elements, full = False, current_compose_start = 0):
        #TODO comments
        
        # If there is no elements which fully taint
        if not elements : 
            return pyt2llvm(64, 0)

        builder = self.builder


        # Initially we do not want to fully taint the dst
        is_fully_tainted = pyt2llvm(64, 0)

        for element in elements:
            if element.is_mem():
                # Infos on the element
                start = self.add_ir(element.ptr)
                start_32 = self.builder.zext(start, LLVMType.IntType(32))
                size = pyt2llvm(32, int(element.size/8-1))
                stop = builder.add(start_32, size)

                # Get the interval_tree of the element
                interval_tree = self.gen_get_taint_generic(element, self.current_color, "mem", start_32, stop)

            elif element.is_slice():
                interval_tree = self.gen_get_taint_generic(str(element.arg), self.current_color, "reg", pyt2llvm(32, element.start), pyt2llvm(32, element.stop))

            elif element.is_id():
                interval_tree = self.gen_get_taint_generic(str(element.name), self.current_color, "reg", pyt2llvm(32, 0), pyt2llvm(32, element.size) )

            if full:
                fc_ptr = self.mod.get_global("check_rb_tree_not_empty")
                fully_tainted = builder.call(fc_ptr, [interval_tree])
                is_fully_tainted = builder.or_(is_fully_tainted, fully_tainted)
            else:
                fc_ptr = self.mod.get_global("taint_merge_interval_tree")
                interval_start_ptr = builder.gep(self.local_vars["interval_ptr"], [pyt2llvm(32, 0), pyt2llvm(32, 0)])
                interval_start = builder.load(interval_start_ptr)
                offset = builder.sub(pyt2llvm(32, int(current_compose_start)), interval_start)
                interval_merged = builder.call(fc_ptr, [offset,
                                                        self.interval_tree_new,
                                                        interval_tree])
        return is_fully_tainted

    def gen_taint_from_all_read_elements(self, read_elements):
        #TODO comments

        # The base case of recursion, we return 0 as fully_tainted
        ret_full = pyt2llvm(64, 0)
        if not read_elements :
            return ret_full
        for composant in read_elements:
            # Analyze the full composants 
            fully_tainted = self.add_ir_taint(composant["full"], full = True)
            if not composant["elements"]:
                pass
            else:
                # If not fully_tainted analyze the other elements
                predicat = self.builder.trunc(fully_tainted, LLVMType.IntType(1))
                with self.builder.if_then(self.builder.not_(predicat)) as then_block: 
                    fully_tainted = self.add_ir_taint(composant["elements"], current_compose_start = composant["start"])
            if composant["composition"]:
                is_fully_tainted = self.gen_taint_from_all_read_elements(composant["composition"])
                fully_tainted = self.builder.or_(fully_tainted, is_fully_tainted)
            ret_full = self.builder.or_(ret_full, fully_tainted)
                
        return ret_full
        


    def gen_pre_code(self, instr_attrib):
        current_block = self.builder.block
        self.builder.position_at_start(self.bb_list[current_block.name][current_block.name + "_taint_0"])        
        super(LLVMFunction_Taint, self).gen_pre_code(instr_attrib)
        self.builder.position_at_end(current_block)
        

    def gen_irblock(self, instr_attrib, attributes, instr_offsets, irblock):
        """ Overload of LLVMFunction.gen_irblock to use taint engine

        """ 

        current_block = self.builder.block
        label = current_block.name + "_taint_0"
        self.is_mem = False
            

        # Cycling through each assignblock of the irblock
        for index, assignblk in enumerate(irblock):
            line_nb = 0 # Correspond to the ExprAssign number

            # Cycling through each ExprAssign of the assignblk 
            for dst, src in viewitems(assignblk):
                #TODO gérer le cache
                if line_nb == 0:
                    self.builder.position_at_end(self.bb_list[current_block.name][label])

                # Analysing the ExprAssign with the taint engine if the dst is not an IRDst
                if dst != self.llvm_context.ir_arch.IRDst or ("IRDst" not in str(dst)):
                    # Special case, dont know if it will be kept, 
                    # of form - IRdst = Expr(...),
                    #         - Expr(...) = loc_key
                    # We could also choose to not do anything in this case

                    if src == self.llvm_context.ir_arch.IRDst :
                        print("Analysing %s = %s, Special case" % (dst, src))
                        self.gen_branch(src, current_block, label = label)
                        continue

                    self.current_color = self.builder.load(self.ptr_current_color)

                    read_elements = get_detailed_read_elements(dst, src)
                    fc_ptr = self.mod.get_global("taint_generic_structure")
                    fc_new = self.mod.get_global("interval_tree_new_llvm")
                    self.interval_tree_new = externalCall(fc_new, [], self.builder) 

                    if dst.is_mem():
                        # Find the range of the mem being targeted
                        addr_start_32 = self.add_ir(dst.ptr)
                        addr_end = self.builder.add(addr_start_32, pyt2llvm(32, int(dst.size/8 - 1)))
                        
                        # Get the interval_tree of the dst
                        interval_tree_before = self.gen_get_taint_generic(str(dst), self.current_color, "mem", addr_start_32, addr_end, llvm_name = "interval_tree_before")

                       
                        # Generate the code to analyze all the elements 
                        fully_tainted = self.gen_taint_from_all_read_elements([read_elements])

                        # Infos on the structure that is going to be tainted
                        index_or_addr = self.builder.zext(addr_start_32, LLVMType.IntType(64))
                        structure_size = pyt2llvm(64, int(dst.size/8 - 1))
                        structure_type = pyt2llvm(64, 2)


                    # The dst is a register in this case
                    else:
                        # Infos on the structure going to be tainted
                        structure_size_32 = pyt2llvm(32, dst.size)
                        structure_type = pyt2llvm(64, 1)
                        index_or_addr = pyt2llvm(64, self.llvm_context.regs_index[str(dst)])

                        # Get the interval_tree of the dst
                        interval_tree_before = self.gen_get_taint_generic(str(dst), self.current_color, "reg", pyt2llvm(32, 0), structure_size_32)

                        # Generate the llvm code
                        fully_tainted = self.gen_taint_from_all_read_elements([read_elements])

                        structure_size = self.builder.zext(structure_size_32, LLVMType.IntType(64))

                        # Calling the taint function
                    self.builder.call(fc_ptr,
                                      [fully_tainted,
                                       index_or_addr,
                                       structure_size,
                                       self.current_color,
                                       self.local_vars["jitcpu"],
                                       self.local_vars["vmmngr"],
                                       structure_type,
                                       interval_tree_before,
                                       self.interval_tree_new
                                       ])  

                    # Update the line_nb and the label
                    line_nb += 1
                    label = current_block.name + "_taint_%d" % line_nb
                    
                    try:
                        # Trying to branch to the next ExprAssign, if not succesful it means we're jumping on another assignblk
                        self.builder.branch(self.bb_list[current_block.name][label])
                        self.builder.position_at_start(self.bb_list[current_block.name][label])
                    except:
                        # Exception: the basic block does not exist in self.bb_list
                        continue

                # Make the branching for the next assignblk
                else:
                    self.gen_branch(src, current_block, label = label)
                    

        self.builder.position_at_start(current_block)
        super(LLVMFunction_Taint, self).gen_irblock(instr_attrib, attributes, instr_offsets, irblock)

class LLVMContext_JIT_Taint(LLVMContext_JIT): 
     #TODO comments
    def __init__(self, libs, arch):
        LLVMContext_JIT.__init__(self, libs, arch)      

    def add_taint_structures(self):
        self.interval_type = llvm_ir.LiteralStructType( 
            [
                LLVMType.IntType(32), # interval.start
                LLVMType.IntType(32) # interval.last
            ]
        )

    def add_taint_functions(self):
         i8 = LLVMType.IntType(8)
         p8 = llvm_ir.PointerType(i8)
         i32 = LLVMType.IntType(32)
         itype = LLVMType.IntType(64)
         fc = {"get_generic_structure": {"ret":llvm_ir.VoidType(), 
                                        "args":[p8,  
                                                itype,
                                                itype, 
                                                self.interval_type,
                                                itype,
                                                p8]},
            "taint_merge_interval_tree": {"ret":llvm_ir.VoidType(),
                                        "args":[i32,
                                                p8,
                                                p8 ]},
            "taint_generic_structure": {"ret":llvm_ir.VoidType(), 
                                        "args":[itype, 
                                                itype,
                                                itype,
                                                itype, 
                                                p8,
                                                p8,
                                                itype,
                                                p8,
                                                p8]},
            "interval_tree_new_llvm" : {"ret": llvm_ir.VoidType(),
                                        "args" : [p8]},
            "check_rb_tree_not_empty" : {"ret": itype,
                                     "args": [p8]}
         }
         super(LLVMContext_JIT_Taint, self).add_fc(fc, readonly = False) 

    def add_op(self): 
        self.add_taint_structures()
        self.add_taint_functions()
        super(LLVMContext_JIT_Taint, self).add_op()



# API functions
def init_registers_index(jitter):
    """ Associate register names with an index (needed during JiT) """

    regs_index = dict()
    regs_name = dict()
    index = 0
    for reg in jitter.arch.regs.all_regs_ids_byname.keys():
        regs_index[reg] = index
        regs_name[index] = reg
        index += 1
    jitter.jit.context.regs_index = regs_index
    jitter.jit.context.regs_name = regs_name
    return len(regs_index)

def enable_taint_analysis(jitter, nb_colors = 1):
    """method to initalize the taint analysis
        @jitter : the jitter should used llvm as a back-end
        @nb_colors : number of colors that will be used to taint, should be superior to 1 
    """

    if nb_colors < 1:
        raise "At least 1 color is required to enable taint analysis"
    try:
        nb_regs = init_registers_index(jitter)
        jitter.taint.init_taint_analysis(nb_colors, nb_regs)
        jitter.jit.context.nb_colors = nb_colors
    except:
        print("No LLVMContext created, the jitter should be set to llvm")
        sys.exit(0)

#Function utils
def pyt2llvm(size, value):
    return llvm_ir.Constant(LLVMType.IntType(size),value)

def externalCall(fc_ptr, args,builder, var_name = ""):
    rb_root_pointer = builder.alloca(LLVMType.IntType(32))
    rb_root_u8 = builder.bitcast(rb_root_pointer, llvm_ir.IntType(8).as_pointer())
    args.append(rb_root_u8)
    builder.call(fc_ptr, args, name = var_name )
    #ret = builder.load(rb_root_u8)
    return rb_root_u8
