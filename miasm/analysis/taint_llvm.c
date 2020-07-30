#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include "../jitter/compat_py23.h"
#include "../jitter/bn.h"
#include "../jitter/queue.h"
#include "../jitter/vm_mngr.h"
#include "../jitter/vm_mngr_py.h"
#include "../jitter/JitCore.h"
#include "../jitter/interval_tree/interval_tree.h"
#include "../jitter/interval_tree/rbtree.h"

#include "taint.h"
#include "taint_llvm.h"



struct rb_root*
interval_tree_new_llvm(struct rb_root* interval_tree)
{
    *interval_tree = interval_tree_new();
    return interval_tree;
}


struct rb_root*
taint_merge_interval_tree(signed long offset, struct rb_root* interval_tree_new, struct rb_root* interval_tree_tmp)
{
   interval_tree_merge(interval_tree_new, interval_tree_tmp, offset);
   return interval_tree_new;
}

void 
wrap_clean_callback_info(JitCpu* jitter, uint64_t clean_callback_infos, uint64_t color)
{
   if (clean_callback_infos)
      taint_clean_callback_info(jitter->taint->taint, color);

}


struct rb_root*
get_generic_structure(JitCpu* jitter,
                      uint64_t color_index,
                      uint64_t register_index,
                      struct interval interval,
                      uint64_t type,
                      struct rb_root* structure_interval_tree)
{
    if(type == REG)
        *structure_interval_tree = taint_get_register_color(jitter->taint->taint,
                                                           color_index,
                                                           register_index,
                                                           interval);
    else if(type == MEM){
        *structure_interval_tree = taint_get_memory(jitter->taint->taint,
                                                   color_index,
                                                   interval);
    } 

    else{
        fprintf(stderr, "Can't get an other structure than registers or memory\n");
        exit(1);
    }

    return structure_interval_tree;
}

void
taint_generic_structure(uint64_t fully_tainted,
                        uint64_t index_or_addr,
                        uint64_t structure_size,
                        uint64_t current_color,
                        JitCpu* jitter,
                        vm_mngr_t* vm_mngr,
                        uint64_t type,
                        struct rb_root* interval_tree_before,
                        struct rb_root* interval_tree_new)
{
    if(type == REG)
        taint_register(fully_tainted,
                       index_or_addr,
                       structure_size,
                       current_color,
                       jitter->taint->taint,
                       vm_mngr,
                       interval_tree_before,
                       interval_tree_new);
    else if (type == MEM)
        taint_memory(fully_tainted,
                     index_or_addr,
                     structure_size,
                     current_color,
                     jitter->taint->taint,
                     vm_mngr,
                     interval_tree_before,
                     interval_tree_new);
    else{
        fprintf(stderr, "Can't taint other than registers and memory\n");
        exit(1);
    }

    interval_tree_free(interval_tree_before);
    interval_tree_free(interval_tree_new);
}

uint64_t check_rb_tree_not_empty(struct rb_root* interval_tree)
{
    uint64_t fully_tainted = 0;
    if(rb_first(interval_tree) != NULL){
        fully_tainted = 1;
    }
    return fully_tainted;
}
