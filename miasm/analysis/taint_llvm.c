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



void
interval_tree_new_llvm(char* ptr){
    //fprintf(stderr, "Enter : interval_tree_new_llvm\n");
    struct rb_root interval_tree;
    interval_tree = interval_tree_new();
    memcpy(ptr, (char*) &interval_tree, 4);
    //fprintf(stderr, "Exit : interval_tree_new_llvm\n");
}


void
taint_merge_interval_tree(signed long offset, char* ptr_new, char* ptr_tmp)
{
   struct rb_root interval_tree_new, interval_tree_tmp;
   memcpy(&interval_tree_new, ptr_new, 4);
   memcpy(&interval_tree_tmp, ptr_tmp, 4);
   interval_tree_merge(&interval_tree_new, &interval_tree_tmp, offset);
   memcpy(ptr_new, (char*)&interval_tree_new, 4);

}


void
get_generic_structure(JitCpu* jitter,
                      uint64_t color_index,
                      uint64_t register_index,
                      struct interval interval,
                      uint64_t type,
                      char* ptr)
{
    //fprintf(stderr, "Enter : get_generic_structure\n");
    struct rb_root structure_interval_tree;
   // fprintf(stderr, "Get generic\n");
   // fprintf(stderr, "type : %lld, value %lld \n", type, register_index);
   // fprintf(stderr, "\tThe interval: %ld -> %ld\n", interval.start, interval.last);
    if(type == REG){
        structure_interval_tree = taint_get_register_color(jitter->taint->taint,
                                                           color_index,
                                                           register_index,
                                                           interval);
    }
    else if(type == MEM){
        structure_interval_tree = taint_get_memory(jitter->taint->taint,
                                                   color_index,
                                                   interval);
        }
    else
    {
        fprintf(stderr, "Can't get an other structure than registers or memory\n");
        exit(1);
    }
    if(rb_first(&structure_interval_tree)!= NULL){
        fprintf(stderr, "register_index: %lld\n", register_index);
        interval_tree_print(&structure_interval_tree);
    }
    memcpy(ptr, (char*)&structure_interval_tree, 4);
    //fprintf(stderr, "Exit : get_generic_structure\n");

}

void
taint_generic_structure(uint64_t fully_tainted,
                        uint64_t index_or_addr,
                        uint64_t structure_size,
                        uint64_t current_color,
                        JitCpu* jitter,
                        vm_mngr_t* vm_mngr,
                        uint64_t type,
                        char* ptr_before,
                        char* ptr_new)
{
    struct rb_root taint_interval_tree_before;
    struct rb_root taint_interval_tree_new;
    memcpy(&taint_interval_tree_before, ptr_before, 4);
    memcpy(&taint_interval_tree_new, ptr_new, 4);
    if(type == REG)
        taint_register(fully_tainted,
                       index_or_addr,
                       structure_size,
                       current_color,
                       jitter->taint->taint,
                       vm_mngr,
                       &taint_interval_tree_before,
                       &taint_interval_tree_new);
    else if (type == MEM)
        taint_memory(fully_tainted,
                     index_or_addr,
                     structure_size,
                     current_color,
                     jitter->taint->taint,
                     vm_mngr,
                     &taint_interval_tree_before,
                     &taint_interval_tree_new);
    else
    {
        fprintf(stderr, "Can't taint other than registers and memory\n");
        exit(1);
    }
    interval_tree_free(&taint_interval_tree_before);
    interval_tree_free(&taint_interval_tree_new);
    //fprintf(stderr,"Exit : taint_generic_structure\n");

}

uint64_t check_rb_tree_not_empty(char* ptr)
{
    uint64_t fully_tainted = 0;
    struct rb_root interval_tree;
    memcpy(&interval_tree, ptr,4);
    if(rb_first(&interval_tree) != NULL){
        fully_tainted = 1;
    }
    return fully_tainted;
}
