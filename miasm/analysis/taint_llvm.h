#include "../jitter/interval_tree/interval_tree.h"
#include "../jitter/vm_mngr.h"
#include "../jitter/arch/JitCore_x86.h"
#if _WIN32
#define _MIASM_EXPORT __declspec(dllexport)
#else
#define _MIASM_EXPORT
#endif

#define REG 1
#define MEM 2
/**
 * Wrapper for interval_tree_new
 * This function uses the trick described in llvmconvert by fabrice and camille
 *
 * @param interval_tree A pointer to save the interval_tree created by interval_tree_new
*/

_MIASM_EXPORT struct rb_root* interval_tree_new_llvm(struct rb_root* interval_tree);
/**
 * Wrapper for interval_tree_merge.
 * This function uses the trick described in llvmconvert by fabrice and camille
 *
 * @param offset A signed long object which indicate the offset between the trees
 * @param interval_tree_new The pointer to the new interval_tree
 * @param interval_tree_tmp The pointer to the interval_tree of the current structure examined
*/
_MIASM_EXPORT struct rb_root* taint_merge_interval_tree(signed long offset, 
                                                        struct rb_root* interval_tree_new, 
                                                        struct rb_root* interval_tree_tmp);

_MIASM_EXPORT void wrap_clean_all_callback_info(JitCpu* jitter);

/**
 * Taint wether a register or a range of the memory
 * Wraps the functions taint_register and taint_memory from taint.c
 *
 * @param fully_tainted Needed to optimize the taint process, an uint64_t value
 * @param index_or_addr Can be and index or an adress depending of the structure
 * @param structure_size The size of the register, or the range of the memory
 * @param current_color Index of the current color
 * @param jitter A jitter class. Used to retrieve the taint_t object
 * @param vm_mngr The vm manager
 * @param type The type of the structure
 * @param interval_tree_before A pointer to retrieve the rb_root of interval_tree_before
 * @param interval_tree_new A pointer to retrieve the rb_root of interval_tree_new
*/

_MIASM_EXPORT void taint_generic_structure(uint64_t fully_tainted,
                                           uint64_t index_or_addr,
                                           uint64_t structure_size,
                                           uint64_t current_color,
                                           JitCpu* jitter,
                                           vm_mngr_t* vm_mngr,
                                           uint64_t type,
                                           struct rb_root* interval_tree_before,
                                           struct rb_root* interval_tree_new);

/**
 * Get wether the interval_tree of a register or a range of the memory
 * Wraps the functions taint_get_register and taint_get_memory from taint.c
 *
 * @param jitter A jitter class. Used to retrieve the taint_t object
 * @param color_index Index of the current color
 * @param register_index The index of the register, is equal to 0 when getting memory
 * @param interval The interval examinated of the structure
 * @param type The type of the structure
 * @param interval_tree_before A pointer to save the interval_tree returned
*/
_MIASM_EXPORT struct rb_root* get_generic_structure(JitCpu* jitter,
                                         uint64_t color_index,
                                         uint64_t register_index,
                                         struct interval interval,
                                         uint64_t type,
                                         struct rb_root* structure_interval_tree);

/**
 * Check that the interval_tree sent is not empty
 *
 * @param interval_tree A pointer to the interval_tree examined
*/
_MIASM_EXPORT uint64_t check_rb_tree_not_empty(struct rb_root* interval_tree);
