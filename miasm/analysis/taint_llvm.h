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
 * Wrapper of interval_tree_new
 * This function handles the pointers and not the real structure
 *
 * @param interval_tree A pointer to save the new interval_tree 
 * @return A pointer to the interval_tree 
*/
_MIASM_EXPORT struct rb_root* interval_tree_new_llvm(struct rb_root* interval_tree);

/**
 * Wrapper of interval_tree_merge.
 *
 * @param offset The offset is equal to the adress of the memory analysed
 * @param interval_tree_new A pointer to the new interval_tree
 * @param interval_tree_tmp A pointer to the interval_tree of the current structure analysed
*/
_MIASM_EXPORT struct rb_root* taint_merge_interval_tree(signed long offset, 
                                                        struct rb_root* interval_tree_new, 
                                                        struct rb_root* interval_tree_tmp);

/**
 * Wrapper of clean_callback_info
 *
 * @param jitter To retrieve the callbacks informations
 * @param clean_callback_infos A boolean value to clean or not
 * @param color Clean the callback informations of this color
 */
_MIASM_EXPORT void wrap_clean_callback_info(JitCpu* jitter, uint64_t clean_callback_infos, uint64_t color);

/**
 * Taint wether a register or a range of memory
 * Wraper of taint_register and taint_memory from taint.c
 *
 * @param fully_tainted A boolean value, if the destination should be completely taint
 * @param index_or_addr Regarding the structure, wether the index of the register of the address of the memory 
 * @param structure_size An uint64_t
 * @param current_color Index of the current color
 * @param jitter A jitter class. Used to retrieve the taint_t object
 * @param vm_mngr To taint the memory
 * @param type The type of structure
 * @param interval_tree_before A pointer to interval_tree_before
 * @param interval_tree_new A pointer to interval_tree_new
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
 * @param register_index The index of the register, is equal to -1 when getting memory
 * @param interval The interval analysed for the current structure
 * @param type The type structure
 * @param interval_tree_before A pointer to the interval_tree
*/
_MIASM_EXPORT struct rb_root* get_generic_structure(JitCpu* jitter,
                                         uint64_t color_index,
                                         uint64_t register_index,
                                         struct interval interval,
                                         uint64_t type,
                                         struct rb_root* structure_interval_tree);

/**
 * Check that the interval_tree is not empty
 *
 * @param interval_tree A pointer to the interval_tree 
*/
_MIASM_EXPORT uint64_t check_rb_tree_not_empty(struct rb_root* interval_tree);
