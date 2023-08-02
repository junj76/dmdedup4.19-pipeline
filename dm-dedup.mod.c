#include <linux/build-salt.h>
#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x17ed7d45, "module_layout" },
	{ 0x7551b46e, "dm_tm_open_with_sm" },
	{ 0x573a6530, "alloc_pages_current" },
	{ 0x52be5ba2, "kmalloc_caches" },
	{ 0xd2b09ce5, "__kmalloc" },
	{ 0x48e323be, "dm_bm_unlock" },
	{ 0xb9d99025, "bio_alloc_bioset" },
	{ 0x49081644, "dm_btree_remove" },
	{ 0xa4a9f3a5, "crypto_alloc_shash" },
	{ 0xd6ee688f, "vmalloc" },
	{ 0xdaf485b9, "pv_lock_ops" },
	{ 0x754d539c, "strlen" },
	{ 0x8df1d64b, "__ubsan_handle_load_invalid_value" },
	{ 0x381e7e01, "dm_get_device" },
	{ 0xb3672773, "dm_io" },
	{ 0x43a53735, "__alloc_workqueue_key" },
	{ 0x263ed23b, "__x86_indirect_thunk_r12" },
	{ 0xf398644f, "dm_btree_lookup_next" },
	{ 0x6d0f1f89, "dm_table_get_mode" },
	{ 0x764567c8, "dm_btree_find_highest_key" },
	{ 0x688d422d, "dm_bm_block_size" },
	{ 0xad27f361, "__warn_printk" },
	{ 0x9300507b, "mempool_destroy" },
	{ 0xc29957c3, "__x86_indirect_thunk_rcx" },
	{ 0x867050ac, "bioset_init" },
	{ 0xa6093a32, "mutex_unlock" },
	{ 0xfebeb5cd, "crypto_shash_final" },
	{ 0x999e8297, "vfree" },
	{ 0x4c90629, "dm_register_target" },
	{ 0xc623371d, "__ubsan_handle_sub_overflow" },
	{ 0xb4e20c35, "__ubsan_handle_builtin_unreachable" },
	{ 0x97651e6c, "vmemmap_base" },
	{ 0x9fb8630a, "kthread_create_on_node" },
	{ 0xd163cade, "dm_tm_commit" },
	{ 0x24621ca3, "dm_sm_disk_open" },
	{ 0x9e4faeef, "dm_io_client_destroy" },
	{ 0x2417c5c4, "dm_btree_empty" },
	{ 0xfb578fc5, "memset" },
	{ 0xb4c76e76, "dm_set_target_max_io_len" },
	{ 0x752d5f5b, "kstrtobool" },
	{ 0x4f477261, "dm_bm_checksum" },
	{ 0x2ce6d155, "__ubsan_handle_divrem_overflow" },
	{ 0x7c32d0f0, "printk" },
	{ 0x62d33cea, "kthread_stop" },
	{ 0x449ad0a7, "memcmp" },
	{ 0x72289260, "dm_block_manager_destroy" },
	{ 0x94c38bc5, "crypto_shash_update" },
	{ 0xa5128c13, "bio_add_page" },
	{ 0xa69291cd, "zero_fill_bio_iter" },
	{ 0xdee10e6c, "bio_clone_fast" },
	{ 0x5349c64, "dm_unregister_target" },
	{ 0xaafdc258, "strcasecmp" },
	{ 0x48d1c7dc, "dm_btree_find_lowest_key" },
	{ 0x5eb24829, "dm_shift_arg" },
	{ 0x593c1bac, "__x86_indirect_thunk_rbx" },
	{ 0x5375ca71, "dm_bm_write_lock" },
	{ 0x41aed6e7, "mutex_lock" },
	{ 0x8c03d20c, "destroy_workqueue" },
	{ 0x82137c69, "generic_make_request" },
	{ 0x42160169, "flush_workqueue" },
	{ 0x6a9d3fc3, "bio_endio" },
	{ 0xc2b69e4e, "bio_put" },
	{ 0x7ade1071, "dm_tm_destroy" },
	{ 0x7485935a, "dm_btree_lookup" },
	{ 0x30c37cc0, "dm_bm_write_lock_zero" },
	{ 0x7cd8d75e, "page_offset_base" },
	{ 0xc115a0ef, "__ubsan_handle_out_of_bounds" },
	{ 0x86c45796, "mempool_alloc" },
	{ 0xa916b694, "strnlen" },
	{ 0xd51c29f1, "dm_sm_disk_create" },
	{ 0x5cf0d0bb, "dm_tm_create_with_sm" },
	{ 0xdb7305a1, "__stack_chk_fail" },
	{ 0x7b6b3af5, "dm_bm_read_lock" },
	{ 0x4a4cb558, "dm_btree_insert_notify" },
	{ 0x6a244503, "mempool_create" },
	{ 0x2ea2c95c, "__x86_indirect_thunk_rax" },
	{ 0x6a037cf1, "mempool_kfree" },
	{ 0xd2a4d33, "crypto_destroy_tfm" },
	{ 0xca8c6cf3, "wake_up_process" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0xcbd4898c, "fortify_panic" },
	{ 0x86d10949, "kmem_cache_alloc_trace" },
	{ 0x74b55fe, "mempool_free" },
	{ 0xdbf17652, "_raw_spin_lock" },
	{ 0x4302d0eb, "free_pages" },
	{ 0x54f69d, "dm_tm_pre_commit" },
	{ 0xb3f7646e, "kthread_should_stop" },
	{ 0x601f665f, "dm_io_client_create" },
	{ 0xa05c03df, "mempool_kmalloc" },
	{ 0x5475ba9e, "dm_block_location" },
	{ 0x37a0cba, "kfree" },
	{ 0xa46f2f1b, "kstrtouint" },
	{ 0x69acdf38, "memcpy" },
	{ 0xf05c7b8, "__x86_indirect_thunk_r15" },
	{ 0x4ca9669f, "scnprintf" },
	{ 0xa7401502, "dm_block_manager_create" },
	{ 0x951a2773, "crypto_has_alg" },
	{ 0x9601f0de, "dm_put_device" },
	{ 0x1e3f728d, "dm_block_data" },
	{ 0x2e0d2f7f, "queue_work_on" },
	{ 0xe198232, "dm_btree_insert" },
	{ 0xb0e602eb, "memmove" },
	{ 0xe1095cee, "__ubsan_handle_add_overflow" },
	{ 0x42694cb8, "__ubsan_handle_type_mismatch" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=dm-persistent-data";


MODULE_INFO(srcversion, "198DF3C8854BBF47FF130E8");
