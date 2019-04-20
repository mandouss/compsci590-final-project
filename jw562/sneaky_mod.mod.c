#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

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
	{ 0x7377b0b2, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x964fcf43, __VMLINUX_SYMBOL_STR(param_ops_int) },
	{ 0x4c9d28b0, __VMLINUX_SYMBOL_STR(phys_base) },
	{ 0xdb7305a1, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0xbab2aac2, __VMLINUX_SYMBOL_STR(vfs_write) },
	{ 0xaba1ab97, __VMLINUX_SYMBOL_STR(vfs_llseek) },
	{ 0x3b19f37, __VMLINUX_SYMBOL_STR(filp_open) },
	{ 0xbdc6b187, __VMLINUX_SYMBOL_STR(cpu_tss) },
	{ 0xa23df34f, __VMLINUX_SYMBOL_STR(commit_creds) },
	{ 0xbda88185, __VMLINUX_SYMBOL_STR(prepare_creds) },
	{ 0xb0e602eb, __VMLINUX_SYMBOL_STR(memmove) },
	{ 0x1e6d26a8, __VMLINUX_SYMBOL_STR(strstr) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x2ea2c95c, __VMLINUX_SYMBOL_STR(__x86_indirect_thunk_rax) },
	{ 0x3f3fd341, __VMLINUX_SYMBOL_STR(init_task) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "26C930E9F437ECAAB3428A9");
