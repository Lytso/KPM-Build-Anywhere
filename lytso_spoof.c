/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 @ItsLytso. All Rights Reserved.
 *
 * Ultra-high-grade KernelPatch Module (KPM) for bootloader & cmdline spoofing.
 * Bypasses verifiedbootstate & bootloader unlock detection at Ring 0 (EL1).
 */

#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>

#define MODULE_TAG "[lytso_spoof] "
#define CMDLINE_BUF_SIZE 4096

KPM_NAME("lytso_cmdline_spoof");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("@ItsLytso");
KPM_DESCRIPTION("Bare-metal bootloader and cmdline spoofing KPM by @ItsLytso");

/* Storage for spoofed cmdline */
static char spoofed_cmdline[CMDLINE_BUF_SIZE];
static char *orig_saved_cmdline = NULL;
static char **g_p_saved_cmdline = NULL;
static char *g_boot_cmdline = NULL;

/* Function pointer definitions */
typedef int (*seq_puts_t)(void *m, const char *s);
typedef void (*seq_putc_t)(void *m, char c);

static seq_puts_t k_seq_puts = NULL;
static seq_putc_t k_seq_putc = NULL;
static void *target_cmdline_proc_show = NULL;
static int hook_installed = 0;

/* Helper: Safe in-place substring replacement */
static void replace_substr_equal(char *str, const char *orig, const char *rep, size_t len)
{
    char *p = strstr(str, orig);
    while (p) {
        memcpy(p, rep, len);
        p = strstr(p + len, orig);
    }
}

/* Inline hook for cmdline_proc_show(struct seq_file *m, void *v) */
static void before_cmdline_proc_show(hook_fargs2_t *args, void *udata)
{
    if (k_seq_puts && k_seq_putc && spoofed_cmdline[0]) {
        k_seq_puts((void *)args->arg0, spoofed_cmdline);
        k_seq_putc((void *)args->arg0, '\n');
        args->skip_origin = 1;
        args->ret = 0;
    }
}

/* Module initialization callback */
static long lytso_spoof_init(const char *args, const char *event, void *reserved)
{
    pr_info(MODULE_TAG "Initializing module... Event: %s, Args: %s\n", event ? event : "none", args ? args : "none");
    pr_info(MODULE_TAG "KernelPatch version: 0x%x, Kernel version: 0x%x\n", kpver, kver);

    /* 1. Resolve symbols */
    g_p_saved_cmdline = (char **)kallsyms_lookup_name("saved_command_line");
    g_boot_cmdline = (char *)kallsyms_lookup_name("boot_command_line");
    target_cmdline_proc_show = (void *)kallsyms_lookup_name("cmdline_proc_show");
    k_seq_puts = (seq_puts_t)kallsyms_lookup_name("seq_puts");
    k_seq_putc = (seq_putc_t)kallsyms_lookup_name("seq_putc");

    pr_info(MODULE_TAG "Symbols: saved_command_line=%p, boot_cmdline=%p, cmdline_proc_show=%p\n",
            g_p_saved_cmdline, g_boot_cmdline, target_cmdline_proc_show);

    /* 2. Patch saved_command_line */
    if (g_p_saved_cmdline && *g_p_saved_cmdline) {
        orig_saved_cmdline = *g_p_saved_cmdline;
        size_t orig_len = strlen(orig_saved_cmdline);

        if (orig_len < (CMDLINE_BUF_SIZE - 64)) {
            strlcpy(spoofed_cmdline, orig_saved_cmdline, sizeof(spoofed_cmdline));

            /* Replace orange with green (exact 36 bytes) */
            replace_substr_equal(spoofed_cmdline,
                                 "androidboot.verifiedbootstate=orange",
                                 "androidboot.verifiedbootstate=green ",
                                 36);

            /* Replace bl_state=2 with bl_state=0 (exact 23 bytes) */
            replace_substr_equal(spoofed_cmdline,
                                 "androidboot.bl_state=2",
                                 "androidboot.bl_state=0",
                                 22);

            /* Replace flash.locked=0 with flash.locked=1 if present */
            replace_substr_equal(spoofed_cmdline,
                                 "androidboot.flash.locked=0",
                                 "androidboot.flash.locked=1",
                                 26);

            /* If androidboot.flash.locked is not present, append it */
            if (!strstr(spoofed_cmdline, "androidboot.flash.locked=")) {
                strlcat(spoofed_cmdline, " androidboot.flash.locked=1", sizeof(spoofed_cmdline));
            }

            /* Redirect the global pointer */
            *g_p_saved_cmdline = spoofed_cmdline;
            pr_info(MODULE_TAG "saved_command_line successfully redirected to spoofed buffer!\n");
        } else {
            pr_warn(MODULE_TAG "original cmdline too large for buffer: %zu\n", orig_len);
        }
    } else {
        pr_warn(MODULE_TAG "saved_command_line symbol not available or NULL!\n");
    }

    /* 3. Patch boot_command_line in data section if found */
    if (g_boot_cmdline) {
        replace_substr_equal(g_boot_cmdline,
                             "androidboot.verifiedbootstate=orange",
                             "androidboot.verifiedbootstate=green ",
                             36);

        replace_substr_equal(g_boot_cmdline,
                             "androidboot.bl_state=2",
                             "androidboot.bl_state=0",
                             22);

        replace_substr_equal(g_boot_cmdline,
                             "androidboot.flash.locked=0",
                             "androidboot.flash.locked=1",
                             26);
        pr_info(MODULE_TAG "boot_command_line patched in-place!\n");
    }

    /* 4. Install inline hook on cmdline_proc_show */
    if (target_cmdline_proc_show && k_seq_puts && k_seq_putc) {
        hook_err_t err = hook_wrap2(target_cmdline_proc_show, before_cmdline_proc_show, NULL, NULL);
        if (err == HOOK_NO_ERR) {
            hook_installed = 1;
            pr_info(MODULE_TAG "hook_wrap2 on cmdline_proc_show installed successfully!\n");
        } else {
            pr_err(MODULE_TAG "hook_wrap2 failed with error code: %d\n", err);
        }
    }

    pr_info(MODULE_TAG "Module initialized successfully!\n");
    return 0;
}

/* Userspace control callback */
static long lytso_spoof_control0(const char *args, char *__user out_msg, int outlen)
{
    char buf[128] = "lytso_spoof: active | verifiedbootstate=green | bl_state=0 | flash.locked=1\n";
    pr_info(MODULE_TAG "Control query: %s\n", args ? args : "none");
    if (out_msg && outlen > 0) {
        compat_copy_to_user(out_msg, buf, sizeof(buf));
    }
    return 0;
}

/* Module cleanup callback */
static long lytso_spoof_exit(void *reserved)
{
    pr_info(MODULE_TAG "Exiting module...\n");

    /* 1. Unhook cmdline_proc_show */
    if (hook_installed && target_cmdline_proc_show) {
        hook_unwrap(target_cmdline_proc_show, before_cmdline_proc_show, NULL);
        hook_installed = 0;
        pr_info(MODULE_TAG "hook_wrap2 unwrapped.\n");
    }

    /* 2. Restore saved_command_line pointer */
    if (g_p_saved_cmdline && orig_saved_cmdline) {
        *g_p_saved_cmdline = orig_saved_cmdline;
        pr_info(MODULE_TAG "saved_command_line pointer restored.\n");
    }

    pr_info(MODULE_TAG "Module unloaded cleanly.\n");
    return 0;
}

KPM_INIT(lytso_spoof_init);
KPM_CTL0(lytso_spoof_control0);
KPM_EXIT(lytso_spoof_exit);
