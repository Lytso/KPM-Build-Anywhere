/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 @ItsLytso. All Rights Reserved.
 *
 * Ultra-high-grade KernelPatch Module (KPM) for bootloader & cmdline spoofing.
 * Bypasses verifiedbootstate & bootloader unlock detection at Ring 0 (EL1).
 */

#include <compiler.h>
#include <kpmodule.h>
#include <hotpatch.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>

#define MODULE_TAG "[lytso_spoof] "
#define CMDLINE_BUF_SIZE 4096

KPM_NAME("lytso_cmdline_spoof");
KPM_VERSION("1.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("@ItsLytso");
KPM_DESCRIPTION("Bare-metal bootloader and cmdline spoofing KPM by @ItsLytso");

static char spoofed_cmdline[CMDLINE_BUF_SIZE];
static char *orig_saved_cmdline = NULL;
static char **g_p_saved_cmdline = NULL;

/* Safe 64-bit kernel pointer write using KernelPatch's hotpatch */
static int safe_write_ptr(void *target_addr, void *new_val)
{
    uint64_t val = (uint64_t)new_val;
    uint32_t low = (uint32_t)(val & 0xFFFFFFFF);
    uint32_t high = (uint32_t)(val >> 32);

    int r1 = hotpatch_nosync(target_addr, low);
    if (r1) {
        pr_err(MODULE_TAG "hotpatch_nosync low failed: %d\n", r1);
        return r1;
    }
    int r2 = hotpatch_nosync((char *)target_addr + 4, high);
    if (r2) {
        pr_err(MODULE_TAG "hotpatch_nosync high failed: %d\n", r2);
        return r2;
    }
    return 0;
}

/* Helper: In-place substring replacement */
static void replace_substr_equal(char *str, const char *orig, const char *rep, size_t len)
{
    char *p = strstr(str, orig);
    while (p) {
        memcpy(p, rep, len);
        p = strstr(p + len, orig);
    }
}

static long lytso_spoof_init(const char *args, const char *event, void *reserved)
{
    pr_info(MODULE_TAG "Initializing v1.1.0... Event: %s, Args: %s\n",
            event ? event : "none", args ? args : "none");
    pr_info(MODULE_TAG "KernelPatch: 0x%x, Kernel: 0x%x\n", kpver, kver);

    /* 1. Resolve saved_command_line symbol */
    g_p_saved_cmdline = (char **)kallsyms_lookup_name("saved_command_line");
    if (!g_p_saved_cmdline) {
        pr_err(MODULE_TAG "saved_command_line symbol lookup failed!\n");
        return -1;
    }

    orig_saved_cmdline = *g_p_saved_cmdline;
    if (!orig_saved_cmdline) {
        pr_err(MODULE_TAG "*saved_command_line is NULL!\n");
        return -1;
    }

    size_t orig_len = strlen(orig_saved_cmdline);
    if (orig_len >= (CMDLINE_BUF_SIZE - 64)) {
        pr_err(MODULE_TAG "original cmdline too large: %zu\n", orig_len);
        return -1;
    }

    /* 2. Copy to our static buffer */
    strlcpy(spoofed_cmdline, orig_saved_cmdline, sizeof(spoofed_cmdline));

    /* 3. Perform replacements in our buffer */
    replace_substr_equal(spoofed_cmdline,
                         "androidboot.verifiedbootstate=orange",
                         "androidboot.verifiedbootstate=green ",
                         36);

    replace_substr_equal(spoofed_cmdline,
                         "androidboot.bl_state=2",
                         "androidboot.bl_state=0",
                         22);

    replace_substr_equal(spoofed_cmdline,
                         "androidboot.flash.locked=0",
                         "androidboot.flash.locked=1",
                         26);

    if (!strstr(spoofed_cmdline, "androidboot.flash.locked=")) {
        strlcat(spoofed_cmdline, " androidboot.flash.locked=1", sizeof(spoofed_cmdline));
    }

    /* 4. Safely redirect saved_command_line via hotpatch_nosync */
    int rc = safe_write_ptr(g_p_saved_cmdline, spoofed_cmdline);
    if (rc) {
        pr_err(MODULE_TAG "Failed to redirect saved_command_line: %d\n", rc);
        return rc;
    }

    pr_info(MODULE_TAG "saved_command_line successfully redirected to spoofed buffer!\n");
    return 0;
}

static long lytso_spoof_control0(const char *args, char *__user out_msg, int outlen)
{
    char buf[128] = "lytso_spoof: active | verifiedbootstate=green | bl_state=0 | flash.locked=1\n";
    if (out_msg && outlen > 0) {
        compat_copy_to_user(out_msg, buf, sizeof(buf));
    }
    return 0;
}

static long lytso_spoof_exit(void *reserved)
{
    pr_info(MODULE_TAG "Exiting module...\n");

    if (g_p_saved_cmdline && orig_saved_cmdline) {
        safe_write_ptr(g_p_saved_cmdline, orig_saved_cmdline);
        pr_info(MODULE_TAG "saved_command_line restored to original.\n");
    }

    pr_info(MODULE_TAG "Unloaded cleanly.\n");
    return 0;
}

KPM_INIT(lytso_spoof_init);
KPM_CTL0(lytso_spoof_control0);
KPM_EXIT(lytso_spoof_exit);
