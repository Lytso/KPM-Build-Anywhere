# KPM-Build-Anywhere & Lytso Cmdline Spoof

Build KernelPatch KPM modules anywhere (locally in Termux / Linux / macOS / Windows or via GitHub Actions).

## Modules Included

### `lytso_spoof.kpm` (by @ItsLytso)
Ultra-high-grade bare-metal KernelPatch Module that spoofs the bootloader unlock state and kernel commandline at Ring 0 (EL1).
- **Substitutes**:
  - `androidboot.verifiedbootstate=orange` -> `androidboot.verifiedbootstate=green `
  - `androidboot.bl_state=2` -> `androidboot.bl_state=0`
  - `androidboot.flash.locked=0` -> `androidboot.flash.locked=1`
- **Hook mechanism**:
  - Direct kernel `saved_command_line` pointer redirection.
  - In-place patching of `boot_command_line`.
  - Dynamic ARM64 inline hook on `cmdline_proc_show` using `hook_wrap2`.
- **Formatting Proof**:
  - When embedded into `boot.img` with FolkPatch or `kptools`, triggers at `pre-kernel-init` before Android `/system/bin/init` starts.
  - Survives system formatting and factory resets without requiring userspace root daemons.

## How to Test / Load Runtime (FolkPatch)

1. Open **FolkPatch** / **APatch**.
2. Go to **KPM** -> Select `lytso_spoof.kpm`.
3. Tap **Load** (Carregar) to test in real-time memory without flashing.
4. Verify `/proc/cmdline` and Native Detector.

## How to Embed into `boot.img` (Format-Proof)

In **FolkPatch**:
- Select `lytso_spoof.kpm` -> Tap **Embed** (Embutir).

Via **kptools CLI**:
```bash
kptools -p -i /dev/block/by-name/boot_a -k /path/to/kpimg -s <superkey> -M lytso_spoof.kpm -T kpm -V pre-kernel-init -o /sdcard/boot_patched.img
```

## Credits
- Author: @ItsLytso
- KernelPatch: https://github.com/bmax121/KernelPatch & https://github.com/LyraVoid/KernelPatch
