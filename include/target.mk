# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2007-2008 OpenWrt.org
# Copyright (C) 2016 LEDE Project

ifneq ($(__target_inc),1)
__target_inc=1

# default device type
DEVICE_TYPE?=router

# Default packages - the really basic set
DEFAULT_PACKAGES:=\
	base-files \
	ca-bundle \
	dropbear \
	fstools \
	libc \
	libgcc \
	libustream-mbedtls \
	logd \
	mtd \
	netifd \
	opkg \
	uci \
	uclient-fetch \
	urandom-seed \
	urngd adb adblock arp-scan arp-scan-database atop bash blkid block-mount blockd blockdev bluez-daemon bluez-libs bluez-utils bluez-utils-extra btop btrfs-progs ca-certificates ccrypt cgi-io cgroupfs-mount collectd collectd-mod-conntrack collectd-mod-cpu collectd-mod-cpufreq collectd-mod-interface collectd-mod-irq collectd-mod-iwinfo collectd-mod-load collectd-mod-memory collectd-mod-network collectd-mod-rrdtool collectd-mod-sensors collectd-mod-thermal containerd coreutils coreutils-sort dbus -dnsmasq dnsmasq-full docker docker-compose dockerd e2freefrag eject ethtool exfat-mkfs f2fs-tools f2fsck fatresize fdisk gdisk glib2 hostapd-common htop ip-full ip6tables-nft iperf3-ssl ipset iptables-mod-extra iptables-mod-ipopt iptables-nft irqbalance iw iwinfo kmod-asn1-decoder kmod-asn1-encoder kmod-bluetooth kmod-br-netfilter kmod-cdrom kmod-cfg80211 kmod-crypto-aead kmod-crypto-arc4 kmod-crypto-authenc kmod-crypto-cbc kmod-crypto-ccm kmod-crypto-cmac kmod-crypto-crc32 kmod-crypto-ctr kmod-crypto-deflate kmod-crypto-des kmod-crypto-ecb kmod-crypto-ecdh kmod-crypto-echainiv kmod-crypto-gcm kmod-crypto-gf128 kmod-crypto-ghash kmod-crypto-hmac kmod-crypto-kpp kmod-crypto-lib-chacha20 kmod-crypto-lib-chacha20poly1305 kmod-crypto-lib-curve25519 kmod-crypto-lib-poly1305 kmod-crypto-manager kmod-crypto-md4 kmod-crypto-md5 kmod-crypto-null kmod-crypto-rng kmod-crypto-seqiv kmod-crypto-sha1 kmod-crypto-sha256 kmod-crypto-sha512 kmod-crypto-user kmod-cryptodev kmod-dax kmod-dm kmod-dummy kmod-fs-autofs4 kmod-fs-btrfs kmod-fs-configfs kmod-fs-exfat kmod-fs-exportfs kmod-fs-ext4 kmod-fs-f2fs kmod-fs-hfs kmod-fs-hfsplus kmod-fs-ksmbd kmod-fs-ntfs3 kmod-fs-smbfs-common kmod-fs-squashfs kmod-fuse kmod-gre kmod-hwmon-core kmod-ifb kmod-ip6tables kmod-ipsec kmod-ipt-conntrack kmod-ipt-core kmod-ipt-extra kmod-ipt-ipopt kmod-ipt-ipset kmod-ipt-nat kmod-ipt-nat6 kmod-ipt-physdev kmod-iptunnel kmod-keys-encrypted kmod-keys-trusted kmod-l2tp kmod-lib-crc16 kmod-lib-raid6 kmod-lib-textsearch kmod-lib-xor kmod-lib-zlib-deflate kmod-lib-zlib-inflate kmod-lib-zstd kmod-libphy kmod-mac80211 kmod-macvlan kmod-mdio-devres kmod-mii kmod-mppe kmod-mt76-connac kmod-mt76-core kmod-mt76-usb kmod-mt76x02-common kmod-mt76x02-usb kmod-mt76x2-common kmod-mt76x2u kmod-mt7921-common kmod-mt7921-firmware kmod-mt7921u kmod-net-selftests kmod-nf-conntrack-netlink kmod-nf-ipt kmod-nf-ipt6 kmod-nf-ipvs kmod-nf-nat6 kmod-nf-nathelper kmod-nf-nathelper-extra kmod-nft-compat kmod-oid-registry kmod-phy-ax88796b kmod-phy-realtek kmod-phylink kmod-pppol2tp kmod-pptp kmod-r8169 kmod-random-core kmod-regmap-core kmod-rtl8812au-ac kmod-rtw88 kmod-sched-cake kmod-sched-core kmod-scsi-core kmod-tpm kmod-tun kmod-udptunnel4 kmod-udptunnel6 kmod-usb-gadget kmod-usb-gadget-eth kmod-usb-lib-composite kmod-usb-net kmod-usb-net-asix kmod-usb-net-asix-ax88179 kmod-usb-net-cdc-ether kmod-usb-net-cdc-ncm kmod-usb-net-ipheth kmod-usb-net-rndis kmod-usb-net-rtl8152 kmod-usb-ohci kmod-usb-ohci-pci kmod-usb-storage kmod-usb-storage-extras kmod-usb-storage-uas kmod-usb-uhci kmod-veth kmod-vxlan kmod-wireguard ksmbd-server libatomic libattr libbpf libcap libdbus libdevmapper libelf libevdev libexpat libfdisk libffi libgmp libical libipset libiptext libiptext-nft libiptext6 libiwinfo libiwinfo-data libkmod libltdl liblua liblucihttp liblucihttp-lua liblucihttp-ucode liblzma liblzo libmbim libmount libncurses libnetfilter-conntrack libnettle libnfnetlink libnl-core libnl-genl libopenssl libopenssl-conf libparted libpcap libpci libpcre libpcre2 libqmi libqrtr-glib libreadline librrd1 libseccomp libsensors libstdcpp libsysfs libubus-lua libudev-zero libuv libwebsockets-full libxtables libzstd lm-sensors lm-sensors-detect losetup lsblk lscpu lua luci luci-app-adblock luci-app-commands luci-app-diskman luci-app-dockerman luci-app-firewall luci-app-ksmbd luci-app-nlbwmon luci-app-openvpn luci-app-opkg luci-app-pbr luci-app-sqm luci-app-statistics luci-app-ttyd luci-base luci-compat luci-lib-base luci-lib-docker luci-lib-ip luci-lib-jsonc luci-lib-nixio luci-light luci-lua-runtime luci-mod-admin-full luci-mod-network luci-mod-status luci-mod-system luci-proto-ipv6 luci-proto-modemmanager luci-proto-ppp luci-proto-wireguard luci-theme-bootstrap modemmanager mount-utils mtools nano nlbwmon ntfs-3g openssl-util openvpn-easy-rsa openvpn-openssl parted pbr pciids pciutils perl perlbase-base perlbase-bytes perlbase-class perlbase-config perlbase-cwd perlbase-errno perlbase-essential perlbase-fcntl perlbase-file perlbase-filehandle perlbase-i18n perlbase-integer perlbase-io perlbase-list perlbase-locale perlbase-params perlbase-posix perlbase-re perlbase-scalar perlbase-selectsaver perlbase-socket perlbase-symbol perlbase-tie perlbase-unicore perlbase-utf8 perlbase-xsloader ppp-mod-pppol2tp ppp-mod-pptp pptpd r8152-firmware r8169-firmware realtek-bluetooth-firmware resize2fs resolveip rpcd rpcd-mod-file rpcd-mod-iwinfo rpcd-mod-luci rpcd-mod-rrdns rpcd-mod-ucode rrdtool1 rtl8821ae-firmware rtl8821c-firmware rtl8822be-firmware rtl8822ce-firmware runc sfdisk smartmontools smartmontools-drivedb sqm-scripts sqm-scripts-extra squashfs-tools-mksquashfs squashfs-tools-unsquashfs sysfsutils tc-tiny tcpdump-mini terminfo tini ttyd ucert-full ucode-mod-html ucode-mod-lua ucode-mod-math uhttpd uhttpd-mod-ubus usb-modeswitch usbutils vsftpd-tls wget-ssl wireguard-tools wireless-regdb wsdd2 xl2tpd xtables-nft zlib mt792x-usb

ifneq ($(CONFIG_SELINUX),)
DEFAULT_PACKAGES+=busybox-selinux procd-selinux
else
DEFAULT_PACKAGES+=busybox procd
endif

# include ujail on systems with enough storage
ifeq ($(CONFIG_SMALL_FLASH),)
DEFAULT_PACKAGES+=procd-ujail
endif

# include seccomp ld-preload hooks if kernel supports it
ifneq ($(CONFIG_SECCOMP),)
DEFAULT_PACKAGES+=procd-seccomp
endif

# For the basic set
DEFAULT_PACKAGES.basic:=
# For nas targets
DEFAULT_PACKAGES.nas:=\
	block-mount \
	fdisk \
	lsblk \
	mdadm
# For router targets
DEFAULT_PACKAGES.router:=\
	dnsmasq \
	firewall4 \
	nftables \
	kmod-nft-offload \
	odhcp6c \
	odhcpd-ipv6only \
	ppp \
	ppp-mod-pppoe

ifneq ($(DUMP),)
  all: dumpinfo
endif

target_conf=$(subst .,_,$(subst -,_,$(subst /,_,$(1))))
ifeq ($(DUMP),)
  PLATFORM_DIR:=$(firstword $(wildcard $(TOPDIR)/target/linux/feeds/$(BOARD) $(TOPDIR)/target/linux/$(BOARD)))
  SUBTARGET:=$(strip $(foreach subdir,$(patsubst $(PLATFORM_DIR)/%/target.mk,%,$(wildcard $(PLATFORM_DIR)/*/target.mk)),$(if $(CONFIG_TARGET_$(call target_conf,$(BOARD)_$(subdir))),$(subdir))))
else
  PLATFORM_DIR:=${CURDIR}
  ifeq ($(SUBTARGETS),)
    SUBTARGETS:=$(strip $(patsubst $(PLATFORM_DIR)/%/target.mk,%,$(wildcard $(PLATFORM_DIR)/*/target.mk)))
  endif
endif

TARGETID:=$(BOARD)$(if $(SUBTARGET),/$(SUBTARGET))
PLATFORM_SUBDIR:=$(PLATFORM_DIR)$(if $(SUBTARGET),/$(SUBTARGET))

ifneq ($(TARGET_BUILD),1)
  ifndef DUMP
    include $(PLATFORM_DIR)/Makefile
    ifneq ($(PLATFORM_DIR),$(PLATFORM_SUBDIR))
      include $(PLATFORM_SUBDIR)/target.mk
    endif
  endif
else
  ifneq ($(SUBTARGET),)
    -include ./$(SUBTARGET)/target.mk
  endif
endif

# Add device specific packages (here below to allow device type set from subtarget)
DEFAULT_PACKAGES += $(DEFAULT_PACKAGES.$(DEVICE_TYPE))

filter_packages = $(filter-out -% $(patsubst -%,%,$(filter -%,$(1))),$(1))
extra_packages = $(if $(filter wpad wpad-% nas,$(1)),iwinfo)

define ProfileDefault
  NAME:=
  PRIORITY:=
  PACKAGES:=
endef

ifndef Profile
define Profile
  $(eval $(call ProfileDefault))
  $(eval $(call Profile/$(1)))
  dumpinfo : $(call shexport,Profile/$(1)/Description)
  PACKAGES := $(filter-out -%,$(PACKAGES))
  DUMPINFO += \
	echo "Target-Profile: $(1)"; \
	$(if $(PRIORITY), echo "Target-Profile-Priority: $(PRIORITY)"; ) \
	echo "Target-Profile-Name: $(NAME)"; \
	echo "Target-Profile-Packages: $(PACKAGES) $(call extra_packages,$(DEFAULT_PACKAGES) $(PACKAGES))"; \
	echo "Target-Profile-Description:"; \
	echo "$$$$$$$$$(call shvar,Profile/$(1)/Description)"; \
	echo "@@"; \
	echo;
endef
endif

ifneq ($(PLATFORM_DIR),$(PLATFORM_SUBDIR))
  define IncludeProfiles
    -include $(sort $(wildcard $(PLATFORM_DIR)/profiles/*.mk))
    -include $(sort $(wildcard $(PLATFORM_SUBDIR)/profiles/*.mk))
  endef
else
  define IncludeProfiles
    -include $(sort $(wildcard $(PLATFORM_DIR)/profiles/*.mk))
  endef
endif

PROFILE?=$(call qstrip,$(CONFIG_TARGET_PROFILE))

ifeq ($(TARGET_BUILD),1)
  ifneq ($(DUMP),)
    $(eval $(call IncludeProfiles))
  endif
endif

ifneq ($(TARGET_BUILD)$(if $(DUMP),,1),)
  include $(INCLUDE_DIR)/kernel-version.mk
endif

GENERIC_PLATFORM_DIR := $(TOPDIR)/target/linux/generic
GENERIC_BACKPORT_DIR := $(GENERIC_PLATFORM_DIR)/backport$(if $(wildcard $(GENERIC_PLATFORM_DIR)/backport-$(KERNEL_PATCHVER)),-$(KERNEL_PATCHVER))
GENERIC_PATCH_DIR := $(GENERIC_PLATFORM_DIR)/pending$(if $(wildcard $(GENERIC_PLATFORM_DIR)/pending-$(KERNEL_PATCHVER)),-$(KERNEL_PATCHVER))
GENERIC_HACK_DIR := $(GENERIC_PLATFORM_DIR)/hack$(if $(wildcard $(GENERIC_PLATFORM_DIR)/hack-$(KERNEL_PATCHVER)),-$(KERNEL_PATCHVER))
GENERIC_FILES_DIR := $(foreach dir,$(wildcard $(GENERIC_PLATFORM_DIR)/files $(GENERIC_PLATFORM_DIR)/files-$(KERNEL_PATCHVER)),"$(dir)")

__config_name_list = $(1)/config-$(KERNEL_PATCHVER) $(1)/config-default
__config_list = $(firstword $(wildcard $(call __config_name_list,$(1))))
find_kernel_config=$(if $(__config_list),$(__config_list),$(lastword $(__config_name_list)))

GENERIC_LINUX_CONFIG = $(call find_kernel_config,$(GENERIC_PLATFORM_DIR))
LINUX_TARGET_CONFIG = $(call find_kernel_config,$(PLATFORM_DIR))
ifneq ($(PLATFORM_DIR),$(PLATFORM_SUBDIR))
  LINUX_SUBTARGET_CONFIG = $(call find_kernel_config,$(PLATFORM_SUBDIR))
endif

# config file list used for compiling
LINUX_KCONFIG_LIST = $(wildcard $(GENERIC_LINUX_CONFIG) $(LINUX_TARGET_CONFIG) $(LINUX_SUBTARGET_CONFIG) $(TOPDIR)/env/kernel-config)

# default config list for reconfiguring
# defaults to subtarget if subtarget exists and target does not
# defaults to target otherwise
USE_SUBTARGET_CONFIG = $(if $(wildcard $(LINUX_TARGET_CONFIG)),,$(if $(LINUX_SUBTARGET_CONFIG),1))

LINUX_RECONFIG_LIST = $(wildcard $(GENERIC_LINUX_CONFIG) $(LINUX_TARGET_CONFIG) $(if $(USE_SUBTARGET_CONFIG),$(LINUX_SUBTARGET_CONFIG)))
LINUX_RECONFIG_TARGET = $(if $(USE_SUBTARGET_CONFIG),$(LINUX_SUBTARGET_CONFIG),$(LINUX_TARGET_CONFIG))

CFG_TARGET = $(CONFIG_TARGET)
ifeq ($(CFG_TARGET),platform)
  CFG_TARGET = target
  $(warning Deprecation warning: use CONFIG_TARGET=target instead.)
else ifeq ($(CFG_TARGET),subtarget_platform)
  CFG_TARGET = subtarget_target
  $(warning Deprecation warning: use CONFIG_TARGET=subtarget_target instead.)
endif

# select the config file to be changed by kernel_menuconfig/kernel_oldconfig
ifeq ($(CFG_TARGET),target)
  LINUX_RECONFIG_LIST = $(wildcard $(GENERIC_LINUX_CONFIG) $(LINUX_TARGET_CONFIG))
  LINUX_RECONFIG_TARGET = $(LINUX_TARGET_CONFIG)
else ifeq ($(CFG_TARGET),subtarget)
  LINUX_RECONFIG_LIST = $(wildcard $(GENERIC_LINUX_CONFIG) $(LINUX_TARGET_CONFIG) $(LINUX_SUBTARGET_CONFIG))
  LINUX_RECONFIG_TARGET = $(LINUX_SUBTARGET_CONFIG)
else ifeq ($(CFG_TARGET),subtarget_target)
  LINUX_RECONFIG_LIST = $(wildcard $(GENERIC_LINUX_CONFIG) $(LINUX_SUBTARGET_CONFIG) $(LINUX_TARGET_CONFIG))
  LINUX_RECONFIG_TARGET = $(LINUX_TARGET_CONFIG)
else ifeq ($(CFG_TARGET),env)
  LINUX_RECONFIG_LIST = $(LINUX_KCONFIG_LIST)
  LINUX_RECONFIG_TARGET = $(TOPDIR)/env/kernel-config
else ifneq ($(strip $(CFG_TARGET)),)
  $(error CONFIG_TARGET=$(CFG_TARGET) is invalid. Valid: target|subtarget|subtarget_target|env)
endif

__linux_confcmd = $(2) $(patsubst %,+,$(wordlist 2,9999,$(1))) $(1)

LINUX_CONF_CMD = $(SCRIPT_DIR)/kconfig.pl $(call __linux_confcmd,$(LINUX_KCONFIG_LIST))
LINUX_RECONF_CMD = $(SCRIPT_DIR)/kconfig.pl $(call __linux_confcmd,$(LINUX_RECONFIG_LIST))
LINUX_RECONF_DIFF = $(SCRIPT_DIR)/kconfig.pl - '>' $(call __linux_confcmd,$(filter-out $(LINUX_RECONFIG_TARGET),$(LINUX_RECONFIG_LIST))) $(1) $(GENERIC_PLATFORM_DIR)/config-filter

ifeq ($(DUMP),1)
  BuildTarget=$(BuildTargets/DumpCurrent)

  CPU_CFLAGS = -Os -pipe
  ifneq ($(findstring mips,$(ARCH)),)
    ifneq ($(findstring mips64,$(ARCH)),)
      CPU_TYPE ?= mips64
    else
      CPU_TYPE ?= mips32
    endif
    CPU_CFLAGS += -mno-branch-likely
    CPU_CFLAGS_mips32 = -mips32 -mtune=mips32
    CPU_CFLAGS_mips64 = -mips64 -mtune=mips64 -mabi=64
    CPU_CFLAGS_mips64r2 = -mips64r2 -mtune=mips64r2 -mabi=64
    CPU_CFLAGS_4kec = -mips32r2 -mtune=4kec
    CPU_CFLAGS_24kc = -mips32r2 -mtune=24kc
    CPU_CFLAGS_74kc = -mips32r2 -mtune=74kc
    CPU_CFLAGS_octeonplus = -march=octeon+ -mabi=64
  endif
  ifeq ($(ARCH),i386)
    CPU_TYPE ?= pentium-mmx
    CPU_CFLAGS_pentium-mmx = -march=pentium-mmx
    CPU_CFLAGS_pentium4 = -march=pentium4
  endif
  ifneq ($(findstring arm,$(ARCH)),)
    CPU_TYPE ?= xscale
  endif
  ifeq ($(ARCH),powerpc)
    CPU_CFLAGS_603e:=-mcpu=603e
    CPU_CFLAGS_8540:=-mcpu=8540
    CPU_CFLAGS_8548:=-mcpu=8548
    CPU_CFLAGS_405:=-mcpu=405
    CPU_CFLAGS_440:=-mcpu=440
    CPU_CFLAGS_464fp:=-mcpu=464fp
  endif
  ifeq ($(ARCH),powerpc64)
    CPU_TYPE ?= powerpc64
    CPU_CFLAGS_e5500:=-mcpu=e5500
    CPU_CFLAGS_powerpc64:=-mcpu=powerpc64
  endif
  ifeq ($(ARCH),sparc)
    CPU_TYPE = sparc
    CPU_CFLAGS_ultrasparc = -mcpu=ultrasparc
  endif
  ifeq ($(ARCH),aarch64)
    CPU_TYPE ?= generic
    CPU_CFLAGS_generic = -mcpu=generic
    CPU_CFLAGS_cortex-a53 = -mcpu=cortex-a53
  endif
  ifeq ($(ARCH),arc)
    CPU_TYPE ?= arc700
    CPU_CFLAGS += -matomic
    CPU_CFLAGS_arc700 = -mcpu=arc700
    CPU_CFLAGS_archs = -mcpu=archs
  endif
  ifeq ($(ARCH),riscv64)
    CPU_TYPE ?= riscv64
    CPU_CFLAGS_riscv64:=-mabi=lp64d -march=rv64imafdc
  endif
  ifneq ($(CPU_TYPE),)
    ifndef CPU_CFLAGS_$(CPU_TYPE)
      $(warning CPU_TYPE "$(CPU_TYPE)" doesn't correspond to a known type)
    endif
  endif
  DEFAULT_CFLAGS=$(strip $(CPU_CFLAGS) $(CPU_CFLAGS_$(CPU_TYPE)) $(CPU_CFLAGS_$(CPU_SUBTYPE)))

  ifneq ($(BOARD),)
    TMP_CONFIG:=$(TMP_DIR)/.kconfig-$(call target_conf,$(TARGETID))
    $(TMP_CONFIG): $(LINUX_KCONFIG_LIST)
		$(LINUX_CONF_CMD) > $@ || rm -f $@
    -include $(TMP_CONFIG)
    .SILENT: $(TMP_CONFIG)
    .PRECIOUS: $(TMP_CONFIG)

    ifdef KERNEL_TESTING_PATCHVER
      ifneq ($(KERNEL_TESTING_PATCHVER),$(KERNEL_PATCHVER))
        FEATURES += testing-kernel
      endif
    endif
    ifneq ($(CONFIG_OF),)
      FEATURES += dt
    endif
    ifneq ($(CONFIG_GENERIC_GPIO)$(CONFIG_GPIOLIB),)
      FEATURES += gpio
    endif
    ifneq ($(CONFIG_PCI),)
      FEATURES += pci
    endif
    ifneq ($(CONFIG_PCIEPORTBUS),)
      FEATURES += pcie
    endif
    ifneq ($(CONFIG_USB)$(CONFIG_USB_SUPPORT),)
      ifneq ($(CONFIG_USB_ARCH_HAS_HCD)$(CONFIG_USB_EHCI_HCD),)
        FEATURES += usb
      endif
    endif
    ifneq ($(CONFIG_PCMCIA)$(CONFIG_PCCARD),)
      FEATURES += pcmcia
    endif
    ifneq ($(CONFIG_VGA_CONSOLE)$(CONFIG_FB),)
      FEATURES += display
    endif
    ifneq ($(CONFIG_RTC_CLASS),)
      FEATURES += rtc
    endif
    ifneq ($(CONFIG_VIRTIO),)
      FEATURES += virtio
    endif
    ifneq ($(CONFIG_CPU_MIPS32_R2),)
      FEATURES += mips16
    endif
    FEATURES += $(foreach v,6 7,$(if $(CONFIG_CPU_V$(v)),arm_v$(v)))

    # remove duplicates
    FEATURES:=$(sort $(FEATURES))
  endif
endif

CUR_SUBTARGET:=$(SUBTARGET)
ifeq ($(SUBTARGETS),)
  CUR_SUBTARGET := default
endif

define BuildTargets/DumpCurrent
  .PHONY: dumpinfo
  dumpinfo : export DESCRIPTION=$$(Target/Description)
  dumpinfo:
	@echo 'Target: $(TARGETID)'; \
	 echo 'Target-Board: $(BOARD)'; \
	 echo 'Target-Name: $(BOARDNAME)$(if $(SUBTARGETS),$(if $(SUBTARGET),))'; \
	 echo 'Target-Arch: $(ARCH)'; \
	 echo 'Target-Arch-Packages: $(if $(ARCH_PACKAGES),$(ARCH_PACKAGES),$(ARCH)$(if $(CPU_TYPE),_$(CPU_TYPE))$(if $(CPU_SUBTYPE),_$(CPU_SUBTYPE)))'; \
	 echo 'Target-Features: $(FEATURES)'; \
	 echo 'Target-Depends: $(DEPENDS)'; \
	 echo 'Target-Optimization: $(if $(CFLAGS),$(CFLAGS),$(DEFAULT_CFLAGS))'; \
	 echo 'CPU-Type: $(CPU_TYPE)$(if $(CPU_SUBTYPE),+$(CPU_SUBTYPE))'; \
	 echo 'Linux-Version: $(LINUX_VERSION)'; \
	$(if $(LINUX_TESTING_VERSION),echo 'Linux-Testing-Version: $(LINUX_TESTING_VERSION)';) \
	 echo 'Linux-Release: $(LINUX_RELEASE)'; \
	 echo 'Linux-Kernel-Arch: $(LINUX_KARCH)'; \
	$(if $(SUBTARGET),,$(if $(DEFAULT_SUBTARGET), echo 'Default-Subtarget: $(DEFAULT_SUBTARGET)'; )) \
	 echo 'Target-Description:'; \
	 echo "$$$$DESCRIPTION"; \
	 echo '@@'; \
	 echo 'Default-Packages: $(DEFAULT_PACKAGES) $(call extra_packages,$(DEFAULT_PACKAGES))'; \
	 $(DUMPINFO)
	$(if $(CUR_SUBTARGET),$(SUBMAKE) -r --no-print-directory -C image -s DUMP=1 SUBTARGET=$(CUR_SUBTARGET))
	$(if $(SUBTARGET),,@$(foreach SUBTARGET,$(SUBTARGETS),$(SUBMAKE) -s DUMP=1 SUBTARGET=$(SUBTARGET); ))
endef

include $(INCLUDE_DIR)/kernel.mk
ifeq ($(TARGET_BUILD),1)
  include $(INCLUDE_DIR)/kernel-build.mk
  BuildTarget?=$(BuildKernel)
endif

endif #__target_inc
