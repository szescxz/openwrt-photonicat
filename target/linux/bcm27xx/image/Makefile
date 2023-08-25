# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2012-2019 OpenWrt.org
# Copyright (C) 2016-2017 LEDE project

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/image.mk

FAT32_BLOCK_SIZE=1024
FAT32_BLOCKS=$(shell echo $$(($(CONFIG_TARGET_KERNEL_PARTSIZE)*1024*1024/$(FAT32_BLOCK_SIZE))))

define Build/Compile
	$(CP) $(LINUX_DIR)/COPYING $(KDIR)/COPYING.linux
endef

### Image scripts ###
define Build/boot-common
	rm -f $@.boot
	mkfs.fat -n boot -C $@.boot $(FAT32_BLOCKS)
	mcopy -i $@.boot $(KDIR)/COPYING.linux ::
	mcopy -i $@.boot $(KDIR)/LICENCE.broadcom ::
	mcopy -i $@.boot cmdline.txt ::
	mcopy -i $@.boot config.txt ::
	mcopy -i $@.boot distroconfig.txt ::
	mcopy -i $@.boot $(IMAGE_KERNEL) ::$(KERNEL_IMG)
	$(foreach dts,$(shell echo $(DEVICE_DTS)),mcopy -i $@.boot $(DTS_DIR)/$(dts).dtb ::;)
	mmd -i $@.boot ::/overlays
	mcopy -i $@.boot $(DTS_DIR)/overlays/*.dtbo ::/overlays/
	mcopy -i $@.boot $(DTS_DIR)/overlays/README ::/overlays/
endef

define Build/boot-2708
	mcopy -i $@.boot $(KDIR)/bootcode.bin ::
	mcopy -i $@.boot $(KDIR)/start.elf ::
	mcopy -i $@.boot $(KDIR)/start_cd.elf ::
	mcopy -i $@.boot $(KDIR)/start_x.elf ::
	mcopy -i $@.boot $(KDIR)/fixup.dat ::
	mcopy -i $@.boot $(KDIR)/fixup_cd.dat ::
	mcopy -i $@.boot $(KDIR)/fixup_x.dat ::
endef

define Build/boot-2711
	mcopy -i $@.boot $(KDIR)/start4.elf ::
	mcopy -i $@.boot $(KDIR)/start4cd.elf ::
	mcopy -i $@.boot $(KDIR)/start4x.elf ::
	mcopy -i $@.boot $(KDIR)/fixup4.dat ::
	mcopy -i $@.boot $(KDIR)/fixup4cd.dat ::
	mcopy -i $@.boot $(KDIR)/fixup4x.dat ::
endef

define Build/sdcard-img
	./gen_rpi_sdcard_img.sh $@ $@.boot $(IMAGE_ROOTFS) \
		$(CONFIG_TARGET_KERNEL_PARTSIZE) $(CONFIG_TARGET_ROOTFS_PARTSIZE)
endef

### Devices ###
define Device/Default
  DEVICE_VENDOR := Raspberry Pi
  KERNEL := kernel-bin
  KERNEL_IMG := kernel.img
  IMAGES := factory.img.gz sysupgrade.img.gz
  IMAGE/sysupgrade.img.gz := boot-common | boot-2708 | sdcard-img | gzip | append-metadata
  IMAGE/factory.img.gz := boot-common | boot-2708 | sdcard-img | gzip
endef

define Device/rpi
  DEVICE_MODEL := B/B+/CM/Zero/ZeroW
  DEVICE_DTS := \
	bcm2708-rpi-b bcm2708-rpi-b-rev1 bcm2708-rpi-b-plus \
	bcm2708-rpi-cm \
	bcm2708-rpi-zero bcm2708-rpi-zero-w
  SUPPORTED_DEVICES := \
	rpi-b rpi-b-plus rpi-cm rpi-zero rpi-zero-w \
	raspberrypi,model-b raspberrypi,model-b-plus raspberrypi,model-b-rev2 \
	raspberrypi,compute-module raspberrypi,compute-module-1 \
	raspberrypi,model-zero raspberrypi,model-zero-w
  DEVICE_PACKAGES := \
	cypress-firmware-43430-sdio \
	brcmfmac-nvram-43430-sdio \
	kmod-brcmfmac wpad-basic-mbedtls
endef
ifeq ($(SUBTARGET),bcm2708)
  TARGET_DEVICES += rpi
endif

define Device/rpi-2
  DEVICE_MODEL := 2B/2B 1.2
  DEVICE_VARIANT := (32bit)
  DEVICE_ALT0_VENDOR := Raspberry Pi
  DEVICE_ALT0_MODEL := 3B/3B+/CM3
  DEVICE_ALT0_VARIANT := (32bit)
  DEVICE_ALT1_VENDOR := Raspberry Pi
  DEVICE_ALT1_MODEL := 4B/400/CM4
  DEVICE_ALT1_VARIANT := (32bit)
  DEVICE_DTS := \
	bcm2709-rpi-2-b bcm2710-rpi-2-b \
	bcm2710-rpi-3-b bcm2710-rpi-3-b-plus \
	bcm2711-rpi-4-b bcm2711-rpi-400 \
	bcm2710-rpi-cm3 bcm2711-rpi-cm4 \
	bcm2710-rpi-zero-2
  SUPPORTED_DEVICES := \
	rpi-2-b rpi-3-b rpi-3-b-plus rpi-cm rpi-zero-2 \
	raspberrypi,2-model-b raspberrypi,2-model-b-rev2 \
	raspberrypi,3-model-b raspberrypi,3-model-b-plus \
	raspberrypi,3-compute-module raspberrypi,compute-module-3 \
	raspberrypi,400 raspberrypi,4-compute-module raspberrypi,4-model-b \
	raspberrypi,model-zero-2
  DEVICE_PACKAGES := \
	cypress-firmware-43430-sdio \
	brcmfmac-nvram-43430-sdio \
	cypress-firmware-43455-sdio \
	brcmfmac-nvram-43455-sdio \
	kmod-brcmfmac wpad-basic-mbedtls
  IMAGE/sysupgrade.img.gz := boot-common | boot-2708 | boot-2711 | sdcard-img | gzip | append-metadata
  IMAGE/factory.img.gz := boot-common | boot-2708 | boot-2711 | sdcard-img | gzip
endef
ifeq ($(SUBTARGET),bcm2709)
  TARGET_DEVICES += rpi-2
endif

define Device/rpi-3
  DEVICE_MODEL := 3B/3B+/CM3
  DEVICE_VARIANT := (64bit)
  DEVICE_ALT0_VENDOR := Raspberry Pi
  DEVICE_ALT0_MODEL := 2B-1.2
  DEVICE_ALT0_VARIANT := (64bit)
  KERNEL_IMG := kernel8.img
  DEVICE_DTS := \
	broadcom/bcm2710-rpi-2-b \
	broadcom/bcm2710-rpi-3-b broadcom/bcm2710-rpi-3-b-plus \
	broadcom/bcm2710-rpi-cm3 \
	broadcom/bcm2710-rpi-zero-2
  SUPPORTED_DEVICES := \
	rpi-3-b rpi-3-b-plus rpi-zero-2 \
	raspberrypi,2-model-b-rev2 \
	raspberrypi,3-model-b raspberrypi,3-model-b-plus \
	raspberrypi,3-compute-module raspberrypi,compute-module-3 \
	raspberrypi,model-zero-2
  DEVICE_PACKAGES := \
	cypress-firmware-43430-sdio \
	brcmfmac-nvram-43430-sdio \
	cypress-firmware-43455-sdio \
	brcmfmac-nvram-43455-sdio \
	kmod-brcmfmac wpad-basic-mbedtls
endef
ifeq ($(SUBTARGET),bcm2710)
  TARGET_DEVICES += rpi-3
endif

define Device/rpi-4
  DEVICE_MODEL := 4B/400/CM4
  DEVICE_VARIANT := (64bit)
  KERNEL_IMG := kernel8.img
  DEVICE_DTS := \
	broadcom/bcm2711-rpi-400 \
	broadcom/bcm2711-rpi-4-b \
	broadcom/bcm2711-rpi-cm4
  SUPPORTED_DEVICES := \
	raspberrypi,400 \
	raspberrypi,4-compute-module \
	raspberrypi,4-model-b
  DEVICE_PACKAGES := \
	cypress-firmware-43455-sdio \
	brcmfmac-nvram-43455-sdio \
	kmod-brcmfmac wpad-basic-mbedtls \
	kmod-usb-net-lan78xx \
	kmod-r8169 adb adblock arp-scan arp-scan-database atop bash blkid block-mount blockd blockdev bluez-daemon bluez-libs bluez-utils bluez-utils-extra btop btrfs-progs ca-certificates ccrypt cgi-io cgroupfs-mount collectd collectd-mod-conntrack collectd-mod-cpu collectd-mod-cpufreq collectd-mod-interface collectd-mod-irq collectd-mod-iwinfo collectd-mod-load collectd-mod-memory collectd-mod-network collectd-mod-rrdtool collectd-mod-sensors collectd-mod-thermal containerd coreutils coreutils-sort dbus -dnsmasq dnsmasq-full docker docker-compose dockerd e2freefrag eject ethtool exfat-mkfs f2fs-tools f2fsck fatresize fdisk gdisk glib2 hostapd-common htop ip-full ip6tables-nft iperf3-ssl ipset iptables-mod-extra iptables-mod-ipopt iptables-nft irqbalance iw iwinfo kmod-asn1-decoder kmod-asn1-encoder kmod-bluetooth kmod-br-netfilter kmod-cdrom kmod-cfg80211 kmod-crypto-aead kmod-crypto-arc4 kmod-crypto-authenc kmod-crypto-cbc kmod-crypto-ccm kmod-crypto-cmac kmod-crypto-crc32 kmod-crypto-ctr kmod-crypto-deflate kmod-crypto-des kmod-crypto-ecb kmod-crypto-ecdh kmod-crypto-echainiv kmod-crypto-gcm kmod-crypto-gf128 kmod-crypto-ghash kmod-crypto-hmac kmod-crypto-kpp kmod-crypto-lib-chacha20 kmod-crypto-lib-chacha20poly1305 kmod-crypto-lib-curve25519 kmod-crypto-lib-poly1305 kmod-crypto-manager kmod-crypto-md4 kmod-crypto-md5 kmod-crypto-null kmod-crypto-rng kmod-crypto-seqiv kmod-crypto-sha1 kmod-crypto-sha256 kmod-crypto-sha512 kmod-crypto-user kmod-cryptodev kmod-dax kmod-dm kmod-dummy kmod-fs-autofs4 kmod-fs-btrfs kmod-fs-configfs kmod-fs-exfat kmod-fs-exportfs kmod-fs-ext4 kmod-fs-f2fs kmod-fs-hfs kmod-fs-hfsplus kmod-fs-ksmbd kmod-fs-ntfs3 kmod-fs-smbfs-common kmod-fs-squashfs kmod-fuse kmod-gre kmod-hwmon-core kmod-ifb kmod-ip6tables kmod-ipsec kmod-ipt-conntrack kmod-ipt-core kmod-ipt-extra kmod-ipt-ipopt kmod-ipt-ipset kmod-ipt-nat kmod-ipt-nat6 kmod-ipt-physdev kmod-iptunnel kmod-keys-encrypted kmod-keys-trusted kmod-l2tp kmod-lib-crc16 kmod-lib-raid6 kmod-lib-textsearch kmod-lib-xor kmod-lib-zlib-deflate kmod-lib-zlib-inflate kmod-lib-zstd kmod-libphy kmod-mac80211 kmod-macvlan kmod-mdio-devres kmod-mii kmod-mppe kmod-mt76-connac kmod-mt76-core kmod-mt76-usb kmod-mt76x02-common kmod-mt76x02-usb kmod-mt76x2-common kmod-mt76x2u kmod-mt7921-common kmod-mt7921-firmware kmod-mt7921u kmod-net-selftests kmod-nf-conntrack-netlink kmod-nf-ipt kmod-nf-ipt6 kmod-nf-ipvs kmod-nf-nat6 kmod-nf-nathelper kmod-nf-nathelper-extra kmod-nft-compat kmod-oid-registry kmod-phy-ax88796b kmod-phy-realtek kmod-phylink kmod-pppol2tp kmod-pptp kmod-random-core kmod-regmap-core kmod-rtl8812au-ac kmod-rtw88 kmod-sched-cake kmod-sched-core kmod-scsi-core kmod-tpm kmod-tun kmod-udptunnel4 kmod-udptunnel6 kmod-usb-gadget kmod-usb-gadget-eth kmod-usb-lib-composite kmod-usb-net kmod-usb-net-asix kmod-usb-net-asix-ax88179 kmod-usb-net-cdc-ether kmod-usb-net-cdc-ncm kmod-usb-net-ipheth kmod-usb-net-rndis kmod-usb-net-rtl8152 kmod-usb-ohci kmod-usb-ohci-pci kmod-usb-storage kmod-usb-storage-extras kmod-usb-storage-uas kmod-usb-uhci kmod-veth kmod-vxlan kmod-wireguard ksmbd-server libatomic libattr libbpf libcap libdbus libdevmapper libelf libevdev libexpat libfdisk libffi libgmp libical libipset libiptext libiptext-nft libiptext6 libiwinfo libiwinfo-data libkmod libltdl liblua liblucihttp liblucihttp-lua liblucihttp-ucode liblzma liblzo libmbim libmount libncurses libnetfilter-conntrack libnettle libnfnetlink libnl-core libnl-genl libopenssl libopenssl-conf libparted libpcap libpci libpcre libpcre2 libqmi libqrtr-glib libreadline librrd1 libseccomp libsensors libstdcpp libsysfs libubus-lua libudev-zero libuv libwebsockets-full libxtables libzstd lm-sensors lm-sensors-detect losetup lsblk lscpu lua luci luci-app-adblock luci-app-commands luci-app-diskman luci-app-dockerman luci-app-firewall luci-app-ksmbd luci-app-nlbwmon luci-app-openvpn luci-app-opkg luci-app-pbr luci-app-sqm luci-app-statistics luci-app-ttyd luci-base luci-compat luci-lib-base luci-lib-docker luci-lib-ip luci-lib-jsonc luci-lib-nixio luci-light luci-lua-runtime luci-mod-admin-full luci-mod-network luci-mod-status luci-mod-system luci-proto-ipv6 luci-proto-modemmanager luci-proto-ppp luci-proto-wireguard luci-theme-bootstrap modemmanager mount-utils mtools nano nlbwmon ntfs-3g openssl-util openvpn-easy-rsa openvpn-openssl parted pbr pciids pciutils perl perlbase-base perlbase-bytes perlbase-class perlbase-config perlbase-cwd perlbase-errno perlbase-essential perlbase-fcntl perlbase-file perlbase-filehandle perlbase-i18n perlbase-integer perlbase-io perlbase-list perlbase-locale perlbase-params perlbase-posix perlbase-re perlbase-scalar perlbase-selectsaver perlbase-socket perlbase-symbol perlbase-tie perlbase-unicore perlbase-utf8 perlbase-xsloader ppp-mod-pppol2tp ppp-mod-pptp pptpd r8152-firmware r8169-firmware realtek-bluetooth-firmware resize2fs resolveip rpcd rpcd-mod-file rpcd-mod-iwinfo rpcd-mod-luci rpcd-mod-rrdns rpcd-mod-ucode rrdtool1 rtl8821ae-firmware rtl8821c-firmware rtl8822be-firmware rtl8822ce-firmware runc sfdisk smartmontools smartmontools-drivedb sqm-scripts sqm-scripts-extra squashfs-tools-mksquashfs squashfs-tools-unsquashfs sysfsutils tc-tiny tcpdump-mini terminfo tini ttyd ucert-full ucode-mod-html ucode-mod-lua ucode-mod-math uhttpd uhttpd-mod-ubus usb-modeswitch usbutils vsftpd-tls wget-ssl wireguard-tools wireless-regdb wsdd2 xl2tpd xtables-nft zlib mt792x-usb
  IMAGE/sysupgrade.img.gz := boot-common | boot-2711 | sdcard-img | gzip | append-metadata
  IMAGE/factory.img.gz := boot-common | boot-2711 | sdcard-img | gzip
endef
ifeq ($(SUBTARGET),bcm2711)
  TARGET_DEVICES += rpi-4
endif

$(eval $(call BuildImage))
