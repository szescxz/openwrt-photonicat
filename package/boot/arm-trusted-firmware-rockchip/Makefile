#
# Copyright (C) 2020 Tobias Maedel <openwrt@tbspace.de>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=arm-trusted-firmware-rockchip
PKG_VERSION:=2.8.6
PKG_RELEASE:=1

PKG_SOURCE:=atf-v$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://github.com/mj22226/atf/releases/download/V$(PKG_VERSION)-1682115933/atf-v$(PKG_VERSION).tar.gz?
PKG_HASH:=d368949761374c8f7525f0c8d03fc030ea3ebd39aef7f4a01f9728b0499b4fb1

PKG_LICENSE:=BSD-3-Clause
PKG_LICENSE_FILES:=license.md

PKG_MAINTAINER:=Tobias Maedel <openwrt@tbspace.de>

MAKE_PATH:=$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/arm-trusted-firmware-rockchip
    SECTION:=boot
    CATEGORY:=Boot Loaders
    TITLE:=ARM Trusted Firmware for Rockchip
    DEPENDS:=@TARGET_rockchip_armv8
endef

define Build/Prepare
	$(TAR) -C $(PKG_BUILD_DIR) -xf $(DL_DIR)/$(PKG_SOURCE)
endef

define Build/Compile
endef

define Build/InstallDev
	$(INSTALL_DIR) -p $(STAGING_DIR_IMAGE)
	$(CP) $(PKG_BUILD_DIR)/rk*.elf $(STAGING_DIR_IMAGE)/
	$(CP) $(PKG_BUILD_DIR)/rk*.bin $(STAGING_DIR_IMAGE)/
endef

define Package/arm-trusted-firmware-rockchip/install
endef

$(eval $(call BuildPackage,arm-trusted-firmware-rockchip))
