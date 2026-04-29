include $(TOPDIR)/rules.mk

PKG_NAME:=drcomd
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/drcomd
  SECTION:=net
  CATEGORY:=Network
  TITLE:=DrCOM client daemon
  DEPENDS:=+libubus +libubox +libuci
endef

define Package/drcomd/description
  Lightweight DrCOM client daemon (challenge/login/keepalive) for campus networks.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_CPPFLAGS) -std=c11 -D_GNU_SOURCE \
		-I$(STAGING_DIR)/usr/include \
		-o $(PKG_BUILD_DIR)/drcomd \
		$(PKG_BUILD_DIR)/drcomd.c \
		$(TARGET_LDFLAGS) -lubus -lubox -luci
endef

define Package/drcomd/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/drcomd $(1)/usr/sbin/drcomd
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/drcomd.init $(1)/etc/init.d/drcomd
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/drcom.config $(1)/etc/config/drcom
endef

$(eval $(call BuildPackage,drcomd))
