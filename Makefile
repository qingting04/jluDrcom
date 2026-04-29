include $(TOPDIR)/rules.mk

LUCI_TITLE:=吉林大学 DrCOM 客户端
LUCI_DEPENDS:=+luci-base +drcomd
LUCI_PKGARCH:=all

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
