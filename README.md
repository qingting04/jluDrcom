# luci-app-jludrcom

吉林大学校园网 DrCOM 客户端 OpenWrt/ImmortalWrt 插件。

本仓库包含两部分：

- `luci-app-jludrcom`：LuCI 管理界面（纯 JS 页面，不写 Lua）。
- `drcomd/`：后端 C 守护进程（procd 管理 + ubus 状态/控制 + UCI 配置）。

## 功能

- `drcomd`（C 重构）实现 DrCOM challenge/login/keepalive，运行更快、更省资源。
- UCI 配置：`/etc/config/drcom`
- ubus 接口：
  - `ubus call drcom status`
  - `ubus call drcom reconnect`
  - `ubus call drcom reload '{"force":true}'`
- LuCI（JS）页面：配置 + 状态 + 操作
  - 配置项：启用 / 账号 / 密码 / 接口(选择) / IP(必填) / MAC(必填) / 网关(必填)
  - 4 个按钮集中在同一块“操作”区域：一键配置 / 一键恢复 / 重连 / 重载配置
  - 页面文案已直接中文化（不依赖额外翻译包）

### 一键配置做了什么

点击“一键配置”后会：

1. 保存当前页面中的 drcom 配置（UCI：`drcom.main`）
2. 修改 `/etc/config/network` 中所选接口：
   - `proto=static`
   - `ipaddr=<填写的IP>`
   - `macaddr=<填写的MAC>`
   - `gateway=<填写的网关>`
   - `dns=10.10.10.10 202.98.18.3`
3. 修改 `/etc/config/dhcp` 中 `dnsmasq`：`rebind_protection=0`
4. 执行：
   - `ubus call network reload`
   - 重启 dnsmasq
5. 自动保存备份信息，用于“一键恢复”

“一键恢复”会将上述修改恢复到“一键配置”之前的状态（基于备份）。

## 日志

`drcomd` 使用 OpenWrt 系统日志链路（ulog → logd）。

- 查看日志：
  ```sh
  logread -e drcomd
  logread | grep -i drcom
  ```

## 编译（推荐在目标系统版本的 SDK / 源码树中编译）

> 注意：OpenWrt/ImmortalWrt 不同大版本之间 ABI 包名会变化（例如 libubus/libubox/libuci 的版本化依赖）。
> 因此 **必须用目标路由器对应版本/target** 的 SDK 或源码树重新编译，不能拿旧版本 ipk 直接跨版本安装。

### 在 OpenWrt/ImmortalWrt 源码树中使用

将本仓库内容复制到 buildroot：

- LuCI 包（仓库根目录内容）放到：`package/luci-app-jludrcom/`
- 后端包（本仓库 `drcomd/`）放到：`package/drcomd/`

然后：
```sh
make menuconfig
# 选中 LuCI -> Applications -> luci-app-jludrcom
# 以及 Network -> drcomd（名称可能在对应菜单中）

make package/drcomd/compile -j$(nproc) V=s
make package/luci-app-jludrcom/compile -j$(nproc) V=s
```

## 安装

编译完成后将生成的 `*.ipk` 复制到路由器安装：

```sh
opkg install drcomd_*.ipk
opkg install luci-app-jludrcom_*.ipk
```

安装后：
- 服务：`/etc/init.d/drcomd enable && /etc/init.d/drcomd start`
- LuCI：系统 → 服务（Services）→ 吉林大学 DrCOM

## 配置文件示例

`/etc/config/drcom`：

```conf
config drcom 'main'
option enabled '1'
option username 'YOUR_USERNAME'
option password 'YOUR_PASSWORD'
option interface 'wan'
option ip '10.x.x.x'
option mac 'aa:bb:cc:dd:ee:ff'
option gateway '10.x.x.1'
```

## 免责声明

本项目仅用于学习与网络接入的自动化管理，请遵守学校网络使用规范。
