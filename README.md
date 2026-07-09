# jluDrcom

吉林大学校园网 DrCOM 认证客户端 —— OpenWrt/ImmortalWrt 插件集合。

本仓库包含两个 OpenWrt 包：

| 目录 | 说明 |
|------|------|
| `drcomd/` | C 语言守护进程，实现 DrCOM 协议的 challenge → login → keepalive 循环 |
| `luci-app-jludrcom/` | LuCI 管理页面（纯 JS），提供配置、状态查看与一键操作 |

## 特性

- **轻量高效**：纯 C 实现（C11），无外部依赖，仅链接 libubus/libubox/libuci
- **procd 管理**：由 OpenWrt 原生进程管理器托管，支持自动 respawn 和 UCI reload trigger
- **ubus 接口**：通过 ubus RPC 暴露 `status`、`reconnect`、`reload` 三个方法，可被其他服务或脚本调用
- **系统日志**：通过 ulog 写入 logd，使用 `logread` 即可查看
- **LuCI 页面**：中文界面，无需额外翻译包

## LuCI 页面功能

**设置区域**：启用开关、账号、密码、网络接口（下拉选择）、IP 地址、网关、MAC 地址

**状态区域**：实时轮询显示连接状态（空闲 / 已在线 / 获取挑战中 / 登录中 / 保持在线）和最近错误

**操作按钮**：

| 按钮 | 功能 |
|------|------|
| 一键配置 | 将所选接口改为静态地址、写入 IP/MAC/网关/DNS，关闭 DNS 重绑定保护，执行前自动备份 |
| 一键恢复 | 恢复到上次一键配置前的网络设置，重新启用 DNS 重绑定保护 |
| 重连 | 断开当前连接并重新发起 challenge → login 流程 |

### 一键配置做了什么

1. 保存当前 `drcom.main` 的 UCI 配置
2. 将 `/etc/config/network` 中选中接口设为 `static` 模式，写入 IP、MAC、网关，DNS 固定为 `10.10.10.10` `202.98.18.3`
3. 在 `/etc/config/dhcp` 中关闭 dnsmasq 的 `rebind_protection`
4. 执行 `ubus call network reload` 并重启 dnsmasq
5. 自动备份修改前的状态，供一键恢复使用

## ubus 接口

```sh
# 查看当前状态（连接状态、IP、MAC、最后错误等）
ubus call drcom status

# 手动重连
ubus call drcom reconnect

# 重新加载 UCI 配置并重连
ubus call drcom reload
ubus call drcom reload '{ "force": true }'
```

## UCI 配置

配置文件：`/etc/config/drcom`

```conf
config drcom 'main'
    option enabled '1'
    option username '你的学号'
    option password '你的密码'
    option interface 'wan'
    option ip '10.100.61.100'
    option mac 'aa:bb:cc:dd:ee:ff'
    option gateway '10.100.61.1'
    # 可选
    option server '10.100.61.3'       # DrCOM 服务器地址，默认 10.100.61.3
    option client_port '61440'        # 客户端端口，默认 61440
    option retry_interval '28'        # 断线重试间隔（秒），默认 28
    option hostname 'OpenWrt'         # 登录上报的主机名，默认取系统 hostname
    option dns '10.10.10.10'         # 登录上报的 DNS，默认 10.10.10.10
```

## 查看日志

```sh
logread -e drcomd
logread | grep -i drcom
```

## 编译与安装

> **注意**：OpenWrt/ImmortalWrt 不同大版本间 ABI 包名（libubus/libubox/libuci 版本化依赖）可能不同，**必须使用目标路由器对应版本和 target 的 SDK 或源码树编译**，不可跨版本安装旧 ipk。

### 放入源码树

将仓库中的两个目录复制到 buildroot：

```sh
cp -r drcomd           openwrt/package/drcomd/
cp -r luci-app-jludrcom openwrt/package/luci-app-jludrcom/
```

### 编译

```sh
make menuconfig
# LuCI  → Applications  → luci-app-jludrcom
# Network               → drcomd

make package/drcomd/compile -j$(nproc) V=s
make package/luci-app-jludrcom/compile -j$(nproc) V=s
```

### 安装

将生成的 `*.ipk` 复制到路由器：

```sh
opkg install drcomd_*.ipk
opkg install luci-app-jludrcom_*.ipk
```

安装后：

```sh
/etc/init.d/drcomd enable
/etc/init.d/drcomd start
```

LuCI 入口：**系统 → 服务 → 吉林大学 DrCOM**

## 协议流程

```
challenge  →  login  →  keepalive (stage 0 → 1 → 2 → 循环)
    ↓ 超时       ↓ 失败        ↓ 超时
  断线重试     断线重试      断线重试
```

- 发送 UDP challenge 包（`0x01`）到服务器
- 收到 salt 后构造 login 包（含 MD5 校验、口令混淆、MAC 绑定）
- 登录成功后进入三段式 keepalive 保活，每 20 秒一轮

## 文件结构

```
jluDrcom/
├── drcomd/
│   ├── Makefile              # OpenWrt 包定义
│   ├── src/drcomd.c           # 守护进程（单文件 C 实现）
│   └── files/
│       ├── drcomd.init         # procd init 脚本
│       └── drcom.config        # 默认 UCI 配置
└── luci-app-jludrcom/
    ├── Makefile                # LuCI 包定义（luci.mk）
    └── root/
        ├── usr/share/luci/menu.d/luci-app-jludrcom.json
        ├── usr/share/rpcd/acl.d/luci-app-jludrcom.json
        └── www/luci-static/resources/view/jludrcom.js   # JS 页面
```

## 免责声明

本项目仅用于学习研究与校园网接入自动化，请遵守学校网络使用规范。
