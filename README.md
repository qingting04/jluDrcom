# jluDrcom

吉林大学（JLU）校园网 DrCOM 认证客户端 —— 面向 OpenWrt / ImmortalWrt 的插件集合。

> DrCOM（Dr.COM）是深澜软件出品的高校校园网认证系统。本插件在路由器上以守护进程形式运行，
> 完成 challenge → login → keepalive 的认证循环，让路由器下的所有设备无需各自登录即可上网。

## 组成

| 目录 | 说明 |
|------|------|
| `drcomd/` | C 语言守护进程（C11，单文件），实现 DrCOM 协议认证循环 |
| `luci-app-jludrcom/` | LuCI 管理页面（纯 JS，无翻译包依赖），提供配置、状态查看与一键操作 |

## 特性

- **轻量高效**：纯 C 实现，无第三方依赖，仅链接 OpenWrt 自带的 libubus / libubox / libuci
- **procd 托管**：由 OpenWrt 原生进程管理器管理，断线自动 respawn，UCI 变更自动 reload
- **ubus RPC 接口**：暴露 `status` / `reconnect` / `reload` 三个方法，可被脚本或其它服务调用
- **系统日志**：经 ulog 写入 logd，`logread` 即可查看
- **中文界面**：LuCI 页面内置中文，无需额外语言包

## LuCI 页面功能

**设置区**：启用开关、账号、密码、网络接口（下拉）、IP 地址、网关、MAC 地址

**状态区**：轮询显示连接状态（空闲 / 已在线 / 获取挑战中 / 登录中 / 保持在线）与最近错误

**操作按钮**：

| 按钮 | 功能 |
|------|------|
| 一键配置 | 将所选接口改为静态地址，写入 IP / MAC / 网关 / DNS，关闭 DNS 重绑定保护；执行前自动备份 |
| 一键恢复 | 恢复上次「一键配置」前的接口设置，重新启用 DNS 重绑定保护 |
| 重连 | 断开当前连接并重新发起 challenge → login 流程 |

### 一键配置做了什么

1. 备份当前 `drcom.main` 的 UCI 配置
2. 将 `/etc/config/network` 中选中接口改为 `static`，写入 IP、MAC、网关；DNS 固定为 `10.10.10.10`、`202.98.18.3`，若无掩码则补 `255.255.255.0`
3. 关闭 `/etc/config/dhcp` 中 dnsmasq 的 `rebind_protection`
4. `ubus call network reload` 并重启 dnsmasq
5. 自动备份修改前的状态，供「一键恢复」使用

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
```

| 选项 | 必填 | 默认值 | 说明 |
|------|:---:|--------|------|
| `enabled` | 是 | `0` | 是否启用认证 |
| `username` | 是 | — | 学号 |
| `password` | 是 | — | 密码（建议不超过 16 位，见下文） |
| `interface` | 是 | `wan` | 接入校园网的接口 |
| `ip` | 是 | — | 认证时绑定的源 IP |
| `mac` | 是 | — | 认证时绑定的源 MAC |
| `gateway` | 一键配置时 | — | 网关（仅「一键配置」需要） |
| `server` | 否 | `10.100.61.3` | DrCOM 服务器地址 |
| `client_port` | 否 | `61440` | 客户端源端口 |
| `retry_interval` | 否 | `28` | 断线重试间隔（秒） |
| `hostname` | 否 | 系统 hostname | 登录上报的主机名 |
| `dns` | 否 | `10.10.10.10` | 登录上报的 DNS |

> **密码长度**：登录包对密码做混淆时使用 16 字节的密钥，超过 16 位的密码会按 16 位循环使用密钥。
> 建议使用不超过 16 位的密码；如遇登录失败，请先缩短密码再试。

## ubus 接口

```sh
# 查看状态（连接状态、IP、MAC、最后错误等）
ubus call drcom status

# 手动重连
ubus call drcom reconnect

# 重新加载 UCI 配置并重连（force 可跳过 UCI 加载失败检查）
ubus call drcom reload
ubus call drcom reload '{ "force": true }'
```

## 查看日志

```sh
logread -e drcomd
logread | grep -i drcom
```

## 编译与安装

> **注意**：OpenWrt / ImmortalWrt 不同大版本之间 ABI 包名（libubus / libubox / libuci 的版本化依赖）可能不同，
> **必须使用目标路由器对应版本与 target 的 SDK 或源码树编译**，不可跨版本安装旧 ipk。

### 放入源码树

```sh
cp -r drcomd            openwrt/package/drcomd/
cp -r luci-app-jludrcom openwrt/package/luci-app-jludrcom/
```

### 编译

```sh
make menuconfig
# LuCI  → Applications  → luci-app-jludrcom
# Network → drcomd

make package/drcomd/compile -j$(nproc) V=s
make package/luci-app-jludrcom/compile -j$(nproc) V=s
```

### 安装

```sh
opkg install drcomd_*.ipk
opkg install luci-app-jludrcom_*.ipk

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

- 向服务器发送 UDP challenge 包（`0x01`），请求 4 字节 salt
- 收到 salt 后构造 login 包（含 MD5 校验、口令混淆、MAC 绑定、主机名等字段）
- 登录成功后进入三段式 keepalive 保活，约每 20 秒一轮，断线自动重试

## 常见问题

| 现象 | 原因 / 处理 |
|------|-------------|
| 状态「空闲」，日志提示 `ip required` | 未填写 `ip` 选项 |
| 日志提示 `mac required` | 未填写 `mac` 选项 |
| `login failed: wrong credentials` | 账号或密码错误，或密码过长 |
| `kicked: other device logged in` | 该账号已在其它设备登录 |
| 安装后始终无法在线 | 确认接口为接入校园网的接口，且 IP / MAC 与校园网分配的静态信息一致 |

## 文件结构

```
jluDrcom/
├── drcomd/
│   ├── Makefile                # OpenWrt 包定义
│   ├── src/drcomd.c            # 守护进程（单文件 C 实现）
│   └── files/
│       ├── drcomd.init         # procd init 脚本
│       └── drcom.config        # 默认 UCI 配置
└── luci-app-jludrcom/
    ├── Makefile                # LuCI 包定义（luci.mk）
    └── root/
        ├── usr/share/luci/menu.d/luci-app-jludrcom.json
        ├── usr/share/rpcd/acl.d/luci-app-jludrcom.json
        └── www/luci-static/resources/view/jludrcom.js
```

## 免责声明

本项目仅用于学习研究与校园网接入自动化，请遵守学校网络使用规范。
