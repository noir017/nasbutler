# nasbutler

让 AI agent 帮你整理 NAS 上的个人文件库，**但看不到你的敏感信息，也碰不坏你的文件**。

nasbutler 给文件库建一份索引，通过 [MCP](https://modelcontextprotocol.io) 把它提供给 Claude Code、opencode 等 agent。agent 能看到目录结构、大小、时间、文件类型、重复文件、媒体编码参数；身份证号、手机号、银行卡号、密钥和机密目录的名字在离开服务器之前都被换成了化名，文件内容一个字节都不出去。

> **状态：v0.1，只读。** 现在能做的是"摸底"：让 agent 看清楚文件库里有什么、哪里有重复、哪里有敏感信息，并据此提出整理方案。移动、改名、清理要等 v0.2 的"计划 + 人工审批 + 独立执行器"。设计见 [docs/design.md](docs/design.md)。

## agent 看到的是什么

```json
{"id": 2,  "path": "docs/contacts.txt",           "kind": "text",  "level": "personal", "findings": {"cn_mobile": 1}}
{"id": 7,  "path": "docs/ID_[cn-id#2f81c0aa].jpg", "kind": "image", "level": "personal", "findings": {"cn_id": 1}}
{"id": 9,  "path": "docs/[secret#9b1e44d0]",       "kind": "text",  "level": "secret",   "findings": {"api_token": 1}}
{"id": 12, "path": "手机备份/[secret-dir#51aa0c3e]/[secret#c07d9e12]", "kind": "database", "level": "secret"}
```

- `[cn-id#…]`、`[phone#…]` 这类化名代表一个敏感值。同一个值永远是同一个化名，所以 agent 能看出"这些文件都和同一个号码有关"，但拿不到号码本身。
- `[secret#…]` 是名字被整体隐去的机密文件（密钥、密码库、含 token 的配置……），`[secret-dir#…]` 是整个被隐去的目录（比如聊天记录）。
- 配置成 `hidden` 的目录完全不可见；配置成 `opaque` 的目录只给总数和总大小。

## 安全模型

- **MCP 是 agent 接触数据的唯一通道。** 跑整理任务的 agent 不应该有这台机器的 shell；有 shell 的话，它绕过 MCP 就能直接读文件。
- **只读**：扫描器以 `O_RDONLY|O_NOFOLLOW|O_NOATIME` 打开文件，不跟随符号链接；MCP 服务以 SQLite 只读模式（`query_only`）打开索引。
- **扫描时脱敏**：路径在写进索引时就已经脱敏，agent 用脱敏路径导航；按路径判定为机密的文件，内容不读。
- **出口过滤**：所有工具返回值在发出前统一再检测一遍，超过大小上限的整体拒绝，发出的内容逐条记入审计日志 `egress.jsonl`。
- **HTTP 模式必须带 token**（至少 24 个字符），默认只监听 `127.0.0.1`。

内置的检测：

| 类型 | 级别 | 怎么认 |
|---|---|---|
| 身份证号 | 个人 | 18 位，地区码 + 出生日期 + 校验位 |
| 手机号 | 个人 | 11 位 `1[3-9]` 开头，支持 `+86`/`0086` 和空格分隔 |
| 银行卡号 | 个人 | 15–19 位，发卡行前缀 + Luhn 校验 |
| 邮箱 | 个人 | 排除 `icon@2x.png` 这类资源文件名 |
| 私钥 | 机密 | PEM、OpenSSH、PGP、PuTTY |
| API token | 机密 | AWS、GitHub、Slack、Google、JWT、Telegram bot、`sk-` 类密钥 |
| 密码赋值 | 机密 | `password = "…"`、`DB_PASSWORD=…`，排除 `${VAR}`、`changeme` 这类占位符 |
| 密码库 | 机密 | KeePass 文件头 |

外加 50 多条内置的机密路径规则：`.ssh`、`.gnupg`、`*.kdbx`、`*.pem`、`.env`、微信/QQ/Telegram 聊天记录目录、浏览器的密码和 Cookie 库、加密货币钱包等，见 [internal/rules/builtin.go](internal/rules/builtin.go)。

## 快速上手

### 1. 构建

需要 Go 1.26+。产物是 Linux 静态单文件（SQLite 是纯 Go 实现，不需要 cgo）：

```bash
./build.sh                    # dist/nasbutler，linux/amd64
GOARCH=arm64 ./build.sh       # 交叉编译 arm64
```

媒体探测（视频编码、分辨率、时长）需要机器上有 `ffprobe`，没有也能跑，只是 `inspect` 不返回媒体信息。

### 2. 配置

```bash
cp config.example.toml config.toml
```

最少只需要两项：

```toml
root = "/srv/archive"             # 要整理的目录，只读访问
state_dir = "/var/lib/nasbutler"  # 索引、化名密钥、审计日志

[rules]
hidden = ["/private"]             # 完全不可见
opaque = ["/backup"]              # 只给总数和总大小
secret = ["病历"]                  # 追加的机密规则
```

规则写法同 `.gitignore`：不带斜杠的模式匹配任意深度，开头的斜杠锚定到根，不区分大小写，匹配到目录就覆盖其下全部内容。配置里写错的键会直接报错，不会被静默忽略。

```bash
nasbutler check -c config.toml    # 校验配置，查看索引状态
```

### 3. 扫描

```bash
nasbutler scan -c config.toml
```

第一次扫描会读每个文本类文件的开头（默认 1 MiB）做敏感检测，然后对大小相同的文件算哈希找重复。之后再扫描时，大小、修改时间、inode 都没变的文件直接跳过，接近一次目录遍历的开销。可以放进 cron 定期跑；两次扫描重叠时，后一次会直接退出。

### 4. 接入 agent

**同一台机器（stdio）：**

```bash
claude mcp add nasbutler -- nasbutler serve -c /path/to/config.toml -stdio
```

**跨机器（HTTP）：**

```bash
openssl rand -hex 24 > /var/lib/nasbutler/token && chmod 600 /var/lib/nasbutler/token
# config.toml: [serve] listen = "192.168.1.10:8765", token_file = "/var/lib/nasbutler/token"
nasbutler serve -c config.toml

# 在 agent 那台机器上
claude mcp add --transport http nasbutler http://192.168.1.10:8765/mcp \
  --header "Authorization: Bearer $(cat token)"
```

HTTP 本身不加密。跨网络访问请走 VPN 或加 TLS 反向代理，别直接暴露到公网。

## MCP 工具

| 工具 | 作用 |
|---|---|
| `status` | 索引总览：文件数、容量、敏感文件数、重复文件、最后一次扫描时间 |
| `survey` | 列出一个目录的子项（按大小排序），带文件数、容量、时间范围、各类型占比、敏感文件数 |
| `query` | 按目录、类型、扩展名、大小、修改时间、敏感级别、名字片段查文件 |
| `inspect` | 单个文件的详情：类型、敏感检测结果、内容相同的其他副本、媒体的编码/分辨率/帧率/时长 |
| `duplicates` | 内容完全相同的文件组，按浪费的空间排序 |
| `extensions` | 按扩展名汇总，方便发现监控录像（`.dav`、`.264`）、磁盘镜像这类格式 |
| `sensitive_report` | 各目录下有多少个人/机密文件、各含哪类敏感信息、有多少文档没做内容检测 |

[skills/nas-organize](skills/nas-organize/SKILL.md) 是给 agent 用的工作流说明：怎么摸底、怎么提整理方案、哪些事不要做。

## 局限

- 规则抓不到人名、住址这类自由文本。
- Office 文档、PDF、压缩包的内容 v0.1 不检测；图片里的证件照要等 OCR。
- 化名挡住了具体的值，挡不住上下文：目录结构、文件名、数量还是会发给模型。一点都不想外发的，用 `hidden`。

## 路线图

- **v0.2**：计划 + 人工审批 + 独立执行器（移动、改名、建目录、隔离；没有删除），操作日志可撤销。审批是可扩展接口，第一个实现是飞书确认码。
- **v0.3**：监控录像识别、无损合并、硬件转码、只保留有动静的片段。
- **v0.4**：机密文件移进加密目录；OCR 识别证件照。

## 许可证

[GPL-3.0-or-later](LICENSE)
