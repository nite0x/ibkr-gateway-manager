# IBKR Gateway Manager

管理多个 Interactive Brokers **Client Portal Gateway** 实例，提供 Web 管理页面、安装与升级、进程启停、登录入口和会话保活。每个实例独立管理配置与会话，可共用一份 Gateway 程序。IBKR 登录及双重验证仍需手动完成。

当前为早期预览版，适合自行部署和验证；真实账户登录、每日重新认证和故障恢复需要使用者验收。

## 1. 需要准备什么

| 项目 | 说明 |
|---|---|
| Docker 与 Docker Compose | 镜像包含 Manager 与 Java；首次启动实例时从 IBKR 官方下载并校验 Gateway |
| IBKR 账户 | 用于 Gateway 登录，不需要把账户密码写入配置 |
| 登录和 API 访问 | 管理用户名／密码；登录后生成管理 API Token，每个 Gateway 使用独立 Proxy Token |
| 持久存储 | 保存配置、Gateway 程序和实例状态；下方 Compose 已配置数据卷 |
| 域名与 HTTPS（对外使用时） | 例如管理域名 `manager.ibkr.example.com`、实例域名 `primary.ibkr.example.com`；也可用 `*.ibkr.example.com`，配置 DNS 和覆盖这些域名的证书 |
| 网络 | 构建需访问 Go 模块和镜像源；首次安装 Gateway、登录及升级需联网 |

仅在本机查看管理页面不需要域名。多个实例同时在浏览器登录时应使用不同主机名，避免 Cookie 冲突。

**本地 Docker 完整登录流程：**启用 `IBKR_GATEWAY_LOCAL_TLS=true` 可自动生成、保存和续签本地 HTTPS 证书，使用 `manager.localhost` 和实例子域名。配套 Mac 脚本处理首次证书信任及必要的域名解析。详见 [本地 HTTPS 部署](https://github.com/nite0x/traio-doc/blob/main/docs/ibkr-manager/local-tls.zh-CN.md)，也可直接使用独立的 [compose.local.yaml](compose.local.yaml)。

## 2. 从源码打包 Docker 镜像

```sh
git clone https://github.com/nite0x/ibkr-gateway-manager.git
cd ibkr-gateway-manager
docker build -t ibkr-gateway-manager:local .
```

后续命令均在此目录执行。

## 3. 安装与启动

先准备配置：

```sh
cp .env.example .env
openssl rand -hex 32
```

在 `.env` 中填写管理用户名、密码、端口和基础域名（见第 4 节）；可将生成的随机值用作密码。全新本地部署可暂时留空域名。

**使用本地构建的镜像：**

```sh
docker compose up -d --no-build
```

**从 Docker Hub 或 GitHub Container Registry（GHCR）拉取：**

当前仓库未配置镜像发布流程，以下是拉取方式模板；需先取得实际已发布的镜像地址和标签，不能直接使用占位符。使用远程镜像时，只需克隆源码取得 Compose 文件，无需执行上一节的 `docker build`。

```sh
# 二选一，并替换命名空间和版本标签
export IBKR_GATEWAY_MANAGER_IMAGE='docker.io/<namespace>/ibkr-gateway-manager:<tag>'
# export IBKR_GATEWAY_MANAGER_IMAGE='ghcr.io/<owner>/ibkr-gateway-manager:<tag>'

docker compose pull
docker compose up -d --no-build
```

私有镜像需先运行 `docker login`（Docker Hub）或 `docker login ghcr.io`。GitHub 源码仓库按上一节克隆构建，GHCR 用于拉取已发布的镜像。

配置 `ibkr.example.com` 后访问 `https://manager.ibkr.example.com/manager/`；全新部署未配置域名时访问 [本地管理页面](http://127.0.0.1:8088/manager/)（端口按配置替换），输入管理用户名和密码。全新数据卷的实例列表为空，点击「新建 Gateway」创建第一个 Gateway（默认建议 ID 为 `primary`，可修改），创建表单会生成独立 Proxy Token；可显示、复制或重新生成。保存后按所选的自动启动设置运行，也可手动启动。已有实例和数据保留，删除最后一个实例后重启仍保持为空。默认本次登录有效 30 分钟，刷新不会续期；过期后重新登录。点击「API Token」生成并复制供外部程序使用的密钥。

```sh
curl --fail http://127.0.0.1:8088/healthz
docker compose logs --tail=100
```

Compose 的宿主机端口默认仅绑定本机；公网访问通过下方 HTTPS 代理转发。`/healthz` 只表示 Manager 存活；完成 IBKR 登录后，应在管理页面确认会话就绪。

## 4. 启动配置

公网部署只需四项：

```dotenv
IBKR_GATEWAY_MANAGER_USERNAME=admin
IBKR_GATEWAY_MANAGER_PASSWORD=替换成管理密码
IBKR_GATEWAY_MANAGER_PORT=8088
IBKR_GATEWAY_PUBLIC_DOMAIN=ibkr.example.com
```

| 配置 | 规则 |
|---|---|
| `IBKR_GATEWAY_MANAGER_USERNAME` | 管理用户名（JSON：`username`） |
| `IBKR_GATEWAY_MANAGER_PASSWORD` | 管理密码（JSON：`password`） |
| `IBKR_GATEWAY_MANAGER_PORT` | 内部 HTTP 监听端口，默认 `8088`（JSON：`port`）；Compose 的端口映射和健康检查同步使用此值 |
| `IBKR_GATEWAY_PUBLIC_DOMAIN` | 基础域名，如 `ibkr.example.com`，不带协议、端口或 `manager.` 前缀（JSON：`public_domain`） |

程序自动监听 `0.0.0.0:<端口>`，管理地址为 `https://manager.<域名>/manager/`，实例地址为 `https://<实例ID>.<域名>`。公网 HTTPS 默认由反向代理或托管平台处理，转发时保留原始 `Host`。端口配置不会追加到公网 URL。实例 ID 使用字母、数字和连字符，`manager` 保留给管理页面。

将管理与实例子域名（或 `*.<域名>`）的 DNS、HTTPS 证书及转发指向该服务即可。宿主机代理转发到 `127.0.0.1:<端口>`，同一 Docker 网络的代理转发到 `ibkr-gateway-manager:<端口>`；云平台的目标端口也应与此一致。无需映射 Java Gateway 内部端口。

管理会话默认 30 分钟，实例 Proxy Token 在创建时自动生成，持久存储由 Compose 数据卷提供。全新部署尚未确定域名时可留空，先通过本地 HTTP 管理页面配置实例；浏览器登录 Gateway 前再补上域名和 HTTPS。已有部署更换基础域名或端口后重启，派生配置会重新生成，继承默认值的实例地址同步更新，数据与 Token 保留。

## 5. 可选配置

基础域名模式按规则生成监听、URL 和外部 HTTPS 终止配置；以下高级环境变量可覆盖生成结果，普通部署无需设置。额外变量需通过 Compose 的 `environment` 传入，仅写入 `.env` 不会自动传给容器。实例和高级参数可在管理页面或数据卷中的 `config.json` 设置，空实例启动示例见 [config.example.json](config.example.json)。

| 配置 | 用途 / 默认行为 |
|---|---|
| `IBKR_GATEWAY_MANAGER_IMAGE` | Compose 使用的镜像，默认 `ibkr-gateway-manager:local` |
| `IBKR_GATEWAY_MANAGER_SESSION_TTL_MINUTES` | 可覆盖默认的 30 分钟管理会话期限 |
| `IBKR_GATEWAY_SHARED_LISTEN` | 覆盖共享监听地址，例如 `127.0.0.1:9088` |
| `IBKR_GATEWAY_PROXY_TLS_TERMINATED` | 覆盖 HTTPS 终止方式；`true` 表示外部代理处理，`false` 表示程序处理 |
| `IBKR_GATEWAY_PROXY_TLS_CERT` / `IBKR_GATEWAY_PROXY_TLS_KEY` | 由 Manager 直接提供 HTTPS 时同时配置并挂载证书和私钥；未指定终止方式时自动使用证书，已有显式 `proxy_tls_terminated: true` 需改为 `false` |
| `auto_start` | 实例是否随 Manager 自动启动 |
| `installation_mode` / `shared_gateway_dir` | 选择共享或独立安装，以及共享程序目录 |
| `gateway_port` | 每个实例的内部端口，必须互不相同；第一个实例建议为 `5680` |
| `gateway_lifecycle` | `managed` 随 Manager 停止；`persistent` 可保留 Java 进程，但 Manager 停止后不再保活 |
| `bundled_gateway_dir` | 自定义、自行提供的 Gateway 模板目录；默认留空，从官方下载安装，已有安装优先复用 |
| `download_proxy` | 仅用于下载 Gateway 的 HTTP(S) 代理，默认不使用 |

详细说明：[首次创建实例与镜像更新](https://github.com/nite0x/traio-doc/blob/main/docs/ibkr-manager/onboarding.zh-CN.md) · [本地 HTTPS 部署](https://github.com/nite0x/traio-doc/blob/main/docs/ibkr-manager/local-tls.zh-CN.md)

## License

本项目采用 [MIT License](LICENSE)。第三方软件（包括 IBKR Gateway）遵循各自许可，详见 [第三方声明](THIRD_PARTY_NOTICES.md)。本项目与 Interactive Brokers 无隶属关系。

管理登录、API Token 与会话行为见 [管理登录与外部 API](https://github.com/nite0x/traio-doc/blob/main/docs/ibkr-manager/api-and-sessions.zh-CN.md)。

开发、验证及发布步骤见 [开发与发布](https://github.com/nite0x/traio-doc/blob/main/docs/ibkr-manager/releasing.md)；漏洞反馈见 [SECURITY.md](SECURITY.md)。
