    (() => {
      "use strict";
      const API = "/management/v1";
      const state = { config: null, statuses: [], editingId: null, busy: new Set(), authenticated: false, expiresAt: 0, authVersion: 0 };
      const $ = (id) => document.getElementById(id);
      const grid = $("gatewayGrid");
      const editor = $("editorDialog");
      const settingsDialog = $("settingsDialog");
      const tokenDialog = $("tokenDialog");
      const form = $("editorForm");
      const settingsForm = $("settingsForm");

      function escapeHTML(value) {
        return String(value ?? "").replace(/[&<>'"]/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"})[char]);
      }
      function notify(message, error = false) {
        const node = $("notice");
        node.textContent = message;
        node.className = `notice show${error ? " error" : ""}`;
        clearTimeout(notify.timer);
        notify.timer = setTimeout(() => node.className = "notice", 4200);
      }
      async function request(path, options = {}) {
        const headers = new Headers(options.headers || {});

        if (options.body) headers.set("Content-Type", "application/json");
        const response = await fetch(`${API}${path}`, {...options, headers, credentials:"same-origin"});
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
          if (response.status === 401) {
            showLogin("登录已过期，请重新登录。");
          }
          throw new Error(data.details || data.error || `${response.status} ${response.statusText}`);
        }
        return data;
      }
      function duration(seconds) {
        if (!seconds) return "—";
        if (seconds < 60) return `${seconds} 秒`;
        if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟`;
        const hours = Math.floor(seconds / 3600);
        return hours < 24 ? `${hours} 小时` : `${Math.floor(hours / 24)} 天 ${hours % 24} 小时`;
      }
      function generateToken() {
        const bytes = crypto.getRandomValues(new Uint8Array(32));
        return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      }
      function resetProxyTokenFeedback() {
        form.elements.proxy_token.type = "password";
        $("generateProxyToken").textContent = "重新生成";
        $("proxyTokenHint").textContent = "新建时自动生成；编辑时留空会保留原值。";
      }
      function portFromAddress(value, fallback = 0) {
        const match = String(value || "").match(/:(\d+)$/);
        return match ? Number(match[1]) : fallback;
      }
      function usesSharedProxy() { return Boolean(state.config?.shared_proxy_listen_addr); }
      function proxyOrigin(id, proxyPort) {
        const template = state.config.proxy_public_url_template || "http://127.0.0.1:{port}";
        const origin = template.replaceAll("{id}", id || "<实例 ID>");
        return usesSharedProxy() ? origin : origin.replaceAll("{port}", proxyPort || "<代理端口>");
      }
      function inheritedPreview(id, gatewayPort, proxyPort) {
        const publicURL = proxyOrigin(id, proxyPort);
        return `私有 URL https://localhost:${gatewayPort || "<私有端口>"} · 对外 ${publicURL}`;
      }
      function installationMode(gateway) {
        if (gateway.installation_mode) return gateway.installation_mode;
        if (!gateway.gateway_dir || gateway.gateway_dir === state.config.shared_gateway_dir) return "shared";
        const users = Object.values(state.config.gateways).filter((item) => item.gateway_dir === gateway.gateway_dir);
        return users.length > 1 ? "shared" : "independent";
      }
      function installationPaths() {
        const id = form.elements.id.value.trim() || "<实例 ID>";
        const root = String(state.config.gateway_root_dir || "gateways").replace(/[\\/]$/, "");
        const shared = form.elements.installation_mode.value === "shared";
        const original = state.config.gateways[state.editingId];
        const unchanged = original && installationMode(original) === form.elements.installation_mode.value;
        return {
          dir: shared ? (unchanged ? original.gateway_dir : state.config.shared_gateway_dir) || `${root}/shared` : form.elements.gateway_dir.value.trim() || `${root}/${id}`,
          conf: form.elements.gateway_config_file.value || (shared ? `root/conf-${id}.yaml` : "root/conf.yaml"),
          stateDir: form.elements.gateway_state_dir.value || (shared ? `${root}/.instances/${id}` : form.elements.gateway_dir.value.trim() || `${root}/${id}`)
        };
      }
      function syncInstallationUI() {
        const independent = form.elements.installation_mode.value === "independent";
        $("independentDirectory").hidden = !independent;
        $("independentTemplate").hidden = !independent;
        $("installationHint").textContent = independent
          ? "仅在需要运行不同 Gateway 版本时推荐独立安装。程序单独存放，可独立升级和回滚。"
          : "通常只需共享安装：共用程序文件，每个实例有独立配置、进程和登录会话。升级和回滚会影响共用程序的实例。";
        const paths = installationPaths();
        const installed = state.statuses.some((item) => state.config.gateways[item.id]?.gateway_dir === paths.dir && item.status?.installed_version);
        const action = installed ? (independent ? "复用此目录已有程序" : "复用已有程序，只创建或更新实例配置")
          : independent ? "首次启动：目录已有程序则复用，否则从本地模板安装或下载固定官方版本"
          : "首次启动：复用共享目录；尚未安装时只安装一次，后续实例仅新增配置";
        $("installationPreview").innerHTML = `<strong>${escapeHTML(action)}</strong><p>程序目录：${escapeHTML(paths.dir)}</p><p>配置文件：${escapeHTML(paths.conf)}</p><p>状态目录：${escapeHTML(paths.stateDir)}</p>`;
      }
      function changeInstallationMode() {
        const original = state.config.gateways[state.editingId];
        const restore = original && installationMode(original) === form.elements.installation_mode.value;
        for (const name of ["gateway_dir", "gateway_config_file", "gateway_state_dir", "bundled_gateway_dir"]) {
          form.elements[name].value = restore ? original[name] || "" : "";
        }
        syncInstallationUI();
      }
      function syncInheritanceUI() {
        const inherited = form.elements.use_global_defaults.checked;
        const shared = usesSharedProxy();
        $("proxyPortField").hidden = shared;
        form.elements.proxy_port.disabled = shared;
        form.elements.proxy_port.required = !shared;
        $("proxyListenAddrField").hidden = shared;
        form.elements.proxy_listen_addr.disabled = shared;
        $("sharedAccessHint").hidden = !shared;
        $("instanceOverrides").hidden = inherited;
        $("inheritPreview").textContent = inherited ? inheritedPreview(form.elements.id.value.trim(), form.elements.gateway_port.value, form.elements.proxy_port.value) : "使用下方自定义网络设置；安装方式保持不变。";
        syncInstallationUI();
      }
      function changeNetworkInheritance() {
        if (!form.elements.use_global_defaults.checked) {
          const config = state.config;
          const host = config.proxy_listen_host || "127.0.0.1";
          const values = {
            gateway_url: `https://localhost:${form.elements.gateway_port.value}`,
            download_proxy: config.download_proxy || "",
            gateway_proxy_host: config.gateway_proxy_host || "https://api.ibkr.com",
            gateway_allow_ips: (config.gateway_allow_ips || ["127.0.0.1"]).join(", "),
            proxy_public_url: proxyOrigin(form.elements.id.value.trim(), form.elements.proxy_port.value)
          };
          if (!usesSharedProxy()) values.proxy_listen_addr = `${host.includes(":") && !host.startsWith("[") ? `[${host}]` : host}:${form.elements.proxy_port.value}`;
          for (const [name, value] of Object.entries(values)) if (!form.elements[name].value) form.elements[name].value = value;
          $("instanceOverrides").open = true;
        }
        syncInheritanceUI();
      }
      function statusFor(id) { return state.statuses.find((item) => item.id === id); }
      function setMetrics() {
        const entries = Object.entries(state.config?.gateways || {});
        const statuses = entries.map(([id]) => statusFor(id));
        $("totalMetric").textContent = entries.length;
        $("runningMetric").textContent = statuses.filter((item) => item?.status?.running).length;
        $("authMetric").textContent = statuses.filter((item) => item?.status?.authenticated).length;
        $("attentionMetric").textContent = statuses.filter((item) => { const s = item?.status || {}; return s.last_error || s.session_error || ((!s.desired_state || s.desired_state === "connected") && (!s.running || !s.authenticated)); }).length;
      }
      function render() {
        setMetrics();
        const gateways = Object.entries(state.config?.gateways || {}).sort(([a], [b]) => a.localeCompare(b));
        if (!gateways.length) {
          grid.innerHTML = '<div class="empty"><h2>创建第一个 Gateway</h2><div>点击右上角“新建 Gateway”，填写实例名称。访问密钥会自动生成，保存后即可启动并登录 IBKR。</div></div>';
          return;
        }
        grid.innerHTML = gateways.map(([id, gateway]) => {
          const snapshot = statusFor(id);
          const status = snapshot?.status || {};
          const busy = state.busy.has(id);
          const enabled = true;
          const error = status.session_error || status.last_error;
          const sessionLabels = {unknown:"状态待确认",ready:"交易就绪",initializing:"正在建立交易会话",recovering:"正在恢复连接",competing:"其他会话占用",takeover_required:"需要接管连接",login_required:"需要登录",logged_out:"已主动退出",stopped:"已停止"};
          const sessionLabel = sessionLabels[status.session_state] || "状态待确认";
          const processLabel = {stopped:"已停止",detached:"已保留进程",installing:"正在安装",starting:"正在启动",running:"运行中",stopping:"正在停止",restarting:"正在重启",upgrading:"正在升级",rolling_back:"正在回滚",error:"异常",unknown:"待确认"}[status.process_state || status.state] || "待确认";
          const ssoLabel = {unknown:"待确认",valid:"有效",expired:"已失效"}[status.sso_state] || "待确认";
          const checkedAt = status.last_checked_at ? new Date(status.last_checked_at).toLocaleTimeString() : "尚未检查";
          const nextRetry = status.next_retry_at ? new Date(status.next_retry_at).toLocaleTimeString() : "—";
          return `<article class="card"><div class="card-main"><header class="card-head"><div class="identity"><span class="icon">▣</span><div><h2>${escapeHTML(id)}</h2><code>${escapeHTML(gateway.gateway_lifecycle || "managed")}</code></div></div><div class="pills"><span class="pill">${installationMode(gateway) === "independent" ? "独立安装" : "共享安装"}</span><span class="pill ${status.running ? "good" : ""}">${status.running ? "运行中" : "未运行"}</span><span class="pill ${status.authenticated ? "good" : "warn"}">${escapeHTML(sessionLabel)}</span>${snapshot?.proxy_listening ? '<span class="pill good">代理在线</span>' : '<span class="pill warn">代理未配置</span>'}</div></header><div class="origin">${escapeHTML(gateway.proxy_public_url || "未配置 proxy_public_url")}</div><div class="directory">${escapeHTML(gateway.gateway_dir)} · ${escapeHTML(gateway.gateway_config_file || "root/conf.yaml")}</div><dl class="metrics"><div><dt>运行状态</dt><dd>${escapeHTML(processLabel)}</dd></div><div><dt>认证账户</dt><dd>${escapeHTML(status.account || "—")}</dd></div><div><dt>当前版本</dt><dd>${escapeHTML(status.installed_version || "未安装")}</dd></div><div><dt>交易会话时长</dt><dd>${duration(status.session_age_seconds)}</dd></div><div><dt>基础登录</dt><dd>${escapeHTML(ssoLabel)}</dd></div><div><dt>最近检查</dt><dd>${escapeHTML(checkedAt)}${status.stale ? "（待确认）" : ""}</dd></div><div><dt>恢复尝试</dt><dd>${escapeHTML(status.retry_count || 0)}</dd></div><div><dt>下次重试</dt><dd>${escapeHTML(nextRetry)}</dd></div></dl>${error ? `<div class="card-error">${escapeHTML(error)}</div>` : ""}</div><footer class="card-actions"><button class="button primary small" data-action="${status.running ? "login" : "start"}" data-id="${escapeHTML(id)}" ${busy || !enabled ? "disabled" : ""}>${status.running ? "打开登录" : "启动"}</button><button class="button small" data-action="recover" data-id="${escapeHTML(id)}" ${busy || !status.running ? "disabled" : ""}>恢复连接</button>${(status.competing || status.session_state === "takeover_required") ? `<button class="button small" data-action="takeover" data-id="${escapeHTML(id)}" ${busy ? "disabled" : ""}>接管连接</button>` : ""}<button class="button small" data-action="logout" data-id="${escapeHTML(id)}" ${busy || !status.running || (status.desired_state === "logged_out" && !error) ? "disabled" : ""}>退出 IBKR</button><button class="button small" data-action="restart" data-id="${escapeHTML(id)}" ${busy || !status.running ? "disabled" : ""}>重启 Gateway</button><button class="button small" data-action="stop" data-id="${escapeHTML(id)}" ${busy || !status.running ? "disabled" : ""}>停止</button><button class="button small" data-action="upgrade" data-id="${escapeHTML(id)}" ${busy ? "disabled" : ""}>升级</button><button class="button small" data-action="rollback" data-id="${escapeHTML(id)}" ${busy || !status.rollback_available ? "disabled" : ""}>回滚</button><span class="spacer"></span><button class="button small" data-action="edit" data-id="${escapeHTML(id)}" ${busy ? "disabled" : ""}>编辑</button><button class="button danger small" data-action="delete" data-id="${escapeHTML(id)}" ${busy ? "disabled" : ""}>删除</button></footer></article>`;
        }).join("");
      }
      async function load() {
        if (!state.authenticated) return;
        const authVersion = state.authVersion;
        $("refreshButton").disabled = true;
        try {
          const [config, statusResponse] = await Promise.all([request("/config"), request("/gateways")]);
          if (!state.authenticated || authVersion !== state.authVersion) return;
          state.config = config;
          state.statuses = statusResponse.gateways || [];
          render();
        } catch (error) {
          if (!state.config) grid.innerHTML = `<div class="empty"><h2>无法读取 Gateway</h2><div>${escapeHTML(error.message)}</div></div>`;
          notify(error.message, true);
        } finally { $("refreshButton").disabled = false; }
      }
      function nextDefaults() {
        const gateways = state.config?.gateways || {};
        let n = Object.keys(gateways).length + 1;
        while (gateways[`gateway-${n}`]) n++;
        const id = Object.keys(gateways).length === 0 ? "primary" : `gateway-${n}`;
        const ports = Object.values(gateways).map((gateway) => Number(gateway.gateway_port) || 5680);
        const port = Math.max(5679, ...ports) + 1;
        const defaults = { id, installation_mode: "shared", use_global_defaults: true, auto_start: true, gateway_port: port, gateway_lifecycle: "managed", proxy_token: generateToken() };
        if (!usesSharedProxy()) {
          const proxyPorts = Object.values(gateways).map((gateway) => Number(gateway.proxy_port) || portFromAddress(gateway.proxy_listen_addr, 18080));
          defaults.proxy_port = Math.max(18080, ...proxyPorts) + 1;
        }
        return defaults;
      }
      function openEditor(id) {
        state.editingId = id || null;
        resetProxyTokenFeedback();
        const suggested = nextDefaults();
        const value = id ? {id, ...state.config.gateways[id]} : suggested;
        if (id && !statusFor(id)?.proxy_token_configured) value.proxy_token = suggested.proxy_token;
        $("editorTitle").textContent = id ? `编辑 ${id}` : "新建 Gateway";
        form.elements.id.value = value.id;
        form.elements.id.readOnly = Boolean(id);
        for (const name of ["gateway_dir","gateway_config_file","gateway_state_dir","bundled_gateway_dir","gateway_url","gateway_lifecycle","download_proxy","gateway_proxy_host","proxy_listen_addr","proxy_public_url"]) form.elements[name].value = value[name] || "";
        form.elements.gateway_port.value = value.gateway_port || "";
        form.elements.proxy_port.value = usesSharedProxy() ? "" : value.proxy_port || portFromAddress(value.proxy_listen_addr, suggested.proxy_port);
        form.elements.gateway_allow_ips.value = (value.gateway_allow_ips || []).join(", ");
        form.elements.proxy_token.value = value.proxy_token || "";
        form.elements.auto_start.checked = Boolean(value.auto_start);
        form.elements.use_global_defaults.checked = id ? Boolean(value.use_global_defaults) : true;
        form.elements.installation_mode.value = installationMode(value);
        $("instanceOverrides").open = !form.elements.use_global_defaults.checked;
        syncInheritanceUI();
        editor.showModal();
      }
      async function saveEditor(event) {
        event.preventDefault();
        const data = new FormData(form);
        const id = String(data.get("id")).trim();
        if (!state.editingId && state.config.gateways[id]) return notify(`实例 ${id} 已存在`, true);
        const gateway = {use_global_defaults: form.elements.use_global_defaults.checked};
        const original = state.config.gateways[state.editingId];
        const mode = form.elements.installation_mode.value;
        // Preserve older custom paths when editing without changing the mode.
        const legacySharedDirectory = original && !original.installation_mode && mode === "shared" && installationMode(original) === mode && original.gateway_dir !== state.config.shared_gateway_dir;
        if (!legacySharedDirectory) gateway.installation_mode = mode;
        for (const name of ["gateway_dir", "gateway_config_file", "gateway_state_dir", "bundled_gateway_dir"]) {
          const value = String(data.get(name) || "").trim();
          if (value) gateway[name] = value;
        }
        gateway.gateway_lifecycle = String(data.get("gateway_lifecycle") || "managed");
        gateway.gateway_port = Number(data.get("gateway_port"));
        if (!usesSharedProxy()) gateway.proxy_port = Number(data.get("proxy_port"));
        if (!gateway.use_global_defaults) {
          for (const name of ["gateway_url","download_proxy","gateway_proxy_host","proxy_listen_addr","proxy_public_url"]) {
            if (name === "proxy_listen_addr" && usesSharedProxy()) continue;
            const value = String(data.get(name) || "").trim();
            if (value || ["gateway_dir","gateway_url","gateway_proxy_host"].includes(name)) gateway[name] = value;
          }
          gateway.gateway_allow_ips = String(data.get("gateway_allow_ips") || "").split(",").map((value) => value.trim()).filter(Boolean);
        }
        const proxyToken = String(data.get("proxy_token") || "").trim();
        if (proxyToken) gateway.proxy_token = proxyToken;
        gateway.auto_start = form.elements.auto_start.checked;
        const gateways = {...state.config.gateways, [id]: gateway};
        $("saveButton").disabled = true;
        try {
          await request("/config", {method:"PUT", body:JSON.stringify({gateways})});
          editor.close(); notify(`${id} 已保存`); await load();
        } catch (error) { notify(error.message, true); }
        finally { $("saveButton").disabled = false; }
      }
      function openSettings() {
        if (!state.config) return notify("配置仍在加载，请稍后再试。", true);
        const config = state.config;
        for (const name of ["gateway_root_dir","shared_gateway_dir","bundled_gateway_dir","download_proxy","gateway_proxy_host","proxy_listen_host","shared_proxy_listen_addr","proxy_public_url_template","listen_addr","public_url","proxy_tls_cert_file","proxy_tls_key_file"]) {
          settingsForm.elements[name].value = config[name] || "";
        }
        settingsForm.elements.gateway_allow_ips.value = (config.gateway_allow_ips || []).join(", ");
        settingsForm.elements.proxy_tls_terminated.checked = Boolean(config.proxy_tls_terminated);
        const localTLS = Boolean(config.local_tls);
        const publicDomain = Boolean(config.public_domain);
        for (const name of ["public_url", "proxy_public_url_template"]) {
          settingsForm.elements[name].readOnly = publicDomain;
          settingsForm.elements[name].title = publicDomain ? "由启动配置中的公网域名自动生成；更改域名后重启生效。" : "";
        }
        $("localTLSInfo").hidden = !localTLS;
        settingsForm.elements.proxy_tls_terminated.disabled = localTLS || publicDomain;
        settingsForm.elements.proxy_tls_cert_file.disabled = localTLS || publicDomain;
        settingsForm.elements.proxy_tls_key_file.disabled = localTLS || publicDomain;
        if (localTLS) {
          $("localTLSStatus").textContent = "正在读取证书状态…";
          request("/local-tls").then((status) => {
            $("localTLSStatus").textContent = `服务证书到期：${new Date(status.certificate_expires).toLocaleDateString()}；CA 到期：${new Date(status.ca_expires).toLocaleDateString()}。CA SHA-256：${status.ca_sha256}`;
          }).catch((error) => { $("localTLSStatus").textContent = error.message; });
        }
        syncSettingsProxyUI();
        settingsDialog.showModal();
      }
      function syncSettingsProxyUI() {
        const shared = Boolean(settingsForm.elements.shared_proxy_listen_addr.value.trim());
        $("proxyListenHostField").hidden = shared;
        settingsForm.elements.proxy_listen_host.disabled = shared;
        settingsForm.elements.proxy_listen_host.required = !shared;
        if (!shared && !settingsForm.elements.proxy_listen_host.value) settingsForm.elements.proxy_listen_host.value = "127.0.0.1";
        $("proxyTemplateHint").textContent = state.config?.public_domain
          ? `由公网域名 ${state.config.public_domain} 自动生成，每个实例使用独立子域名。`
          : shared
          ? "共享入口使用 {id} 区分实例，例如 https://{id}.localhost:8081。所有实例共用入口端口，不支持 {port}。"
          : "独立代理使用 {port} 表示实例端口，例如 http://127.0.0.1:{port}。";
      }
      async function saveSettings(event) {
        event.preventDefault();
        const data = new FormData(settingsForm);
        const payload = {gateways: state.config.gateways};
        for (const name of ["gateway_root_dir","shared_gateway_dir","bundled_gateway_dir","download_proxy","gateway_proxy_host","proxy_listen_host","shared_proxy_listen_addr","proxy_public_url_template","listen_addr","public_url","proxy_tls_cert_file","proxy_tls_key_file"]) {
          payload[name] = String(data.get(name) || "").trim();
        }
        payload.gateway_allow_ips = String(data.get("gateway_allow_ips") || "").split(",").map((value) => value.trim()).filter(Boolean);
        payload.proxy_tls_terminated = settingsForm.elements.proxy_tls_terminated.checked;
        $("saveSettingsButton").disabled = true;
        try {
          await request("/config", {method:"PUT", body:JSON.stringify(payload)});
          settingsDialog.close(); notify("全局设置已保存，继承设置的实例已同步更新"); await load();
        } catch (error) { notify(error.message, true); }
        finally { $("saveSettingsButton").disabled = false; }
      }
      async function run(id, action) {
        if (action === "edit") return openEditor(id);
        if (action === "delete") {
          if (!confirm(`删除 Gateway「${id}」？安装文件不会被删除。`)) return;
          const gateways = {...state.config.gateways}; delete gateways[id];
          try { await request("/config", {method:"PUT", body:JSON.stringify({gateways})}); notify(`${id} 已删除`); await load(); }
          catch (error) { notify(error.message, true); }
          return;
        }
        if (action === "login") {
          const gateway = state.config.gateways[id];
          if (!gateway.proxy_public_url || !statusFor(id)?.proxy_listening) {
            notify(`${id} 的访问入口未配置或尚未监听，无法打开登录。`, true);
            return;
          }
          const loginTab = window.open("about:blank", "_blank");
          if (!loginTab) {
            notify("浏览器阻止了新标签页，请允许此站点打开弹窗后重试。", true);
            return;
          }
          loginTab.opener = null;
          try {
            await request(`/gateways/${encodeURIComponent(id)}/resume`, {method:"POST"});
            const ticket = await request(`/gateways/${encodeURIComponent(id)}/login-ticket`, {method:"POST"});
            loginTab.location.replace(ticket.url);
          } catch (error) {
            loginTab.close();
            notify(error.message, true);
          }
          return;
        }
        if (action === "restart" && !confirm(`重启 Gateway「${id}」？当前连接会中断，重启后将检查会话，必要时重新登录。`)) return;
        if (action === "takeover" && !confirm(`接管「${id}」的交易连接？这会断开同一用户在其他平台上的交易会话。`)) return;
        if (action === "logout" && !confirm(`退出「${id}」的 IBKR 登录？自动恢复将暂停，直至再次登录或恢复连接。`)) return;
        if (action === "stop" && !confirm(`停止「${id}」？`)) return;
        if (action === "upgrade" || action === "rollback") {
          const independent = installationMode(state.config.gateways[id]) === "independent";
          const operation = action === "upgrade" ? "升级" : "回滚";
          const effect = independent ? "仅影响此独立安装，实例配置将保留。" : "请先停止共用此目录的其他实例，所有实例配置将保留。";
          const version = action === "upgrade" ? "升级目标是管理器固定的官方版本。" : "";
          if (!confirm(`${operation}「${id}」使用的${independent ? "独立" : "共享"}程序？${effect}${version}`)) return;
        }
        state.busy.add(id); render();
        try { await request(`/gateways/${encodeURIComponent(id)}/${action}`, {method:"POST"}); notify(`${id}：操作完成`); await load(); }
        catch (error) { notify(error.message, true); }
        finally { state.busy.delete(id); await load(); }
      }

      grid.addEventListener("click", (event) => { const button = event.target.closest("button[data-action]"); if (button) void run(button.dataset.id, button.dataset.action); });
      $("refreshButton").addEventListener("click", () => void load());
      $("createButton").addEventListener("click", () => openEditor());
      $("settingsButton").addEventListener("click", openSettings);
      $("tokenButton").addEventListener("click", () => { $("apiToken").value = ""; $("tokenFeedback").textContent = ""; tokenDialog.showModal(); });
      tokenDialog.addEventListener("close", () => { $("apiToken").value = ""; });
      $("generateProxyToken").addEventListener("click", () => {
        const input = form.elements.proxy_token;
        input.value = generateToken();
        input.type = "text";
        input.focus();
        input.select();
        $("generateProxyToken").textContent = "再次生成";
        $("proxyTokenHint").textContent = "已生成新密钥并选中。保存后生效，请同步更新使用此代理的客户端。";
      });
      $("tokenForm").addEventListener("submit", async (event) => {
        event.preventDefault();
        if (!confirm("生成新 API Token 后，旧 Token 将立即失效。继续？")) return;
        $("saveTokenButton").disabled = true;
        try {
          const data = await authRequest("/api-token", {method:"POST"});
          $("apiToken").value = data.api_token;
          $("apiToken").focus(); $("apiToken").select();
          $("tokenFeedback").textContent = "新 Token 已保存并生效，请立即复制。";
        } catch (error) { notify(error.message, true); }
        finally { $("saveTokenButton").disabled = false; }
      });
      $("copyTokenButton").addEventListener("click", async () => {
        if (!$("apiToken").value) return;
        try { await navigator.clipboard.writeText($("apiToken").value); $("tokenFeedback").textContent = "已复制"; }
        catch { $("apiToken").focus(); $("apiToken").select(); $("tokenFeedback").textContent = "请手动复制选中的 Token。"; }
      });
      $("revokeTokenButton").addEventListener("click", async () => {
        if (!confirm("撤销后外部程序将无法调用管理 API，直到配置新的 Token。继续？")) return;
        try { await authRequest("/api-token", {method:"DELETE"}); $("apiToken").value = ""; $("tokenFeedback").textContent = "API Token 已撤销。"; }
        catch (error) { notify(error.message, true); }
      });
      async function authRequest(path, options = {}) {
        const response = await fetch(`/auth/v1${path}`, {...options, credentials:"same-origin", headers:{"Content-Type":"application/json"}});
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
          if (response.status === 401 && state.authenticated) showLogin("登录已过期，请重新登录。");
          throw new Error(data.error || "请求失败");
        }
        return data;
      }
      function showLogin(message = "") {
        state.authenticated = false; state.authVersion++; state.config = null; state.statuses = [];
        clearTimeout(showSession.timer);
        for (const dialog of [editor, settingsDialog, tokenDialog]) if (dialog.open) dialog.close();
        $("apiToken").value = ""; form.reset(); settingsForm.reset(); state.editingId = null;
        grid.innerHTML = "";
        $("managerScreen").hidden = true; $("loginScreen").hidden = false;
        $("loginError").textContent = message; $("password").value = "";
      }
      function showSession(session) {
        state.authenticated = true; state.authVersion++; state.expiresAt = Date.parse(session.expires_at);
        $("loginScreen").hidden = true; $("managerScreen").hidden = false;
        $("password").value = "";
        $("sessionInfo").textContent = `${session.username} · 本次登录有效至 ${new Date(state.expiresAt).toLocaleString()}`;
        clearTimeout(showSession.timer);
        showSession.timer = setTimeout(() => void restoreSession(), Math.min(2147483647, Math.max(0, state.expiresAt - Date.now())));
      }
      async function restoreSession() {
        try { showSession(await authRequest("/session")); await load(); }
        catch (error) { showLogin(error.message); }
      }
      $("loginForm").addEventListener("submit", async (event) => {
        event.preventDefault(); $("loginButton").disabled = true; $("loginError").textContent = "";
        try {
          showSession(await authRequest("/session", {method:"POST", body:JSON.stringify({username:$("username").value, password:$("password").value})}));
          await load();
        } catch (error) { $("loginError").textContent = error.message; }
        finally { $("loginButton").disabled = false; }
      });
      $("logoutButton").addEventListener("click", async () => {
        try { await authRequest("/session", {method:"DELETE"}); showLogin(); }
        catch (error) { notify(error.message, true); }
      });
      form.addEventListener("submit", saveEditor);
      settingsForm.addEventListener("submit", saveSettings);
      settingsForm.elements.shared_proxy_listen_addr.addEventListener("input", syncSettingsProxyUI);
      for (const name of ["id","gateway_port","proxy_port"]) form.elements[name].addEventListener("input", syncInheritanceUI);
      form.elements.use_global_defaults.addEventListener("change", changeNetworkInheritance);
      form.elements.installation_mode.addEventListener("change", changeInstallationMode);
      form.elements.gateway_dir.addEventListener("input", syncInstallationUI);
      form.elements.gateway_port.addEventListener("input", () => { if (!state.editingId || /^https:\/\/127\.0\.0\.1:\d+$/.test(form.elements.gateway_url.value)) form.elements.gateway_url.value = `https://127.0.0.1:${form.elements.gateway_port.value}`; });
      document.addEventListener("click", (event) => { const button = event.target.closest("[data-close]"); if (button) $(button.dataset.close).close(); });
      void restoreSession();
      document.addEventListener("visibilitychange", () => { if (!document.hidden) void restoreSession(); });
      setInterval(() => { if (state.authenticated && !document.hidden && !editor.open && !settingsDialog.open && !tokenDialog.open) void load(); }, 15000);
    })();
