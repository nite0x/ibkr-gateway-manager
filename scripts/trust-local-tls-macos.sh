#!/bin/sh
# Run on the Mac host, never inside Docker. The only exported material is a
# public CA certificate. Usage: sh trust-local-tls-macos.sh [container] [id ...]
set -eu

if [ "$(uname -s)" != Darwin ]; then
  echo '此脚本用于 macOS。其他系统请用 -export-local-ca 导出并信任 CA 公共证书。' >&2
  exit 1
fi
container=${1:-ibkr-gateway-manager}
if [ "$#" -gt 0 ]; then shift; fi
if [ "$#" -eq 0 ]; then set -- primary; fi

# Validate all inputs before touching trust settings or hosts.
for id in "$@"; do
  if ! printf '%s\n' "$id" | LC_ALL=C grep -Eq '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'; then
    echo "实例 ID 必须是小写 DNS 标签（字母、数字、连字符）：$id" >&2
    exit 1
  fi
done

work=$(mktemp -d "${TMPDIR:-/tmp}/ibkr-local-trust.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
docker exec "$container" /usr/local/bin/ibkr-gateway-manager -export-local-ca > "$work/ca.crt"
openssl x509 -in "$work/ca.crt" -noout -subject -dates -fingerprint -sha256

echo '将上面的本地 CA 加入当前用户登录钥匙串；macOS 可能要求解锁钥匙串。'
security add-trusted-cert -r trustRoot \
  -k "$HOME/Library/Keychains/login.keychain-db" "$work/ca.crt"

# Browsers often resolve *.localhost themselves. Add explicit records only for
# host tools that cannot resolve the requested names, and never overwrite a
# conflicting hosts entry. This operation may require the Mac password.
for name in manager.localhost $(printf '%s.localhost\n' "$@"); do
  addresses=$(dscacheutil -q host -a name "$name" | awk '/ip_address:/ {print $2}')
  if [ -n "$addresses" ]; then
    if printf '%s\n' "$addresses" | grep -Ev '^(127\.0\.0\.1|::1)$' >/dev/null; then
      echo "$name 已解析到其他地址，请检查 DNS 或 /etc/hosts；未覆盖现有记录。" >&2
      exit 1
    fi
    continue
  fi
  if awk -v name="$name" '{sub(/#.*/, ""); for(i=2;i<=NF;i++) if($i==name) found=1} END {exit !found}' /etc/hosts; then
    echo "$name 已在 /etc/hosts 中，但解析失败，请检查该记录。" >&2
    exit 1
  fi
  echo "为本机添加 $name；可能需要输入 Mac 密码。"
  printf '127.0.0.1 %s # ibkr-gateway-manager local TLS\n' "$name" | sudo tee -a /etc/hosts >/dev/null
done
sudo -n dscacheutil -flushcache 2>/dev/null || true
echo '本地 CA 已信任。打开容器日志中显示的 HTTPS 管理地址（默认 https://manager.localhost:8088/manager/）。'
echo '若浏览器仍提示证书错误，请完全退出并重开浏览器。Firefox 使用独立证书库时需另行导入 CA。'
