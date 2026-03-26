#!/bin/bash
# ============================================================
# Apifox 供应链投毒事件 - macOS 泄露信息检查脚本
# ============================================================
# 攻击窗口: 2026-03-04 ~ 2026-03-22
# 参考: https://rce.moe/2026/03/25/apifox-supply-chain-attack-analysis/
#
# 根据恶意 payload 分析，攻击者窃取了:
#
# [Stage-2 v1]
#   - ~/.ssh/ 目录 (所有文件，包括私钥)
#   - ~/.zsh_history (zsh 命令历史)
#   - ~/.bash_history (bash 命令历史)
#   - ~/.git-credentials (Git 明文凭据)
#   - ps aux 输出 (进程列表)
#
# [Stage-2 v2 新增]
#   - ~/.kube/ (Kubernetes 配置和凭据)
#   - ~/.npmrc (npm registry token)
#   - SVN 凭据
#
# [C2 beacon]
#   - Apifox accessToken / 用户邮箱 / 用户名
#   - 系统指纹 (MAC地址, CPU型号, 主机名, 用户名, OS类型)
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

HOME_DIR="$HOME"
LEVELDB_DIR="$HOME/Library/Application Support/apifox/Local Storage/leveldb"

print_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "============================================================"
    echo "  Apifox 供应链投毒事件 - 泄露信息检查"
    echo "  检测时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "============================================================"
    echo -e "${NC}"
}

danger() {
    echo -e "  ${RED}[危险] $1${NC}"
}

warn() {
    echo -e "  ${YELLOW}[警告] $1${NC}"
}

safe() {
    echo -e "  ${GREEN}[安全] $1${NC}"
}

info() {
    echo -e "  ${CYAN}[信息] $1${NC}"
}

section() {
    echo ""
    echo -e "${BOLD}[$1] $2${NC}"
    echo "------------------------------------------------------------"
}

# ============================================================
# 1. SSH 密钥泄露检查
# ============================================================
check_ssh() {
    section "1" "SSH 密钥泄露风险 (攻击者窃取了整个 ~/.ssh/ 目录)"

    ssh_dir="$HOME_DIR/.ssh"

    if [ ! -d "$ssh_dir" ]; then
        info "未找到 ~/.ssh/ 目录"
        return
    fi

    danger "~/.ssh/ 目录存在，以下文件内容可能已被窃取:"
    echo ""

    # 列出所有文件及其权限
    while IFS= read -r file; do
        if [ -f "$file" ]; then
            filename=$(basename "$file")
            file_size=$(stat -f%z "$file" 2>/dev/null || echo "?")
            file_mod=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M" "$file" 2>/dev/null || echo "?")
            file_perms=$(stat -f "%Sp" "$file" 2>/dev/null || echo "?")

            case "$filename" in
                id_rsa|id_ed25519|id_ecdsa|id_dsa)
                    danger "  🔑 私钥: $file ($file_perms, ${file_size}B, $file_mod)"
                    danger "     ⚠ 此私钥必须立即轮换!"
                    ;;
                id_rsa.pub|id_ed25519.pub|id_ecdsa.pub|id_dsa.pub)
                    warn "  📄 公钥: $file ($file_perms, ${file_size}B, $file_mod)"
                    ;;
                known_hosts)
                    warn "  🌐 已知主机: $file (攻击者可获知你连接过的服务器列表)"
                    host_count=$(wc -l < "$file" 2>/dev/null | tr -d ' ')
                    info "     包含 $host_count 条主机记录"
                    ;;
                authorized_keys)
                    warn "  🔓 授权密钥: $file (攻击者知道哪些密钥可登录此机器)"
                    ;;
                config)
                    danger "  ⚙ SSH配置: $file (包含主机别名、用户名、端口等敏感信息)"
                    # 提取配置的主机列表
                    hosts=$(grep -i "^Host " "$file" 2>/dev/null | awk '{print $2}' | tr '\n' ', ' || true)
                    if [ -n "$hosts" ]; then
                        info "     配置的主机: $hosts"
                    fi
                    ;;
                *)
                    warn "  📁 其他文件: $file ($file_perms, ${file_size}B)"
                    ;;
            esac
        fi
    done < <(find "$ssh_dir" -type f 2>/dev/null)

    echo ""
    danger "建议操作:"
    echo "  1. 重新生成所有 SSH 密钥:"
    echo "     ssh-keygen -t ed25519 -C \"your_email@example.com\""
    echo "  2. 在所有服务器/平台上更新公钥 (GitHub, GitLab, 服务器等)"
    echo "  3. 检查 authorized_keys 是否被篡改添加了未知密钥"
    echo "  4. 检查 known_hosts 中的服务器是否有异常登录记录"
}

# ============================================================
# 2. Shell 历史泄露检查
# ============================================================
check_shell_history() {
    section "2" "Shell 命令历史泄露风险"

    local histories=("$HOME_DIR/.zsh_history" "$HOME_DIR/.bash_history")
    local sensitive_patterns=(
        "export.*KEY\|export.*TOKEN\|export.*SECRET\|export.*PASSWORD"
        "curl.*-H.*[Aa]uthoriz\|curl.*-u "
        "mysql.*-p\|psql.*password\|mongo.*-p"
        "aws configure\|gcloud auth\|az login"
        "echo.*>.*\.env\|cat.*\.env"
        "ssh-keygen\|ssh-add"
        "docker login\|npm login\|pip.*--index-url.*://"
        "openssl.*-pass\|gpg.*--passphrase"
        "PRIVATE_KEY\|API_KEY\|api_key\|apikey"
        "heroku.*login\|vercel.*login\|netlify.*login"
    )

    for hist_file in "${histories[@]}"; do
        if [ ! -f "$hist_file" ]; then
            info "$(basename "$hist_file") 不存在"
            continue
        fi

        file_size=$(stat -f%z "$hist_file" 2>/dev/null || echo "?")
        line_count=$(wc -l < "$hist_file" 2>/dev/null | tr -d ' ')
        danger "$(basename "$hist_file") 已泄露 ($line_count 行, ${file_size}B)"

        echo ""
        warn "  以下命令可能包含敏感信息 (摘要):"

        for pattern in "${sensitive_patterns[@]}"; do
            matches=$(grep -i "$pattern" "$hist_file" 2>/dev/null | head -5 || true)
            if [ -n "$matches" ]; then
                echo "$matches" | while read -r line; do
                    # 脱敏显示 - 保留命令名但隐藏可能的密码/token
                    sanitized=$(echo "$line" | sed -E 's/(password|token|key|secret|credential)[=: ]*[^ ]*/\1=***REDACTED***/gi')
                    danger "    → $sanitized"
                done
            fi
        done
    done

    echo ""
    warn "建议操作:"
    echo "  1. 轮换所有在历史命令中出现过的凭据/密钥/Token"
    echo "  2. 清理敏感历史: history -c && rm -f ~/.zsh_history ~/.bash_history"
    echo "  3. 配置 HISTIGNORE 排除敏感命令"
}

# ============================================================
# 3. Git 凭据泄露检查
# ============================================================
check_git_credentials() {
    section "3" "Git 凭据泄露风险"

    git_cred="$HOME_DIR/.git-credentials"

    if [ ! -f "$git_cred" ]; then
        safe "~/.git-credentials 文件不存在"
    else
        line_count=$(wc -l < "$git_cred" 2>/dev/null | tr -d ' ')
        danger "~/.git-credentials 已泄露! 包含 $line_count 条凭据:"

        echo ""
        while IFS= read -r line; do
            if [ -n "$line" ]; then
                # 提取平台和用户名 (隐藏密码)
                platform=$(echo "$line" | sed -E 's|https?://[^:]+:[^@]+@||' | cut -d'/' -f1)
                username=$(echo "$line" | sed -E 's|https?://([^:]+):.*|\1|')
                danger "  🔐 平台: $platform | 用户: $username | 密码: ***已泄露***"
            fi
        done < "$git_cred"
    fi

    # 检查 git config 中的凭据存储方式
    cred_helper=$(git config --global credential.helper 2>/dev/null || echo "")
    if [ -n "$cred_helper" ]; then
        info "Git 凭据存储方式: $cred_helper"
        if [ "$cred_helper" = "store" ]; then
            danger "使用明文存储 (store)，凭据已暴露!"
        elif [ "$cred_helper" = "osxkeychain" ]; then
            info "使用 macOS Keychain 存储 (相对安全，但建议仍然轮换)"
        fi
    fi

    # 检查 .gitconfig 中的敏感信息
    gitconfig="$HOME_DIR/.gitconfig"
    if [ -f "$gitconfig" ]; then
        info "~/.gitconfig 内容 (可能暴露用户身份):"
        name=$(git config --global user.name 2>/dev/null || echo "")
        email=$(git config --global user.email 2>/dev/null || echo "")
        [ -n "$name" ] && warn "  用户名: $name"
        [ -n "$email" ] && warn "  邮箱: $email"
    fi

    echo ""
    warn "建议操作:"
    echo "  1. 立即撤销所有 Git Personal Access Token"
    echo "  2. 在 GitHub/GitLab/Bitbucket 上生成新 Token"
    echo "  3. 检查仓库是否有异常 Push/PR"
    echo "  4. 切换到 osxkeychain 存储: git config --global credential.helper osxkeychain"
    echo "  5. 删除明文凭据: rm -f ~/.git-credentials"
}

# ============================================================
# 4. Apifox 账户泄露检查
# ============================================================
check_apifox_account() {
    section "4" "Apifox 账户信息泄露风险"

    if [ ! -d "$LEVELDB_DIR" ]; then
        info "未找到 Apifox localStorage 数据"
        return
    fi

    # 搜索 accessToken
    token_found=$(strings "$LEVELDB_DIR"/*.log "$LEVELDB_DIR"/*.ldb 2>/dev/null | grep -i "accessToken\|common.accessToken" | head -1 || true)
    if [ -n "$token_found" ]; then
        danger "发现 Apifox accessToken 存储记录 (可能已被窃取)"
        danger "攻击者使用此 Token 调用 Apifox API 获取了你的邮箱和用户名"
    else
        info "未在 localStorage 中发现 accessToken"
    fi

    echo ""
    warn "被窃取的信息包括:"
    echo "  - Apifox 登录邮箱"
    echo "  - Apifox 用户名"
    echo "  - Apifox accessToken (可用于 API 调用)"
    echo ""
    warn "建议操作:"
    echo "  1. 立即在 Apifox 中注销并重新登录 (刷新 Token)"
    echo "  2. 在 Apifox 设置中检查是否有异常的 API 访问记录"
    echo "  3. 检查团队成员列表是否有异常变动"
    echo "  4. 检查项目/接口数据是否被导出或修改"
}

# ============================================================
# 5. 系统指纹泄露检查
# ============================================================
check_system_fingerprint() {
    section "5" "系统指纹信息泄露情况"

    warn "以下系统信息已被攻击者收集 (通过 01 号 payload):"
    echo ""

    # MAC 地址
    mac_addr=$(ifconfig en0 2>/dev/null | grep ether | awk '{print $2}' || echo "未获取")
    danger "  MAC 地址: $mac_addr"

    # CPU 型号
    cpu_model=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "未获取")
    danger "  CPU 型号: $cpu_model"

    # 主机名
    danger "  主机名: $(hostname)"

    # 用户名
    danger "  用户名: $(whoami)"

    # OS 信息
    os_info="$(uname -s) $(uname -r)"
    danger "  操作系统: $os_info"

    # 计算攻击者生成的 SHA-256 指纹
    fingerprint="${mac_addr}-${cpu_model}-$(hostname)-$(whoami)-$(uname -s)"
    machine_id=$(echo -n "$fingerprint" | shasum -a 256 | awk '{print $1}')
    info "  机器指纹 (af_uuid): $machine_id"

    echo ""
    warn "被窃取的信息还包括 (通过 03 号 payload):"
    echo ""
    danger "  进程列表 (ps aux): 攻击者知道你在运行什么软件"
}

# ============================================================
# 6. Kubernetes 配置泄露检查 (Stage-2 v2 新增)
# ============================================================
check_kube() {
    section "6" "Kubernetes 配置泄露风险 (Stage-2 v2 新增目标)"

    kube_dir="$HOME_DIR/.kube"
    if [ ! -d "$kube_dir" ]; then
        safe "~/.kube/ 目录不存在"
        return
    fi

    danger "~/.kube/ 目录存在，以下内容可能已被窃取:"
    echo ""

    if [ -f "$kube_dir/config" ]; then
        danger "  ~/.kube/config (集群凭据、API Server 地址、证书)"
        # 提取集群名称
        clusters=$(grep -E "^\s+cluster:" "$kube_dir/config" 2>/dev/null | awk '{print $2}' | tr '\n' ', ' || true)
        if [ -n "$clusters" ]; then
            info "    配置的集群: $clusters"
        fi
        contexts=$(grep -E "^\s+name:" "$kube_dir/config" 2>/dev/null | awk '{print $2}' | head -5 | tr '\n' ', ' || true)
        if [ -n "$contexts" ]; then
            info "    Context: $contexts"
        fi
    fi

    # 检查其他 kubeconfig 文件
    other_configs=$(find "$kube_dir" -type f -name "*.conf" -o -name "*.yaml" -o -name "*.yml" 2>/dev/null | head -5 || true)
    if [ -n "$other_configs" ]; then
        echo "$other_configs" | while read -r f; do
            warn "  其他配置: $f"
        done
    fi

    echo ""
    danger "建议操作:"
    echo "  1. 重置所有 K8s 集群的 OIDC token / service account token"
    echo "  2. 轮换 kubeconfig 中的客户端证书"
    echo "  3. 审计集群操作日志，检查异常 API 调用"
    echo "  4. 检查是否有异常的 ClusterRoleBinding 或 Pod 创建"
}

# ============================================================
# 7. npm 凭据泄露检查 (Stage-2 v2 新增)
# ============================================================
check_npm() {
    section "7" "npm / 包管理器凭据泄露风险 (Stage-2 v2 新增目标)"

    npmrc="$HOME_DIR/.npmrc"
    if [ -f "$npmrc" ]; then
        danger "~/.npmrc 文件存在，内容可能已被窃取:"
        # 检查是否包含 token
        if grep -qE "//.*:_authToken=" "$npmrc" 2>/dev/null; then
            token_count=$(grep -cE "//.*:_authToken=" "$npmrc" 2>/dev/null || echo "0")
            danger "  包含 $token_count 个 registry auth token!"
            # 显示 registry (隐藏 token 值)
            grep -E "//.*:_authToken=" "$npmrc" 2>/dev/null | sed 's/=.*/=***REDACTED***/' | while read -r line; do
                danger "  → $line"
            done
        fi
        if grep -qi "_password" "$npmrc" 2>/dev/null; then
            danger "  包含 base64 编码的密码!"
        fi
    else
        safe "~/.npmrc 不存在"
    fi

    # 检查 yarn
    yarnrc="$HOME_DIR/.yarnrc.yml"
    if [ -f "$yarnrc" ] && grep -qi "npmAuthToken\|npmRegistries" "$yarnrc" 2>/dev/null; then
        warn "~/.yarnrc.yml 中包含 npm 认证信息 (可能也在窃取范围内)"
    fi

    echo ""
    warn "建议操作:"
    echo "  1. 撤销 npm token: npm token revoke <token>"
    echo "  2. 重新登录: npm login"
    echo "  3. 检查 npm 包是否有异常发布 (npm access ls-packages)"
    echo "  4. 检查私有 registry 的审计日志"
}

# ============================================================
# 8. SVN 凭据泄露检查 (Stage-2 v2 新增)
# ============================================================
check_svn() {
    section "8" "SVN 凭据泄露风险 (Stage-2 v2 新增目标)"

    svn_dir="$HOME_DIR/.subversion"
    if [ ! -d "$svn_dir" ]; then
        safe "~/.subversion/ 目录不存在"
        return
    fi

    auth_dir="$svn_dir/auth"
    if [ -d "$auth_dir" ]; then
        danger "~/.subversion/auth/ 存在，SVN 缓存凭据可能已被窃取"
        for sub in "$auth_dir"/svn.*; do
            if [ -d "$sub" ]; then
                cred_count=$(find "$sub" -type f 2>/dev/null | wc -l | tr -d ' ')
                warn "  → $(basename "$sub"): $cred_count 个缓存凭据"
            fi
        done
    fi

    echo ""
    warn "建议操作:"
    echo "  1. 清除 SVN 缓存凭据: rm -rf ~/.subversion/auth/"
    echo "  2. 更改 SVN 服务器密码"
}

# ============================================================
# 9. 汇总与紧急建议
# ============================================================
print_summary() {
    echo ""
    echo -e "${RED}${BOLD}"
    echo "============================================================"
    echo "  泄露影响汇总与紧急修复建议"
    echo "============================================================"
    echo -e "${NC}"

    echo -e "${BOLD}如果你确认中招，请按以下优先级处理:${NC}"
    echo ""
    echo -e "${RED}[紧急 - 立即处理]${NC}"
    echo "  1. 轮换所有 SSH 密钥并更新到所有平台"
    echo "     ssh-keygen -t ed25519 -C \"your_email@example.com\" -f ~/.ssh/id_ed25519"
    echo ""
    echo "  2. 撤销并重新生成所有 Git Personal Access Token"
    echo "     GitHub: Settings → Developer settings → Personal access tokens"
    echo "     GitLab: Preferences → Access Tokens"
    echo ""
    echo "  3. 删除 ~/.git-credentials 并切换凭据管理方式"
    echo "     rm -f ~/.git-credentials"
    echo "     git config --global credential.helper osxkeychain"
    echo ""
    echo "  4. 在 Apifox 中注销并重新登录"
    echo ""
    echo -e "${YELLOW}[重要 - 尽快处理]${NC}"
    echo "  5. 检查 GitHub/GitLab 安全日志，是否有异常的:"
    echo "     - 新增 Deploy Key"
    echo "     - 新增 OAuth 应用授权"
    echo "     - 异常地区/IP 的登录记录"
    echo "     - 异常的 Push / PR / Webhook"
    echo ""
    echo "  6. 检查服务器 authorized_keys 是否被注入后门密钥"
    echo "     cat ~/.ssh/authorized_keys"
    echo ""
    echo "  7. 轮换历史命令中暴露的所有密码/Token/API Key"
    echo ""
    echo -e "${YELLOW}[重要 - Stage-2 v2 新增]${NC}"
    echo "  5. 轮换 K8s 凭据:"
    echo "     检查 ~/.kube/config，重置 OIDC token 和集群凭据"
    echo ""
    echo "  6. 轮换 npm token:"
    echo "     npm token revoke <token> && npm login"
    echo ""
    echo "  7. 清除 SVN 缓存凭据: rm -rf ~/.subversion/auth/"
    echo ""
    echo -e "${CYAN}[建议 - 后续处理]${NC}"
    echo "  8. 清理 shell 历史: rm -f ~/.zsh_history ~/.bash_history"
    echo "  9. 更新 Apifox 到最新安全版本"
    echo " 10. 启用所有平台的两步验证 (2FA)"
    echo " 11. 对 SSH 私钥添加密码保护: ssh-keygen -p -f ~/.ssh/id_ed25519"
    echo ""
    echo "============================================================"
}

# ============================================================
# Main
# ============================================================
print_banner
check_ssh
check_shell_history
check_git_credentials
check_apifox_account
check_system_fingerprint
check_kube
check_npm
check_svn
print_summary
