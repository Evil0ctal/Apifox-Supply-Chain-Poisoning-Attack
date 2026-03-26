#!/bin/bash
# ============================================================
# Apifox 供应链投毒事件 - macOS 中招检测脚本
# ============================================================
# 攻击窗口: 2026-03-04 ~ 2026-03-22 (18天)
# 影响范围: 所有在此期间启动过 Apifox 桌面版的用户 (全平台)
# 恶意域名: apifox.it.com
# 参考: https://rce.moe/2026/03/25/apifox-supply-chain-attack-analysis/
#
# 核心判定逻辑:
#   恶意脚本会在 Electron 的 localStorage (LevelDB) 中写入
#   _rl_mc (机器指纹) 和 _rl_headers (采集信息缓存)。
#   Apifox 更新不会清除这些数据，因此它们是最可靠的历史感染指标。
#   如果 LevelDB 中包含这两个 key，即判定为中招。
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

MALICIOUS_DOMAIN="apifox.it.com"
APIFOX_DATA_DIR="$HOME/Library/Application Support/apifox"
LEVELDB_DIR="$APIFOX_DATA_DIR/Local Storage/leveldb"

compromised=0

print_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "============================================================"
    echo "  Apifox 供应链投毒事件 - macOS 中招检测"
    echo "  攻击窗口: 2026-03-04 ~ 2026-03-22"
    echo "  检测时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "============================================================"
    echo -e "${NC}"
}

found() {
    echo -e "  ${RED}[!] $1${NC}"
}

safe() {
    echo -e "  ${GREEN}[✓] $1${NC}"
}

info() {
    echo -e "  ${YELLOW}[i] $1${NC}"
}

section() {
    echo ""
    echo -e "${BOLD}[$1] $2${NC}"
    echo "------------------------------------------------------------"
}

# ============================================================
# [核心检测] 检查 LevelDB 中是否存在 rl_mc / rl_headers
# 这是最准确的判定方式，即使已更新到最新版本也有效
# ============================================================
check_core_verdict() {
    section "核心" "检查 localStorage 感染标记 (rl_mc / rl_headers)"

    if [ ! -d "$LEVELDB_DIR" ]; then
        info "未找到 Apifox localStorage 目录: $LEVELDB_DIR"
        info "可能原因: 从未安装过 Apifox / 已手动清理过数据目录"
        echo ""
        info "如果你在 2026-03-04 ~ 2026-03-22 期间使用过 Apifox 桌面版，"
        info "但数据目录已被清理，建议仍然预防性轮换所有凭据。"
        return
    fi

    info "正在扫描: $LEVELDB_DIR"

    # 核心检测命令 (等同于社区通用命令)
    # grep -arlE "rl_mc|rl_headers" ~/Library/Application\ Support/apifox/Local\ Storage/leveldb
    hit_files=$(grep -arlE "rl_mc|rl_headers" "$LEVELDB_DIR" 2>/dev/null || true)

    echo ""
    if [ -n "$hit_files" ]; then
        compromised=1
        echo -e "${RED}${BOLD}"
        echo "  ██████████████████████████████████████████████████████"
        echo "  █                                                    █"
        echo "  █              !! 确认中招 !!                        █"
        echo "  █                                                    █"
        echo "  █  在 localStorage 中发现恶意标记 rl_mc / rl_headers █"
        echo "  █  你的敏感信息 (SSH密钥/凭据等) 已被窃取并上传     █"
        echo "  █                                                    █"
        echo "  ██████████████████████████████████████████████████████"
        echo -e "${NC}"
        echo ""
        found "匹配文件:"
        echo "$hit_files" | while read -r f; do
            echo -e "    ${RED}→ $f${NC}"
        done
    else
        echo -e "${GREEN}${BOLD}"
        echo "  ✓ 未在 localStorage 中发现感染标记"
        echo "  ✓ 基于核心指标判断: 未中招"
        echo -e "${NC}"
    fi
}

# ============================================================
# [补充检测] 其他感染痕迹 (当核心检测无法确定时提供参考)
# ============================================================
check_supplementary() {
    section "补充" "其他感染痕迹检测"

    local evidence_count=0

    # 1. Apifox 版本 & 安装时间
    if [ -d "/Applications/Apifox.app" ]; then
        plist="/Applications/Apifox.app/Contents/Info.plist"
        if [ -f "$plist" ]; then
            version=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$plist" 2>/dev/null || echo "未知")
            info "当前 Apifox 版本: $version"
        fi
        app_modified=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M" "/Applications/Apifox.app" 2>/dev/null || echo "未知")
        info "应用最后修改: $app_modified"

        # 检查当前版本是否仍包含恶意代码
        asar_path="/Applications/Apifox.app/Contents/Resources/app.asar"
        if [ -f "$asar_path" ] && strings "$asar_path" 2>/dev/null | grep -q "$MALICIOUS_DOMAIN"; then
            found "当前版本 app.asar 中仍包含恶意域名! 请立即更新!"
            ((evidence_count++))
        else
            safe "当前版本未发现恶意代码 (已更新或从未感染)"
        fi
    else
        info "未检测到 Apifox.app 安装"
    fi

    # 2. Electron 用户数据目录残留
    if [ -d "$APIFOX_DATA_DIR" ]; then
        # Network Persistent State (Electron 网络连接记录)
        net_state="$APIFOX_DATA_DIR/Network Persistent State"
        if [ -f "$net_state" ] && grep -q "$MALICIOUS_DOMAIN" "$net_state" 2>/dev/null; then
            found "Network Persistent State 中发现恶意域名 (Electron 曾连接过 C2)"
            ((evidence_count++))
        fi

        # TransportSecurity (HSTS 记录)
        ts_file="$APIFOX_DATA_DIR/TransportSecurity"
        if [ -f "$ts_file" ] && grep -q "$MALICIOUS_DOMAIN" "$ts_file" 2>/dev/null; then
            found "TransportSecurity 中发现恶意域名 HSTS 记录"
            ((evidence_count++))
        fi

        # 各类缓存目录
        for dir in "$APIFOX_DATA_DIR/Cache" "$APIFOX_DATA_DIR/Code Cache" "$APIFOX_DATA_DIR/Service Worker"; do
            if [ -d "$dir" ]; then
                hits=$(find "$dir" -type f -exec strings {} \; 2>/dev/null | grep -c "$MALICIOUS_DOMAIN" || true)
                if [ "$hits" -gt 0 ]; then
                    found "$(basename "$dir") 缓存中发现 $hits 处恶意域名引用"
                    ((evidence_count++))
                fi
            fi
        done

        # Session Storage
        session_dir="$APIFOX_DATA_DIR/Session Storage"
        if [ -d "$session_dir" ] && strings "$session_dir"/* 2>/dev/null | grep -qE "rl_mc|rl_headers|$MALICIOUS_DOMAIN"; then
            found "Session Storage 中发现恶意特征"
            ((evidence_count++))
        fi
    fi

    # 3. 系统日志 (统一日志 30 天)
    info "正在搜索系统日志 (最近30天，可能需要30秒)..."
    unified_log=$(log show \
        --predicate "eventMessage contains '$MALICIOUS_DOMAIN' OR eventMessage contains 'apifox.it'" \
        --last 30d --style compact \
        2>/dev/null | grep -i "$MALICIOUS_DOMAIN" | head -5 || true)

    if [ -n "$unified_log" ]; then
        found "统一日志中发现恶意域名连接记录"
        ((evidence_count++))
    else
        safe "统一日志 (30天) 中未发现恶意域名记录"
    fi

    # 4. /var/log 搜索
    if [ -d /var/log ]; then
        log_match=$(grep -rl "$MALICIOUS_DOMAIN" /var/log/ 2>/dev/null | head -3 || true)
        if [ -n "$log_match" ]; then
            found "系统日志中发现恶意域名记录"
            ((evidence_count++))
        fi
    fi

    # 5. 废纸篓 / 下载目录旧版本
    trash_apifox=$(find "$HOME/.Trash" -maxdepth 2 -name "*Apifox*" -o -name "*apifox*" 2>/dev/null | head -3 || true)
    if [ -n "$trash_apifox" ]; then
        info "废纸篓中发现旧版 Apifox (可分析确认感染时间线)"
    fi

    echo ""
    if [ $evidence_count -gt 0 ]; then
        found "发现 $evidence_count 处补充证据"
        compromised=1
    else
        safe "补充检测未发现额外异常痕迹"
    fi
}

# ============================================================
# 结果汇总
# ============================================================
print_summary() {
    echo ""
    echo -e "${CYAN}${BOLD}"
    echo "============================================================"
    echo "  检测结果"
    echo "============================================================"
    echo -e "${NC}"

    if [ $compromised -eq 1 ]; then
        echo -e "${RED}${BOLD}  结论: 已中招 — 敏感信息已被窃取${NC}"
        echo ""
        echo -e "${YELLOW}  根据恶意 payload 分析，以下信息已被上传到攻击者服务器:${NC}"
        echo ""
        echo "  [Stage-2 v1 窃取内容]"
        echo "    - ~/.ssh/ 目录 (所有文件，包括私钥)"
        echo "    - ~/.zsh_history / ~/.bash_history"
        echo "    - ~/.git-credentials"
        echo "    - ps aux 进程列表"
        echo ""
        echo "  [Stage-2 v2 额外窃取]"
        echo "    - ~/.kube/ (Kubernetes 配置)"
        echo "    - ~/.npmrc (npm 凭据)"
        echo "    - SVN 凭据"
        echo ""
        echo "  [C2 beacon 窃取]"
        echo "    - Apifox accessToken / 邮箱 / 用户名"
        echo "    - 系统指纹 (MAC地址/CPU/主机名/用户名/OS)"
        echo ""
        echo -e "${RED}${BOLD}  !! 紧急修复步骤 !!${NC}"
        echo ""
        echo "  1. 轮换所有 SSH 密钥:"
        echo "     rm -f ~/.ssh/id_* && ssh-keygen -t ed25519 -C \"your_email\""
        echo "     并在所有平台更新公钥 (GitHub/GitLab/服务器)"
        echo ""
        echo "  2. 撤销所有 Git Personal Access Token:"
        echo "     GitHub → Settings → Developer settings → Tokens → 全部 Revoke"
        echo ""
        echo "  3. 删除明文 Git 凭据:"
        echo "     rm -f ~/.git-credentials"
        echo "     git config --global credential.helper osxkeychain"
        echo ""
        echo "  4. 轮换 K8s 凭据:"
        echo "     检查 ~/.kube/config，重置 OIDC token 和集群凭据"
        echo ""
        echo "  5. 轮换 npm token:"
        echo "     npm token revoke <token> && npm login"
        echo ""
        echo "  6. 在 Apifox 中注销并重新登录"
        echo ""
        echo "  7. 检查所有平台的安全日志:"
        echo "     - GitHub: Settings → Security log"
        echo "     - 服务器: 检查 authorized_keys 是否被注入后门密钥"
        echo "     - K8s: 审计集群操作日志"
        echo ""
        echo "  8. 清理 Apifox 历史数据 (消除残留标记):"
        echo "     rm -rf \"$APIFOX_DATA_DIR\""
        echo "     (重启 Apifox 后会重新生成，本地设置会丢失)"
        echo ""
        echo "  9. 运行 check_leaked_info.sh 查看详细泄露范围"
    else
        echo -e "${GREEN}${BOLD}  结论: 未发现感染迹象${NC}"
        echo ""
        echo "  如果你确信在 2026-03-04 ~ 2026-03-22 期间使用过 Apifox 桌面版,"
        echo "  但未检测到标记，可能的原因:"
        echo "    - 已手动清理过 Apifox 数据目录"
        echo "    - 恶意 CDN 资源未加载成功 (网络问题/防火墙拦截)"
        echo "    - 使用的是 Web 版而非桌面版"
        echo ""
        echo "  仍建议预防性检查: 运行 check_leaked_info.sh 确认敏感文件状态"
    fi

    echo ""
    echo "============================================================"
}

# ============================================================
# Main
# ============================================================
print_banner
check_core_verdict
check_supplementary
print_summary
