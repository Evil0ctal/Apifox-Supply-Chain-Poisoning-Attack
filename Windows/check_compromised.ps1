# ============================================================
# Apifox 供应链投毒事件 - Windows 中招检测脚本
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
# 使用方法: 以管理员权限打开 PowerShell，运行:
#   Set-ExecutionPolicy -Scope Process Bypass
#   .\check_compromised.ps1
# ============================================================

$ErrorActionPreference = "Continue"

$MALICIOUS_DOMAIN = "apifox.it.com"
$APIFOX_DATA_DIR = "$env:APPDATA\apifox"
$LEVELDB_DIR = "$APIFOX_DATA_DIR\Local Storage\leveldb"

$compromised = $false

function Print-Banner {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  Apifox 供应链投毒事件 - Windows 中招检测" -ForegroundColor Cyan
    Write-Host "  攻击窗口: 2026-03-04 ~ 2026-03-22" -ForegroundColor Cyan
    Write-Host "  检测时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Found($msg) {
    Write-Host "  [!] $msg" -ForegroundColor Red
}

function Safe($msg) {
    Write-Host "  [OK] $msg" -ForegroundColor Green
}

function Info($msg) {
    Write-Host "  [i] $msg" -ForegroundColor Yellow
}

function Section($num, $title) {
    Write-Host ""
    Write-Host "[$num] $title" -ForegroundColor White
    Write-Host "------------------------------------------------------------"
}

function Search-BinaryForString($filePath, $searchString) {
    try {
        $bytes = [System.IO.File]::ReadAllBytes($filePath)
        $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
        return $ascii -match [regex]::Escape($searchString)
    } catch {
        return $false
    }
}

# ============================================================
# [核心检测] 检查 LevelDB 中是否存在 rl_mc / rl_headers
# 这是最准确的判定方式，即使已更新到最新版本也有效
# ============================================================
function Check-CoreVerdict {
    Section "核心" "检查 localStorage 感染标记 (rl_mc / rl_headers)"

    if (-not (Test-Path $LEVELDB_DIR)) {
        Info "未找到 Apifox localStorage 目录: $LEVELDB_DIR"
        Info "可能原因: 从未安装过 Apifox / 已手动清理过数据目录"
        Write-Host ""
        Info "如果你在 2026-03-04 ~ 2026-03-22 期间使用过 Apifox 桌面版，"
        Info "但数据目录已被清理，建议仍然预防性轮换所有凭据。"
        return
    }

    Info "正在扫描: $LEVELDB_DIR"

    # 核心检测命令 (等同于社区通用命令)
    # Select-String -Path "$env:APPDATA\apifox\Local Storage\leveldb\*" -Pattern "rl_mc","rl_headers" -List | Select-Object Path
    $hitFiles = Select-String -Path "$LEVELDB_DIR\*" -Pattern "rl_mc", "rl_headers" -List -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty Path

    Write-Host ""
    if ($hitFiles) {
        $script:compromised = $true
        Write-Host ""
        Write-Host "  ██████████████████████████████████████████████████████" -ForegroundColor Red
        Write-Host "  █                                                    █" -ForegroundColor Red
        Write-Host "  █              !! 确认中招 !!                        █" -ForegroundColor Red
        Write-Host "  █                                                    █" -ForegroundColor Red
        Write-Host "  █  在 localStorage 中发现恶意标记 rl_mc / rl_headers █" -ForegroundColor Red
        Write-Host "  █  你的敏感信息 (SSH密钥/凭据等) 已被窃取并上传     █" -ForegroundColor Red
        Write-Host "  █                                                    █" -ForegroundColor Red
        Write-Host "  ██████████████████████████████████████████████████████" -ForegroundColor Red
        Write-Host ""
        Found "匹配文件:"
        foreach ($f in $hitFiles) {
            Write-Host "    -> $f" -ForegroundColor Red
        }
    } else {
        Write-Host "  OK 未在 localStorage 中发现感染标记" -ForegroundColor Green
        Write-Host "  OK 基于核心指标判断: 未中招" -ForegroundColor Green
    }
}

# ============================================================
# [补充检测] 其他感染痕迹
# ============================================================
function Check-Supplementary {
    Section "补充" "其他感染痕迹检测"

    $evidenceCount = 0

    # 1. Apifox 安装 & 版本
    $installPaths = @(
        "$env:LOCALAPPDATA\Programs\Apifox",
        "$env:PROGRAMFILES\Apifox",
        "${env:PROGRAMFILES(x86)}\Apifox"
    )

    $foundInstall = $false
    foreach ($p in $installPaths) {
        if (Test-Path $p) {
            $foundInstall = $true
            $exePath = Join-Path $p "Apifox.exe"
            if (Test-Path $exePath) {
                $fileInfo = Get-Item $exePath
                Info "当前版本: $($fileInfo.VersionInfo.ProductVersion) (最后修改: $($fileInfo.LastWriteTime.ToString('yyyy-MM-dd HH:mm')))"
            }

            $jsHits = Get-ChildItem -Path $p -Filter "*.js" -Recurse -ErrorAction SilentlyContinue |
                      Select-String -Pattern $MALICIOUS_DOMAIN -ErrorAction SilentlyContinue
            if ($jsHits) {
                Found "当前版本仍包含恶意域名! 请立即更新!"
                $evidenceCount++
            } else {
                Safe "当前版本未发现恶意代码 (已更新或从未感染)"
            }
        }
    }

    if (-not $foundInstall) {
        Info "未检测到 Apifox 安装"
    }

    # 2. Electron 用户数据目录残留
    if (Test-Path $APIFOX_DATA_DIR) {
        # Network Persistent State
        $netState = "$APIFOX_DATA_DIR\Network Persistent State"
        if ((Test-Path $netState) -and (Get-Content $netState -Raw -ErrorAction SilentlyContinue) -match [regex]::Escape($MALICIOUS_DOMAIN)) {
            Found "Network Persistent State 中发现恶意域名 (Electron 曾连接过 C2)"
            $evidenceCount++
        }

        # TransportSecurity
        $tsFile = "$APIFOX_DATA_DIR\TransportSecurity"
        if ((Test-Path $tsFile) -and (Get-Content $tsFile -Raw -ErrorAction SilentlyContinue) -match [regex]::Escape($MALICIOUS_DOMAIN)) {
            Found "TransportSecurity 中发现恶意域名 HSTS 记录"
            $evidenceCount++
        }

        # 缓存目录
        foreach ($dir in @("$APIFOX_DATA_DIR\Cache", "$APIFOX_DATA_DIR\Code Cache", "$APIFOX_DATA_DIR\Service Worker")) {
            if (Test-Path $dir) {
                $hitCount = 0
                Get-ChildItem -Path $dir -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
                    if (Search-BinaryForString $_.FullName $MALICIOUS_DOMAIN) { $hitCount++ }
                }
                if ($hitCount -gt 0) {
                    Found "$(Split-Path $dir -Leaf) 缓存中发现 $hitCount 个文件包含恶意域名"
                    $evidenceCount++
                }
            }
        }
    }

    # 3. DNS 事件日志
    Info "正在搜索 DNS 事件日志..."
    try {
        $dnsEvents = Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" -MaxEvents 50000 -ErrorAction SilentlyContinue |
                     Where-Object { $_.Message -like "*$MALICIOUS_DOMAIN*" }
        if ($dnsEvents) {
            Found "DNS 事件日志中发现恶意域名查询 ($($dnsEvents.Count) 条, 最早: $($dnsEvents[-1].TimeCreated))"
            $evidenceCount++
        } else {
            Safe "DNS 事件日志中未发现恶意域名查询"
        }
    } catch {
        Info "无法读取 DNS 事件日志 (需要管理员权限)"
    }

    # 4. DNS 缓存 (短期)
    try {
        $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue |
                    Where-Object { $_.Entry -like "*$MALICIOUS_DOMAIN*" }
        if ($dnsCache) {
            Found "DNS 缓存中发现恶意域名"
            $evidenceCount++
        } else {
            Safe "DNS 缓存清洁"
        }
    } catch {}

    # 5. Sysmon 日志 (如果安装了)
    try {
        $sysmonDns = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue |
                     Where-Object { $_.Id -eq 22 -and $_.Message -like "*$MALICIOUS_DOMAIN*" } |
                     Select-Object -First 5
        if ($sysmonDns) {
            Found "Sysmon 日志中发现恶意域名 DNS 查询"
            $evidenceCount++
        }
    } catch {}

    # 6. Windows Defender
    try {
        $threats = Get-MpThreatDetection -ErrorAction SilentlyContinue |
                   Where-Object { $_.ProcessName -like "*apifox*" -or $_.Resources -like "*apifox*" }
        if ($threats) {
            Found "Windows Defender 曾检测到 Apifox 相关威胁"
            $evidenceCount++
        } else {
            Safe "Windows Defender 未报告 Apifox 相关威胁"
        }
    } catch {}

    # 7. 防火墙日志
    $fwLog = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
    if (Test-Path $fwLog) {
        $fwHits = Select-String -Path $fwLog -Pattern $MALICIOUS_DOMAIN -ErrorAction SilentlyContinue
        if ($fwHits) {
            Found "防火墙日志中发现恶意域名连接记录"
            $evidenceCount++
        }
    }

    Write-Host ""
    if ($evidenceCount -gt 0) {
        Found "发现 $evidenceCount 处补充证据"
        $script:compromised = $true
    } else {
        Safe "补充检测未发现额外异常痕迹"
    }
}

# ============================================================
# 结果汇总
# ============================================================
function Print-Summary {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  检测结果" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""

    if ($script:compromised) {
        Write-Host "  结论: 已中招 -- 敏感信息已被窃取" -ForegroundColor Red
        Write-Host ""
        Write-Host "  根据恶意 payload 分析，以下信息已被上传到攻击者服务器:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  [Stage-2 v1 窃取内容]"
        Write-Host "    - %USERPROFILE%\.ssh\ 目录 (所有文件，包括私钥)"
        Write-Host "    - tasklist 进程列表"
        Write-Host ""
        Write-Host "  [Stage-2 v2 额外窃取]"
        Write-Host "    - ~/.kube/ (Kubernetes 配置)"
        Write-Host "    - ~/.npmrc (npm 凭据)"
        Write-Host "    - SVN 凭据"
        Write-Host ""
        Write-Host "  [C2 beacon 窃取]"
        Write-Host "    - Apifox accessToken / 邮箱 / 用户名"
        Write-Host "    - 系统指纹 (MAC地址/CPU/主机名/用户名/OS)"
        Write-Host ""
        Write-Host "  !! 紧急修复步骤 !!" -ForegroundColor Red
        Write-Host ""
        Write-Host "  1. 轮换所有 SSH 密钥:"
        Write-Host '     Remove-Item ~\.ssh\id_* -Force'
        Write-Host '     ssh-keygen -t ed25519 -C "your_email"'
        Write-Host "     并在所有平台更新公钥 (GitHub/GitLab/服务器)"
        Write-Host ""
        Write-Host "  2. 撤销所有 Git Personal Access Token:"
        Write-Host "     GitHub -> Settings -> Developer settings -> Tokens -> Revoke"
        Write-Host ""
        Write-Host "  3. 轮换 K8s 凭据:"
        Write-Host "     检查 ~\.kube\config，重置 OIDC token 和集群凭据"
        Write-Host ""
        Write-Host "  4. 轮换 npm token:"
        Write-Host "     npm token revoke <token> && npm login"
        Write-Host ""
        Write-Host "  5. 在 Apifox 中注销并重新登录"
        Write-Host ""
        Write-Host "  6. 检查所有平台的安全日志:"
        Write-Host "     - GitHub: Settings -> Security log"
        Write-Host "     - 服务器: 检查 authorized_keys 是否被注入后门密钥"
        Write-Host "     - K8s: 审计集群操作日志"
        Write-Host ""
        Write-Host "  7. 清理 Apifox 历史数据 (消除残留标记):"
        Write-Host "     Remove-Item -Recurse -Force '$APIFOX_DATA_DIR'"
        Write-Host "     (重启 Apifox 后会重新生成，本地设置会丢失)"
        Write-Host ""
        Write-Host "  8. 运行 check_leaked_info.ps1 查看详细泄露范围"
    } else {
        Write-Host "  结论: 未发现感染迹象" -ForegroundColor Green
        Write-Host ""
        Write-Host "  如果你确信在 2026-03-04 ~ 2026-03-22 期间使用过 Apifox 桌面版,"
        Write-Host "  但未检测到标记，可能的原因:"
        Write-Host "    - 已手动清理过 Apifox 数据目录"
        Write-Host "    - 恶意 CDN 资源未加载成功 (网络问题/防火墙拦截)"
        Write-Host "    - 使用的是 Web 版而非桌面版"
        Write-Host ""
        Write-Host "  仍建议预防性检查: 运行 check_leaked_info.ps1 确认敏感文件状态"
    }

    Write-Host ""
    Write-Host "============================================================"
}

# ============================================================
# Main
# ============================================================
Print-Banner
Check-CoreVerdict
Check-Supplementary
Print-Summary
