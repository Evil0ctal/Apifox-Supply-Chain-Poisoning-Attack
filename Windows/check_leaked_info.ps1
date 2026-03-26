# ============================================================
# Apifox 供应链投毒事件 - Windows 泄露信息检查脚本
# ============================================================
# 攻击窗口: 2026-03-04 ~ 2026-03-22
# 参考: https://rce.moe/2026/03/25/apifox-supply-chain-attack-analysis/
#
# 根据恶意 payload 分析，攻击者在 Windows 上窃取了:
#
# [Stage-2 v1]
#   - %USERPROFILE%\.ssh\ 目录 (所有文件，包括私钥)
#   - tasklist 输出 (进程列表)
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
# 使用方法: 以管理员权限打开 PowerShell，运行:
#   Set-ExecutionPolicy -Scope Process Bypass
#   .\check_leaked_info.ps1
# ============================================================

$ErrorActionPreference = "Continue"

$APIFOX_DATA_DIR = "$env:APPDATA\apifox"
$LEVELDB_DIR = "$APIFOX_DATA_DIR\Local Storage\leveldb"

function Print-Banner {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  Apifox 供应链投毒事件 - 泄露信息检查 (Windows)" -ForegroundColor Cyan
    Write-Host "  检测时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Danger($msg) {
    Write-Host "  [危险] $msg" -ForegroundColor Red
}

function Warn($msg) {
    Write-Host "  [警告] $msg" -ForegroundColor Yellow
}

function Safe($msg) {
    Write-Host "  [安全] $msg" -ForegroundColor Green
}

function Info($msg) {
    Write-Host "  [信息] $msg" -ForegroundColor Cyan
}

function Section($num, $title) {
    Write-Host ""
    Write-Host "[$num] $title" -ForegroundColor White
    Write-Host "------------------------------------------------------------"
}

# ============================================================
# 1. SSH 密钥泄露检查
# ============================================================
function Check-SSH {
    Section "1" "SSH 密钥泄露风险 (攻击者窃取了整个 .ssh 目录)"

    $sshDir = "$env:USERPROFILE\.ssh"

    if (-not (Test-Path $sshDir)) {
        Info ".ssh 目录不存在"
        return
    }

    Danger ".ssh 目录存在，以下文件内容可能已被窃取:"
    Write-Host ""

    Get-ChildItem -Path $sshDir -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $file = $_
        $size = $file.Length
        $modified = $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm")

        switch -Wildcard ($file.Name) {
            "id_rsa"       { Danger "  Key 私钥: $($file.FullName) (${size}B, $modified)"; Danger "     >> 此私钥必须立即轮换!" }
            "id_ed25519"   { Danger "  Key 私钥: $($file.FullName) (${size}B, $modified)"; Danger "     >> 此私钥必须立即轮换!" }
            "id_ecdsa"     { Danger "  Key 私钥: $($file.FullName) (${size}B, $modified)"; Danger "     >> 此私钥必须立即轮换!" }
            "id_dsa"       { Danger "  Key 私钥: $($file.FullName) (${size}B, $modified)"; Danger "     >> 此私钥必须立即轮换!" }
            "*.pub"        { Warn  "  Doc 公钥: $($file.FullName) (${size}B, $modified)" }
            "known_hosts"  {
                Warn "  Web 已知主机: $($file.FullName) (攻击者可获知你连接过的服务器列表)"
                $hostCount = (Get-Content $file.FullName -ErrorAction SilentlyContinue | Measure-Object -Line).Lines
                Info "     包含 $hostCount 条主机记录"
            }
            "authorized_keys" { Warn "  Lock 授权密钥: $($file.FullName)" }
            "config" {
                Danger "  Gear SSH 配置: $($file.FullName) (包含主机别名、用户名、端口等)"
                $hosts = Select-String -Path $file.FullName -Pattern "^Host\s+" -ErrorAction SilentlyContinue |
                         ForEach-Object { ($_ -split "\s+")[1] }
                if ($hosts) {
                    Info "     配置的主机: $($hosts -join ', ')"
                }
            }
            default { Warn "  File 其他文件: $($file.FullName) (${size}B)" }
        }
    }

    Write-Host ""
    Danger "建议操作:"
    Write-Host "  1. 重新生成所有 SSH 密钥:"
    Write-Host '     ssh-keygen -t ed25519 -C "your_email@example.com"'
    Write-Host "  2. 在所有服务器/平台上更新公钥 (GitHub, GitLab, 服务器等)"
    Write-Host "  3. 检查 authorized_keys 是否被篡改"
}

# ============================================================
# 2. 进程列表泄露检查 (Windows 特有)
# ============================================================
function Check-TaskList {
    Section "2" "进程列表泄露风险 (攻击者执行了 tasklist 命令)"

    Danger "攻击者已获取你的完整进程列表，以下信息已暴露:"
    Write-Host ""

    # 显示当前运行的敏感进程类型
    $sensitiveProcesses = @{
        "vpn"       = "VPN 客户端"
        "keepass"   = "密码管理器 (KeePass)"
        "1password" = "密码管理器 (1Password)"
        "bitwarden" = "密码管理器 (Bitwarden)"
        "lastpass"  = "密码管理器 (LastPass)"
        "putty"     = "SSH 客户端 (PuTTY)"
        "winscp"    = "SFTP 客户端 (WinSCP)"
        "filezilla" = "FTP 客户端 (FileZilla)"
        "telegram"  = "即时通讯 (Telegram)"
        "slack"     = "即时通讯 (Slack)"
        "teams"     = "即时通讯 (Teams)"
        "outlook"   = "邮件客户端 (Outlook)"
        "thunderbird" = "邮件客户端 (Thunderbird)"
        "sqlserver" = "数据库 (SQL Server)"
        "mysql"     = "数据库 (MySQL)"
        "postgres"  = "数据库 (PostgreSQL)"
        "docker"    = "容器 (Docker)"
        "vmware"    = "虚拟化 (VMware)"
        "virtualbox" = "虚拟化 (VirtualBox)"
    }

    $currentProcesses = Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName -Unique

    foreach ($key in $sensitiveProcesses.Keys) {
        $matched = $currentProcesses | Where-Object { $_ -like "*$key*" }
        if ($matched) {
            Warn "  发现敏感进程: $($sensitiveProcesses[$key]) ($($matched -join ', '))"
        }
    }

    Write-Host ""
    Warn "攻击者通过进程列表可以了解到:"
    Write-Host "  - 你使用的开发工具和 IDE"
    Write-Host "  - 你连接的数据库和远程服务"
    Write-Host "  - 你使用的安全/VPN 工具 (可用于规避检测)"
    Write-Host "  - 你使用的通讯工具 (潜在社工信息)"
}

# ============================================================
# 3. Git 凭据泄露检查
# ============================================================
function Check-GitCredentials {
    Section "3" "Git 凭据泄露风险"

    # Windows 上恶意脚本虽然主要窃取 .ssh 和 tasklist
    # 但仍然检查 git credentials 作为完整性检查
    $gitCredFile = "$env:USERPROFILE\.git-credentials"

    if (-not (Test-Path $gitCredFile)) {
        Safe ".git-credentials 文件不存在 (Windows payload 未直接窃取此文件)"
    } else {
        $lines = Get-Content $gitCredFile -ErrorAction SilentlyContinue
        Warn ".git-credentials 文件存在 (包含 $($lines.Count) 条凭据)"
        Write-Host ""

        foreach ($line in $lines) {
            if ($line -match "https?://([^:]+):([^@]+)@(.+)") {
                $username = $Matches[1]
                $platform = $Matches[3]
                Warn "  Lock 平台: $platform | 用户: $username | 密码: ***存在***"
            }
        }

        Write-Host ""
        Info "注意: Windows payload (03-02ab429d.js) 的代码路径未包含窃取 .git-credentials"
        Info "但如果攻击者通过 C2 远程代码 (eval) 下发了额外 payload，此文件可能也被窃取"
    }

    # 检查 Windows 凭据管理器中的 Git 凭据
    try {
        $cmdKeyOutput = cmdkey /list 2>&1 | Select-String -Pattern "git|github|gitlab|bitbucket" -ErrorAction SilentlyContinue
        if ($cmdKeyOutput) {
            Warn "Windows 凭据管理器中发现 Git 相关凭据:"
            $cmdKeyOutput | ForEach-Object { Info "  $($_.Line.Trim())" }
            Info "这些凭据存储在系统凭据管理器中，相对安全，但建议仍然轮换"
        }
    } catch {}

    # 检查 git config
    $credHelper = git config --global credential.helper 2>$null
    if ($credHelper) {
        Info "Git 凭据存储方式: $credHelper"
        if ($credHelper -eq "store") {
            Danger "使用明文存储 (store)! 建议切换到 manager-core"
        } elseif ($credHelper -like "*manager*") {
            Info "使用 Windows 凭据管理器 (相对安全)"
        }
    }

    Write-Host ""
    Warn "建议操作:"
    Write-Host "  1. 撤销并重新生成所有 Git Personal Access Token"
    Write-Host "  2. 切换到安全凭据存储: git config --global credential.helper manager-core"
    Write-Host "  3. 删除明文凭据: Remove-Item ~\.git-credentials -Force"
}

# ============================================================
# 4. Apifox 账户泄露检查
# ============================================================
function Check-ApifoxAccount {
    Section "4" "Apifox 账户信息泄露风险"

    if (-not (Test-Path $LEVELDB_DIR)) {
        Info "未找到 Apifox localStorage 数据"
        return
    }

    $tokenFound = $false
    Get-ChildItem -Path $LEVELDB_DIR -Include "*.log", "*.ldb" -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
            $text = [System.Text.Encoding]::ASCII.GetString($bytes)
            if ($text -match "accessToken|common\.accessToken") {
                $tokenFound = $true
            }
        } catch {}
    }

    if ($tokenFound) {
        Danger "发现 Apifox accessToken 存储记录 (可能已被窃取)"
        Danger "攻击者使用此 Token 调用 Apifox API 获取了你的邮箱和用户名"
    } else {
        Info "未在 localStorage 中发现 accessToken"
    }

    Write-Host ""
    Warn "被窃取的信息包括:"
    Write-Host "  - Apifox 登录邮箱"
    Write-Host "  - Apifox 用户名"
    Write-Host "  - Apifox accessToken"
    Write-Host ""
    Warn "建议操作:"
    Write-Host "  1. 立即在 Apifox 中注销并重新登录"
    Write-Host "  2. 检查团队成员列表是否有异常变动"
    Write-Host "  3. 检查项目/接口数据是否被导出或修改"
}

# ============================================================
# 5. 系统指纹泄露检查
# ============================================================
function Check-SystemFingerprint {
    Section "5" "系统指纹信息泄露情况"

    Warn "以下系统信息已被攻击者收集:"
    Write-Host ""

    # MAC 地址
    $mac = (Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
            Where-Object { $_.Status -eq "Up" } |
            Select-Object -First 1 -ExpandProperty MacAddress) -replace "-", ":"
    Danger "  MAC 地址: $mac"

    # CPU 型号
    $cpu = (Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue).Name
    Danger "  CPU 型号: $cpu"

    # 主机名
    Danger "  主机名: $env:COMPUTERNAME"

    # 用户名
    Danger "  用户名: $env:USERNAME"

    # OS 信息
    $osInfo = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue)
    Danger "  操作系统: $($osInfo.Caption) $($osInfo.Version)"

    Write-Host ""
    Warn "攻击者使用以上信息生成了机器唯一指纹 (SHA-256)，可用于:"
    Write-Host "  - 跟踪和识别你的机器"
    Write-Host "  - 定向攻击"
    Write-Host "  - 关联你在不同平台上的身份"
}

# ============================================================
# 6. Kubernetes 配置泄露检查 (Stage-2 v2 新增)
# ============================================================
function Check-Kube {
    Section "6" "Kubernetes 配置泄露风险 (Stage-2 v2 新增目标)"

    $kubeDir = "$env:USERPROFILE\.kube"
    if (-not (Test-Path $kubeDir)) {
        Safe ".kube 目录不存在"
        return
    }

    Danger ".kube 目录存在，以下内容可能已被窃取:"
    Write-Host ""

    $kubeConfig = "$kubeDir\config"
    if (Test-Path $kubeConfig) {
        Danger "  ~/.kube/config (集群凭据、API Server 地址、证书)"
        $clusters = Select-String -Path $kubeConfig -Pattern "^\s+cluster:" -ErrorAction SilentlyContinue |
                    ForEach-Object { ($_ -split "\s+")[-1] }
        if ($clusters) { Info "    配置的集群: $($clusters -join ', ')" }
    }

    $otherConfigs = Get-ChildItem -Path $kubeDir -Include "*.conf", "*.yaml", "*.yml" -ErrorAction SilentlyContinue
    foreach ($f in $otherConfigs) {
        Warn "  其他配置: $($f.Name)"
    }

    Write-Host ""
    Danger "建议操作:"
    Write-Host "  1. 重置所有 K8s 集群的 OIDC token / service account token"
    Write-Host "  2. 轮换 kubeconfig 中的客户端证书"
    Write-Host "  3. 审计集群操作日志，检查异常 API 调用"
}

# ============================================================
# 7. npm 凭据泄露检查 (Stage-2 v2 新增)
# ============================================================
function Check-Npm {
    Section "7" "npm 凭据泄露风险 (Stage-2 v2 新增目标)"

    $npmrc = "$env:USERPROFILE\.npmrc"
    if (Test-Path $npmrc) {
        Danger ".npmrc 文件存在，内容可能已被窃取:"
        $tokenLines = Select-String -Path $npmrc -Pattern "authToken|_password" -ErrorAction SilentlyContinue
        if ($tokenLines) {
            $tokenLines | ForEach-Object {
                $sanitized = $_.Line -replace '=.*', '=***REDACTED***'
                Danger "  -> $sanitized"
            }
        }
    } else {
        Safe ".npmrc 不存在"
    }

    Write-Host ""
    Warn "建议操作:"
    Write-Host "  1. 撤销 npm token: npm token revoke <token>"
    Write-Host "  2. 重新登录: npm login"
    Write-Host "  3. 检查 npm 包是否有异常发布"
}

# ============================================================
# 8. SVN 凭据泄露检查 (Stage-2 v2 新增)
# ============================================================
function Check-Svn {
    Section "8" "SVN 凭据泄露风险 (Stage-2 v2 新增目标)"

    $svnDir = "$env:APPDATA\Subversion\auth"
    if (-not (Test-Path $svnDir)) {
        Safe "SVN auth 目录不存在"
        return
    }

    Danger "SVN 缓存凭据目录存在: $svnDir"
    Get-ChildItem -Path $svnDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $credCount = (Get-ChildItem $_.FullName -File -ErrorAction SilentlyContinue).Count
        Warn "  -> $($_.Name): $credCount 个缓存凭据"
    }

    Write-Host ""
    Warn "建议操作:"
    Write-Host "  1. 清除 SVN 缓存: Remove-Item -Recurse '$svnDir'"
    Write-Host "  2. 更改 SVN 服务器密码"
}

# ============================================================
# 9. 额外的 Windows 特定检查
# ============================================================
function Check-WindowsSpecific {
    Section "6" "Windows 额外安全检查"

    # 检查计划任务是否有可疑项
    Warn "检查是否有可疑的计划任务..."
    try {
        $suspTasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
                     Where-Object {
                         $_.TaskName -like "*apifox*" -or
                         $_.TaskPath -like "*apifox*" -or
                         ($_.Actions | ForEach-Object { $_.Execute } ) -like "*apifox*"
                     }
        if ($suspTasks) {
            Danger "发现与 Apifox 相关的计划任务!"
            $suspTasks | ForEach-Object { Info "  -> $($_.TaskName) ($($_.TaskPath))" }
        } else {
            Safe "未发现与 Apifox 相关的可疑计划任务"
        }
    } catch {
        Info "无法检查计划任务 (需要管理员权限)"
    }

    # 检查启动项
    Warn "检查启动项..."
    $startupLocations = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    )

    foreach ($loc in $startupLocations) {
        try {
            $items = Get-ItemProperty $loc -ErrorAction SilentlyContinue
            $props = $items.PSObject.Properties | Where-Object {
                $_.Value -like "*apifox*" -and
                $_.Name -notmatch "^PS"
            }
            if ($props) {
                Warn "发现与 Apifox 相关的启动项: $($props.Name)"
            }
        } catch {}
    }

    Safe "启动项检查完成"

    # 检查 Windows Firewall 出站规则
    Warn "检查防火墙出站规则..."
    try {
        $fwRules = Get-NetFirewallRule -Direction Outbound -ErrorAction SilentlyContinue |
                   Where-Object { $_.DisplayName -like "*apifox*" }
        if ($fwRules) {
            Info "发现 Apifox 相关防火墙规则:"
            $fwRules | ForEach-Object { Info "  -> $($_.DisplayName) | 状态: $($_.Enabled)" }
        }
    } catch {
        Info "无法检查防火墙规则"
    }
}

# ============================================================
# 7. 汇总与紧急建议
# ============================================================
function Print-Summary {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host "  泄露影响汇总与紧急修复建议 (Windows)" -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host ""

    Write-Host "如果你确认中招，请按以下优先级处理:" -ForegroundColor White
    Write-Host ""
    Write-Host "[紧急 - 立即处理]" -ForegroundColor Red
    Write-Host "  1. 轮换所有 SSH 密钥并更新到所有平台"
    Write-Host '     ssh-keygen -t ed25519 -C "your_email@example.com"'
    Write-Host ""
    Write-Host "  2. 撤销并重新生成所有 Git Personal Access Token"
    Write-Host "     GitHub: Settings -> Developer settings -> Personal access tokens"
    Write-Host ""
    Write-Host "  3. 在 Apifox 中注销并重新登录"
    Write-Host ""
    Write-Host "[重要 - Stage-2 v2 新增]" -ForegroundColor Yellow
    Write-Host "  4. 轮换 K8s 凭据:"
    Write-Host "     检查 ~\.kube\config，重置 OIDC token 和集群凭据"
    Write-Host ""
    Write-Host "  5. 轮换 npm token:"
    Write-Host "     npm token revoke <token> && npm login"
    Write-Host ""
    Write-Host "  6. 清除 SVN 缓存凭据"
    Write-Host ""
    Write-Host "[重要 - 尽快处理]" -ForegroundColor Yellow
    Write-Host "  7. 检查 GitHub/GitLab 安全日志:"
    Write-Host "     - 新增 Deploy Key"
    Write-Host "     - 异常地区/IP 的登录记录"
    Write-Host "     - 异常的 Push / PR / Webhook"
    Write-Host ""
    Write-Host "  8. 检查服务器 authorized_keys 是否被注入后门密钥"
    Write-Host ""
    Write-Host "[建议 - 后续处理]" -ForegroundColor Cyan
    Write-Host "  9. 更新 Apifox 到最新安全版本"
    Write-Host " 10. 启用所有平台的两步验证 (2FA)"
    Write-Host " 11. 对 SSH 私钥添加密码保护:"
    Write-Host "     ssh-keygen -p -f ~\.ssh\id_ed25519"
    Write-Host " 12. 运行完整的杀毒扫描"
    Write-Host "     Windows Defender: Start-MpScan -ScanType FullScan"
    Write-Host ""
    Write-Host "============================================================"
}

# ============================================================
# Main
# ============================================================
Print-Banner
Check-SSH
Check-TaskList
Check-GitCredentials
Check-ApifoxAccount
Check-SystemFingerprint
Check-Kube
Check-Npm
Check-Svn
Check-WindowsSpecific
Print-Summary
