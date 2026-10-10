#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
连通性探针：分层验证「网络可达」与「签名密钥有效」，全程不需要登录态。

设计目的：抓包拿 refreshToken 是有成本的一步。先用这个探针确认当前网络
         （尤其是 GitHub Actions 的境外 runner）能不能连上领克网关，
         避免白忙一场。

分三层诊断，能精确定位卡点：
  [A] 网络层  —— 能否 TCP/TLS 连上 app-services.lynkco.com.cn（不需密钥）
  [B] 密钥层  —— nativeAppKey / nativeAppSecret 是否已配置（不需联网）
  [C] 网关层  —— 用真密钥对无效 refreshToken 发带签名请求，看网关怎么回
                 · 回合法 JSON 且是业务错误 → 签名被接受 ✅
                 · 回合法 JSON 但提示签名/鉴权错 → 密钥不对 ⚠️
                 · 超时/连不上/回 HTML → 被拦截 ❌

退出码：0=通，2=没配密钥，3=密钥无效，4=网络被拦
用法（在 LynkCoHelper 目录下）：python test_connectivity.py
"""
import os
import sys
import uuid

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

EXIT_OK, EXIT_NOKEY, EXIT_BADKEY, EXIT_BLOCKED = 0, 2, 3, 4

PROBE_RT = "bearer00000000-0000-0000-0000-000000000000"
SIG_ERROR_KEYWORDS = ("signature", "appkey", "appcode", "unauthorized",
                      "forbidden", "signatureheaders", "签名", "鉴权", "未授权")

# 业务层错误码：网关已放行（说明签名通过），只是 token/账号层面无效。
# 探针故意传无效 refreshToken，命中这一类即代表验证成功。
BUSINESS_ERROR_KEYWORDS = ("user_", "token", "expired", "invalid",
                           "not_login", "notlogin", "not_found",
                      "未登录", "过期", "无效")


def mask_value(v: str) -> str:
    if not v:
        return "(空)"
    return "***" if len(v) <= 5 else f"{v[:3]}***{v[-2:]}"


def layer_a_network() -> bool:
    """第 A 层：纯连通性，不依赖任何凭证。"""
    print("\n[A] 网络层：能否连上领克网关 ...")
    try:
        import requests
    except ImportError:
        print("    缺少 requests，请先 pip install requests")
        return False

    targets = [
        ("原生网关", "https://app-services.lynkco.com.cn"),
        ("业务网关", "https://app-api-gw-toc.lynkco.com"),
    ]
    ok = False
    for label, base in targets:
        try:
            resp = requests.get(base, timeout=15)
            print(f"    {label} {base} -> HTTP {resp.status_code}  (可达)")
            ok = True
        except Exception as e:
            print(f"    {label} {base} -> 失败 [{type(e).__name__}]")
            print("       " + str(e)[:180])
    return ok


def layer_b_keys():
    """第 B 层：密钥是否配置。返回 (key, secret) 或 (None, None)。"""
    print("\n[B] 密钥层：签名密钥是否已配置 ...")
    try:
        import lynkco_common
        key = lynkco_common.NATIVE_APP_KEY
        secret = lynkco_common.NATIVE_APP_SECRET
    except Exception as e:
        print("    读取失败：" + str(e)[:200])
        return None, None
    print(f"    nativeAppKey    = {mask_value(key)}")
    print(f"    nativeAppSecret = {mask_value(secret)}")
    return key, secret


def layer_c_gateway(key, secret):
    """第 C 层：用真密钥发带签名请求，按网关返回判定。"""
    print("\n[C] 网关层：发送带签名的探测请求 ...")
    print("    （refreshToken 故意用无效值，业务报错属预期）")
    from lynkco_login import refresh_token_by_signature

    device_id = os.environ.get("LYNKCO_DEVICE_ID", "").strip() or uuid.uuid4().hex[:16]
    result = refresh_token_by_signature(PROBE_RT, device_id)
    data = result if isinstance(result, dict) else {"raw": result}
    code = str(data.get("code", ""))
    message = str(data.get("message", ""))
    print("    网关返回合法 JSON：")
    print(f"      code    = {code}")
    print(f"      message = {message[:120] or '(无)'}")

    low = (code + " " + message).lower()

    # 1) 网关层错误：签名/鉴权没过，请求根本没进业务
    if any(k in low for k in SIG_ERROR_KEYWORDS):
        print("\n>>> 结论：网络可达，但密钥无效/未授权 ⚠️")
        print("    处理：重跑 extract-appsecret 拿最新密钥。")
        return EXIT_BADKEY

    # 2) 业务层错误码：说明网关已放行、签名被接受，只是 token 本身无效
    #    （探针故意用无效 refreshToken，报业务错属预期）
    if any(k in low for k in BUSINESS_ERROR_KEYWORDS):
        print("\n>>> 结论：网络可达 + 签名体系通过 ✅")
        print("    网关认了签名，返回的是业务错误码（refreshToken 无效是探针故意的）。")
        print("    下一步：iPhone 抓包拿真 refreshToken 和 deviceId。")
        return EXIT_OK

    print("\n>>> 结论：返回了 JSON，但错误码未归类，请把上面日志发我判断。")
    print(f"    code = {code}")
    return EXIT_BLOCKED


def main():
    print("=" * 62)
    print("领克网关连通性探针（无需登录态）")
    print("=" * 62)

    net_ok = layer_a_network()
    key, secret = layer_b_keys()

    if not key or not secret:
        print("\n>>> 结论：尚未配置签名密钥，无法完成 C 层探测。")
        print("    处理：先跑一次 extract-appsecret workflow，把得到的")
        print("          nativeAppKey / nativeAppSecret 填进 Secrets。")
        if not net_ok:
            print("    另外：A 层网络也不通，若这是 GitHub runner，")
            print("          基本可判定为境外 IP 被拦，建议直接改本地跑。")
        return EXIT_NOKEY

    try:
        return layer_c_gateway(key, secret)
    except Exception as e:
        name = type(e).__name__
        msg = str(e)
        print(f"\n[C] 探测请求失败：{name}")
        print("    " + msg[:400])
        if name in ("ConnectionError", "ConnectTimeout", "ReadTimeout",
                    "Timeout", "SSLError", "ProxyError"):
            print("\n>>> 结论：网络层被拦截 ❌")
            print("    若此处是 GitHub Actions runner，高度疑似境外 IP 限制。")
            print("    处理：改用本地 Windows 定时跑。")
        elif "Expecting value" in msg or "JSONDecodeError" in name:
            print("\n>>> 结论：网关返回非 JSON（疑似 HTML 拦截页）❌")
            print("    处理：换网络环境，或改用本地跑。")
        else:
            print("\n>>> 结论：未归类失败，请把上面日志发我判断。")
        return EXIT_BLOCKED


if __name__ == "__main__":
    sys.exit(main())
