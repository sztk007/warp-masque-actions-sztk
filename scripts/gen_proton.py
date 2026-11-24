#!/usr/bin/env python3
"""登录 Proton，产出一段可粘贴进 Worker 的凭据文本。

Worker 不碰 Proton 登录（那会触发风控），只消费这段文本。
证书最长 7 天，过期重跑本流水线换新的。

用法: PROTON_USER=x PROTON_PASS=y python3 gen_proton.py <输出目录>

关于客户端版本：Proton 会周期性抬高 API 接受的最低 appversion，低于门槛
一律返回 5003 "app is no longer supported"。硬编码版本号迟早会失效
（4.8.2 -> 4.13.0 修过一次，4.13.0 又被退役），所以登录前先用 /auth/info
匿名探测版本，被拒就自动往上换。PROTON_APP_VERSION 只是候选列表的起点，
不设也行。
"""
import asyncio
import base64
import hashlib
import json
import os
import re
import sys
import time

import aiohttp
from proton.session import ProtonAPIError, Session
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

API_BASE = "https://vpn-api.proton.me"
RELEASE_NOTES = "https://protonvpn.com/support/release-notes-linux"
DEFAULT_APP_VERSION = "4.19.1"     # 2026-11-24 实测被 API 接受
PROBE_USER = "version-probe@invalid.example"  # 探测用假用户名，不碰真实账号
RETIRED_CODES = {5003, 5005}       # app version 不再被支持
HUMAN_CHECK_CODES = {9001, 9002}   # 人机验证 / 设备验证

# 只挑这些国家的落地，够用且不会让配置爆炸
WANT = {"JP": "日本", "SG": "新加坡", "US": "美国", "NL": "荷兰",
        "CH": "瑞士", "CA": "加拿大", "PL": "波兰", "RO": "罗马尼亚",
        "NO": "挪威", "MX": "墨西哥"}
PER_COUNTRY = 3     # 每国取几台


def normalize_version(value):
    """允许 '4.19.1' 或 'linux-vpn@4.19.1'，空值回落到默认。"""
    v = (value or "").strip().split("@")[-1].strip()
    return v or DEFAULT_APP_VERSION


def app_headers(ver):
    return {
        "x-pm-appversion": f"linux-vpn@{ver}",
        "User-Agent": f"ProtonVPN/{ver} (Linux; Ubuntu/24.04)",
    }


async def fetch_latest_release(http):
    """抓官方 Linux 客户端最新稳定版当候选之一。抓不到就算了，不制造新故障点。"""
    try:
        async with http.get(RELEASE_NOTES, timeout=aiohttp.ClientTimeout(total=10)) as r:
            if r.status != 200:
                return None
            m = re.search(r"Version\s+(\d+\.\d+\.\d+)", await r.text())
            return m.group(1) if m else None
    except Exception:
        return None


def build_candidates(preferred, latest):
    """首选 -> 官方最新 -> 往后若干小版本 -> 大版本兜底，去重保序。

    Proton 目前只做「最低版本」检查，比门槛高的版本号都能通过（4.20.0、
    4.25.0、5.0.0 实测均可用），所以往上递增是有效的自愈手段。
    """
    cand = [preferred]
    if latest:
        cand.append(latest)
    nums = re.findall(r"\d+", latest or preferred)
    major = int(nums[0]) if nums else 4
    minor = int(nums[1]) if len(nums) > 1 else 19
    for m in range(minor + 1, minor + 9):
        cand.append(f"{major}.{m}.0")
    cand += [f"{major}.99.0", f"{major + 1}.0.0", f"{major + 2}.0.0"]
    seen, out = set(), []
    for v in cand:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


async def probe_version(http, ver):
    """匿名 /auth/info：Code 1000 = 版本可用；5003/5005 = 已被退役。

    这个接口对不存在的用户名也返回 Modulus，所以探测不需要账号密码，
    也不会消耗真实账号的登录次数。
    """
    try:
        async with http.post(f"{API_BASE}/auth/info",
                            json={"Username": PROBE_USER},
                            headers=app_headers(ver),
                            timeout=aiohttp.ClientTimeout(total=15)) as r:
            data = await r.json(content_type=None)
            if not isinstance(data, dict):
                return None, f"返回不是 JSON：{str(data)[:120]}"
            return data.get("Code"), data.get("Error") or ""
    except Exception as e:
        return None, f"探测请求异常：{type(e).__name__}: {e}"


def explain(code, err):
    if code in HUMAN_CHECK_CODES:
        return (f"Proton 要求人机/设备验证（Code {code}）。先在浏览器登录一次该账号，"
                "或换 runner 出口 IP 再跑；换客户端版本没用。")
    return f"Proton API 返回 Code {code}: {err}"


async def open_session(user, pwd, preferred):
    """挑一个还没被退役的 appversion 登录，返回 Session。"""
    async with aiohttp.ClientSession() as http:
        latest = await fetch_latest_release(http)
        if latest:
            print(f"官方最新 Linux 客户端：{latest}")
        candidates = build_candidates(preferred, latest)
        print(f"候选 appversion：{', '.join(candidates)}")
        retired = []
        for ver in candidates:
            code, err = await probe_version(http, ver)
            if code in RETIRED_CODES:
                print(f"  {ver} 已被 Proton 退役（Code {code}），换下一个")
                retired.append(ver)
                continue
            if code != 1000:
                detail = explain(code, err) if code else err
                sys.exit(f"版本探测失败：{detail}\n"
                         "这不是版本退役问题，别改版本号，先查网络和 Proton 状态。")
            print(f"  {ver} 可用，开始登录")
            session = Session(appversion=f"linux-vpn@{ver}",
                              user_agent=f"ProtonVPN/{ver} (Linux; Ubuntu/24.04)")
            try:
                ok = await session.async_authenticate(user, pwd)
            except ProtonAPIError as e:
                if e.body_code in RETIRED_CODES:
                    print(f"  登录时又被判定为旧版本（Code {e.body_code}），继续换版本")
                    retired.append(ver)
                    continue
                sys.exit(f"登录被 Proton 拒绝：{explain(e.body_code, e.error)} "
                         f"(HTTP {e.http_code})")
            if not ok:
                sys.exit("登录失败：账号密码不对，或账号被风控要求人工验证。"
                         "检查 PROTON_USER / PROTON_PASS，或先在浏览器登录一次。")
            print(f"登录成功（appversion={ver}）")
            return session
    sys.exit("所有候选客户端版本都被 Proton 退役了：" + ", ".join(retired) +
             "。用 PROTON_APP_VERSION 指定一个更新的官方版本号再试。")


def ed25519_to_wg(raw_sk: bytes) -> str:
    """Proton 的 wg 私钥是从 Ed25519 私钥推的：SHA512 前 32 字节 + clamp。"""
    h = bytearray(hashlib.sha512(raw_sk).digest()[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return base64.b64encode(bytes(h)).decode()


async def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "dist"
    user = os.environ.get("PROTON_USER", "")
    pwd = os.environ.get("PROTON_PASS", "")
    if not user or not pwd:
        sys.exit("缺 PROTON_USER / PROTON_PASS 环境变量")

    preferred = normalize_version(os.environ.get("PROTON_APP_VERSION"))
    s = await open_session(user, pwd, preferred)

    vpn = (await s.async_api_request("/vpn/v2")).get("VPN", {})
    print(f"套餐 {vpn.get('PlanName')} / Tier {vpn.get('MaxTier')} / 最大连接 {vpn.get('MaxConnect')}")

    # 申请证书。Duration 写多久都封顶 7 天，实测过
    sk = ed25519.Ed25519PrivateKey.generate()
    pem = sk.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    raw = sk.private_bytes(serialization.Encoding.Raw,
                           serialization.PrivateFormat.Raw,
                           serialization.NoEncryption())
    cert = await s.async_api_request("/vpn/v1/certificate", jsondata={
        "ClientPublicKey": pem, "Mode": "session",
        "Duration": "10080 min", "DeviceName": "worker",
    })
    exp = cert["ExpirationTime"]
    wg_sk = ed25519_to_wg(raw)
    print(f"证书到期 {time.strftime('%F %T', time.gmtime(exp))} UTC "
          f"（{(exp - time.time()) / 86400:.1f} 天）")

    # 服务器列表，只要免费的
    lg = await s.async_api_request("/vpn/logicals")
    free = [x for x in lg["LogicalServers"] if x.get("Tier") == 0]

    picked, by_cc = [], {}
    for srv in sorted(free, key=lambda x: x.get("Score", 99)):
        cc = srv["ExitCountry"]
        if cc not in WANT or by_cc.get(cc, 0) >= PER_COUNTRY:
            continue
        phys = (srv.get("Servers") or [{}])[0]
        pub = phys.get("X25519PublicKey")
        ip = phys.get("EntryIP")
        if not (pub and ip):
            continue
        by_cc[cc] = by_cc.get(cc, 0) + 1
        picked.append({
            "name": f"{WANT[cc]}{by_cc[cc]}",
            "cc": cc, "ip": ip, "port": 51820, "pub": pub,
        })

    if not picked:
        sys.exit("免费服务器列表为空（Tier=0 一台没匹配到）。Proton API 结构可能变了，"
                 "别把空配置推给 Worker。")

    print(f"选中 {len(picked)} 台，覆盖 {len(by_cc)} 国: "
          + " ".join(f"{c}x{n}" for c, n in sorted(by_cc.items())))

    payload = {
        "v": 1,
        "privateKey": wg_sk,
        "expiresAt": exp,
        "generatedAt": int(time.time()),
        "servers": picked,
    }

    os.makedirs(outdir, exist_ok=True)
    # 压成一行 base64，方便整段复制粘贴，不会被换行搞乱
    blob = base64.b64encode(
        json.dumps(payload, separators=(",", ":")).encode()).decode()

    with open(os.path.join(outdir, "proton-blob.txt"), "w") as f:
        f.write(blob + "\n")
    with open(os.path.join(outdir, "proton.json"), "w") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    print(f"\n已生成 {outdir}/proton-blob.txt（{len(blob)} 字符）")
    print("由工作流通过 WORKER_PUSH_URL 推送给 Worker；本流水线不上传 artifact、不落公开产物。")


try:
    asyncio.run(main())
except ProtonAPIError as e:
    sys.exit(f"Proton API 报错 [{e.body_code}] {e.error} (HTTP {e.http_code})")
