#!/usr/bin/env bash
# 把凭据/配置目录打成加密包，供 artifact 上传。
#
# 公开仓库的 artifact 任何登录用户都能下载，含 WireGuard 私钥的明文配置
# 绝不能直接上传。这里用 AES-256-CBC + PBKDF2 加密，明文只走管道不落盘。
#
# 用法: ARTIFACT_PASSPHRASE='口令' pack_encrypted.sh <源目录> <输出文件>
# 解密: ARTIFACT_PASSPHRASE='口令' openssl enc -d -aes-256-cbc -pbkdf2 \
#         -iter 200000 -salt -pass env:ARTIFACT_PASSPHRASE \
#         -in <输出文件> | tar xzf -
set -euo pipefail

SRC=${1:?用法: pack_encrypted.sh <源目录> <输出文件>}
OUT=${2:?缺输出文件路径}

if [ ! -d "$SRC" ]; then
  echo "源目录不存在: $SRC" >&2
  exit 1
fi
if [ -z "$(ls -A "$SRC")" ]; then
  echo "源目录为空，拒绝生成空包: $SRC" >&2
  exit 1
fi
if [ -z "${ARTIFACT_PASSPHRASE:-}" ]; then
  echo "缺 ARTIFACT_PASSPHRASE。到 Settings > Secrets and variables > Actions" >&2
  echo "加一个同名 secret（口令自己定并记住），否则不上传任何产物。" >&2
  exit 1
fi

# tar 的明文只在管道里；openssl 从环境变量读口令，不出现在命令行
tar czf - -C "$SRC" . | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt \
  -pass env:ARTIFACT_PASSPHRASE -out "$OUT"

test -s "$OUT" || { echo "加密包为空: $OUT" >&2; exit 1; }
echo "已生成加密包 $OUT（$(wc -c < "$OUT") 字节）"
