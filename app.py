#!/usr/bin/env python3
"""
NowV v1 兼容卡密验证服务器
实现 Noise_NK_25519_ChaChaPoly_SHA256 握手 + 加密消息通道
"""
import os
import json
import base64
import uuid
import time
import hashlib
from flask import Flask, request, Response
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from noise.connection import NoiseConnection, Keypair

app = Flask(__name__)

# ========== 服务器静态密钥（X25519，Noise NK用）==========
# 首次启动自动生成并保存
KEY_FILE = "server_x25519.key"
if os.path.exists(KEY_FILE):
    with open(KEY_FILE, 'rb') as f:
        priv_bytes = f.read()
    server_priv = X25519PrivateKey.from_private_bytes(priv_bytes)
else:
    server_priv = X25519PrivateKey.generate()
    priv_bytes = server_priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(KEY_FILE, 'wb') as f:
        f.write(priv_bytes)

server_pub_bytes = server_priv.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

def b64url_nopad(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

print(f"服务器X25519公钥(base64url): {b64url_nopad(server_pub_bytes)}")
print(f"公钥hex: {server_pub_bytes.hex()}")

# ========== 卡密存储 ==========
CARDS_FILE = "cards.json"
def load_cards():
    if os.path.exists(CARDS_FILE):
        with open(CARDS_FILE, 'r') as f:
            return json.load(f)
    # 默认卡密
    default = {
        "test123456": {
            "created": time.time(),
            "note": "测试卡密"
        }
    }
    save_cards(default)
    return default

def save_cards(cards):
    with open(CARDS_FILE, 'w') as f:
        json.dump(cards, f, indent=2, ensure_ascii=False)

# ========== 活动会话 ==========
# session_id -> NoiseConnection
sessions = {}

PROLOGUE = b"NowV/v1;Noise_NK_25519_ChaChaPoly_SHA256;ordered-http;device=P256"
APP_ID = "eda7720d-55f0-5e6a-a9c3-3328f5cafc78"

@app.route('/')
def index():
    return "NowV compatible server running"

@app.route('/v1/handshake', methods=['POST'])
def handshake():
    """Noise NK 握手：客户端发第一条消息，服务器返回第二条"""
    msg1 = request.get_data()
    print(f"\n[握手] 收到客户端消息: {len(msg1)} 字节")
    print(f"  hex: {msg1.hex()[:100]}")
    
    try:
        noise = NoiseConnection.from_name(b'Noise_NK_25519_ChaChaPoly_SHA256')
        noise.set_as_responder()
        noise.set_keypair_from_private_bytes(Keypair.STATIC, priv_bytes)
        noise.set_prologue(PROLOGUE)
        noise.start_handshake()
        
        # 读取客户端第一条消息（包含临时公钥）
        noise.read_message(msg1)
        
        # 生成服务器响应
        msg2 = bytes(noise.write_message(b""))
        print(f"  握手响应: {len(msg2)} 字节")
        
        # 生成会话ID
        session_id = str(uuid.uuid4())
        sessions[session_id] = noise
        print(f"  会话ID: {session_id}")
        
        resp = Response(msg2, status=200)
        resp.headers['Content-Type'] = 'application/octet-stream'
        resp.headers['X-NowV-Session'] = session_id
        resp.headers['Cache-Control'] = 'no-store'
        return resp
    except Exception as e:
        print(f"  握手失败: {e}")
        import traceback
        traceback.print_exc()
        return Response(b'', status=400)

@app.route('/v1/message', methods=['POST'])
def message():
    """处理加密的业务消息"""
    session_id = request.headers.get('X-NowV-Session', '')
    encrypted = request.get_data()
    
    print(f"\n[消息] 会话: {session_id}")
    print(f"  密文长度: {len(encrypted)}")
    
    noise = sessions.get(session_id)
    if not noise:
        print("  会话不存在")
        return Response(b'', status=400)
    
    try:
        plaintext = noise.decrypt(encrypted)
        print(f"  明文: {plaintext.decode('utf-8', errors='ignore')}")
        
        req_obj = json.loads(plaintext)
        req_id = req_obj.get('id')
        op = req_obj.get('op', '')
        data = req_obj.get('data', {})
        
        # 路由
        if op == 'auth.license':
            resp_data = handle_auth_license(data)
        elif op == 'client.heartbeat':
            resp_data = handle_heartbeat(data)
        else:
            resp_data = {"ok": False, "error": "UNKNOWN_OP"}
        
        # 包装响应
        resp_obj = {
            "ok": resp_data.get("ok", True),
            "id": req_id,
        }
        if resp_data.get("ok"):
            resp_obj["data"] = resp_data.get("data", {})
        else:
            resp_obj["error"] = resp_data.get("error", "ERROR")
        
        resp_plain = json.dumps(resp_obj, separators=(',', ':')).encode()
        print(f"  响应明文: {resp_plain.decode()[:300]}")
        
        resp_encrypted = bytes(noise.encrypt(resp_plain))
        print(f"  响应密文: {len(resp_encrypted)} 字节")
        
        resp = Response(resp_encrypted, status=200)
        resp.headers['Content-Type'] = 'application/octet-stream'
        resp.headers['X-NowV-Session'] = session_id
        return resp
    except Exception as e:
        print(f"  处理失败: {e}")
        import traceback
        traceback.print_exc()
        return Response(b'', status=400)

def handle_auth_license(data):
    """处理授权请求"""
    print(f"  auth.license data keys: {list(data.keys())}")
    print(f"  auth.license 完整数据: {json.dumps(data, ensure_ascii=False)[:500]}")
    
    # 记录所有字段，方便分析
    device_id = data.get('deviceId', '')
    public_key = data.get('publicKey', '')
    signature = data.get('signature', '')
    app_id = data.get('appId', '')
    
    # 查找卡密 - 尝试各种可能的字段
    card_key = None
    for field in ['licenseKey', 'cardKey', 'key', 'license', 'card', 'code', 'token', 'licenseId']:
        if field in data:
            card_key = data[field]
            print(f"  在字段 '{field}' 找到卡密: {card_key}")
            break
    
    # 如果没找到卡密字段，先返回授权成功（用于调试）
    # 实际使用时应该强制验证卡密
    cards = load_cards()
    
    if card_key is None:
        # 调试模式：没找到卡密字段，先看看数据里有什么
        # 返回AUTH_REQUIRED让客户端继续
        print("  未找到卡密字段，所有字段:", list(data.keys()))
        # 先返回授权成功看看客户端反应
        now = int(time.time())
        return {
            "ok": True,
            "data": {
                "licenseId": str(uuid.uuid4()),
                "expiresAt": now + 86400 * 365,
                "leaseUntil": now + 3600,
                "heartbeatAfterSeconds": 300,
                "deviceAssurance": "KEY_POSSESSION_ONLY",
                "variables": {
                    "announcement": {
                        "version": "1",
                        "values": ["欢迎使用"]
                    }
                }
            }
        }
    
    # 验证卡密
    if card_key not in cards:
        return {"ok": False, "error": "INVALID_LICENSE"}
    
    now = int(time.time())
    return {
        "ok": True,
        "data": {
            "licenseId": str(uuid.uuid4()),
            "expiresAt": now + 86400 * 30,
            "leaseUntil": now + 3600,
            "heartbeatAfterSeconds": 300,
            "deviceAssurance": "KEY_POSSESSION_ONLY",
            "variables": {
                "announcement": {
                    "version": "1",
                    "values": ["授权成功"]
                }
            }
        }
    }

def handle_heartbeat(data):
    """心跳"""
    now = int(time.time())
    return {
        "ok": True,
        "data": {
            "leaseUntil": now + 3600
        }
    }

# ========== 简单管理后台 ==========
@app.route('/admin')
def admin():
    cards = load_cards()
    html = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>卡密管理</title>
<style>body{font-family:sans-serif;max-width:800px;margin:20px auto;padding:20px}
table{width:100%;border-collapse:collapse}td,th{border:1px solid #ddd;padding:8px;text-align:left}
.form{margin:20px 0;padding:15px;background:#f5f5f5}
input,button{padding:8px;margin:5px}</style></head><body>
<h1>卡密管理</h1>
<div class="form">
<h3>生成卡密</h3>
<form action="/admin/generate" method="post">
数量: <input type="number" name="count" value="1" min="1" max="100">
<button type="submit">生成</button>
</form></div>
<table><tr><th>卡密</th><th>创建时间</th><th>备注</th></tr>
"""
    import datetime
    for key, info in cards.items():
        created = datetime.datetime.fromtimestamp(info.get('created', 0)).strftime('%Y-%m-%d %H:%M')
        html += f"<tr><td>{key}</td><td>{created}</td><td>{info.get('note','')}</td></tr>"
    html += "</table></body></html>"
    return html

@app.route('/admin/generate', methods=['POST'])
def generate():
    count = int(request.form.get('count', 1))
    cards = load_cards()
    for _ in range(count):
        key = uuid.uuid4().hex[:16]
        cards[key] = {"created": time.time(), "note": ""}
    save_cards(cards)
    return '<script>window.location="/admin"</script>'

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
