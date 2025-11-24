from flask import Flask, request, Response
import json
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import aiohttp
import asyncio
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from google.protobuf.json_format import MessageToJson
import uid_generator_pb2
import like_count_pb2
import requests

app = Flask(__name__)

# ============================
# LOAD TOKENS
# ============================
def load_tokens():
    try:
        resp = requests.get(
            "https://notoken-production.up.railway.app/get?id=1010",
            timeout=10
        )
        return resp.json()
    except:
        return None


# ============================
# AES ENCRYPTION
# ============================
def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode()
    except:
        return None


# ============================
# PROTOBUF (UID)
# ============================
def create_protobuf(uid):
    try:
        obj = uid_generator_pb2.uid_generator()
        obj.saturn_ = int(uid)
        obj.garena = 1
        return obj.SerializeToString()
    except:
        return None


def enc(uid):
    proto = create_protobuf(uid)
    if not proto:
        return None
    return encrypt_message(proto)


# ============================
# PROTOBUF DECODE (RESPONSE)
# ============================
def decode_protobuf(binary):
    try:
        item = like_count_pb2.Info()
        item.ParseFromString(binary)
        return item
    except:
        return None


# ============================
# ASYNC REQUEST
# ============================
async def make_request_async(encrypted_uid,token, session):
    try:
        url = "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"

        edata = bytes.fromhex(encrypted_uid)

        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; Android 9)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-protobuf",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB51"
        }

        async with session.post(url, data=edata, headers=headers, ssl=False, timeout=5) as resp:
            if resp.status != 200:
                return None

            raw = await resp.read()
            return decode_protobuf(raw)

    except:
        return None


# ============================
# /visit API
# ============================
@app.route('/visit', methods=['GET'])
async def visit():
    target_uid = request.args.get("uid")

    if not target_uid :
        return Response(
            json.dumps({"error": "Target UID are required"}, ensure_ascii=False),
            content_type="application/json; charset=utf-8"
        )

    try:
        tokens = load_tokens()
        if tokens is None:
            raise Exception("Failed to load tokens")

        encrypted_uid = enc(target_uid)
        if encrypted_uid is None:
            raise Exception("UID encryption failed")

        total = len(tokens)
        success = 0
        failed = 0
        nickname = None
        uid_out = None

        async with aiohttp.ClientSession() as session:
            tasks = [
                make_request_async(encrypted_uid, t['token'], session)
                for t in tokens
            ]
            results = await asyncio.gather(*tasks)

        for info in results:
            if info:
                if nickname is None:
                    nickname = info.AccountInfo.PlayerNickname
                    uid_out = info.AccountInfo.UID
                success += 1
            else:
                failed += 1

        summary = {
            "TotalVisits": total,
            "SuccessfulVisits": success,
            "FailedVisits": failed,
            "PlayerNickname": nickname,
            "UID": uid_out
        }

        return Response(
            json.dumps(summary, ensure_ascii=False),
            content_type="application/json; charset=utf-8"
        )

    except Exception as e:
        return Response(
            json.dumps({"error": str(e)}, ensure_ascii=False),
            content_type="application/json; charset=utf-8"
        )


# ============================
# RUN
# ============================
if __name__ == '__main__':
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    app.run(debug=True, use_reloader=False)
