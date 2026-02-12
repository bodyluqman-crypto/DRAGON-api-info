import AccountPersonalShow_pb2
import main_pb2
import FreeFire_pb2
import httpx
import asyncio
import json
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64
from typing import Tuple
import binascii
import time
from cachetools import TTLCache
from Crypto.Util.Padding import pad as crypto_pad
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB52"
USERAGENT = "Free%20Fire/2019118692 CFNetwork/3826.500.111.2.2 Darwin/24.4.0"
SUPPORTED_REGIONS = ["ME"]  
jwt_cache = TTLCache(maxsize=10, ttl=4 * 60 * 60)  
last_request_time = 0
REQUEST_DELAY = 2  

def pad(text: bytes) -> bytes:
    """دالة padding الخاصة بنا"""
    padding_length = AES.block_size - (len(text) % AES.block_size)
    padding = bytes([padding_length] * padding_length)
    return text + padding

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext)
    ciphertext = aes.encrypt(padded_plaintext)
    return ciphertext

async def create_jwt(region: str) -> Tuple[str, str, str]:
    try:
        print(f"🔐 محاولة إنشاء JWT للمنطقة: {region}")
        
        # التحقق من الـ cache أولاً
        cache_key = f"jwt_{region}"
        if cache_key in jwt_cache:
            print(f"✅ استخدام JWT من الـ cache للمنطقة: {region}")
            token = jwt_cache[cache_key]
        else:
            
            region_credentials = {
                'ME': ("4403511787", "CTX_MASRY_FXTHM3ZH9xxxx")
            }
            
            if region not in region_credentials:
                raise Exception(f"❌ Region {region} not supported")
            
            uid, password = region_credentials[region]
            
            
            print(f"🌐 جلب JWT من API خارجي لـ UID: {uid}")
            
           
            api_url = f"http://45.67.15.190:50013/get?uid={uid}&password={password}"
            
            async with httpx.AsyncClient(follow_redirects=True) as client:
                response = await client.get(api_url, timeout=30.0)
                
                if response.status_code != 200:
                    raise Exception(f"❌ API returned status {response.status_code}")
                
                data = response.json()
                
                if "token" not in data:
                    raise Exception(f"❌ No token in API response")
                
                token = data["token"]
                print(f"✅ تم الحصول على JWT من API خارجي")
            
            if not token:
                raise Exception("❌ Failed to get JWT token from API")
            
            # تخزين الـ token في الـ cache
            jwt_cache[cache_key] = token
            print(f"✅ تم تخزين JWT في الـ cache للمنطقة: {region}")
        
        print(f"✅ تم الحصول على JWT بنجاح: {token[:50]}...")
        
       
        region_server = "EUROPE"  
        try:
            
            payload_encoded = token.split('.')[1]
            
            payload_encoded += '=' * ((4 - len(payload_encoded) % 4) % 4)
            payload_decoded = base64.b64decode(payload_encoded)
            payload = json.loads(payload_decoded)
            
            
            region_server = payload.get('lock_region', 'EUROPE')
            print(f"🌍 المنطقة من JWT: {region_server}")
        except Exception as e:
            print(f"⚠️  تعذر استخراج المنطقة من JWT: {e}")
            print(f"🌍 استخدام المنطقة الافتراضية: {region_server}")
        
        
        server_url = "https://clientbp.ggblueshark.com"
        print(f"🔗 رابط السيرفر: {server_url}")
        
        return f"Bearer {token}", region_server, server_url
            
    except Exception as e:
        print(f"❌ خطأ في create_jwt: {str(e)}")
        
        cache_key = f"jwt_{region}"
        if cache_key in jwt_cache:
            del jwt_cache[cache_key]
        raise e

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    serialized_data = proto_message.SerializeToString()
    return serialized_data


def decode_hex_protobuf(hex_data):
    """تحويل البيانات من hex إلى كائن protobuf"""
    try:
        
        byte_data = binascii.unhexlify(hex_data.replace(' ', ''))
        
        
        users = AccountPersonalShow_pb2.AccountPersonalShowInfo()
        users.ParseFromString(byte_data)
        
        return users
    except Exception as e:
        print(f"❌ خطأ في تحويل protobuf: {e}")
        raise e

async def GetAccountInformation(ID, UNKNOWN_ID, regionMain="ME", endpoint="/api/clientbp/GetPlayerPersonalShow"):
    try:
        print(f"👤 جلب معلومات الحساب: ID={ID}, Region={regionMain}")
        
        
        if not isinstance(ID, str):
            ID = str(ID)
        if not isinstance(UNKNOWN_ID, str):
            UNKNOWN_ID = str(UNKNOWN_ID)
        
        json_data = json.dumps({
            "a": ID,
            "b": UNKNOWN_ID
        })
        
        encoded_result = await json_to_proto(json_data, main_pb2.GetPlayerPersonalShow())
        payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, encoded_result)
        
        regionMain = regionMain.upper()
        if regionMain not in SUPPORTED_REGIONS:
            return {
                "error": "Invalid request",
                "message": f"Unsupported 'region' parameter. Supported regions are: {', '.join(SUPPORTED_REGIONS)}."
            }
        
        token, region, serverUrl = await create_jwt(regionMain)
        print(f"🔑 Token: {token[:50]}...")
        print(f"🌍 Server URL: {serverUrl}")
        
        headers = {
            "Host": "clientbp.ggblueshark.com",
            "X-Unity-Version": "2018.4.11f1",
            "Accept": "*/*",
            "Authorization": token,
            "ReleaseVersion": RELEASEVERSION,
            "X-GA": "v1 1",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
            "Content-Type": "application/octet-stream",
            "User-Agent": USERAGENT,
            "Connection": "keep-alive"
        }
        
        full_url = serverUrl + endpoint
        print(f"🌐 إرسال طلب إلى: {full_url}")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(full_url, data=payload, headers=headers)
            print(f"📊 حالة الاستجابة النهائية: {response.status_code}")
            
            if response.status_code != 200:
                raise Exception(f"❌ Server returned status {response.status_code}")
            
            response_content = response.content
            
            
            hex_response = response_content.hex()
            print(f"📦 حجم البيانات المستلمة: {len(hex_response)} حرف hex")
            
            
            message_obj = decode_hex_protobuf(hex_response)
            
          
            message_json = json_format.MessageToJson(message_obj)
            message_data = json.loads(message_json)
            
            print(f"✅ تم جلب معلومات الحساب بنجاح")
            return message_data
            
    except Exception as e:
        print(f"❌ خطأ في GetAccountInformation: {str(e)}")
        raise e


async def test():
    print("🔧 اختبار النظام...")
    try:
      
        token, region, server = await create_jwt("ME")
        print(f"✅ الاختبار ناجح!")
        print(f"Token: {token[:50]}...")
        print(f"Region: {region}")
        print(f"Server: {server}")
    except Exception as e:
        print(f"❌ فشل الاختبار: {e}")

if __name__ == "__main__":
    asyncio.run(test())