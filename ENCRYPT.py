from Crypto.Cipher import AES
from Crypto import Random
import base64
import random
from aes_pkcs5.algorithms.aes_cbc_pkcs5_padding import AESCBCPKCS5Padding
import hashlib
import json

class AES_pkcs5:
    def __init__(self,key:str, mode:AES.MODE_CBC=AES.MODE_CBC,block_size:int=16):
        self.key = self.setKey(key)
        self.mode = mode
        self.block_size = block_size

    def pad(self,byte_array:bytearray):
        """
        pkcs5 padding
        """
        pad_len = (self.block_size - len(byte_array) % self.block_size) *  chr(self.block_size - len(byte_array) % self.block_size)
        return byte_array.decode() + pad_len
    

    def unpad(self,byte_array:bytearray):
        return byte_array[:-ord(byte_array[-1:])]


    def setKey(self,key:str):
        key = key.encode('utf-8')
        md5 = hashlib.md5
        key = md5(key).digest()[:16]
        key = key.zfill(16)
        print(key)
        return key

    def encrypt(self,message:str)->str:
        self.iv = bytearray([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])
        byte_array = message.encode("UTF-8")
        padded = self.pad(byte_array)
        cipher = AES.new(self.key, AES.MODE_CBC,self.iv)
        encrypted = cipher.encrypt(padded.encode())
        message=  base64.b64encode(encrypted).decode('utf-8')
        return message
        # print(message)

    def decrypt(self,message:str)->str:
        byte_array = message.encode("utf-8")
        message = base64.b64decode(byte_array)
        cipher= AES.new(self.key, AES.MODE_CBC, self.iv)
        decrypted = cipher.decrypt(message).decode('utf-8')
        return self.unpad(decrypted)
        
# if __name__ == '_main_':
f=open('ARQUIVO.json',encoding='utf_8')
json_data=f.read()
json_dict = json.loads(json_data)
comandos=json_dict['comandos']

AES_pkcs5_obj = AES_pkcs5(comandos)
encrypted_message = AES_pkcs5_obj.encrypt(comandos)
print(encrypted_message)
json_dict.update(comandos=encrypted_message)
json_dict.update(hash=base64.b64encode(AES_pkcs5_obj.key).decode('utf-8'))
decrypted_comandos = AES_pkcs5_obj.decrypt(encrypted_message)
print(decrypted_comandos)
    # f = open('ARQUIVO.json', 'w',encoding='utf-8')
    # json.dump(json_dict, f,ensure_ascii=False)




