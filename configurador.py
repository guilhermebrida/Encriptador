from queue import Empty
from tkinter import Tk
from tkinter import filedialog
from tkinter.colorchooser import askcolor
from tkinter.filedialog import askopenfilename, askopenfilenames
from Crypto.Cipher import AES
import base64
from aes_pkcs5.algorithms.aes_cbc_pkcs5_padding import AESCBCPKCS5Padding
import hashlib
import json
from pprint import pprint
from tkinter import *
from tkinter import messagebox
from tkinter import ttk

root = Tk()
root.geometry("750x60")
root.title("Encriptador")
root.configure(background="#dde")

class VariosArquivos():
    def __init__(self):
        Label(root, text= "Arquivo: ", background="#dde", foreground="#009", anchor=W).place(x=10,y=10, width=100,height=20)
        Button(root, text="Encriptar", command=self.arquivos).place(x=550,y=10,width=80,height=20)
        Button(root, text="Decriptar",command=self.arquivos2).place(x=650,y=10,width=80,height=20)        


    def arquivos(self):
        path = askopenfilenames()
        if path:
            for i in path:
                f=open(f'{i}',encoding='utf_8')
                json_data=f.read()
                json_dict = json.loads(json_data)
                if json_dict['hash'] == '':
                    comandos=json_dict['comandos']
                    AES_pkcs5_obj = AES_pkcs5(comandos)
                    encrypted_message = AES_pkcs5_obj.encrypt(comandos)
                    json_dict.update(comandos=encrypted_message)
                    json_dict.update(hash=base64.b64encode(AES_pkcs5_obj.key).decode('utf-8'))
                    f = open(f'{i}', 'w',encoding='utf-8')
                    json.dump(json_dict, f,ensure_ascii=False)
                else:
                    continue
            messagebox.showinfo( "","Arquivos Encriptados")
        else:
            messagebox.showinfo( "Escolha os Arquivos","Nenhum arquivo escolhido")

    def arquivos2(self):
            path = askopenfilenames()
            if path:
                for i in path:
                    f=open(f'{i}',encoding='utf_8')
                    json_data=f.read()
                    json_dict = json.loads(json_data)
                    comandos=json_dict['comandos']
                    hsh = json_dict['hash']
                    if hsh != '':
                        AES_pkcs5_obj = AES_pkcs5(comandos)
                        decrypted_comandos = AES_pkcs5_obj.decrypt(hsh,comandos)
                        json_dict.update(comandos=decrypted_comandos)
                        json_dict.update(hash='')
                        f = open(f'{i}', 'w',encoding='utf-8')
                        json.dump(json_dict, f,ensure_ascii=False)
                        f.close()
                    else:
                        continue
                messagebox.showinfo("New Window", "Arquivos Decriptados")
            else:
                messagebox.showinfo( "Escolha os Arquivos","Nenhum arquivo escolhido")
            

class AES_pkcs5:
    def __init__(self,key:str, mode:AES.MODE_CBC=AES.MODE_CBC,block_size:int=16):
        self.key = self.setKey(key)
        self.mode = mode
        self.block_size = block_size

    def pad(self,byte_array:bytearray):
        pad_len = (self.block_size - len(byte_array) % self.block_size) *  chr(self.block_size - len(byte_array) % self.block_size)
        return byte_array.decode() + pad_len
    

    def unpad(self,byte_array:bytearray):
        return byte_array[:-ord(byte_array[-1:])]


    def setKey(self,key:str):
        key = key.encode('utf-8')
        md5 = hashlib.md5
        key = md5(key).digest()[:16]
        key = key.zfill(16)
        return key

    def encrypt(self,message:str)->str:
        self.iv = bytearray([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])
        byte_array = message.encode("UTF-8")
        padded = self.pad(byte_array)
        cipher = AES.new(self.key, AES.MODE_CBC,self.iv)
        encrypted = cipher.encrypt(padded.encode())
        message=  base64.b64encode(encrypted).decode('utf-8')
        return message


    def decrypt(self,hsh,message:str)->str:
        self.iv = bytearray([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])
        byte_array = message.encode("utf-8")
        message = base64.b64decode(byte_array)
        hsh = base64.b64decode(hsh)
        cipher= AES.new(hsh, AES.MODE_CBC, self.iv)
        decrypted = cipher.decrypt(message).decode('utf-8')
        return self.unpad(decrypted)


        
if __name__ == '__main__':
    VariosArquivos()
    mainloop()