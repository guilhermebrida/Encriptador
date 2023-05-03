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
import customtkinter

customtkinter.set_appearance_mode("Dark")

root = customtkinter.CTk()
root.geometry("750x60")
root.title("Encriptador")


class VariosArquivos():
    def __init__(self):
        self.selected_file_label = customtkinter.CTkLabel(root, text="", anchor=W)
        self.selected_file_label.place(x=170, y=10, width=400, height=20)
        customtkinter.CTkButton(root, text="Selecionar arquivo(s)", command=self.select_files).place(x=10,y=10,width=150,height=20)
        customtkinter.CTkButton(root, text="Encriptar", command=self.encrypt_files).place(x=550,y=10,width=80,height=20)
        customtkinter.CTkButton(root, text="Decriptar",command=self.decrypt_files).place(x=650,y=10,width=80,height=20)
        
    def update_file_label(self, file_path):
        self.selected_file_label.configure(text=file_path)

    def select_files(self):
        path = askopenfilenames()
        if path:
            self.update_file_label(path[0].split('/')[-1])
            self.selected_files = path
        else:
            self.update_file_label("Nenhum arquivo selecionado") 

    def encrypt_files(self):
        if hasattr(self, "selected_files"):
            for file_path in self.selected_files:
                f=open(f'{file_path}',encoding='utf_8')
                json_data=f.read()
                json_dict = json.loads(json_data)
                if json_dict['hash'] == '':
                    comandos=json_dict['comandos']
                    AES_pkcs5_obj = AES_pkcs5(comandos)
                    encrypted_message = AES_pkcs5_obj.encrypt(comandos)
                    json_dict.update(comandos=encrypted_message)
                    json_dict.update(hash=base64.b64encode(AES_pkcs5_obj.key).decode('utf-8'))
                    f = open(f'{file_path}', 'w',encoding='utf-8')
                    json.dump(json_dict, f,ensure_ascii=False)
                else:
                    continue
            messagebox.showinfo( "","Arquivos Encriptados")
        else:
            messagebox.showinfo( "Escolha os Arquivos","Nenhum arquivo selecionado")

    def decrypt_files(self):
        if hasattr(self, "selected_files"):
            for file_path in self.selected_files:
                f=open(f'{file_path}',encoding='utf_8')
                json_data=f.read()
                json_dict = json.loads(json_data)
                comandos=json_dict['comandos']
                hsh = json_dict['hash']
                if hsh != '':
                    AES_pkcs5_obj = AES_pkcs5(comandos)
                    decrypted_comandos = AES_pkcs5_obj.decrypt(hsh,comandos)
                    json_dict.update(comandos=decrypted_comandos)
                    json_dict.update(hash='')
                    f = open(f'{file_path}', 'w',encoding='utf-8')
                    json.dump(json_dict, f,ensure_ascii=False)
                    f.close()
                else:
                    continue
            messagebox.showinfo("New Window", "Arquivos Decriptados")
        else:
            messagebox.showinfo( "Escolha os Arquivos","Nenhum arquivo selecionado")

            

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
    root.mainloop()