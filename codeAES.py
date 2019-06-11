from Crypto import Random
from Crypto.Cipher import AES
import os
import os.path
from os import listdir
from os.path import isfile, join
import time

class Criptografia:
    def __init__(self, chave):
        self.chave = chave

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encripta(self, mensagem,chave, tam_chave=256):
        mensagem = self.pad(mensagem)
        iv = Random.new().read(AES.block_size)
        cifra = AES.new(chave, AES.MODE_CBC, iv)
        return iv + cifra.encripta(mensagem)
    
    def desencripta(self, texto_cifrado, chave):
        iv = texto_cifrado[:AES.block_size]
        cifra = AES.new(chave, AES.MODE_CBC, iv)
        mensagem = cifra.desencripta(texto_cifrado[AES.block_size:])
        return mensagem.rstrip(b"\0")
    
    def encripta_arquivo(self, nome_arquivo):
        with open(nome_arquivo, 'rb') as arquivo:
            mensagem = arquivo.read()
        encrip = self.encripta(mensagem, self.chave)
        with open(nome_arquivo + ".criptado", 'wb') as arquivo:
            arquivo.write(encrip)
        os.remove(nome_arquivo)
    
    def desencripta_arquivo(self, nome_arquivo):
        with open(nome_arquivo, 'rb') as arquivo:
            texto_cifrado = arquivo.read()
        desenc = self.desencripta(texto_cifrado, self.chave)
        with open(nome_arquivo[:-4], 'wb') as arquivo:
            arquivo.write(desenc)
        os.remove(nome_arquivo)

opr = input("Favor digite a 1 para Criptografar ou 2 para Desencriptografar:\n")
chave = input("Favor Insira a Chave:\n")
if opr == 1:
    nome_arquivo = input("Insira o nome de Arquivo:\n")
    encrip = Criptografia(chave)
    encrip.encripta_arquivo(nome_arquivo)
elif opr == 2:
    nome_arquivo = input("Insira o nome de Arquivo:\n")
    desencrip = Criptografia(chave)
    desencrip.desencripta_arquivo(nome_arquivo)