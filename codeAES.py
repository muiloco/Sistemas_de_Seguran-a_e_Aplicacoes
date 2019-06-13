from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode
import os
import os.path

class Criptografia:
    def __init__(self, chave):
        self.chave = chave

    #configuracao para completar o tamanho para multiplo de 16
    def padAES(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)
    
    def padDES3(self, s):
        return s + b"\0" * (DES3.block_size - len(s) % DES3.block_size)
    

    def encriptaAES(self, mensagem,chave, tam_chave=256):
        mensagem = self.padAES(mensagem)
        iv = Random.new().read(AES.block_size) #Vetor ou um tipo de senha usada pela biblioteca no AES
        cifra = AES.new(chave, AES.MODE_CBC, iv) # AES.MODE_CBC e um parametro de como a criptografia sera realizada, esse parametro e de bloco
        return iv + cifra.encrypt(mensagem)
    
    def desencriptaAES(self, texto_cifrado, chave):
        iv = texto_cifrado[:AES.block_size] #parametriza uma especie de tamanho dos blocos para o AES
        cifra = AES.new(chave, AES.MODE_CBC, iv)
        mensagem = cifra.decrypt(texto_cifrado[AES.block_size:])
        return mensagem.rstrip(b"\0")

    def encripta3DES(self, mensagem,chave, tam_chave=256):
        mensagem = self.padDES3(mensagem)
        iv = Random.new().read(DES3.block_size) #Vetor ou um tipo de senha usada pela biblioteca no AES
        cifra = DES3.new(chave, DES3.MODE_CBC, iv) # DES3.MODE_CBC e um parametro de como a criptografia sera realizada, esse parametro e de bloco
        return iv + cifra.encrypt(mensagem)
    
    def desencripta3DES(self, texto_cifrado, chave):
        iv = texto_cifrado[:DES3.block_size] #parametriza uma especie de tamanho dos blocos para o AES
        cifra = DES3.new(chave, DES3.MODE_CBC, iv)
        mensagem = cifra.decrypt(texto_cifrado[DES3.block_size:])
        return mensagem.rstrip(b"\0")
    
    def encriptaRSA(self, mensagem, chave_publica):
        cifra = PKCS1_OAEP.new(chave_publica)
        return cifra.encrypt(message)
    
    def desencriptaRSA(self, mensagem, chave_privada):
        cifra = PKCS1_OAEP.new(chave_privada)
        return cifra.decrypt(mensagem)

    def encripta_arquivo(self, nome_arquivo, tipodeCripto):
        with open(nome_arquivo, 'rb') as arquivo:
            mensagem = arquivo.read()
        if tipodeCripto == 1:
            encrip = self.encriptaAES(mensagem, self.chave)
        elif tipodeCripto == 2:
            encrip = self.encripta3DES(mensagem,self.chave)
        elif tipodeCripto == 3:
            encrip = self.encriptaRSA(mensagem, self.chave)
        with open(nome_arquivo + ".enc", 'wb') as arquivo:
            arquivo.write(encrip)
        os.remove(nome_arquivo)#remove o arquivo antigo da pasta
    
    def desencripta_arquivo(self, nome_arquivo, tipodeCripto):
        with open(nome_arquivo, 'rb') as arquivo:
            texto_cifrado = arquivo.read()
        if tipodeCripto == 1:
            desenc = self.desencriptaAES(texto_cifrado, self.chave)
        elif tipodeCripto == 2:
            desenc = self.desencripta3DES(texto_cifrado, self.chave)
        elif tipodeCripto == 3:
            desenc = self.desencriptaRSA(texto_cifrado, self.chave)
        with open(nome_arquivo[:-4], 'wb') as arquivo: #excluio posicoes do nome do arquivo
            arquivo.write(desenc)
        os.remove(nome_arquivo)

def gerarChaveRSA(tamanhoChave): #gerador de chaves para RSA, tamanho em bits
    random = Random.new().read
    chave = RSA.generate(tamanhoChave, random)
    chave_privada, chave_publica = chave, chave.publickey()
    with open("chave_privada.txt", 'w') as arq:
        arq.write(RSA.importKey(chave_privada))
    with open("chave_publica.txt", 'w') as arq:
        arq.write(RSA.importKey(chave_publica))
    return RSA.importKey(chave_publica), RSA.importKey(chave_privada)

if __name__ == "__main__":
    pub, priv = gerarChaveRSA(2048)
    print(priv)
    """
    opr = int(input("Favor digite a 1 para Criptografar ou 2 para Desencriptografar:\n"))
    tipodeCripto = int(input("Qual algoritmo de criptografia sera usado: 1-AES 2-3DES\n"))
    chave = input("Favor Insira a Chave:\n")
    if opr == 1:
        nome_arquivo = input("Insira o nome de Arquivo:\n")
        encrip = Criptografia(chave)
        encrip.encripta_arquivo(nome_arquivo,tipodeCripto)
    elif opr == 2:
        nome_arquivo = input("Insira o nome de Arquivo:\n")
        if tipodeCripto == 1:
            chave = "{: <32}".format(chave).encode("utf-8")
        elif tipodeCripto == 2:
            chave = "{: <24}".format(chave).encode("utf-8")
        desencrip = Criptografia(chave)
        desencrip.desencripta_arquivo(nome_arquivo,tipodeCripto)
    else:
        print("erro")
    """