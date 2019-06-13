from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512, SHA384, SHA256, SHA, MD5
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from base64 import b64encode, b64decode
import os
import os.path


class CriptografiaRSA:
    def __init__(self, arquivoChave):
        self.nomeArquivoChave = arquivoChave

    def encriptaRSA(self, mensagem, chave_publica):
        chave = RSA.importKey(open(self.nomeArquivoChave).read())
        cifra = PKCS1_OAEP.new(chave, MD5)
        return cifra.encrypt(mensagem)

    def desencriptaRSA(self, mensagem, chave_privada):
        chave = RSA.importKey(open(self.nomeArquivoChave).read())
        cifra = PKCS1_OAEP.new(chave, MD5)
        return cifra.decrypt(mensagem)

    def encripta_arquivo(self, nomeDoArquivo):
        with open(nomeDoArquivo, "rb") as arquivo:
            mensagem = arquivo.read()
        encrip = self.encriptaRSA(mensagem, self.nomeArquivoChave)
        with open(nomeDoArquivo + ".enc", "wb") as arquivo:
            arquivo.write(encrip)
        os.remove(nomeDoArquivo)  # remove o arquivo antigo da pasta

    def desencripta_arquivo(self, nomeDoArquivo):
        with open(nomeDoArquivo, "rb") as arquivo:
            texto_cifrado = arquivo.read()
        desenc = self.desencriptaRSA(texto_cifrado, self.nomeArquivoChave)
        with open(
            nomeDoArquivo[:-4], "wb"
        ) as arquivo:  # excluio posicoes do nome do arquivo
            arquivo.write(desenc)
        os.remove(nomeDoArquivo)

"""
def gerarChaveRSA(tamanhoChave):  # gerador de chaves para RSA, tamanho em bits
    random = Random.new().read
    chave_privada = RSA.generate(tamanhoChave, random)
    # arquivo de chave privada
    with open("chave_privada.pem", "wb") as arq:
        arq.write(chave_privada.exportKey(format="PEM"))
    with open("chave_publica.pem", "wb") as arq:
        chave_publica = chave_privada.publickey()
        arq.write(chave_publica.exportKey(format="PEM"))
"""

if __name__ == "__main__":
   opr = int(
      input("Favor digite a 1 para Criptografar ou 2 para Desencriptografar:\n")
   )
   #gerarChaveRSA(2048)
   if opr == 1:
      nomeArquivoChave = input("Insira o nome do arquivo de chave publica:\n")
      nomeArquivoAlvo = input("Insira o nome do arquivo que queira cifrar:\n")
      encrip = CriptografiaRSA(nomeArquivoChave)
      encrip.encripta_arquivo(nomeArquivoAlvo)
   elif opr == 2:
      nomeArquivoChave = input("Insira o nome do arquivo de chave privada:\n")
      nomeArquivoAlvo = input("Insira o nome do arquivo que queira decifrar:\n")
      desencrip = CriptografiaRSA(nomeArquivoChave)
      desencrip.desencripta_arquivo(nomeArquivoAlvo)