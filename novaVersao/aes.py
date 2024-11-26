import os
import hmac
from hashlib import pbkdf2_hmac  
import hashlib  
from cryptography.hazmat.primitives.hashes import SHA256

AES_KEY_SIZE = 16
IV_SIZE = 16
HMAC_KEY_SIZE = 32

def pad(input):
    pad_len = 16 - (len(input) % 16)
    padding = bytes([pad_len] * pad_len)
    return input + padding

def gera_chave(password, salt, workload=100000):
    kdf = pbkdf2_hmac(
        'sha256',
        password,
        salt,
        workload,
        AES_KEY_SIZE + IV_SIZE + HMAC_KEY_SIZE
    )
    aes_key = kdf[:AES_KEY_SIZE]
    hmac_key = kdf[AES_KEY_SIZE:AES_KEY_SIZE + HMAC_KEY_SIZE]
    iv = kdf[AES_KEY_SIZE + HMAC_KEY_SIZE:]
    return aes_key, hmac_key, iv

def bytes_matriz(texto):
    return [list(texto[i:i + 4]) for i in range(0, len(texto), 4)]

def matriz_bytes(m):
    return bytes(sum(m, []))

def xor_bytes(a, b):
    return bytes(i ^ j for i, j in zip(a, b))
  
def add_chave_rodada(a, b):
  for i in range(4):
    for j in range(4):
      a[i][j] ^= b[i][j]

class AES:
    rodadas_tamanho_chave = {16: 10, 24: 12, 32: 14}
  
    def __init__(self, chave):
        assert len(chave) in AES.rodadas_tamanho_chave
        self.chave = self._expandir_chave(chave)
        self.nr = AES.rodadas_tamanho_chave[len(chave)] 
        
    def _expandir_chave(self, chave):

      def pseudo_sbox(word, round_constant):
        rotated = word[1:] + word[:1]  # Rotação circular
        return [b ^ round_constant for b in rotated]

      col_chave = bytes_matriz(chave)
      tam_i = len(chave) // 4

      i = 1  
      while len(col_chave) < (len(chave) // 4 + 6 + 1) * 4:
          p = list(col_chave[-1])

          if len(col_chave) % tam_i == 0:
              p = pseudo_sbox(p, i)
              i += 1
          elif len(chave) == 32 and len(col_chave) % tam_i == 4:
              p = pseudo_sbox(p, i)

          p = xor_bytes(p, col_chave[-tam_i])
          col_chave.append(p)

      return [col_chave[4 * i: 4 * (i + 1)] for i in range(len(col_chave) // 4)]

    
    def encriptar_bloco(self, texto):
        assert len(texto) == 16
        estado = bytes_matriz(texto)
        
        add_chave_rodada(estado, self.chave[0])
        for i in range(1, self.nr):
          print("aaaaaaaaaaaaaaaaaa")
        
        return matriz_bytes(estado)

    def encriptar(self, texto, iv):
        assert len(iv) == IV_SIZE
        texto = pad(texto)
        blocos = []
        ant = iv
        
        for i in range(0, len(texto), 16):
            bloco_txt = texto[i:i + 16]
            bloco = self.encriptar_bloco(xor_bytes(bloco_txt, ant))
            blocos.append(bloco)
            ant = bloco
        
        return b''.join(blocos)

def criptografar(chave, texto):
  if isinstance(chave, str):
    chave = chave.encode('utf-8')
  if isinstance(texto, str):
    texto = texto.encode('utf-8')
    
  salt = os.urandom(16)
  aes_key, hmac_key, iv = gera_chave(chave, salt)
  aes = AES(aes_key)
    
  texto_cifrado = aes.encriptar(texto, iv)
  hmac_code = hmac.new(hmac_key, salt + texto_cifrado, hashlib.sha256).digest()
  assert len(hmac_code) == HMAC_KEY_SIZE

  return hmac_code + salt + texto_cifrado

if __name__ == '__main__':
    key = '1234567890123456'
    text = 'Texto para teste'
    
    resultado = criptografar(key, text)
    print('Texto criptografado:', resultado.hex())
