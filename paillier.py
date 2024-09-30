import sympy
import random
import numpy as np
import json

class Paillier():
    """
    Based on the original study made by Pascal Paillier
    https://link.springer.com/content/pdf/10.1007/3-540-48910-X_16.pdf

    and the corresponding wiki article
    https://en.wikipedia.org/wiki/Paillier_cryptosystem


    """
    plaintext_modulo = 0
    ciphertext_modulo = 0

    def __init__(self, keys = None):
        self.keys = self.read_keys()
        self.plaintext_modulo = self.keys['public_key']['n']
        self.ciphertext_modulo = self.keys['public_key']['n']**2


    def read_keys(self):
        #I could generate the keys normally, but I really don't want to wait
        #several minutes every time I test this script.
        with open('keys.txt') as f:
            data = f.read()

        keys = json.loads(data)

        return keys

    def encrypt(self, message: int):
        n = self.keys['public_key']['n']
        assert message < n  # The message cannot be larger than the modulo

        # A one-time random key has to be generated for every encryption
        r = random.randint(0, n)
        g = self.keys['public_key']['g']
        while sympy.gcd(r,n) != 1:
            r = random.randint(0, n)

        ciphertext = (pow(g,message,n*n) * pow(r,n,n*n)) % (n*n)
        # Note to self: NEVER use the ** operator for exponentiation of large
        # numbers, it is S L O W as hell. Use the pow() function instead

        return ciphertext

    def decrypt(self, ciphertext: int):
        n = self.keys['public_key']['n']
        phi = self.keys['private_key']['phi']
        mu = pow(phi,-1,n)

        plaintext = (self.lx(pow(ciphertext, phi, n*n)) * mu) % n 

        return plaintext

    #Convenience method for the L function 
    def lx(self, x):
        return (x-1) // self.plaintext_modulo

    def add(self, cipher1, cipher2):
        n = self.keys['public_key']['n']
        return (cipher1 * cipher2 ) % (n*n)

    def reencrypt(self, cipher):
        neutral_element = 1
        neutral_cipher = self.encrypt(neutral_element)

        return self.add(cipher,neutral_cipher)

    def multiply_by_constant(self, cipher, constant):
        n = self.keys['public_key']['n']
        assert n > constant

        return pow(cipher,constant, n*n)

cryptosystem = Paillier()

message1 = 10
ciphertext1 = cryptosystem.encrypt(message=message1)
decrypted1 = cryptosystem.decrypt(ciphertext = ciphertext1)

print(f'Original message is: {message1}')
print(f'Ciphertext is: {ciphertext1}')
print(f'Decrypted message is: {decrypted1}')

multiplier = 2
print(f'\nI can also multiply the ciphertext with a constant. For example, if I multiply by 2, I will get the following ciphertext:')
multiplied_cipher = cryptosystem.multiply_by_constant(ciphertext1, 2)
print(multiplied_cipher)
print(f'But if I decrypt, I will get: {cryptosystem.decrypt(ciphertext=multiplied_cipher)}')

print('\nThe Paillier cryptosystem also has an additively homomorphic property, showcased below:')

ciphertext2 = cryptosystem.encrypt(message=5)

print(f'\nEncrypting the number 5 will yield the following ciphertext:\n {ciphertext2}')

ciphertext_sum = cryptosystem.add(cipher1 = ciphertext1, cipher2 = ciphertext2)
print(f'\nIf I add these two ciphertexts, I will get\n {ciphertext_sum}\n\n which decrypts to: {cryptosystem.decrypt(ciphertext_sum)}')
