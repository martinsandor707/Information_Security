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
        #self.keys = self.generate_keys() #God forbid we make new keys every time
        self.keys = self.read_keys("keys_paillier.txt")
        self.plaintext_modulo = self.keys['public_key']['n']
        self.ciphertext_modulo = self.keys['public_key']['n']**2


    def generate_keys(self):
        
        # This is the regular key generation method
        p = sympy.randprime(200, pow(2,4096)-1) # DON'T ACTUALLY USE THIS LIBRARY FOR REAL KEYGEN
        q = sympy.randprime(200, pow(2,4096)-1) # sympy.randprime() is not mathematically safe
        phi = (p-1)*(q-1)
        while p == q or sympy.gcd(p*q,phi) != 1: #Enforcing mathematical properties
            q = sympy.randprime(200, pow(2,4096)-1)
        # Public (Encryption) key
        n = p*q
        g = n + 1
        # Private (Decryption) key
        mu = pow(phi,-1,n)
        #myLambda = sympy.lcm(p-1,q-1) #This should be the real private key, but it takes really long to calculate
                                       #It has been stated that for implementational purposes, using phi is sufficient
        ciphertext_modulo = n**2
        keys = {}
        keys['private_key'] = {}
        keys['public_key'] = {}
        keys['private_key']['phi'] = phi
        keys['public_key']['n'] = n
        keys['public_key']['g'] = g

        return keys


    def read_keys(self, filename:str):
        with open(filename) as f:
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
        neutral_element = 0
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
print(f'\nI can also multiply the ciphertext with a constant. For example, if I multiply by {multiplier}, I will get the following ciphertext:')
multiplied_cipher = cryptosystem.multiply_by_constant(ciphertext1, multiplier)
print(multiplied_cipher)
print(f'But if I decrypt, I will get: {cryptosystem.decrypt(ciphertext=multiplied_cipher)}')

print('\nThe Paillier cryptosystem also has an additively homomorphic property, showcased below:')

message2 = 5
ciphertext2 = cryptosystem.encrypt(message=message2)

print(f'\nEncrypting the number {message2} will yield the following ciphertext:\n {ciphertext2}')

ciphertext_sum = cryptosystem.add(cipher1 = ciphertext1, cipher2 = ciphertext2)
print(f'\nIf I add these two ciphertexts, I will get\n {ciphertext_sum}\n\n which decrypts to: {cryptosystem.decrypt(ciphertext_sum)}')
