import sympy
import random

class Paillier():

    plaintext_modulo = 0
    ciphertext_modulo = 0

    def __init__(self, keys = None):
        self.keys = self.generate_keys()

        self.plaintext_modulo = self.keys['public_key']['n']
        self.ciphertext_modulo = self.keys['public_key']['n']**2


    def generate_keys(self):
        
        p = sympy.randprime(200, 2**4096-1)
        q = sympy.randprime(200, 2**4096-1)
        phi = (p-1)*(q-1)
        while p == q or sympy.gcd(p*q,phi) != 1:
            q = sympy.randprime(200, 2**4096-1)

        # Public (Encryption) key
        n = p*q
        g = n + 1

        # Private (Decryption) key
        mu = pow(phi,-1,n)
        myLambda = sympy.lcm(p-1,q-1)

        ciphertext_modulo = n**2

        keys = {}
        keys['private_key'] = {}
        keys['public_key'] = {}
        keys['private_key']['mu'] = mu
        keys['private_key']['lambda'] = myLambda
        keys['public_key']['n'] = n
        keys['public_key']['g'] = g

        return keys

    def encrypt(self, message: int):
        n = self.keys['public_key']['n']
        assert message < n  # The message cannot be larger than the modulo

        # A one-time random key has to be generated for every encryption
        r = random.randint(0, n)

        while sympy.gcd(r,n) != 1:
            r = random.randint(0, n)

        ciphertext = (self.keys['public_key']['g']**message * r**n) % n**2
        #TODO: This line is S L O W ! Need to rewrite in numpy  

        return ciphertext

    def decrypt(self, ciphertext: int):
        n = self.keys['public_key']['n']
        myLambda = self.keys['private_key']['lambda']
        mu = self.keys['private_key']['mu'] 

        plaintext = (self.L_function(pow(ciphertext, myLambda, n**2)) * mu) % n 

        return plaintext

    #Convenience method for the L function 
    def L_function(self, x):

        return (x-1) // self.plaintext_modulo

#TODO:Add homomorphic addition
cryptosystem = Paillier()

message = 10
ciphertext = cryptosystem.encrypt(message=message)
decrypted = cryptosystem.decrypt(ciphertext = ciphertext)


print(f'Original message is: {message}')
print(f'Ciphertext is: {ciphertext}')
print(f'Decrypted message is: {decrypted}')
