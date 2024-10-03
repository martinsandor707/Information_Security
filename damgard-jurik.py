import sympy
import random
import numpy as np
import json

class Damgard_Jurik():
    """
    Based on the original study made by Ivan Damgard and Mads Jurik
    http://www.brics.dk/RS/00/45/

    and the corresponding wiki article
    https://en.wikipedia.org/wiki/Damg%C3%A5rd%E2%80%93Jurik_cryptosystem


    Trivia: The Damgard-Jurik cryptosystem is a generalization of the Paillier cryptosystem
    A.K.A.: A Paillier encrypted ciphertext can be decrypted using the Damgard-Jurik algorithm
    """
    plaintext_modulo = 0
    ciphertext_modulo = 0

    def __init__(self, keys = None):
        #self.keys = self.read_keys()
        self.keys = self.generate_keys()
        self.plaintext_modulo = self.keys['public_key']['n']
        self.ciphertext_modulo = self.keys['public_key']['n']**2

    def generate_keys(self, s = 1):
        """ Generates the private and public keys using the encryption.
        Args:
            s (int): The cryptosystem's modulo will be n^(s+1). If s == 1 then the system is identical to the Paillier cryptosystem.
        
        Returns:
            A dict containing the keys
        """

        # Regular key generation method
        p = sympy.randprime(200, pow(2,4096)-1)
        q = sympy.randprime(200, pow(2,4096)-1)

        n = p * q
        d = sympy.lcm(p-1,q-1) # This is the simplest value of d, similar to Paillier cryptosystem.
        # Requirement for d: d = 1 mod n^s && d = 0 mod sympy.lcm(p-1,q-1)
        g = n+1 #This is the simplified version for calculating g, used for demonstration.
        
        keys = {}
        keys['public_key'] = {}
        keys['public_key']['n'] = n
        keys['public_key']['g'] = g
        keys['public_key']['s'] = s

        keys['private_key']['d'] = d
        # Saving the keys if we don't want to generate new ones every time
        with open('keys_dj.txt', 'w') as file:
            file.write(json.dumps(keys))

        return keys


    def read_keys(self):
        #I could generate the keys normally, but I really don't want to wait
        #several minutes every time I test this script.
        with open('keys_dj.txt') as f:
            data = f.read()

        keys = json.loads(data)
        return keys

    def encrypt(self, message: int):
        n = self.keys['public_key']['n']
        assert message < n  # The message cannot be larger than the modulo

        # A one-time random key has to be generated for every encryption
        r = random.randint(0, n)
        g = self.keys['public_key']['g']
        s = self.keys['public_key']['s']
        while sympy.gcd(r,n) != 1:
            r = random.randint(0, n)

        ciphertext = (pow(g,message,pow(n,s+1)) * pow(r,pow(n,s, pow(n,s+1))) % pow(n,s+1)
        # Note to self: NEVER use the ** operator for exponentiation of large
        # numbers, it is S L O W as hell. Use the pow() function instead

        return ciphertext


    #TODO: Finish this
    def decrypt(self, ciphertext: int):
        n = self.keys['public_key']['n']
        d = self.keys['private_key']['d']

        plaintext = (self.lx(pow(ciphertext, phi, n*n)) * mu) % n 

        return plaintext

    #Convenience method for the L function 
    def lx(self, x):
        return (x-1) // self.plaintext_modulo

    def add(self, cipher1, cipher2):
        n = self.keys['public_key']['n']
        s = self.keys['public_key']['s']
        return (cipher1 * cipher2 ) % pow(n,s+1)

    def reencrypt(self, cipher):
        neutral_element = 1
        neutral_cipher = self.encrypt(neutral_element)

        return self.add(cipher,neutral_cipher)

    def multiply_by_constant(self, cipher, constant):
        n = self.keys['public_key']['n']
        s = self.keys['public_key']['s']
        assert n > constant

        return pow(cipher,constant, pow(n,s+1))

dj = Damgard_Jurik()
