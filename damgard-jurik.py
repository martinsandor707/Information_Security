import sys
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

    Some implementational ideas were taken from the LightPHE library.

    If you don't want to read through the original paper, here is a shorter, very elegant explanation
    https://sefiks.com/2023/10/20/a-step-by-step-partially-homomorphic-encryption-example-with-damgard-jurik-in-python/

    Trivia: The Damgard-Jurik cryptosystem is a generalization of the Paillier cryptosystem
    A.K.A.: A Paillier encrypted ciphertext can be decrypted using the Damgard-Jurik algorithm
    """
    plaintext_modulo = 0
    ciphertext_modulo = 0

    def __init__(self, keys = None, s = 1):
        self.keys = self.read_keys()
        #self.keys = self.generate_keys(s)
        self.plaintext_modulo = pow(self.keys['public_key']['n'],self.keys['public_key']['s'])
        self.ciphertext_modulo = pow(self.keys['public_key']['n'],self.keys['public_key']['s']+1)

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
        d = (p-1) * (q-1) # This is the simplest value of d, similar to Paillier cryptosystem.
        # Requirement for d: d = 1 mod n^s && d = 0 mod sympy.lcm(p-1,q-1)
        g = n+1 #This is the simplified version for calculating g, used for demonstration.
        
        keys = {}
        keys['public_key'] = {}
        keys['private_key'] = {}
        keys['public_key']['n'] = n
        keys['public_key']['g'] = g
        keys['public_key']['s'] = s

        keys['private_key']['d'] = d

        print(keys)
        # Saving the keys if we don't want to generate new ones every time
        with open('keys_dj.txt', 'w', encoding = 'UTF-8') as file:
            file.write(json.dumps(self.convert_dicts_to_int(keys)))
            #Apparently SymPy uses its own definition of integers
            #And the json module can't convert it by default
        return keys

    def convert_dicts_to_int(self, obj):
        """
            Recursively convert the keys dict containing SymPy Integers to regular Python integers
        """
        if isinstance(obj, dict):
            return {k: self.convert_dicts_to_int(v) for k, v in obj.items()}
        else:
            return int(obj)
        
    def read_keys(self):
        #I could generate the keys normally, but I really don't want to wait
        #several minutes every time I test this script.
        with open('keys_dj.txt') as f:
            data = f.read()

        keys = json.loads(data)
        return keys

    def encrypt(self, message: int):
        n = self.keys['public_key']['n']
        ciphertext_modulo = self.ciphertext_modulo
        plaintext_modulo = self.plaintext_modulo
        assert message < plaintext_modulo  # The message cannot be larger than the modulo

        # A one-time random key has to be generated for every encryption
        r = random.randint(0, n)
        g = self.keys['public_key']['g']
        while sympy.gcd(r, n) != 1:
            r = random.randint(0, n)

        ciphertext = (pow(g, message, ciphertext_modulo) * pow(r, plaintext_modulo, ciphertext_modulo)) % ciphertext_modulo

        return ciphertext


    def decrypt(self, ciphertext: int):
        n = self.keys['public_key']['n']
        d = self.keys['private_key']['d']
        mu = pow(d, -1, n)
        return (self.lx(pow(ciphertext, d, self.ciphertext_modulo)) * mu ) % n  # This is where the magic happens 

    #Convenience method for the L function 
    def lx(self, x):
        n = self.keys['public_key']['n']
        return (x-1) // n 

    def add(self, cipher1, cipher2):
        return (cipher1 * cipher2) % self.ciphertext_modulo

    def reencrypt(self, cipher):
        neutral_element = 0
        neutral_cipher = self.encrypt(neutral_element)

        return self.add(cipher, neutral_cipher)

    def multiply_by_constant(self, cipher, constant):
        
        assert self.plaintext_modulo > constant

        return pow(cipher, constant, self.ciphertext_modulo)

dj = Damgard_Jurik(s=2)
#print(dj.keys)

sys.set_int_max_str_digits(0)

message1 = 10
cipher1 = dj.encrypt(message1)
decrypted = dj.decrypt(cipher1)

print(f"The original message was: {message1}")
print(f"\nThe ciphertext is: {cipher1}")
print(f"\nThe decrypted message is: {decrypted}")
print(f"\nOriginal cipher multiplied by 2 then decrypted: {dj.decrypt(dj.multiply_by_constant(cipher1,2))}")

message2 = 5
cipher2 = dj.encrypt(message2)
print(f"\nThe second message is: {message2}")
print(f"\n The cipher of the second message: {cipher2}")
sum = dj.add(cipher1,cipher2)
print(f"\nThe result of performing homomorphic addition on the two ciphers: {sum}")
print(f"\nThe result of the decryption is: {dj.decrypt(dj.add(cipher1,cipher2))}")
