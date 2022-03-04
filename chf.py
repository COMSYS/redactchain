#!/usr/bin/env python3
""" This module houses chameleon hash functionality based on Vincent's work. """

from hashlib import sha256

from Cryptodome.Random import random
from gmpy2 import mpz, powmod, f_mod as mod

from parameters import bit_length, p, q, g, verify_params


class ChameleonHashFunction(object):

    def __init__(self, public_key, private_key=None):
        self.public_key = mpz(public_key)
        self.private_key = mpz(private_key) if private_key is not None else None

    def get_hash(self, msg, r=None, s=None):

        # Draw r, s randomly if not given
        if r is None:
            r = random.randint(0, int(q - 1))
        r = mpz(r)
        if s is None:
            s = random.randint(0, int(q - 1))
        s = mpz(s)

        # Compute sha256(msg||r)
        r_bytes = int(r).to_bytes(bit_length // 8, 'little')
        sha = sha256()
        sha.update(msg)
        sha.update(r_bytes)
        hash_value = mod(mpz(int.from_bytes(sha.digest(), 'little')), q)

        y_h = powmod(self.public_key, hash_value, p)
        g_s = powmod(g, s, p)

        gs = mod(y_h * g_s, p)
        res = mod(r - gs, q)
        res = int(res).to_bytes(bit_length // 8, 'little')
        return res, r, s

    def validate_hash(self, h, msg, r, s):
        h_check, _, _ = self.get_hash(msg, r=r, s=s)
        return h == h_check

    def compute_collision(self, msg, msg_new, r, s):
        if self.private_key is None:
            raise RuntimeError('Cannot compute collision without private key')

        # Choose a at random
        a = mpz(random.randint(1, int(q - 1)))

        # Recompute original hash value
        hash_original, _, _ = self.get_hash(msg, r=r, s=s)
        hash_original = mod(mpz(int.from_bytes(hash_original, 'little')), q)

        # Get r'
        g_a = powmod(g, a, p)
        r_new = mod(hash_original + g_a, q)
        r_new_bytes = int(r_new).to_bytes(bit_length // 8, 'little')

        # Get new hash value
        sha = sha256()
        sha.update(msg_new)
        sha.update(r_new_bytes)
        hash_value = mod(mpz(int.from_bytes(sha.digest(), 'little')), q)

        # Get s'
        h_k = mod(hash_value * self.private_key, q)
        s_new = mod(a - h_k, q)

        return r_new, s_new


if __name__ == '__main__':
    print('Verifying parameters')
    verify_params(p, q, g)
    print(f'p = {p}')
    print(f'q = {q}')
    print(f'g = {g}')

    # Generate random private key
    private_key = mpz(random.randint(2, int(q - 1)))
    public_key = powmod(g, private_key, p)
    print(f'Private key: {private_key}')
    print(f'Public key: {public_key}')

    chf = ChameleonHashFunction(public_key=public_key, private_key=private_key)

    msg = b'Test message for test CHF validation.'
    print('Computing hash value.')
    h, r, s = chf.get_hash(msg)
    print(f'Hash value: {int.from_bytes(h, "little")}; (r, s) = ({int(r)}, {int(s)})')
    print('Validating hash value')
    check = chf.validate_hash(h, msg, r, s)
    if check:
        print('Hash validation successful!')
    else:
        raise RuntimeError('Hash validation failed.')

    msg_new = b'Updated message, i.e., a redaction.'
    r_new, s_new = chf.compute_collision(msg, msg_new, r, s)
    h_new, _, _ = chf.get_hash(msg_new, r_new, s_new)
    print(f'Collision values: {int.from_bytes(h_new, "little")}; (r, s) = ({int(r_new)}, {int(s_new)})')
    check2 = chf.validate_hash(h, msg_new, r_new, s_new)
    if check2:
        print('Collision validation successful!')
    else:
        raise RuntimeError('Collision validation failed.')
