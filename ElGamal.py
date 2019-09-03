import base64
import json
import time
import math
import sys
import base64
from random import randint
import struct


def read(json_file):
    with open(json_file) as f:
        data = json.load(f)

    return data


def prime_checker(number):
    start = time.time()
    is_prime = True
    divisble_by = None
    steps = 0
    if number > 1:
        # only need to check until square root
        # since square root x square root will give that number
        steps += 1
        if (number % 2) == 0:
            is_prime = False
            divisble_by = 2

        else:
            for i in range(3, int(math.sqrt(number)) + 1, 2):
                steps += 1
                if (number % i) == 0:
                    is_prime = False
                    divisble_by = i
                    break
    # negative numbers and 1 are not primes
    else:
        is_prime = False

    end = time.time()

    print()
    print('Number:', number)
    print('Is a prime:', is_prime)
    print('Is divisible by:', divisble_by)
    print('Number of steps:', steps)
    print('Execution time:', end - start)
    return is_prime



def safe_prime_checker(number):
    print()

    if not prime_checker(number):
        print('Is safe prime:', False)
        return False, None

    is_safe_prime = False
    q = None

    if (number - 1) % 2 == 0:
        q = int((number - 1) / 2)

        if prime_checker(q):
            is_safe_prime = True

    print()
    print('Number:', number)
    print('Is safe prime:', is_safe_prime)

    return is_safe_prime, q


def verify_generator(generator, prime):
    safe_prime, q = safe_prime_checker(prime)
    if not safe_prime:
        return False

    start = time.time()
    print()
    print('g:', generator)
    print('p:', prime)
    is_generator = False

    if pow(generator, q, prime) != 1:
        is_generator = True

    print('Is a generator:', is_generator)
    end = time.time()
    print('Execution time:', end - start)
    return is_generator


def create_public_key(g, a, p):
    public_key = pow(g, a, p)

    print()
    print('Generator:', g)
    print('Private key:', a)
    print('Prime:', p)
    print('Generated public key:', public_key)
    return public_key


def create_shared_key(y, a, p):
    shared_key = pow(y, a, p)

    print()
    print('Public key:', y)
    print('Private key:', a)
    print('Prime:', p)
    print('Generated shared key:', shared_key)
    return shared_key


def decrypt_message(cipherText, shared_key_a, p):
    x = shared_key_a
    x_inverse = pow(x, p - 2, p)

    m = (cipherText * x_inverse) % p
    print('Plaintext integer value:', m)

    encoded = base64.b64encode(m.to_bytes((m.bit_length() + 7) // 8, byteorder="big"))
    base64val = encoded.decode('utf-8')
    text = base64.b64decode(base64val)
    print('Base64 value:', base64val)
    print('Text:', text)


def encrypt_message(plainText, shared_key_a):
    number = int(plainText)
    encoded = base64.b64encode(number.to_bytes((number.bit_length() + 7) // 8, byteorder="big"))
    base64val = encoded.decode('utf-8')
    print()
    print('Encoded plaintext:', number)
    print('Base64 plaintext:', base64val)

    encrypted = number * shared_key_a
    encoded = base64.b64encode(encrypted.to_bytes((encrypted.bit_length() + 7) // 8, byteorder="big"))
    base64val = encoded.decode('utf-8')
    print('Encoded ciphertext:', encrypted)
    print('Base64 ciphertext:', base64val)
    return base64val


def generate_safe_prime(bits):
    start = time.time()
    is_safe_prime = False
    minvalue = '1'
    maxvalue = '9'
    for i in range(bits - 1):
        minvalue += '0'
        maxvalue += '9'

    minvalue = (int(int(minvalue) / 2))
    maxvalue = (int(int(maxvalue) / 2))

    while not is_safe_prime:
        randval = randint(minvalue, maxvalue)
        if (prime_checker(randval)):

            safeval = (randval * 2) + 1
            if (prime_checker(safeval)):
                print('New p:', safeval)
                is_safe_prime = True

    end = time.time()
    print('Execution time(generate safe prime):', end - start)
    return safeval


def generate_generator(prime):
    generator = randint(2, prime - 1)
    start = time.time()

    if (verify_generator(generator, prime)):
        print()
        print('New generator:', generator)
        end = time.time()
        print('Execution time(generate generator):', end - start)
        return generator
    else:
        g = (-generator) % prime
        print()
        print('New generator:', g)
        end = time.time()
        print('Execution time(generate generator):', end - start)
        return g


if __name__ == "__main__":
    data = read('input.json')
    print(data)
    encoded = data['exercise1']['cipherText']['encoded']
    p = int(data['exercise1']['p'])
    g = int(data['exercise1']['g'])
    a = int(data['exercise1']['a'])
    b = int(data['exercise1']['b'])
    cipherText = int(data['exercise1']['cipherText']['encoded'])

    # Question 1 2 and 3
    # prime_checker(p)

    # Question 4
    # boolean, q = safe_prime_checker(p)
    # verify_generator(g, p)

    # Question 5
    # ya = create_public_key(g, a, p)
    # yb = create_public_key(g, b, p)
    #
    # shared_key_a = create_shared_key(yb, a, p)
    # shared_key_b = create_shared_key(ya, b, p)
    #
    # print()
    # print('Same shared keys are generated:', shared_key_a == shared_key_b)

    # Question 6
    # decrypt_message(cipherText, shared_key_a, p)

    # Question 7
    # p, g = generate_new_p_and_g()
    # safe_prime_checker(87040398657970817)

    # p = generate_safe_prime(17)
    # g = generate_generator(14671967537981207)

    # Question 8
    p = 14671967537981207
    g = 7143808017769946

    na = randint(2, p - 2)
    nb = randint(2, p - 2)
    yna = create_public_key(g, na, p)
    ynb = create_public_key(g, nb, p)
    shared_key_new = create_shared_key(ynb, na, p)

    print()
    print('New Alice private key:', na)
    print('New Alice public key:', yna)
    print('New Bob private key:', nb)
    print('New Bob public key:', ynb)
    print('New shared key:', shared_key_new)

    message = data['srn']
    encrypt_message(message, shared_key_new)

    #
    # print()
    # print('New Alice private key: 8833888032707572')
    # print('New Alice public key: 9380028293135896')
    # print('New Bob private key: 12566972861628252')
    # print('New Bob public key: 9380028293135896')
    # print('New shared key: 6066688270758712')
