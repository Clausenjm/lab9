"""
- CS2911 - 0NN
- Fall 2020
- Lab 9
- Names:
  - Josiah Clausen
  - Elisha Hamp

16-bit RSA

Introduction:
This lab is designed to familiarize students with how primes are used with encryption,
and the methods of making private and public keys. It then has the students implement a
brute force algorithm to break the keys.



Question 1: RSA Security
In this lab, Trudy is able to find the private key from the public key. Why is this not a problem for RSA in practice?
RSA in practice uses prime numbers that are so large that trying to break the keys with brute force or algorithms
is impractical to do with modern computers in a normal amount of time.




Question 2: Critical Step(s)
When creating a key, Bob follows certain steps. Trudy follows other steps to break a key.
What is the difference between Bob’s steps and Trudy’s so that Bob is able to run his steps on large numbers,
but Trudy cannot run her steps on large numbers?
To create a key, Bob just needs two prime numbers that fit a set of criteria. To break this, Trudy starts
with a large number produced from the two primes, and has to find which two primes created the number.
This requires a large amount of guess-and-checking and becomes exponentially inefficient as the
numbers get larger.


Checksum Activity:
This activity largely expanded our understanding of the project. Without the formulas and hints on the
paper, and the practice allowed by it, I would have been very lost. The interactive part where we used
each other's encrypted messages to find the original message was also very helpful for making us
understand what we were doing in the lab.




Summary:
    This lab was very easy to understand due to the in-class activity which we completed beforehand.
We had a little difficulty and confusion around a couple components in our break_key and 8_bit_num_generator,
but after talking to the professor we were able to get it all figured out. There were no parts of this lab
that we disliked or considered as needing any changes.

JY: Key examples:
35389, 55161 -- bad?
(41417, 50745) -- works for some but not others...
(6833, 58563) -- bad?


"""
import math
import random
import sys


# Use these named constants as you write your code
MAX_PRIME = 0b11111111  # The maximum value a prime number can have
MIN_PRIME = 0b11000001  # The minimum value a prime number can have 
PUBLIC_EXPONENT = 17  # The default public exponent


def main():
    """ Provide the user with a variety of encryption-related actions """

    # Get chosen operation from the user.
    action = input("Select an option from the menu below:\n"
                   "(1-CK) create_keys\n"
                   "(2-CC) compute_checksum\n"
                   "(3-VC) verify_checksum\n"
                   "(4-EM) encrypt_message\n"
                   "(5-DM) decrypt_message\n"
                   "(6-BK) break_key\n "
                   "Please enter the option you want:\n")
    # Execute the chosen operation.
    if action in ['1', 'CK', 'ck', 'create_keys']:
        create_keys_interactive()
    elif action in ['2', 'CC', 'cc', 'compute_checksum']:
        compute_checksum_interactive()
    elif action in ['3', 'VC', 'vc', 'verify_checksum']:
        verify_checksum_interactive()
    elif action in ['4', 'EM', 'em', 'encrypt_message']:
        encrypt_message_interactive()
    elif action in ['5', 'DM', 'dm', 'decrypt_message']:
        decrypt_message_interactive()
    elif action in ['6', 'BK', 'bk', 'break_key']:
        break_key_interactive()
    else:
        print("Unknown action: '{0}'".format(action))


def create_keys_interactive():
    """
    Create new public keys

    :return: the private key (d, n) for use by other interactive methods
    """

    key_pair = create_keys()
    pub = get_public_key(key_pair)
    priv = get_private_key(key_pair)
    print("Public key: ")
    print(pub)
    print("Private key: ")
    print(priv)
    return priv


def compute_checksum_interactive():
    """
    Compute the checksum for a message, and encrypt it
    """

    priv = create_keys_interactive()

    message = input('Please enter the message to be checksummed: ')

    hsh = compute_checksum(message)
    print('Hash:', "{0:04x}".format(hsh))
    cipher = apply_key(priv, hsh)
    print('Encrypted Hash:', "{0:04x}".format(cipher))


def verify_checksum_interactive():
    """
    Verify a message with its checksum, interactively
    """

    pub = enter_public_key_interactive()
    message = input('Please enter the message to be verified: ')
    recomputed_hash = compute_checksum(message)

    string_hash = input('Please enter the encrypted hash (in hexadecimal): ')
    encrypted_hash = int(string_hash, 16)
    decrypted_hash = apply_key(pub, encrypted_hash)
    print('Recomputed hash:', "{0:04x}".format(recomputed_hash))
    print('Decrypted hash: ', "{0:04x}".format(decrypted_hash))
    if recomputed_hash == decrypted_hash:
        print('Hashes match -- message is verified')
    else:
        print('Hashes do not match -- has tampering occured?')


def encrypt_message_interactive():
    """
    Encrypt a message
    """

    message = input('Please enter the message to be encrypted: ')
    pub = enter_public_key_interactive()
    encrypted = ''
    for c in message:
        encrypted += "{0:04x}".format(apply_key(pub, ord(c)))
    print("Encrypted message:", encrypted)


def decrypt_message_interactive(priv=None):
    """
    Decrypt a message
    """

    encrypted = input('Please enter the message to be decrypted: ')
    if priv is None:
        priv = enter_key_interactive('private')
    message = ''
    for i in range(0, len(encrypted), 4):
        enc_string = encrypted[i:i + 4]
        enc = int(enc_string, 16)
        dec = apply_key(priv, enc)
        if 0 <= dec < 256:
            message += chr(dec)
        else:
            print('Warning: Could not decode encrypted entity: ' + enc_string)
            print('         decrypted as: ' + str(dec) + ' which is out of range.')
            print('         inserting _ at position of this character')
            message += '_'
    print("Decrypted message:", message)


def break_key_interactive():
    """
    Break key, interactively
    """

    pub = enter_public_key_interactive()
    priv = break_key(pub)
    print("Private key:")
    print(priv)
    decrypt_message_interactive(priv)


def enter_public_key_interactive():
    """
    Prompt user to enter the public modulus.

    :return: the tuple (e,n)
    """

    print('(Using public exponent = ' + str(PUBLIC_EXPONENT) + ')')
    string_modulus = input('Please enter the modulus (decimal): ')
    modulus = int(string_modulus)
    return (PUBLIC_EXPONENT, modulus)


def enter_key_interactive(key_type):
    """
    Prompt user to enter the exponent and modulus of a key

    :param key_type: either the string 'public' or 'private' -- used to prompt the user on how
                     this key is interpretted by the program.
    :return: the tuple (e,n)
    """
    string_exponent = input('Please enter the ' + key_type + ' exponent (decimal): ')
    exponent = int(string_exponent)
    string_modulus = input('Please enter the modulus (decimal): ')
    modulus = int(string_modulus)
    return (exponent, modulus)

def compute_checksum(string):
    """
    Compute simple hash

    Given a string, compute a simple hash as the sum of characters
    in the string.

    (If the sum goes over sixteen bits, the numbers should "wrap around"
    back into a sixteen bit number.  e.g. 0x3E6A7 should "wrap around" to
    0xE6A7)

    This checksum is similar to the internet checksum used in UDP and TCP
    packets, but it is a two's complement sum rather than a one's
    complement sum.

    :param str string: The string to hash
    :return: the checksum as an integer
    """

    total = 0
    for c in string:
        total += ord(c)
    total %= 0x8000  # Guarantees checksum is only 4 hex digits
    # How many bytes is that?
    #
    # Also guarantees that that the checksum will
    # always be less than the modulus.
    return total


# ---------------------------------------
# Do not modify code above this line
# ---------------------------------------

def create_keys():
    """
    Create the public and private keys.

    :return: the keys as a three-tuple: (e,d,n)
    """
    p = make_prime_num()
    q = make_prime_num()
    d, n = generate_components(p, q)
    tup = PUBLIC_EXPONENT, d, n
    return tup


def eight_bit_number_generator():
    """
    :author: Eli Hamp
    Generates an 8-bit number within the desired range
    and then ensures the correct bits are set to 1's
    :return:
    """
    i = MIN_PRIME
    j = MAX_PRIME
    rand = random.randint(i, j)
    rand = rand
    rand = rand | 0b11000001
    return int(rand)


def make_prime_num():
    """
    :author: Eli Hamp
    Checks if a number is prime. If not, it adds two to the number
    and checks until it is prime.
    :param num: int input to be turned into a prime
    :return: prime number made from the base.
    """
    i = 2
    num = eight_bit_number_generator()
    while i <= num/2:
        mod = num % i
        if mod != 0:
            i += 1
        else:
            num = make_prime_num()

    return num


def check_coprime(prime_num):
    """
    :author: Eli Hamp
    Subtracts one from a prime number and ensures it is coprime with z
    :param prime_num: a prime number to be checked.
    :return: whether the number is coprime with the e
    """
    num = prime_num - 1
    return (num % PUBLIC_EXPONENT) != 0


def generate_components(p, q):
    """
    :author Josiah Clausen
    :param p: prime number 1
    :param q: prime number 2
    :return: a tuple of the private and public key
    """
    n = p * q
    z = (p - 1) * (q - 1)
    t = 0
    r = z
    newt = 1
    newr = 17
    while not newr == 0:
        quotient = r // newr
        t, newt = (newt, t - quotient * newt)
        r, newr = (newr, r - quotient * newr)
    if r > 1:
        print("a is not invertible")
    if t < 0:
        t = t + z

    return t, n


def apply_key(key, m):
    """
    Apply the key, given as a tuple (e,n) or (d,n) to the message.

    This can be used both for encryption and decryption.

    :param tuple key: (e,n) or (d,n)
    :param int m: the message as a number 1 < m < n (roughly)
    :return: the message with the key applied. For example,
             if given the public key and a message, encrypts the message
             and returns the ciphertext.
    """
    mod, n = key
    message = m**mod % n
    return message


def break_key(pub):
    """
    Break a key.  Given the public key, find the private key.
    Factorizes the modulus n to find the prime numbers p and q.

    You can follow the steps in the "optional" part of the in-class
    exercise.

    :param pub: a tuple containing the public key (e,n)
    :return: a tuple containing the private key (d,n)
    """
    e, n = pub
    q, p = find_n_and_q(n)
    private_key = find_private_key(p, q)
    n = p*q
    return private_key, n


def find_n_and_q(public_key):
    """
    :author Josiah Clausen
    :param public_key:
    :return: returns a pair of the the prime numbers used to create a public key
    """
    n = -1
    q = -1
    for x in range(2, int(public_key / 2)):
        if public_key % x == 0:
            if find_if_prime(x):
                if find_if_prime(public_key / x):
                    n = x
                    q = int(public_key / x)
                    # if not (n - 1) % PUBLIC_EXPONENT != 0 and (q - 1) % PUBLIC_EXPONENT != 0:
                    #     n = -1
                    #     q = -1
    return n, q


def find_if_prime(number):
    """
    :author Josiah clausen
    :param number: the number that is being checked if it is prime
    :return: true or false if the number is prime
    """
    for x in range(2, int(number)):
        if number % x == 0:
            return False
    return True


def find_private_key(p, q):
    """
    :author Josiah Clausen
    :param p: this is one of the prime numbers to make the private key
    :param q: this is one of the prime numbers to make the private key
    :return: the private key with acess to the two prime numbers
    """
    totient = (p-1)*(q-1)
    for x in range(1, int(totient)):
        if x*PUBLIC_EXPONENT % totient == 1:
            return x
    return -1

# ---------------------------------------
# Do not modify code below this line
# ---------------------------------------


def get_public_key(key_pair):
    """
    Pulls the public key out of the tuple structure created by
    create_keys()

    :param key_pair: (e,d,n)
    :return: (e,n)
    """

    return (key_pair[0], key_pair[2])


def get_private_key(key_pair):
    """
    Pulls the private key out of the tuple structure created by
    create_keys()

    :param key_pair: (e,d,n)
    :return: (d,n)
    """

    return (key_pair[1], key_pair[2])


main()
