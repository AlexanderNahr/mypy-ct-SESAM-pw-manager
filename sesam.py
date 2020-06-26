# -*- coding: utf-8 -*-

from hashlib import pbkdf2_hmac

uppercase_letters = list('abcdefghijklmnopqrstuvwxyz')
lowercase_letters = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
numbers = list('0123456789')
special_characters = list('!@#$%^&*()_+-=[]|')
password_character = uppercase_letters + \
                     lowercase_letters + \
                     numbers + \
                     special_characters

salt = "pepper"


def convert_bytes_to_password(hashed_bytes, length):
    """ convert byte stream (non-readable chars) to password 
        return: password
    """
    number = int.from_bytes(hashed_bytes, byteorder='big')
    password = ''
    while number > 0 and len(password) < length:
        password = password + \
                   password_character[number % len(password_character)]
        number = number // len(password_character)  # integer division
    return password


def main():
    """ main functions """
    master_password = input('Master password: ')
    domain = input('Domain: ')

    while len(domain) < 1:
        print('Please enter a domain.')
        domain = input('Domain: ')

    hash_string = domain + master_password

    hashed_bytes = pbkdf2_hmac(
        'sha512',                     # hash algo
        hash_string.encode('utf-8'),  # string to encode as bytestream
        salt.encode('utf-8'),         # unique salt..not unique here
        4096)                         # iterations

    print('Password: ' + convert_bytes_to_password(hashed_bytes, 10))

if __name__ == '__main__':
    main()
