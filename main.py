import sys
import binascii

from xts_aes import XTSAES

TEXT_TYPES = {
    'encryption': 'plaintext',
    'decryption': 'ciphertext',
}

def read_hex_string(name):
    try:
        hex_string = input('{name}: '.format(name=name))
        hex_string = binascii.unhexlify(hex_string)
    except binascii.Error:
        sys.exit('{name} should be hex string'.format(name=name))

    return hex_string

arguments = sys.argv[1:]
mode = 'encryption'
inverse_mode = 'decryption'
if arguments and (arguments[0] == '-d'):
    mode = 'decryption'
    inverse_mode = 'encryption'

key = read_hex_string('key')
if len(key) != 64:
    sys.exit('key should be 64-byte')

tweak = read_hex_string('tweak')
if len(tweak) != 16:
    sys.exit('tweak should be 16-byte')

text = read_hex_string(TEXT_TYPES[mode])
if len(text) < 16:
    sys.exit('{text_type} should be greater than or equal to 16-byte'.format(text_type=TEXT_TYPES[mode]))

xts_aes = XTSAES(key, tweak)

encryptor = xts_aes.encrypt if mode == 'encryption' else xts_aes.decrypt
ciphertext = encryptor(text)

print('{ciphertext_type}: {ciphertext}'.format(ciphertext_type=TEXT_TYPES[inverse_mode], ciphertext=binascii.hexlify(ciphertext).decode()))