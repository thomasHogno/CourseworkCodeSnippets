# generates two round keys (k1, k2) from 10 bit key using permutations and shifts for security through complexity
# feistel structure splits input and applies rounds of processing for strong security
# sboxes introduce non-linearity; prevents simple algebraic attacks
# permutations (P10, P8, IP, FP, etc.) help diffusion, spreading influence of each input bit across output
# expansion + XOR mixes key material into plaintext in a non-reversible way without the key
# -e 0111111101 11101011

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import sys # for input

def permute(bits, perm): # permutes bits based on permutation table
    return ''.join(bits[i] for i in perm)

def left_shift(bits, shift): # circular left shift
    return bits[shift:] + bits[:shift]

def generate_subkeys(key): # 10 bit key -> two 8 bit keys by perm.s + left shifts
    P10 = [2, 4, 1, 6, 3, 9, 0, 8, 7, 5] # p10 to rearrange bits
    P8 = [5, 2, 6, 3, 7, 4, 9, 8] # p8 to create subkeys
    
    key = permute(key, P10)
    left, right = key[:5], key[5:]
    
    left, right = left_shift(left, 1), left_shift(right, 1)
    k1 = permute(left + right, P8) # first sub key, 1 bit left shift
    
    left, right = left_shift(left, 2), left_shift(right, 2)
    k2 = permute(left + right, P8) #second sub key, 2 bit left shift
    
    return k1, k2

def expansion(bits): #expansion perm.
    E = [3, 0, 1, 2, 1, 2, 3, 0] 
    return permute(bits, E)

def sbox_lookup(bits, sbox): # lookup 2 bit output from 4bit sbox ipnut
    row = int(bits[0] + bits[3], 2)
    col = int(bits[1] + bits[2], 2)
    return format(sbox[row][col], '02b')

def f_function(bits, key): # feistel function (f) mixes key into data w/ expansion, sbox, perm.
    SBOX1 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
    SBOX2 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]
    
    expanded = expansion(bits)
    xored = format(int(expanded, 2) ^ int(key, 2), '08b') #xor w/ subkey
    left, right = xored[:4], xored[4:]
    sbox_out = sbox_lookup(left, SBOX1) + sbox_lookup(right, SBOX2) #sbox substitution
    P4 = [1, 3, 2, 0] #perm. = for diffusion
    return permute(sbox_out, P4)

def feistel_round(left, right, key): # apply f, mix with left half
    return format(int(left, 2) ^ int(f_function(right, key), 2), '04b'), right

def encrypt(plaintext, key): # encryption alg. 
    IP = [1, 5, 2, 0, 3, 7, 4, 6] # init. perm.
    plaintext = permute(plaintext, IP)
    left, right = plaintext[:4], plaintext[4:]
    
    k1, k2 = generate_subkeys(key)
    left, right = feistel_round(left, right, k1)
    left, right = right, left  # swap
    left, right = feistel_round(left, right, k2)
    
    FP = [3, 0, 2, 4, 6, 1, 7, 5] # final perm.
    return permute(left + right, FP)

def decrypt(ciphertext, key): # subkeys used in reverse
    IP = [1, 5, 2, 0, 3, 7, 4, 6]
    ciphertext = permute(ciphertext, IP)
    left, right = ciphertext[:4], ciphertext[4:]
    
    k1, k2 = generate_subkeys(key)
    left, right = feistel_round(left, right, k2) #k2 first
    left, right = right, left
    left, right = feistel_round(left, right, k1) #k1 second
    
    FP = [3, 0, 2, 4, 6, 1, 7, 5]
    return permute(left + right, FP)

def main():
    if len(sys.argv) != 4:
        print("args: <mode> <key> <data>")
        return
    
    mode, key, data = sys.argv[1], sys.argv[2], sys.argv[3]
    if len(key) != 10 or len(data) != 8:
        print("error: need 10 bit key, 8 bit data")
        return
    
    if mode == "-e":
        print(encrypt(data, key))
    elif mode == "-d":
        print(decrypt(data, key))
    else:
        print("args: <mode> <key> <data>")

if __name__ == "__main__":
    main()
    
