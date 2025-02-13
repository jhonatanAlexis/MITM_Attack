import random
import hashlib

p = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
g = 2

sAlice = random.getrandbits(256)
sBob = random.getrandbits(256)
sEve = random.getrandbits(256)

A = pow(g, sAlice, p)
B = pow(g, sBob, p)
eve_a  = pow(g, sEve, p)
eve_b = pow(g, sEve, p)

sAliceKey = pow(eve_b, sAlice, p)
sBobKey = pow(eve_a, sBob, p)
sEveKeyA = pow(A, sEve, p)
sEveKeyB = pow(B, sEve, p)

hA = hashlib.sha512(int.to_bytes(sAliceKey, length=1024, byteorder='big')).hexdigest()
hB = hashlib.sha512(int.to_bytes(sBobKey, length=1024, byteorder='big')).hexdigest()
hEveA = hashlib.sha512(int.to_bytes(sEveKeyA, length=1024, byteorder='big')).hexdigest()
hEveB = hashlib.sha512(int.to_bytes(sEveKeyB, length=1024, byteorder='big')).hexdigest()

if hA == hB:
    print("Alice y Bob tienen la misma clave (como debería ser sin MITM)")
else:
    print("Alice y Bob tienen claves distintas (MITM)")

if hA == hEveA and hB == hEveB:
    print("MITM exitoso: Eve tiene las mismas claves que Alice y Bob")
else:
    print("MITM fallido: Eve no tiene las mismas claves que Alice y Bob")