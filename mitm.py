import random
import hashlib
import Crypto.Random
import Crypto.Util.number

p = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
g = 2

sAlice = random.getrandbits(256)
sBob = random.getrandbits(256)
sEve = random.getrandbits(256) #numero privado de eve

A = pow(g, sAlice, p)
B = pow(g, sBob, p)
eve_a  = pow(g, sEve, p) #clave publica de eve, se hace pasar por Alice
eve_b = pow(g, sEve, p) #clave publica de eve, se hace pasar por Bob

sAliceKey = pow(eve_b, sAlice, p) #clave privada de alice, interceptada por eve al hacerse pasar por Bob
sBobKey = pow(eve_a, sBob, p) #clave privada de bob, interceptada por eve al hacerse pasar por Alice
sEveKeyA = pow(A, sEve, p) #clave privada de eve, se hace pasar por Alice
sEveKeyB = pow(B, sEve, p) #clave privada de eve, se hace pasar por Bob

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

#funcion para generar claves RSA
def generar_claves_rsa():
    e = 65537
    p = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
    q = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = Crypto.Util.number.inverse(e, phi)
    return (e, n), d #retorna la clave publica (e, n) y privada (d)

clave_publica_bob, clave_privada_bob = generar_claves_rsa() #e,n se pasaran a clave_publica y d a clave_privada
print("Clave publica de Bob:", clave_publica_bob)
clave_publica_eve, clave_privada_eve = generar_claves_rsa()
print("Clave publica de Eve (haciendose pasar por la de bob):", clave_publica_eve)

mensaje = 12345 #mensaje enviado por alice
print("Mensaje original enviado por Alice:", mensaje)

mensaje_cifrado = pow(mensaje, clave_publica_eve[0], clave_publica_eve[1])
print("Mensaje cifrado:", mensaje_cifrado)

#eve intercepta el mensaje cifrado y lo descifra con su clave privada
mensaje_descifrado = pow(mensaje_cifrado, clave_privada_eve, clave_publica_eve[1])
print("Mensaje interceptado y descifrado por Eve:", mensaje_descifrado)

#eve cambia el mensaje
mensaje_cambiado = mensaje_descifrado + 1
print("Mensaje cambiado por Eve:", mensaje_cambiado)

#eve cifra el mensaje cambiado con la clave publica de bob (la original)
mensaje_recifrado = pow(mensaje_cambiado, clave_publica_bob[0], clave_publica_bob[1])

#bob recibe el mensaje recifrado y lo descifra con su clave privada
mensaje_final = pow(mensaje_recifrado, clave_privada_bob, clave_publica_bob[1])

if mensaje_final != mensaje:
    print("MITM exitoso: Eve ha cambiado el mensaje")
else:
    print("MITM fallido: Eve no ha cambiado el mensaje")