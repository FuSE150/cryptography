import rsa

trent_public_key, trent_private_key = rsa.newkeys(2048)
with open("trent_public.pem", "wb") as f:
    f.write(trent_public_key.save_pkcs1())
with open("trent_private.pem", "wb") as f:
    f.write(trent_private_key.save_pkcs1())

alice_public_key, alice_private_key = rsa.newkeys(2048)
with open("alice_public.pem", "wb") as f:
    f.write(alice_public_key.save_pkcs1())
with open("alice_private.pem", "wb") as f:
    f.write(alice_private_key.save_pkcs1())

bob_public_key, bob_private_key = rsa.newkeys(2048)
with open("bob_public.pem", "wb") as f:
    f.write(bob_public_key.save_pkcs1())
with open("bob_private.pem", "wb") as f:
    f.write(bob_private_key.save_pkcs1())



