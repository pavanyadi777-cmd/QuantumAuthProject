import oqs
import time

kem_name = "ML-KEM-512"
print("Algorithm:", kem_name)

print("\n=== ALICE GENERATES KEY PAIR ===\n")

alice = oqs.KeyEncapsulation(kem_name)

start = time.perf_counter()
alice_public_key = alice.generate_keypair()
end = time.perf_counter()

print(
    "Key Generation Time:",
    round((end - start) * 1000, 3),
    "ms"
)

print("Alice Public Key Generated ✓")
print("Public Key Size:", len(alice_public_key), "bytes")

print("\n=== BOB CREATES SHARED SECRET ===\n")

bob = oqs.KeyEncapsulation(kem_name)

start = time.perf_counter()
ciphertext, bob_secret = bob.encap_secret(alice_public_key)
end = time.perf_counter()

print(
    "Encapsulation Time:",
    round((end - start) * 1000, 3),
    "ms"
)

print("Ciphertext Generated ✓")
print("Ciphertext Size:", len(ciphertext), "bytes")
print("Bob Shared Secret Generated ✓")

print("\n=== ALICE RECOVERS SHARED SECRET ===\n")

start = time.perf_counter()
alice_secret = alice.decap_secret(ciphertext)
end = time.perf_counter()

print(
    "Decapsulation Time:",
    round((end - start) * 1000, 3),
    "ms"
)

print("Alice Shared Secret Generated ✓")

print("\n=== RESULT ===\n")

print("Alice Secret:")
print(alice_secret.hex()[:64])

print("\nBob Secret:")
print(bob_secret.hex()[:64])

print()

if alice_secret == bob_secret:
    print("✓ Shared Secrets Match")
    print("✓ Secure Session Established")
else:
    print("✗ Shared Secrets Do Not Match")