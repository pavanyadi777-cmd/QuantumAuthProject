import oqs

sig_alg = "ML-DSA-44"
print("Algorithm:", sig_alg)

message = b"Hello Bob"

print("\n=== ALICE GENERATES SIGNING KEYS ===\n")

with oqs.Signature(sig_alg) as alice:

    public_key = alice.generate_keypair()

    print("Public Key Generated ✓")

    print("\n=== ALICE SIGNS MESSAGE ===\n")

    signature = alice.sign(message)

    print("Signature Size:", len(signature), "bytes")
    print("Message:", message.decode())
    print("Signature Generated ✓")

    print("\n=== BOB VERIFIES SIGNATURE ===\n")

    with oqs.Signature(sig_alg) as bob:

        is_valid = bob.verify(
            message,
            signature,
            public_key
        )

        if is_valid:
            print("✓ Signature Valid")
            print("✓ Message Authentic")
        else:
            print("✗ Signature Invalid")