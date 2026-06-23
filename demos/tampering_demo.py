import oqs

sig_alg = "ML-DSA-44"

original_message = b"Hello Bob"

print("\n=== ORIGINAL MESSAGE ===\n")
print(original_message.decode())

with oqs.Signature(sig_alg) as alice:

    public_key = alice.generate_keypair()

    signature = alice.sign(original_message)

    print("\nSignature Generated ✓")

    tampered_message = b"Hello Hacker"

    print("\n=== MESSAGE TAMPERED ===\n")
    print(tampered_message.decode())

    with oqs.Signature(sig_alg) as bob:

        is_valid = bob.verify(
            tampered_message,
            signature,
            public_key
        )

        print("\n=== VERIFICATION RESULT ===\n")

        if is_valid:
            print("✓ Signature Valid")
        else:
            print("✗ Signature Invalid")
            print("✗ Message Modified")
            print("✗ Authentication Failed")