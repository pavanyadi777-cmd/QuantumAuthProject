from flask import Flask, render_template, request
import oqs
import time

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/kyber")
def kyber():

    kem_alg = "ML-KEM-512"

    with oqs.KeyEncapsulation(kem_alg) as alice:

        start = time.time()
        public_key = alice.generate_keypair()
        keygen_time = time.time() - start

        with oqs.KeyEncapsulation(kem_alg) as bob:

            start = time.time()
            ciphertext, bob_secret = bob.encap_secret(public_key)
            encap_time = time.time() - start

            start = time.time()
            alice_secret = alice.decap_secret(ciphertext)
            decap_time = time.time() - start

    result = (
        "✓ Shared Secrets Match"
        if alice_secret == bob_secret
        else "✗ Shared Secrets Do Not Match"
    )

    return render_template(
        "kyber.html",
        public_key_size=len(public_key),
        ciphertext_size=len(ciphertext),
        alice_secret=alice_secret.hex(),
        bob_secret=bob_secret.hex(),
        result=result,
        keygen_time=round(keygen_time, 6),
        encap_time=round(encap_time, 6),
        decap_time=round(decap_time, 6)
    )
@app.route("/dilithium")
def dilithium():

    sig_alg = "ML-DSA-44"

    message = b"Hello Bob"

    with oqs.Signature(sig_alg) as signer:

        public_key = signer.generate_keypair()

        start = time.time()
        signature = signer.sign(message)
        sign_time = time.time() - start

        with oqs.Signature(sig_alg) as verifier:

            is_valid = verifier.verify(
                message,
                signature,
                public_key
            )

    result = (
        "✓ Signature Valid"
        if is_valid
        else "✗ Signature Invalid"
    )

    return render_template(
        "dilithium.html",
        message=message.decode(),
        public_key_size=len(public_key),
        signature_size=len(signature),
        sign_time=round(sign_time, 6),
        result=result
    )

@app.route("/tampering")
def tampering():

    sig_alg = "ML-DSA-44"

    original_message = b"Hello Bob"
    tampered_message = b"Hello Hacker"

    with oqs.Signature(sig_alg) as signer:

        public_key = signer.generate_keypair()

        signature = signer.sign(original_message)

        with oqs.Signature(sig_alg) as verifier:

            is_valid = verifier.verify(
                tampered_message,
                signature,
                public_key
            )

    result = (
        "✓ Signature Valid"
        if is_valid
        else "✗ Authentication Failed - Message Modified"
    )

    return render_template(
        "tampering.html",
        original_message=original_message.decode(),
        tampered_message=tampered_message.decode(),
        result=result
    )
@app.route("/architecture")
def architecture():
    return render_template("architecture.html")

@app.route("/secure-message", methods=["GET", "POST"])
def secure_message():

    if request.method == "POST":

        message = request.form["message"]

        kem_alg = "ML-KEM-512"

        with oqs.KeyEncapsulation(kem_alg) as alice:

            public_key = alice.generate_keypair()

            with oqs.KeyEncapsulation(kem_alg) as bob:

                 ciphertext, bob_secret = bob.encap_secret(public_key)

                 alice_secret = alice.decap_secret(ciphertext)

        import base64
        from cryptography.fernet import Fernet

        fernet_key = base64.urlsafe_b64encode(alice_secret[:32])

        cipher = Fernet(fernet_key)

        encrypted_message = cipher.encrypt(
        message.encode()
        )
 
        decrypted_message = cipher.decrypt(
        encrypted_message
        ).decode()

        sig_alg = "ML-DSA-44"

        with oqs.Signature(sig_alg) as signer:

            public_sign_key = signer.generate_keypair()

            signature = signer.sign(
            encrypted_message
        )

            with oqs.Signature(sig_alg) as verifier:

                is_valid = verifier.verify(
                    encrypted_message,
                    signature,
                    public_sign_key
                )

        return render_template(
        "secure_message.html",
        submitted_message=message,
        public_key=public_key.hex()[:80],
        ciphertext=ciphertext.hex()[:80],
        shared_secret=alice_secret.hex()[:80],
        encrypted_message=encrypted_message.decode(),
        decrypted_message=decrypted_message,
        signature_size=len(signature),
        signature=signature.hex()[:120],
        verification_result=(
            "✓ Signature Verified"
            if is_valid
            else "✗ Signature Invalid"
            )
        )
    return render_template("secure_message.html")

if __name__ == "__main__":
    app.run(debug=True)