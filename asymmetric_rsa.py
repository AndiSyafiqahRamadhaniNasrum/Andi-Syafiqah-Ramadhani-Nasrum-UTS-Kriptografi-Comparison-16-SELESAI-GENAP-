

import time                              
import base64                                            
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

print("Sedang membangkitkan kunci RSA-2048, harap tunggu...")
start_keygen = time.perf_counter()

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

akhir_keygen = time.perf_counter()
waktu_keygen = (akhir_keygen - start_keygen) * 1000

public_key = private_key.public_key()

pem_publik = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

pem_privat = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

print("=" * 60)
print("   KRIPTOGRAFI ASIMETRIS — RSA-2048 (OAEP + SHA-256)")
print("=" * 60)
print(f"\n[PEMBANGKITAN KUNCI]")
print(f"  Waktu Generate Key : {waktu_keygen:.4f} ms")
print(f"  Ukuran Kunci       : {private_key.key_size} bit")
print(f"  Public Exponent (e): {public_key.public_numbers().e}")
print(f"  Ukuran Kunci Publik (PEM)  : {len(pem_publik)} byte")
print(f"  Ukuran Kunci Privat (PEM)  : {len(pem_privat)} byte")
print(f"\n  Public Key (PEM):")
print(f"  {pem_publik.decode().strip()}")

plaintext = "Universitas Muhammadiyah Makassar"
plaintext_bytes = plaintext.encode("utf-8")

max_plaintext = private_key.key_size // 8 - 2 * 32 - 2 

print(f"\n[PLAINTEXT]")
print(f"  Teks               : {plaintext}")
print(f"  Panjang            : {len(plaintext_bytes)} byte")
print(f"  Representasi Hex   : {plaintext_bytes.hex()}")
print(f"  Batas Max RSA-2048 : {max_plaintext} byte (OAEP-SHA256)")
print(f"  Status Ukuran      : {'✓ Aman' if len(plaintext_bytes) <= max_plaintext else '✗ Melebihi batas'}")

start_enkripsi = time.perf_counter()
ciphertext_rsa = public_key.encrypt(
    plaintext_bytes,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),  
        algorithm=hashes.SHA256(),                     
        label=None                                     
    )
)
akhir_enkripsi = time.perf_counter()

waktu_enkripsi = (akhir_enkripsi - start_enkripsi) * 1000

ct_b64 = base64.b64encode(ciphertext_rsa).decode()

print(f"\n[ENKRIPSI]")
print(f"  Ciphertext (Base64):")

for i in range(0, len(ct_b64), 60):
    print(f"  {ct_b64[i:i+60]}")
print(f"  Panjang Ciphertext : {len(ciphertext_rsa)} byte (= {private_key.key_size} bit / 8)")
print(f"  Waktu Enkripsi     : {waktu_enkripsi:.6f} ms")
print(f"  Catatan            : Ukuran ciphertext SELALU = ukuran kunci RSA")

start_dekripsi = time.perf_counter()
plaintext_kembali = private_key.decrypt(
    ciphertext_rsa,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
akhir_dekripsi = time.perf_counter()

waktu_dekripsi = (akhir_dekripsi - start_dekripsi) * 1000

print(f"\n[DEKRIPSI]")
print(f"  Hasil Dekripsi     : {plaintext_kembali.decode()}")
print(f"  Waktu Dekripsi     : {waktu_dekripsi:.6f} ms")

status = "✓ BERHASIL" if plaintext_kembali.decode() == plaintext else "✗ GAGAL"

print(f"\n[VERIFIKASI]")
print(f"  Plaintext Asli     : {plaintext}")
print(f"  Hasil Dekripsi     : {plaintext_kembali.decode()}")
print(f"  Identik?           : {plaintext_kembali.decode() == plaintext}")
print(f"  Status             : {status}")

print(f"\n{'=' * 60}")
print(f"  RINGKASAN HASIL PENGUJIAN KRIPTOGRAFI ASIMETRIS")
print(f"{'=' * 60}")
print(f"  Algoritma          : RSA-2048 + OAEP (SHA-256)")
print(f"  Plaintext          : {plaintext}")
print(f"  Panjang Plaintext  : {len(plaintext_bytes)} byte")
print(f"  Panjang Ciphertext : {len(ciphertext_rsa)} byte")
print(f"  Ekspansi Data      : {len(ciphertext_rsa)/len(plaintext_bytes):.2f}x")
print(f"  Waktu Generate Key : {waktu_keygen:.4f} ms")
print(f"  Waktu Enkripsi     : {waktu_enkripsi:.6f} ms")
print(f"  Waktu Dekripsi     : {waktu_dekripsi:.6f} ms")
print(f"  Status Verifikasi  : {status}")
print(f"{'=' * 60}")
