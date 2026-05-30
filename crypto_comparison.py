
import time
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

symmetric_key = Fernet.generate_key()
fernet = Fernet(symmetric_key)

plaintext = "Universitas Muhammadiyah Makassar"
plaintext_bytes = plaintext.encode("utf-8")

start_enc_sym = time.perf_counter()
symmetric_ciphertext = fernet.encrypt(plaintext_bytes)
end_enc_sym = time.perf_counter()
sym_enc_time = (end_enc_sym - start_enc_sym) * 1000  

start_dec_sym = time.perf_counter()
symmetric_decrypted = fernet.decrypt(symmetric_ciphertext)
end_dec_sym = time.perf_counter()
sym_dec_time = (end_dec_sym - start_dec_sym) * 1000  

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

start_enc_asym = time.perf_counter()
rsa_ciphertext = public_key.encrypt(
    plaintext_bytes,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
end_enc_asym = time.perf_counter()
asym_enc_time = (end_enc_asym - start_enc_asym) * 1000

start_dec_asym = time.perf_counter()
rsa_decrypted = private_key.decrypt(
    rsa_ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
end_dec_asym = time.perf_counter()
asym_dec_time = (end_dec_asym - start_dec_asym) * 1000

print("=" * 65)
print("   PERBANDINGAN KRIPTOGRAFI SIMETRIS vs ASIMETRIS")
print("   Soal No. 16 — Keamanan Informasi dan Kriptografi")
print("   Universitas Muhammadiyah Makassar")
print("=" * 65)

print("\n[ KRIPTOGRAFI SIMETRIS — FERNET (AES-128-CBC + HMAC-SHA256) ]")
print(f"  Plaintext          : {plaintext}")
print(f"  Kunci Simetris     : {symmetric_key.decode()[:44]}")
print(f"  Ciphertext         : {symmetric_ciphertext.decode()[:55]}...")
print(f"  Hasil Dekripsi     : {symmetric_decrypted.decode()}")
print(f"  Panjang Plaintext  : {len(plaintext_bytes)} byte")
print(f"  Panjang Ciphertext : {len(symmetric_ciphertext)} byte")
print(f"  Waktu Enkripsi     : {sym_enc_time:.6f} ms")
print(f"  Waktu Dekripsi     : {sym_dec_time:.6f} ms")
sym_ok = symmetric_decrypted.decode() == plaintext
print(f"  Status Dekripsi    : {'✓ BERHASIL' if sym_ok else '✗ GAGAL'}")

rsa_ct_b64 = base64.b64encode(rsa_ciphertext).decode()
print("\n[ KRIPTOGRAFI ASIMETRIS — RSA 2048-bit (OAEP + SHA-256) ]")
print(f"  Plaintext          : {plaintext}")
print(f"  Ciphertext (B64)   : {rsa_ct_b64[:55]}...")
print(f"  Hasil Dekripsi     : {rsa_decrypted.decode()}")
print(f"  Panjang Plaintext  : {len(plaintext_bytes)} byte")
print(f"  Panjang Ciphertext : {len(rsa_ciphertext)} byte")
print(f"  Waktu Enkripsi     : {asym_enc_time:.6f} ms")
print(f"  Waktu Dekripsi     : {asym_dec_time:.6f} ms")
rsa_ok = rsa_decrypted.decode() == plaintext
print(f"  Status Dekripsi    : {'✓ BERHASIL' if rsa_ok else '✗ GAGAL'}")

print("\n[ TABEL PERBANDINGAN KINERJA ]")
print(f"  {'Metode':<30} {'Enkripsi (ms)':<20} {'Dekripsi (ms)':<20} {'Ciphertext'}")
print(f"  {'-'*75}")
print(f"  {'Simetris (Fernet)':<30} {sym_enc_time:<20.6f} {sym_dec_time:<20.6f} {len(symmetric_ciphertext)} byte")
print(f"  {'Asimetris (RSA-2048)':<30} {asym_enc_time:<20.6f} {asym_dec_time:<20.6f} {len(rsa_ciphertext)} byte")

print(f"\n[ ANALISIS PERBANDINGAN ]")
if sym_enc_time < asym_enc_time:
    ratio_enc = asym_enc_time / sym_enc_time
    print(f"  Enkripsi  : Fernet lebih cepat {ratio_enc:.1f}x dari RSA")
else:
    ratio_enc = sym_enc_time / asym_enc_time
    print(f"  Enkripsi  : RSA lebih cepat {ratio_enc:.1f}x dari Fernet (untuk data pendek)")

if sym_dec_time < asym_dec_time:
    ratio_dec = asym_dec_time / sym_dec_time
    print(f"  Dekripsi  : Fernet lebih cepat {ratio_dec:.1f}x dari RSA")
else:
    ratio_dec = sym_dec_time / asym_dec_time
    print(f"  Dekripsi  : RSA lebih cepat {ratio_dec:.1f}x dari Fernet")

ct_ratio = len(rsa_ciphertext) / len(symmetric_ciphertext)
print(f"  Ciphertext: RSA menghasilkan {ct_ratio:.1f}x lebih besar dari Fernet")
print(f"  Catatan   : RSA tidak dapat mengenkripsi data > 190 byte secara langsung")

print("=" * 65)
print("  Kedua metode BERHASIL: dekripsi menghasilkan plaintext asli.")
print("  Sistem modern (TLS, HTTPS) menggunakan KEDUANYA secara hybrid:")
print("  RSA/ECDH untuk key exchange → AES untuk enkripsi data aktual.")
print("=" * 65)
