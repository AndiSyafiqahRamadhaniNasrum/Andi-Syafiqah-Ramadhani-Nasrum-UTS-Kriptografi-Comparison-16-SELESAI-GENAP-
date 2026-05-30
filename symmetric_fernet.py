
import time                              
import base64                            
from cryptography.fernet import Fernet  

symmetric_key = Fernet.generate_key()

fernet = Fernet(symmetric_key)

raw_key = base64.urlsafe_b64decode(symmetric_key)

print("=" * 60)
print("   KRIPTOGRAFI SIMETRIS — FERNET (AES-128-CBC + HMAC-SHA256)")
print("=" * 60)
print(f"\n[KUNCI]")
print(f"  Kunci (Base64URL)  : {symmetric_key.decode()}")
print(f"  Panjang Raw Key    : {len(raw_key)} byte ({len(raw_key)*8} bit total)")
print(f"                       (128-bit encryption key + 128-bit signing key)")

plaintext = "Universitas Muhammadiyah Makassar"
plaintext_bytes = plaintext.encode("utf-8")

print(f"\n[PLAINTEXT]")
print(f"  Teks               : {plaintext}")
print(f"  Panjang            : {len(plaintext_bytes)} byte")
print(f"  Representasi Hex   : {plaintext_bytes.hex()}")


start_enkripsi = time.perf_counter()        
ciphertext = fernet.encrypt(plaintext_bytes)
akhir_enkripsi = time.perf_counter()       

waktu_enkripsi = (akhir_enkripsi - start_enkripsi) * 1000  

print(f"\n[ENKRIPSI]")
print(f"  Ciphertext (Base64URL):")
print(f"  {ciphertext.decode()}")
print(f"  Panjang Ciphertext : {len(ciphertext)} byte")
print(f"  Waktu Enkripsi     : {waktu_enkripsi:.6f} ms")

# Dekompilasi struktur token Fernet untuk edukasi
raw_token = base64.urlsafe_b64decode(ciphertext + b"==")
print(f"\n  [Struktur Token Fernet]")
print(f"    Version   (1 byte) : 0x{raw_token[0]:02X}  (0x80 = Fernet v1)")
print(f"    Timestamp (8 byte) : {int.from_bytes(raw_token[1:9], 'big')} detik (Unix epoch)")
print(f"    IV        (16 byte): {raw_token[9:25].hex()}")
print(f"    Ciphertext         : {raw_token[25:-32].hex()[:32]}...")
print(f"    HMAC-SHA256(32byte): {raw_token[-32:].hex()[:32]}...")

start_dekripsi = time.perf_counter()        
plaintext_kembali = fernet.decrypt(ciphertext)
akhir_dekripsi = time.perf_counter()        

waktu_dekripsi = (akhir_dekripsi - start_dekripsi) * 1000 

print(f"\n[DEKRIPSI]")
print(f"  Hasil Dekripsi     : {plaintext_kembali.decode()}")
print(f"  Waktu Dekripsi     : {waktu_dekripsi:.6f} ms")

status = "✓ BERHASIL" if plaintext_kembali.decode() == plaintext else "✗ GAGAL"

print(f"\n[VERIFIKASI]")
print(f"  Plaintext Asli     : {plaintext}")
print(f"  Hasil Dekripsi     : {plaintext_kembali.decode()}")
print(f"  Status             : {status}")

print(f"\n{'=' * 60}")
print(f"  RINGKASAN HASIL PENGUJIAN KRIPTOGRAFI SIMETRIS")
print(f"{'=' * 60}")
print(f"  Algoritma          : AES-128-CBC + HMAC-SHA256 (Fernet)")
print(f"  Plaintext          : {plaintext}")
print(f"  Panjang Plaintext  : {len(plaintext_bytes)} byte")
print(f"  Panjang Ciphertext : {len(ciphertext)} byte")
print(f"  Ekspansi Data      : {len(ciphertext)/len(plaintext_bytes):.2f}x")
print(f"  Waktu Enkripsi     : {waktu_enkripsi:.6f} ms")
print(f"  Waktu Dekripsi     : {waktu_dekripsi:.6f} ms")
print(f"  Status Verifikasi  : {status}")
print(f"{'=' * 60}")
