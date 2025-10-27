"""
CLIENT (Device 1) - Pengirim & Enkripsi
Program ini akan:
1. Input plaintext dan key dari user
2. Enkripsi plaintext menggunakan DES
3. Kirim key dan ciphertext ke server
4. Menerima hasil dekripsi dari server untuk verifikasi
"""

import socket
import json
from des_lib import encrypt_message, bits_to_hex, pad_key, pad_text

def send_encrypted_message(host, port):
    print("="*60)
    print("🔐 DES ENCRYPTION CLIENT")
    print("="*60)
    
    # Input dari user
    plaintext = input("\nMasukkan plaintext yang ingin dikirim: ")
    key = input("Masukkan key (8 karakter, akan di-pad jika kurang): ")
    
    # Padding
    key = pad_key(key)
    plaintext_padded = pad_text(plaintext)
    
    print(f"\n{'─'*60}")
    print("ENCRYPTION INFO:")
    print(f"Plaintext asli  : '{plaintext}'")
    print(f"Plaintext padded: '{plaintext_padded}' ({len(plaintext_padded)} bytes)")
    print(f"Key             : '{key}' (8 bytes)")
    
    # Enkripsi
    ciphertext_bits = encrypt_message(plaintext, key)
    ciphertext_hex = bits_to_hex(ciphertext_bits)
    
    print(f"\n{'─'*60}")
    print("ENCRYPTION RESULT:")
    print(f"Ciphertext (hex): {ciphertext_hex}")
    print(f"{'─'*60}")
    
    # Siapkan data untuk dikirim
    message = {
        'key': key,
        'ciphertext': ciphertext_hex
    }
    
    # Kirim ke server
    try:
        print(f"\nConnecting to server {host}:{port}...")
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((host, port))
        print("✓ Connected to server!")
        
        # Kirim data
        client_socket.send(json.dumps(message).encode('utf-8'))
        print("✓ Encrypted message sent to server")
        
        # Terima response dari server
        response = client_socket.recv(4096).decode('utf-8')
        result = json.loads(response)
        
        if result['status'] == 'success':
            print(f"\n{'─'*60}")
            print("SERVER RESPONSE:")
            print(f"Decrypted text at server: '{result['plaintext']}'")
            print(f"{'─'*60}")
            
            # Verifikasi
            if result['plaintext'] == plaintext:
                print("\n✓ VERIFICATION SUCCESS - Server berhasil dekripsi!")
            else:
                print("\n✗ VERIFICATION FAILED - Ada kesalahan!")
        
        client_socket.close()
        print("\n" + "="*60)
        
    except ConnectionRefusedError:
        print(f"\n✗ Error: Cannot connect to server at {host}:{port}")
        print("   Pastikan server sudah running!")
    except Exception as e:
        print(f"\n✗ Error: {e}")


if __name__ == "__main__":
    # Konfigurasi server
    # Untuk testing di komputer yang sama: gunakan 'localhost'
    # Untuk testing di komputer berbeda: gunakan IP address server
    
    print("\nSERVER CONFIGURATION:")
    host_input = input("Masukkan IP server (tekan Enter untuk localhost): ").strip()
    HOST = host_input if host_input else 'localhost'
    
    port_input = input("Masukkan port server (tekan Enter untuk 5555): ").strip()
    PORT = int(port_input) if port_input else 5555
    
    send_encrypted_message(HOST, PORT)
