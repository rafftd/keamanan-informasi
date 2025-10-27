"""
SERVER (Device 2) - Penerima & Dekripsi
Program ini akan:
1. Listen di port tertentu
2. Menerima key dan ciphertext dari client
3. Mendekripsi ciphertext menggunakan key yang sama
4. Menampilkan plaintext hasil dekripsi
"""

import socket
import json
from des_lib import decrypt_message, hex_to_bits

def start_server(host='0.0.0.0', port=5555):
    # Buat socket server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((host, port))
        server_socket.listen(1)
        
        print("="*60)
        print("🔒 DES DECRYPTION SERVER")
        print("="*60)
        print(f"Server listening on {host}:{port}")
        print("Waiting for client connection...")
        print("="*60)
        
        while True:
            # Terima koneksi dari client
            client_socket, client_address = server_socket.accept()
            print(f"\n✓ Client connected from {client_address[0]}:{client_address[1]}")
            
            try:
                # Terima data dari client
                data = client_socket.recv(4096).decode('utf-8')
                
                if not data:
                    print("✗ No data received")
                    continue
                
                # Parse JSON data
                message = json.loads(data)
                key = message['key']
                ciphertext_hex = message['ciphertext']
                
                print(f"\n{'─'*60}")
                print("RECEIVED FROM CLIENT:")
                print(f"Key             : '{key}'")
                print(f"Ciphertext (hex): {ciphertext_hex}")
                
                # Konversi hex ke bits
                ciphertext_bits = hex_to_bits(ciphertext_hex)
                
                # Dekripsi
                plaintext = decrypt_message(ciphertext_bits, key)
                
                print(f"\n{'─'*60}")
                print("DECRYPTION RESULT:")
                print(f"Plaintext       : '{plaintext}'")
                print(f"{'─'*60}")
                
                # Kirim response ke client (plaintext hasil dekripsi)
                response = json.dumps({
                    'status': 'success',
                    'plaintext': plaintext
                })
                client_socket.send(response.encode('utf-8'))
                
                print("\n✓ Response sent to client")
                
            except json.JSONDecodeError:
                print("✗ Error: Invalid JSON data")
            except Exception as e:
                print(f"✗ Error: {e}")
            finally:
                client_socket.close()
                print("\n" + "="*60)
                print("Waiting for next client connection...")
                print("="*60)
                
    except KeyboardInterrupt:
        print("\n\nServer shutting down...")
    finally:
        server_socket.close()
        print("Server closed")


if __name__ == "__main__":
    # Default host dan port
    # Gunakan '0.0.0.0' untuk listen di semua network interfaces
    # Atau gunakan 'localhost' untuk testing lokal saja
    HOST = '0.0.0.0'  # Bisa diakses dari komputer lain
    PORT = 5555
    
    print("\nNOTE: Pastikan firewall mengizinkan koneksi di port", PORT)
    print("Untuk testing di komputer yang sama, client gunakan host: 'localhost'")
    print("Untuk testing di komputer berbeda, client gunakan IP address server\n")
    
    start_server(HOST, PORT)
