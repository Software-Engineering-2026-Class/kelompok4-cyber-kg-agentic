import requests
import os
import sys

VIRTUOSO_URL = "http://127.0.0.1:8890/sparql-graph-crud-auth"
GRAPH_URI = "http://w3id.org/sepses/graph/cskg"
TTL_FILE = "linking_agent/output/cve_to_cwe.ttl"

def upload_ttl_to_virtuoso(file_path):
    print("=" * 50)
    print("  VIRTUOSO INGESTION SCRIPT (Issue 8)")
    print("=" * 50)
    
    if not os.path.exists(file_path):
        print(f"[ERROR] File tidak ditemukan: {file_path}")
        print("Pastikan Anda sudah menjalankan linking_agent.")
        sys.exit(1)
        
    print(f"[INFO] Membaca file: {file_path}...")
    with open(file_path, 'r', encoding='utf-8') as f:
        ttl_content = f.read()
        
    print(f"[INFO] Mengunggah {len(ttl_content)} bytes ke graf: {GRAPH_URI}...")
    
    headers = {
        'Content-Type': 'text/turtle',
    }
    
    from requests.auth import HTTPDigestAuth
    try:
        # Default credential untuk Virtuoso OpenSource adalah dba:dba
        response = requests.post(
            VIRTUOSO_URL,
            params={'graph-uri': GRAPH_URI},
            headers=headers,
            data=ttl_content.encode('utf-8'),
            auth=HTTPDigestAuth('dba', 'dba')
        )
        
        if response.status_code in (200, 201):
            print("[SUCCESS] Graf pengetahuan berhasil diunggah ke Virtuoso!")
            print("Anda sekarang bisa menjalankan kueri SELECT di http://localhost:8890/sparql")
        else:
            print(f"[FAILED] HTTP {response.status_code}")
            print(response.text)
            
    except requests.exceptions.ConnectionError:
        print("[ERROR] Gagal terhubung ke Virtuoso.")
        print("Pastikan kontainer Docker Virtuoso Anda berjalan (Gunakan `sudo docker compose up -d`)")
    except Exception as e:
        print(f"[ERROR] Terjadi kesalahan tak terduga: {e}")

if __name__ == "__main__":
    upload_ttl_to_virtuoso(TTL_FILE)
