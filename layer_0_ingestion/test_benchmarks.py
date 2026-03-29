import requests
import json
import os
import sys

# --- CONFIGURATION ---
LAYER_0_URL = "http://localhost:8001/api/v1/ingest/benchmark"
BENCHMARK_DIR = "/home/art3mi5/Documents/Github/TuxSOC/layer_0_ingestion/benchmark_json"

def test_benchmark_file(filename):
    file_path = os.path.join(BENCHMARK_DIR, filename)
    
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        return

    print(f"🚀 Loading {filename}...")
    with open(file_path, 'r') as f:
        # Benchmark files are sequences of objects like: { log1 }, \n\n { log2 }
        content = f.read().strip()
        
        # If the file is a sequence of objects rather than a pure list [...]
        if content.startswith('{') and not content.endswith(']'):
            # Wrap into a list
            # We fix common sequence patterns (commas already present vs missing)
            if '},' in content:
                # Likely already has commas
                json_list_str = "[" + content + "]"
            else:
                # No commas, just newlines? Let's be safe.
                json_list_str = "[" + content.replace('}\n\n{', '},\n{').replace('}\n{', '},\n{') + "]"
            
            try:
                data = json.loads(json_list_str)
            except json.JSONDecodeError as e:
                # Fallback: simple line by line or regex if it's really messy
                # But looking at se1.json, it's {obj}, \n\n {obj}
                print(f"⚠️ Complex JSON sequence detected. Attempting repair...")
                # Remove trailing commas before closing bracket if needed
                json_list_str = json_list_str.replace('},]', '}]')
                try:
                    data = json.loads(json_list_str)
                except Exception as e2:
                    print(f"❌ Failed to parse JSON even after repair: {e2}")
                    return
        else:
            data = json.loads(content)

    print(f"📤 Sending {len(data)} events to Layer 0...")
    try:
        response = requests.post(LAYER_0_URL, json=data, timeout=30)
        if response.status_code == 200:
            print(f"✅ Success! Layer 0 Response:")
            print(json.dumps(response.json(), indent=2))
        else:
            print(f"⚠️ Layer 0 returned status {response.status_code}:")
            print(response.text)
    except Exception as e:
        print(f"❌ Connection error: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        test_benchmark_file(sys.argv[1])
    else:
        # Just test se1.json by default
        test_benchmark_file("se1.json")
