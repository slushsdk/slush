import socket
import json
import socket
import os

def get_own_ip():
  st = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  try:
    st.connect(('10.255.255.255', 1))
    ip = st.getsockname()[0]
  except Exception:
    raise Exception("ERROR: Could not get own IP address\n")
  finally:
    st.close()
  return ip

def load_json(file):
  if not os.path.exists(file):
    raise Exception("ERROR: {} file does not exist. Please initialize first with the following command:\n\n\t./build/slush init validator --home ./valdata\n".format(file))

  with open(file, 'r') as f:
    input_json = json.load(f)
  return input_json

def get_non_validator_start_command(hostname, ip, port):
  persistentPeersString = "{hostname}@{ip}:{port}".format(hostname=hostname, ip=ip, port=port)
  return "./build/slush start --home ./valdata --proxy-app=kvstore --p2p.persistent-peers \"{persistentPeersString}\"".format(persistentPeersString=persistentPeersString)


def print_non_validator_steps(genesis_json_dictionary, non_validator_start_command):
  print("On the other non-validator computers do the following steps:")
  print()
  print("\t1. Initialize a non-validator node with the following command:")
  print()
  print("\t\t./build/slush init full --home ./valdata")
  print()
  print()
  print("\t2. Copy the content of the valdata/config/genesis.json file from this validator node to the valdata/config folder of the other non-validator computer")
  print()
  print("\t\tgenesis.json file content:")
  print()
  print("\t\t\t", json.dumps(genesis_json_dictionary, indent=4).replace("\n", "\n\t\t\t"))
  print()
  print()
  print("\t3. Run the following command to start a non-validator node:")
  print()
  print("\t\t{non_validator_start_command}".format(non_validator_start_command=non_validator_start_command))
  print()

if __name__ == "__main__":
  valdata_folder_path = 'valdata'
  node_key_file_path = valdata_folder_path+'/config/node_key.json'
  genesis_json_file_path = valdata_folder_path+'/config/genesis.json'

  try:
    hostname = load_json(node_key_file_path)["id"]
    ip = get_own_ip()
    genesis_json = load_json(genesis_json_file_path)
  except Exception as e:
    print(e)
    exit(1)

  print_non_validator_steps(genesis_json, get_non_validator_start_command(hostname, ip, 26656))
