import requests, string, random, uuid, base64, json, time, datetime, argparse
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from colorama import init, Fore, Style

class InteractshClient:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.correlation_id = ''.join(
            random.choices(string.ascii_lowercase + string.digits, k=20)
        )
        self.secret_key = str(uuid.uuid4())
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.public_key_b64 = base64.b64encode(pem).decode('utf-8')

    def register(self):
        url = "https://oast.fun/register"
        payload = {
            "public-key": self.public_key_b64,
            "secret-key": self.secret_key,
            "correlation-id": self.correlation_id
        }
        response = requests.post(url, json=payload)
        return response.json()

    def generate_payload(self):
        random_suffix = ''.join(
            random.choices(string.ascii_lowercase + string.digits, k=13)
        )
        return f"{self.correlation_id}{random_suffix}.oast.fun"

    def poll(self):
        url = "https://oast.fun/poll"
        params = {
            "id": self.correlation_id,
            "secret": self.secret_key
        }
        response = requests.get(url, params=params)
        return response.json()

    def decrypt_data(self, poll_response):
        try:
            encrypted_aes_key = base64.b64decode(poll_response['aes_key'])
            aes_key = self.private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            decrypted_data = []
            for encrypted_data in poll_response['data']:
                try:
                    encrypted_bytes = base64.b64decode(encrypted_data)
                    iv = encrypted_bytes[:16]
                    ciphertext = encrypted_bytes[16:]
                    cipher = Cipher(
                        algorithms.AES(aes_key),
                        modes.CFB(iv),
                        backend=default_backend()
                    )
                    decryptor = cipher.decryptor()
                    decrypted_data_bytes = decryptor.update(ciphertext) + decryptor.finalize()
                    decrypted_data.append(json.loads(decrypted_data_bytes.decode('utf-8')))
                except Exception as inner_e:
                    print(f"Error decrypting individual entry: {str(inner_e)}")
                    continue
            return decrypted_data
        except Exception as e:
            print(f"Decryption error: {str(e)}")
            return None

def format_interaction(interaction, verbose=False):
    protocol_colors = {
        'http': Fore.GREEN,
        'dns': Fore.BLUE,
        'smtp': Fore.YELLOW,
        'ldap': Fore.MAGENTA
    }
    
    color = protocol_colors.get(interaction['protocol'], Fore.WHITE)
    timestamp = datetime.datetime.fromisoformat(interaction['timestamp'].replace('Z', '+00:00'))
    base_info = f"{color}[{timestamp.strftime('%H:%M:%S')}] {Style.BRIGHT}{interaction['protocol'].upper()}{Style.RESET_ALL}"
    
    if interaction['protocol'] == 'http':
        method = interaction['raw-request'].split('\n')[0].split()[0]
        path = interaction['raw-request'].split('\n')[0].split()[1]
        user_agent = next((line.split(': ', 1)[1] for line in interaction['raw-request'].split('\n') 
                          if line.startswith('User-Agent: ')), 'Unknown')
        details = f"{color}→{Style.RESET_ALL} {method} {path} {color}|{Style.RESET_ALL} {interaction['remote-address']}"
        
        if verbose:
            details += f"\n{color}Request:{Style.RESET_ALL}\n{interaction['raw-request']}"
            details += f"\n{color}Response:{Style.RESET_ALL}\n{interaction['raw-response']}"
        
    elif interaction['protocol'] == 'dns':
        details = f"{color}→{Style.RESET_ALL} {interaction['q-type']} {color}|{Style.RESET_ALL} {interaction['full-id']} {color}|{Style.RESET_ALL} {interaction['remote-address']}"
        
        if verbose:
            details += f"\n{color}Request:{Style.RESET_ALL}\n{interaction['raw-request']}"
            details += f"\n{color}Response:{Style.RESET_ALL}\n{interaction['raw-response']}"
    
    else:
        details = f"{color}→{Style.RESET_ALL} {interaction['remote-address']}"
        
        if verbose:
            details += f"\n{color}Raw Data:{Style.RESET_ALL}\n{json.dumps(interaction, indent=2)}"
    
    return f"{base_info} {details}"

def print_banner():
    banner = f"""{Fore.CYAN}{Style.BRIGHT}
    ____      __                      __       __  
   /  _/___  / /____  _________ _____/ /______/ /_ 
   / // __ \\/ __/ _ \\/ ___/ __ `/ __  / ___/ __ \\
 _/ // / / / /_/  __/ /  / /_/ / /_/ (__  ) / / /
/___/_/ /_/\\__/\\___/_/   \\__,_/\\__,_/____/_/ /_/ 
{Style.RESET_ALL}
{Fore.YELLOW}     [ Interactsh Python Client - OAST Platform ]{Style.RESET_ALL}
{Fore.CYAN}     [ Created by Aymen @J4k0m ]{Style.RESET_ALL}
"""
    print(banner)

def main():
    parser = argparse.ArgumentParser(description='Interactsh Python Client')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')
    args = parser.parse_args()

    init()
    print_banner()
    client = InteractshClient(verbose=args.verbose)
    client.register()
    interaction_url = client.generate_payload()
    print(f"\n{Fore.YELLOW}Interaction URL: {Style.BRIGHT}{interaction_url}{Style.RESET_ALL}")
    print(f"\n{Fore.GREEN}{Style.BRIGHT}Polling for interactions (Press Ctrl+C to stop)...{Style.RESET_ALL}")
    try:
        while True:
            poll_response = client.poll()
            if poll_response and poll_response.get('data'):
                decrypted_data = client.decrypt_data(poll_response)
                if decrypted_data:
                    for interaction in decrypted_data:
                        print(format_interaction(interaction, verbose=args.verbose))
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}{Style.BRIGHT}Stopping interaction polling...{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
