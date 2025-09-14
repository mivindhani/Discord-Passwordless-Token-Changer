#* CREDITS TO https://github.com/Switch3301/Token-changer FOR THE ORIGINAL CODE

import random
import time
import toml
import ctypes
import threading
import tls_client
import hashlib
import websocket
import base64
import json
import os
import subprocess

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from concurrent.futures import ThreadPoolExecutor, as_completed
from logmagix import Logger, Home
from functools import wraps
import requests.exceptions

with open('input/config.toml') as f:
    config = toml.load(f)

DEBUG = config['dev'].get('Debug', False)

log = Logger()


output_folder = f"output/{time.strftime('%Y-%m-%d %H-%M-%S')}"
if not os.path.exists(output_folder):
    os.makedirs(output_folder)


def debug(func_or_message, *args, **kwargs) -> callable:
    if callable(func_or_message):
        @wraps(func_or_message)
        def wrapper(*args, **kwargs):
            result = func_or_message(*args, **kwargs)
            if DEBUG:
                log.debug(f"{func_or_message.__name__} returned: {result}")
            return result
        return wrapper
    else:
        if DEBUG:
            log.debug(f"Debug: {func_or_message}")

def debug_response(response) -> None:
    debug(response.headers)
    try:
        debug(response.text)
    except:
        debug(response.content)
    debug(response.status_code)

def retry_with_rate_limit(max_retries=5, base_delay=1.0):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries + 1):
                try:
                    result = func(*args, **kwargs)
                    
                    if hasattr(result, 'status_code'):
                        if result.status_code == 429:  # Rate limited
                            if attempt < max_retries:
                                retry_after = result.headers.get('retry-after')
                                if retry_after:
                                    try:
                                        wait_time = float(retry_after)
                                        log.warning(f"Rate limited, waiting {wait_time}s before retry")
                                        time.sleep(wait_time)
                                        continue
                                    except ValueError:
                                        pass
                                
                                # Try to get retry-after from response JSON
                                try:
                                    response_data = result.json()
                                    if 'retry_after' in response_data:
                                        wait_time = response_data['retry_after']
                                        log.warning(f"Rate limited, waiting {wait_time}s before retry")
                                        time.sleep(wait_time)
                                        continue
                                except:
                                    pass
                                
                                # Default rate limit wait
                                log.warning(f"Rate limited, waiting {base_delay}s before retry")
                                time.sleep(base_delay)
                                continue
                            else:
                                log.failure(f"Max retries reached for rate limit in {func.__name__}")
                                return result
                        
                        # Don't retry on 401 (invalid token) or other client errors that won't be fixed by retrying
                        elif result.status_code in [401, 403]:
                            return result
                    
                    return result
                    
                except (requests.exceptions.RequestException, 
                        websocket.WebSocketException,
                        ConnectionError, 
                        TimeoutError) as e:
                    if attempt < max_retries:
                        log.warning(f"Network error in {func.__name__}: {str(e)[:100]}...")
                        time.sleep(base_delay)
                        continue
                    else:
                        log.failure(f"Max retries reached for {func.__name__}: {str(e)[:100]}...")
                        raise e
                except Exception as e:
                    # For non-network errors, don't retry by default
                    log.failure(f"Error in {func.__name__}: {str(e)[:100]}...")
                    raise e
            
            return None
        return wrapper
    return decorator

class Miscellaneous:
    @debug
    def get_proxies(self) -> dict:
        try:
            if config['dev'].get('Proxyless', False):
                return None
                
            with open('input/proxies.txt') as f:
                proxies = [line.strip() for line in f if line.strip()]
                if not proxies:
                    log.warning("No proxies available. Running in proxyless mode.")
                    return None
                
                proxy_choice = random.choice(proxies)
                proxy_dict = {
                    "http": f"http://{proxy_choice}",
                    "https": f"http://{proxy_choice}"
                }
                debug(f"Using proxy: {proxy_choice}")
                return proxy_dict
        except FileNotFoundError:
            log.failure("Proxy file not found. Running in proxyless mode.")
            return None

    @debug
    def randomize_user_agent(self) -> tuple[str, str, str, str]:
        platforms = {
            "Windows NT 10.0; Win64; x64": "Windows",
            "Windows NT 10.0; WOW64": "Windows",
            "Macintosh; Intel Mac OS X 10_15_7": "Mac OS X",
            "Macintosh; Intel Mac OS X 11_2_3": "Mac OS X",
            "X11; Linux x86_64": "Linux",
            "X11; Linux i686": "Linux",
            "X11; Ubuntu; Linux x86_64": "Linux",
        }

        browsers = [
            ("Chrome", f"{random.randint(128, 140)}.0.{random.randint(1000, 4999)}.0"),
            ("Firefox", f"{random.randint(80, 115)}.0"),
            ("Safari", f"{random.randint(13, 16)}.{random.randint(0, 3)}"),
            ("Edge", f"{random.randint(90, 140)}.0.{random.randint(1000, 4999)}.0"),
        ]

        webkit_version = f"{random.randint(500, 600)}.{random.randint(0, 99)}"
        platform_string = random.choice(list(platforms.keys()))
        platform_os = platforms[platform_string]
        browser_name, browser_version = random.choice(browsers)

        if browser_name == "Safari":
            user_agent = (
                f"Mozilla/5.0 ({platform_string}) AppleWebKit/{webkit_version} (KHTML, like Gecko) "
                f"Version/{browser_version} Safari/{webkit_version}"
            )
        elif browser_name == "Firefox":
            user_agent = f"Mozilla/5.0 ({platform_string}; rv:{browser_version}) Gecko/20100101 Firefox/{browser_version}"
        else: # Chrome or Edge
            user_agent = (
                f"Mozilla/5.0 ({platform_string}) AppleWebKit/{webkit_version} (KHTML, like Gecko) "
                f"{browser_name}/{browser_version} Safari/{webkit_version}"
            )

        return user_agent, browser_name, browser_version, platform_os

    def encode_public_key(self, pub_key: rsa.RSAPublicKey) -> str:
        return base64.b64encode(pub_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )).decode('utf-8')
    
    def generate_nonce_proof(self, encrypted_nonce_b64: str, priv_key: rsa.RSAPrivateKey) -> str:
        enc_nonce_bytes = base64.b64decode(encrypted_nonce_b64)
        
        dec_nonce = priv_key.decrypt(
            enc_nonce_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        proof_bytes = hashlib.sha256(dec_nonce).digest()
        proof_b64 = base64.urlsafe_b64encode(proof_bytes).rstrip(b"=").decode()
        
        return proof_b64
    
    def decrypt_data(self, encrypted_data_b64: str, priv_key: rsa.RSAPrivateKey) -> bytes | None:
        if not encrypted_data_b64:
            return None
        
        payload = base64.b64decode(encrypted_data_b64)
        return priv_key.decrypt(
            payload,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def parse_token_line(self, line: str) -> tuple[str, str | None, str]:
        parts = [p for p in line.strip().split(":") if p]
        if not parts:
            raise ValueError("Empty token line")

        for idx, part in enumerate(parts):
            if len(part) == 72:
                token = part
                identifier = ":".join(parts[:idx]) or None
                return line.strip(), identifier, token

        raise ValueError("No valid 72-character token found")

    
    class Title:
        def __init__(self) -> None:
            self.running = False
            self.total = 0

        def start_title_updates(self, start_time) -> None:
            self.running = True
            def updater():
                while self.running:
                    self.update_title(start_time)
                    time.sleep(0.5)
            threading.Thread(target=updater, daemon=True).start()

        def stop_title_updates(self) -> None:
            self.running = False

        def update_title(self, start_time) -> None: 
            try:
                elapsed_time = round(time.time() - start_time, 2)
                title = f'discord.cyberious.xyz | Total: {self.total} | Time Elapsed: {elapsed_time}s'

                sanitized_title = ''.join(c if c.isprintable() else '?' for c in title)
                ctypes.windll.kernel32.SetConsoleTitleW(sanitized_title)
            except Exception as e:
                log.failure(f"Failed to update console title: {e}")

        def increment_total(self):
            self.total += 1

class TokenChanger:
    def __init__(self, misc: Miscellaneous, proxy_dict: dict = None) -> None:
        self.misc = misc
        self.user_agent, self.browser_name, self.browser_version, self.os_name = self.misc.randomize_user_agent()

        self.session = tls_client.Session("chrome_131", random_tls_extension_order=True)
        self.session.headers = {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/json',
            'origin': 'https://discord.com',
            'referer': 'https://discord.com/channels/@me',
            'sec-ch-ua': f'"{self.browser_name}";v="{self.browser_version.split(".")[0]}", "Not_A Brand";v="99", "Chromium";v="{self.browser_version.split(".")[0]}"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': f'"{self.os_name}"',
            'user-agent': self.user_agent,
            'x-debug-options': 'bugReporterEnabled',
            'x-discord-locale': 'en-US',
            'x-discord-timezone': 'Asia/Tokyo',
            'x-super-properties': self.generate_super_propreties(
                self.user_agent, self.browser_name, self.browser_version, self.os_name
            )
        }

        self.session.proxies = proxy_dict

    @debug
    def generate_super_propreties(self, user_agent, browser_name, browser_version, os_name) -> str:
        payload = {
            "os": os_name,
            "browser": browser_name,
            "device": "",
            "system_locale": "en-US",
            "browser_user_agent": user_agent,
            "browser_version": browser_version,
            "os_version": "",
            "referrer": "",
            "referring_domain": "",
            "referrer_current": "",
            "referring_domain_current": "",
            "release_channel": "stable",
            "client_build_number": 380213, 
            "client_event_source": None
            }
        
        return base64.b64encode(json.dumps(payload).encode()).decode()
    
    @debug
    @retry_with_rate_limit()
    def create_handshake(self, token: str, fingerprint: str) -> bool:
        self.session.headers['authorization'] = token

        response = self.session.post(
            "https://discord.com/api/v9/users/@me/remote-auth", 
            json={'fingerprint': fingerprint},
        )

        debug_response(response)

        if response.status_code == 200:
            token = response.json().get('handshake_token')

            response =  self.session.post(
                "https://discord.com/api/v9/users/@me/remote-auth/finish", 
                json={'handshake_token': token}
            )

            debug_response(response)
            
            if response.status_code == 204:
                return True
            
        elif response.status_code == 401:
            return 401
        else:
            log.failure(f"Failed to create handshake: {response.text}, {response.status_code}")
        
        return False
    
    @debug
    @retry_with_rate_limit()
    def logout(self, token: str) -> bool:
        self.session.headers['authorization'] = token
     
        response = self.session.post(
            'https://discord.com/api/v9/auth/logout',
            json={'provider': None, 'voip_provider': None}
        )

        debug_response(response)

        if response.status_code == 204:
            return True
        else:
            log.failure(f"Failed to logout: {response.text}, {response.status_code}")
        
        return False
    
    @debug
    @retry_with_rate_limit()
    def clone_token(self, token: str) -> str | None:
        try:
            ws = websocket.create_connection(
                "wss://remote-auth-gateway.discord.gg/?v=2",
                header=[
                    f"Authorization: {token}",
                    "Origin: https://discord.com"
                ]
            )

            hello_payload = ws.recv()
            debug(f"Received Hello: {hello_payload}")

            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            public_key = private_key.public_key()
            encryption_key = self.misc.encode_public_key(public_key)
            
            ws.send(json.dumps({"op": "init", "encoded_public_key": encryption_key}))
            
            nonce_payload_str = ws.recv()
            debug(f"Received Nonce Payload: {nonce_payload_str}")
            nonce_payload = json.loads(nonce_payload_str)
            encrypted_nonce_b64 = nonce_payload.get("encrypted_nonce")

            if not encrypted_nonce_b64:
                log.failure("Failed to receive encrypted nonce.")
                ws.close()
                return None

            nonce_proof = self.misc.generate_nonce_proof(encrypted_nonce_b64, private_key)
            
            ws.send(json.dumps({"op": "nonce_proof", "proof": nonce_proof}))
            
            fingerprint_payload_str = ws.recv()
            debug(f"Received Fingerprint Payload: {fingerprint_payload_str}")
            fingerprint_payload = json.loads(fingerprint_payload_str)
            fingerprint = fingerprint_payload.get("fingerprint")
            
            if fingerprint:
                handshake_success = self.create_handshake(token, fingerprint)
                if not handshake_success:
                    log.failure("Handshake creation failed after receiving fingerprint.")
                    ws.close()
                    return None
                elif handshake_success == 401:
                    return 401
                
                user_payload_str = ws.recv()
                debug(f"Received User Payload: {user_payload_str}")
                user_payload = json.loads(user_payload_str)
                encrypted_user_payload = user_payload.get("encrypted_user_payload")
                
                if encrypted_user_payload:
                  
                    decrypted_user_info = self.misc.decrypt_data(encrypted_user_payload, private_key)
                    debug(f"Decrypted User Info: {decrypted_user_info}")
                else:
                    log.warning("Did not receive encrypted user payload (might be okay).")
                
                ticket_payload_str = ws.recv()
                debug(f"Received Ticket Payload: {ticket_payload_str}")
                ticket_payload = json.loads(ticket_payload_str)
                ticket = ticket_payload.get("ticket")
                
                ws.close() #

                if ticket:
                    # Handle remote auth login with rate limiting
                    for attempt in range(5):
                        response = self.session.post(
                            "https://discord.com/api/v9/users/@me/remote-auth/login", 
                            json={"ticket": ticket}
                        )

                        debug_response(response)
                        
                        if response.status_code == 200:
                            encrypted_token_b64 = response.json().get("encrypted_token")
                            if encrypted_token_b64:
                                 new_token_bytes = self.misc.decrypt_data(encrypted_token_b64, private_key)
                                 if new_token_bytes:
                                     return new_token_bytes.decode('utf-8')
                                 else:
                                     log.failure("Failed to decrypt the new token.")
                            else:
                                log.failure("Response did not contain 'encrypted_token'.")
                            break
                        elif response.status_code == 429:  # Rate limited
                            if attempt < 4:  # Max 5 attempts (0-4)
                                # Try to get retry-after from headers or response
                                retry_after = response.headers.get('retry-after')
                                wait_time = 1.0
                                
                                if retry_after:
                                    try:
                                        wait_time = float(retry_after)
                                    except ValueError:
                                        pass
                                else:
                                    try:
                                        response_data = response.json()
                                        if 'retry_after' in response_data:
                                            wait_time = response_data['retry_after']
                                    except:
                                        pass
                                
                                log.warning(f"Rate limited on remote auth login, waiting {wait_time}s")
                                time.sleep(wait_time)
                                continue
                            else:
                                log.failure("Max retries reached for remote auth login due to rate limiting")
                                break
                        else:
                             log.failure(f"Failed remote auth login request: {response.status_code} - {response.text}")
                             break

                else:
                    log.failure("Failed to receive ticket.")
            else:
                log.failure("Failed to receive fingerprint.")
            
            ws.close() 
            return None
        except websocket.WebSocketException as e:
            log.failure(f"WebSocket error: {e}")
            return None
        except json.JSONDecodeError as e:
            log.failure(f"Failed to decode JSON from websocket: {e}")
            return None
        except Exception as e:
            if "Ciphertext length must be equal to key size" in str(e):
                 log.failure(f"RSA Decryption error: {e}. Check received data format.")
            else:
                 log.failure(f"An unknown error occurred in clone_token: {e}")
            try:
                if ws and ws.connected:
                    ws.close()
            except: 
                pass
            return None

def change_password(original_line: str, misc: Miscellaneous, file_lock: threading.Lock) -> bool:
    start_time = time.time()
    max_retries = 5
    
    for attempt in range(max_retries + 1):
        try:
            # Parse the token from the line (email:pass:token or just token)
            raw_line, _, token = misc.parse_token_line(original_line)
            
            # Create a new TokenChanger instance for each attempt to get fresh proxies/session
            proxies = misc.get_proxies()
            tokenChanger = TokenChanger(misc, proxies)

            new_token = tokenChanger.clone_token(token)

            if new_token == 401:
                log.failure(f"Invalid token: {token[:30]}...")
                with file_lock:
                    with open(f"{output_folder}/invalid.txt", "a", encoding="utf-8") as f:
                        f.write(f"{raw_line}\n")
                return False

            elif new_token:
                if tokenChanger.logout(token):
                    log.message("Discord", f"Token successfully updated: {new_token[:30]}...", start_time, time.time())

                    # Replace only the old token in the line with the new token
                    new_line = raw_line.replace(token, new_token, 1)

                    with file_lock:
                        with open(f"{output_folder}/tokens.txt", "a", encoding="utf-8") as f:
                            f.write(f"{new_line}\n")

                        # Remove old line from input
                        with open("input/tokens.txt", "r", encoding="utf-8") as f:
                            tokens = [line.strip() for line in f if line.strip()]
                        if raw_line in tokens:
                            tokens.remove(raw_line)
                            with open("input/tokens.txt", "w", encoding="utf-8") as f:
                                f.write('\n'.join(tokens) + '\n')

                    return True
                else:
                    if attempt < max_retries:
                        log.warning(f"Failed to logout, retrying...")
                        time.sleep(1.0)
                        continue
                    else:
                        log.failure(f"Failed to logout original token after {max_retries} retries: {token[:30]}...")
                        with file_lock:
                            with open(f"{output_folder}/failed.txt", "a", encoding="utf-8") as f:
                                f.write(f"{raw_line}\n")
            else:
                if attempt < max_retries:
                    log.warning(f"Failed to clone token, retrying...")
                    time.sleep(1.0)
                    continue
                else:
                    log.failure(f"Failed to clone token after {max_retries} retries: {token[:30]}...")
                    with file_lock:
                        with open(f"{output_folder}/failed.txt", "a", encoding="utf-8") as f:
                            f.write(f"{raw_line}\n")

        except Exception as e:
            if attempt < max_retries:
                log.warning(f"Error updating token, retrying...: {str(e)[:100]}...")
                time.sleep(1.0)
                continue
            else:
                log.failure(f"Error updating token after {max_retries} retries in line: {original_line[:30]}... | {e}")
                with file_lock:
                    with open(f"{output_folder}/failed.txt", "a", encoding="utf-8") as f:
                        f.write(f"{raw_line}\n")

    return False

def main() -> None:
    try:
        start_time = time.time()

        # Initialize classes
        misc = Miscellaneous()
        banner = Home("Passwordless Token Changer", align="center", credits="discord.cyberious.xyz")
        banner.display()

        # Read token lines
        with open("input/tokens.txt", 'r', encoding="utf-8") as f:
            raw_lines = [line.strip() for line in f if line.strip()]

        if not raw_lines:
            log.warning("Input token file is empty. Exiting.")
            return

        # Parse valid token lines
        parsed_lines = []
        for line in raw_lines:
            try:
                misc.parse_token_line(line)  # Validate
                parsed_lines.append(line)
            except ValueError as e:
                log.warning(f"Skipping line: {line[:30]}... | Reason: {e}")

        if not parsed_lines:
            log.warning("No valid tokens found in input. Exiting.")
            return

        thread_count = config['dev'].get('Threads', 1)
        file_lock = threading.Lock()

        # Start title updates
        title_updater = misc.Title()
        title_updater.start_title_updates(start_time)

        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            futures_map = {
                executor.submit(change_password, line, misc, file_lock): line
                for line in parsed_lines
            }

            for future in as_completed(futures_map):
                line = futures_map[future]
                try:
                    if future.result():
                        title_updater.increment_total()
                except Exception as e:
                    log.failure(f"Thread error processing line: {line[:30]}... | {e}")
        
        log.message("Process completed", "All tokens processed. Check output files for results. Please press any key to exit.", start_time, time.time())
        input("")
        
        # Open the output folder after user presses enter
        try:
            output_path = os.path.abspath(output_folder)
            subprocess.run(['explorer', output_path], check=True)
            log.info(f"Opened output folder: {output_path}")
        except Exception as e:
            log.warning(f"Failed to open output folder: {e}")

        title_updater.stop_title_updates()

    except KeyboardInterrupt:
        log.info("Process interrupted by user. Exiting...")
    except Exception as e:
        log.failure(f"An unexpected error occurred in main: {e}")

if __name__ == "__main__":
    main()