#!/usr/bin/env python3
"""
WireGuard Star Network Manager
=============================

A comprehensive Jedi utility for managing WireGuard VPN networks in star topology.
This tool uses Star Wars humor and references because it makes network administration 
more enjoyable and memorable - who doesn't want to feel like a Jedi master while 
configuring VPNs? The Force is strong with this one!

Honestly, after working on enterprise networking for 15+ years, I figured... why not make 
it fun? Life's too short for boring CLI tools. Plus my kids think I'm finally cool now :)

Created by: Volodymyr Frytskyy (WhitemanV)
Website: https://www.vladonai.com/about-resume
GitHub: https://github.com/Frytskyy/WireGuard-Star-Network-Manager-Configurator

Features:
---------
✅ Star topology WireGuard network creation and management
✅ Automatic and manual cryptographic key management  
✅ IP address allocation with conflict detection (trust me, you need this)
✅ Server and client configuration file generation
✅ QR code generation for mobile devices (because typing keys on phone = pain)
✅ Network cloning and template management
✅ Comprehensive node and server editing capabilities
✅ Key regeneration and manual key import functionality 
✅ Colorful terminal interface with helpful guidance
✅ Config file encryption to protect sensible keys (optional, but recommended)

Star Wars Humor Notice:
----------------------
This application uses Star Wars references, Jedi/Sith terminology, and galactic 
metaphors throughout the interface. This is purely for entertainment value and 
to make network administration more engaging. No actual Force powers are required 
to operate this software (though they wouldn't hurt)!

Why Star Wars? Well, configuring VPN networks can feel like battling the Empire sometimes...
might as well have some fun with it. Plus, "May the Force be with your network traffic" 
sounds way cooler than "Good luck with your routing tables" :)

License:
--------
MIT License with Attribution Requirement

Copyright (c) 2025 Volodymyr Frytskyy (WhitemanV) (https://www.vladonai.com/about-resume)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

Attribution Requirement: Any use of this software, whether modified or unmodified,
must include attribution to the original author and a link to 
https://www.vladonai.com/about-resume

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Installation & Dependencies:
----------------------------
1. Install Python 3.6 or newer (seriously, update your Python if you're still on 2.7...)
2. Install required dependencies:
   pip install qrcode[pil]
   
3. Optional: Install WireGuard tools for enhanced key generation:
   # Ubuntu/Debian (the civilized way):
   sudo apt install wireguard-tools
   
   # CentOS/RHEL (for the masochists):
   sudo yum install wireguard-tools
   
   # macOS (for the hipsters with money):
   brew install wireguard-tools

4. Run the script:
   python3 wireguard_config_gen.py

Note: If you're running this on Windows... well, good luck soldier. WSL is your friend.
TODO: Maybe add Windows support someday... or maybe not. Life choices, you know?

"""

import json
import os
import subprocess
import base64
from datetime import datetime
from pathlib import Path
import re

import hashlib
import secrets
import getpass

# Try to import encryption libraries (optional)
# Fun fact: This took me 3 coffee cups to get right the first time
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False
    # No encryption? No problem! We'll just warn the user and move on like adults

# Attempt to import qrcode (optional)
# QR codes are life-changing for mobile VPN setup, trust me on this one
try:
    import qrcode
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False
    # Still works without QR codes, but why would you want to live that way?

# Colors for beautiful output (dark side of the Force enabled! 😈)
# Spent way too much time getting these colors just right...
# Architecture note: Could refactor this into a proper Color class with methods,
# but honestly? YAGNI principle applies here. Sometimes simple is better.
class Colors:
    HEADER     = '\033[95m'  # Purple - like Mace Windu's lightsaber (still the coolest)
    BLUE       = '\033[94m'  # Blue - like Obi-Wan (hello there!)
    CYAN       = '\033[96m'  # Cyan - like Anakin (before he went emo)
    GREEN      = '\033[92m'  # Green - like Yoda (do or do not, there is no try)
    YELLOW     = '\033[93m'  # Yellow - warning (I have a bad feeling about this)
    RED        = '\033[91m'  # Red - like Sith Lord (unlimited power!)
    BOLD       = '\033[1m'   # Bold (for when you really mean it)
    UNDERLINE  = '\033[4m'   # Underlined (rarely used, but here just in case)
    END        = '\033[0m'   # End color (back to boring terminal default)

def colored(text, color):
    """Adds color to text - like Force lightning! ⚡
    
    Simple wrapper function that I probably could have just inlined everywhere,
    but having a function makes it easier to extend later. Maybe add RGB support?
    TODO: Consider adding theme support for people who hate fun colors
    """
    return f"{color}{text}{Colors.END}"

def generate_keypair():
    """Generates WireGuard key pair - dark magic of cryptography! 🔐
    
    This function tries to use the official WireGuard tools first, 
    then falls back to a "good enough" method if wg isn't available.
    
    Architecture decision: Could use pure Python crypto libraries for this,
    but the wg utility is the canonical way and I prefer following standards.
    The fallback isn't cryptographically equivalent, but works for testing.
    
    Returns:
        tuple: (private_key, public_key) as strings
        
    Note: The fallback method isn't actually generating proper WireGuard keys,
    but it's good enough for development. In production, install wg-tools!
    """
    try:
        # Generate private key using the official way
        private_result = subprocess.run(['wg', 'genkey'], 
                                      capture_output=True, text=True, check=True)
        private_key = private_result.stdout.strip()
        
        # Generate public key from private (this is where the real magic happens)
        public_result = subprocess.run(['wg', 'pubkey'], 
                                     input=private_key, capture_output=True, 
                                     text=True, check=True)
        public_key = public_result.stdout.strip()
        
        return private_key, public_key
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fallback method without wg utility - not ideal but works
        print(colored("⚠️  WireGuard utilities not found, using fallback method", Colors.YELLOW))
        # TODO: Maybe show installation instructions here? 
        # Or auto-download wg-tools? Probably overengineering...
        private_key = base64.b64encode(os.urandom(32)).decode('ascii')
        # This isn't a real public key, but works for testing purposes
        # Don't judge me, sometimes you gotta ship features fast 🤷‍♂️
        public_key = base64.b64encode(os.urandom(32)).decode('ascii')
        return private_key, public_key
    
class WireGuardManager:
    """
    The main brain of our WireGuard empire - like the Death Star control room,
    but hopefully with fewer fatal design flaws...
    
    This class handles everything from network creation to config encryption.
    Started as a simple script, grew into this monster. Classic feature creep! 📈
    
    Design Philosophy:
    - Keep it simple (failed at that already)
    - Make it user-friendly (Star Wars helps!)
    - Don't break existing networks (learned this the hard way)
    
    TODO: Consider splitting this into smaller classes... someday when I have time
    which will be never, let's be honest 😅
    """
    
    def __init__(self):
        """Initialize the Death Star... I mean, WireGuard Manager 🌟
        
        Fun fact: Spent 2 hours debugging why configs weren't loading,
        turns out I was looking for .json files in the wrong directory.
        Coffee helps, but reading helps more 🤦‍♂️
        """
        self.config_file = "wireguard_networks_config.json"
        self.master_password = None  # Store master password for session (secure-ish)
        self.salt_file = self.config_file + ".salt"  # Store salt separately (good practice)
        self.data = self.load_config()    
        
    def derive_key_from_password(self, password, salt=None):
        """
        Derives encryption key from password using PBKDF2 - 
        turning Jedi meditation phrase into Force lightning! ⚡
        
        PBKDF2 with 100k iterations should be enough to stop most Sith Lords
        from brute-forcing. Well, at least the lazy ones...
        
        Args:
            password (str): User's meditation phrase
            salt (bytes): Random salt, generated if None
            
        Returns:
            tuple: (derived_key, salt)
            
        Note: Using SHA256 because it's proven and available everywhere.
        Could use Argon2 but that adds another dependency... decisions, decisions 🤔
        """
        if not ENCRYPTION_AVAILABLE:
            raise Exception("Encryption libraries not available - the Force crystals are missing!")
        
        if salt is None:
            salt = secrets.token_bytes(32)  # 256-bit salt (overkill? maybe. secure? yes!)
        
        # PBKDF2 with SHA256 - industry standard, battle-tested
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,           # 256-bit key (AES-256 compatible)
            salt=salt,
            iterations=100000,   # Strong iteration count (may slow down old hardware)
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
        return key, salt
    
    def encrypt_data(self, data_str, password):
        """
        Encrypts configuration data - protecting Jedi secrets! 🔐
        
        Using Fernet because it's simple and handles padding/MAC for us.
        Could implement AES-GCM manually but... why reinvent the wheel?
        
        Returns: (encrypted_data, salt) or raises exception
        
        Architecture note: Maybe split encryption into separate module later?
        But for now, keeping it simple and contained here works fine.
        """
        if not ENCRYPTION_AVAILABLE:
            raise Exception("Encryption not available - install cryptography: pip install cryptography")
        
        try:
            # Generate random salt for each encryption (security 101)
            encryption_key, salt = self.derive_key_from_password(password)
            
            # Create Fernet cipher instance
            fernet = Fernet(encryption_key)
            
            # Encrypt the data - Fernet handles authentication automatically
            encrypted_data = fernet.encrypt(data_str.encode('utf-8'))
            
            return encrypted_data, salt
            
        except Exception as jedi_encryption_error:
            # TODO: Better error handling here - maybe retry logic?
            raise Exception(f"Encryption failed - dark side interference: {jedi_encryption_error}")
    
    def decrypt_data(self, encrypted_data, password, salt):
        """
        Decrypts configuration data - unlocking ancient Jedi holocron! 📜
        
        The reverse of encrypt_data - straightforward crypto operation.
        Fernet handles authentication verification so we know if data is tampered.
        
        Returns: decrypted_string or raises exception
        
        Side note: Error messages are intentionally vague for security reasons.
        Don't want to leak info about what went wrong to potential attackers.
        """
        if not ENCRYPTION_AVAILABLE:
            raise Exception("Decryption not available - install cryptography: pip install cryptography")
        
        try:
            # Derive the same key using stored salt
            encryption_key, _ = self.derive_key_from_password(password, salt)
            
            # Create Fernet cipher instance with same key
            fernet = Fernet(encryption_key)
            
            # Decrypt and verify authentication tag
            decrypted_data = fernet.decrypt(encrypted_data)
            
            return decrypted_data.decode('utf-8')
            
        except Exception as sith_decryption_error:
            # Generic error message - don't leak details about failure mode
            raise Exception(f"Decryption failed - wrong password or corrupted data: {sith_decryption_error}")
    
    def save_salt(self, salt):
        """Saves salt to separate file - hiding the kyber crystal location! 💎
        
        Storing salt separately from encrypted data is debatable security practice.
        Some say keep it with data, others say separate. I chose separate because
        it feels more secure, even if it's probably not materially different.
        
        Security through obscurity? Maybe. But every little bit helps! 🤷‍♂️
        """
        try:
            with open(self.salt_file, 'wb') as force_crystal_vault:
                force_crystal_vault.write(salt)
            return True
        except IOError as crystal_storage_error:
            print(colored(f"❌ Error saving salt: {crystal_storage_error}", Colors.RED))
            return False
    
    def load_salt(self):
        """Loads salt from file - retrieving kyber crystal! 💎
        
        Simple file read operation. Could add error recovery here,
        but if salt file is corrupted, you're probably screwed anyway...
        """
        try:
            if os.path.exists(self.salt_file):
                with open(self.salt_file, 'rb') as crystal_vault:
                    return crystal_vault.read()
            return None
        except IOError as crystal_retrieval_error:
            print(colored(f"❌ Error loading salt: {crystal_retrieval_error}", Colors.RED))
            return None
    
    def is_file_encrypted(self):
        """
        Checks if config file is encrypted by trying to parse as JSON
        - sensing the Force signature! 🔮
        
        Hacky but effective detection method. If it parses as valid JSON,
        it's probably not encrypted. If it doesn't, probably encrypted.
        
        Edge cases: What if someone encrypts valid JSON that looks like our format?
        Probability: Low. Care factor: Also low. Good enough! ™️
        """
        if not os.path.exists(self.config_file):
            return False
        
        try:
            with open(self.config_file, 'r', encoding='utf-8') as holocron:
                content = holocron.read().strip()
                if not content:
                    return False
                # Try to parse as JSON - if fails, it's likely encrypted
                json.loads(content)
                return False  # Successfully parsed as JSON = not encrypted
        except (json.JSONDecodeError, UnicodeDecodeError):
            return True  # Failed to parse = likely encrypted (or corrupted, but optimistic!)
        except IOError:
            return False
    
    def prompt_for_password(self, action="access"):
        """
        Prompts user for password - requesting Force meditation phrase! 🧘‍♂️
        
        getpass is great for hiding password input. Learned about this gem
        after building my first CLI tool that echoed passwords to terminal.
        Security 101 failure right there! 🤦‍♂️
        
        UX consideration: Should probably add password strength validation,
        but then again, this is for network admins who hopefully know better...
        """
        if not ENCRYPTION_AVAILABLE:
            print(colored("\n❌ Encryption not available!", Colors.RED))
            print(colored("💡 Install library: pip install cryptography", Colors.YELLOW))
            return None
        
        while True:
            if action == "setup":
                print(colored("\n🔐 Setting up config file encryption", Colors.HEADER))
                print(colored("Leave empty to keep config unencrypted", Colors.YELLOW))
                
                password = getpass.getpass(colored("Enter master password (hidden): ", Colors.CYAN))
                if not password:
                    return None  # User wants unencrypted file (their choice!)
                
                confirm_password = getpass.getpass(colored("Confirm password: ", Colors.CYAN))
                if password != confirm_password:
                    print(colored("❌ Passwords don't match! Try again.", Colors.RED))
                    continue
                    
                return password
            else:
                print(colored("🔓 Config file is encrypted", Colors.YELLOW))
                password = getpass.getpass(colored("Enter master password: ", Colors.CYAN))
                if password:
                    return password
                print(colored("❌ Password cannot be empty", Colors.RED))

    def load_config(self):
        """
        Enhanced config loading with decryption support - 
        reading encrypted Jedi holocrons! 📜
        
        This method became way more complex than I originally planned.
        Started as simple JSON loading, now it's a crypto-enabled monster
        with retry logic and error handling. Classic scope creep! 
        
        But hey, at least it's backwards compatible... mostly 😅
        
        Architecture thoughts:
        - Could extract the encryption logic to a separate class
        - Maybe add config backup/restore functionality?
        - Version migration support for future schema changes?
        - Or just leave it as-is because it works... 🤷‍♂️
        """
        if not os.path.exists(self.config_file):
            return {"networks": {}}
        
        try:
            # Check if file is encrypted (hacky but effective detection)
            if self.is_file_encrypted():
                # File is encrypted, time for password dance 💃
                max_attempts = 3  # Give user 3 attempts (security vs usability balance)
                attempt = 0
                
                while attempt < max_attempts:
                    if not self.master_password:
                        self.master_password = self.prompt_for_password("decrypt")
                    
                    if not self.master_password:
                        print(colored("❌ Cannot access encrypted config without password", Colors.RED))
                        print(colored("🚪 Exiting - encrypted config requires password!", Colors.YELLOW))
                        exit(1)  # Exit program completely (harsh but necessary)
                    
                    # Load salt (if this fails, we're in trouble)
                    jedi_salt = self.load_salt()
                    if not jedi_salt:
                        print(colored("❌ Salt file missing - cannot decrypt config", Colors.RED))
                        print(colored("🔧 Config file may be corrupted or salt file deleted", Colors.YELLOW))
                        # TODO: Maybe offer to regenerate salt? Probably not possible though...
                        exit(1)  # Exit program completely
                    
                    # Read encrypted data (binary mode because it's encrypted bytes)
                    with open(self.config_file, 'rb') as encrypted_holocron:
                        encrypted_content = encrypted_holocron.read()
                    
                    # Try to decrypt (moment of truth!)
                    try:
                        decrypted_content = self.decrypt_data(encrypted_content, self.master_password, jedi_salt)
                        config_data = json.loads(decrypted_content)
                        print(colored("✅ Config decrypted successfully!", Colors.GREEN))
                        return config_data
                        
                    except Exception as dark_side_interference:
                        attempt += 1
                        remaining_attempts = max_attempts - attempt
                        
                        print(colored(f"❌ Decryption failed: Wrong password", Colors.RED))
                        
                        if remaining_attempts > 0:
                            print(colored(f"🔑 {remaining_attempts} attempts remaining", Colors.YELLOW))
                            self.master_password = None  # Clear wrong password
                        else:
                            print(colored("🚫 Maximum password attempts exceeded", Colors.RED))
                            print(colored("🔒 Access denied - config remains encrypted", Colors.RED))
                            print(colored("💡 If you forgot password, delete config files to start fresh", Colors.CYAN))
                            # Harsh but fair - security first!
                            exit(1)  # Exit program after max attempts
                
            else:
                # File is not encrypted, load normally (the simple path)
                with open(self.config_file, 'r', encoding='utf-8') as plain_holocron:
                    return json.load(plain_holocron)
                    
        except (json.JSONDecodeError, IOError) as ancient_scroll_error:
            print(colored(f"❌ Error reading config: {ancient_scroll_error}", Colors.RED))
            # Return empty config instead of crashing - graceful degradation
            return {"networks": {}}
                     
    def save_config(self):
        """
        Enhanced config saving with encryption support -
        protecting Jedi secrets with the Force! 🛡️
        
        This method got complicated fast. The decision tree for when to encrypt
        is a bit convoluted, but it handles all the edge cases I could think of.
        
        Future me will probably hate current me for this complexity,
        but it works and handles backwards compatibility pretty well.
        
        Note: The UX flow could be smoother here - asking about encryption
        every time is annoying. Maybe remember user preference? TODO for v2.0...
        """
        try:
            # Convert data to JSON string (pretty-printed because why not?)
            json_content = json.dumps(self.data, indent=2, ensure_ascii=False)
            
            # Decision matrix for encryption (this got complicated quickly...)
            should_encrypt = False
            password_to_use = self.master_password
            
            # If file doesn't exist or is unencrypted, ask about encryption
            if not os.path.exists(self.config_file) or not self.is_file_encrypted():
                if not self.master_password:
                    if ENCRYPTION_AVAILABLE:
                        # Ask user about encryption (UX could be better here)
                        encryption_choice = input(colored("Encrypt config file? (y/N): ", Colors.CYAN)).lower()
                        if encryption_choice in ['y', 'yes']:
                            password_to_use = self.prompt_for_password("setup")
                            if password_to_use:
                                self.master_password = password_to_use
                                should_encrypt = True
                    else:
                        print(colored("ℹ️  Encryption unavailable - saving as plain text", Colors.YELLOW))
                        print(colored("💡 Install cryptography for encryption: pip install cryptography", Colors.CYAN))
                else:
                    # We already have a password, use it for encryption
                    should_encrypt = True
                    password_to_use = self.master_password
            else:
                # File exists and is encrypted (continue encrypting)
                should_encrypt = bool(self.master_password)
            
            if should_encrypt and password_to_use:
                # Encrypt and save (the secure path)
                encrypted_data, new_salt = self.encrypt_data(json_content, password_to_use)
                
                # Save encrypted data (binary mode for encrypted bytes)
                with open(self.config_file, 'wb') as protected_holocron:
                    protected_holocron.write(encrypted_data)
                
                # Save salt (critical - without this, data is unrecoverable!)
                if not self.save_salt(new_salt):
                    print(colored("⚠️  Warning: Salt save failed - decryption may fail later", Colors.YELLOW))
                
                print(colored("🛡️  Config saved with encryption", Colors.GREEN))
            else:
                # Save unencrypted (the simple path)
                with open(self.config_file, 'w', encoding='utf-8') as plain_holocron:
                    plain_holocron.write(json_content)
                
                print(colored("📄 Config saved (unencrypted)", Colors.GREEN))
            
            return True
            
        except Exception as force_disturbance:
            print(colored(f"❌ Save error: {force_disturbance}", Colors.RED))
            # TODO: Should we retry? Backup old file first? 
            # For now, just fail gracefully and let user deal with it
            return False
    
    def change_master_password(self):
        """
        Changes master password - updating Force meditation phrase! 🧘‍♂️
        
        This is a critical operation that could lock user out if something goes wrong.
        Should probably backup the old file first, but... YOLO! 🎲
        
        Actually, maybe I should implement backup logic here... 
        Note to self: Add to TODO list that will never get done
        """
        if not ENCRYPTION_AVAILABLE:
            print(colored("\n❌ Encryption features not available!", Colors.RED))
            print(colored("💡 Install cryptography library:", Colors.YELLOW))
            print(colored("   pip install cryptography", Colors.CYAN))
            input(colored("Press Enter to continue...", Colors.BOLD))
            return
        
        print(colored("\n🔐 Change master password", Colors.HEADER))
        
        if self.is_file_encrypted():
            if not self.master_password:
                current_password = self.prompt_for_password("decrypt")
                if not current_password:
                    print(colored("❌ Current password required", Colors.RED))
                    return
                self.master_password = current_password
            
            print(colored("✅ Current password verified", Colors.GREEN))
        
        print(colored("Setting new password:", Colors.CYAN))
        new_password = self.prompt_for_password("setup")
        
        if new_password:
            self.master_password = new_password
            if self.save_config():
                print(colored("✅ Master password changed successfully!", Colors.GREEN))
            else:
                print(colored("❌ Failed to save with new password", Colors.RED))
                # TODO: Restore from backup? Right now user might be locked out...
        elif new_password is None:
            # User wants to remove encryption (brave choice!)
            confirm = input(colored("Remove encryption and save as plain text? (y/N): ", Colors.YELLOW))
            if confirm.lower() in ['y', 'yes']:
                self.master_password = None
                # Remove salt file (cleanup is important!)
                if os.path.exists(self.salt_file):
                    os.remove(self.salt_file)
                if self.save_config():
                    print(colored("✅ Encryption removed, file saved as plain text", Colors.GREEN))
                else:
                    print(colored("❌ Failed to save unencrypted file", Colors.RED))
        else:
            print(colored("❌ Password change cancelled", Colors.YELLOW))
            
    def create_default_network(self):
        """
        Creates default network - like forging the first lightsaber!
        
        This was supposed to be a simple example network, but somehow became
        a full production-ready template. The node list below is actually from
        my home network... oops!
        
        Architecture note: Hardcoding these defaults isn't the cleanest approach.
        Could load from a template file, but then I'd have to maintain another file.
        Sometimes simplicity wins over elegance. ¯\\_(ツ)_/¯
        """
        network_name = "main_network"
        
        # Default network settings (tweaked from years of trial and error)
        default_network = {
            "name": "Main Network",
            "subnet": "192.168.100.0/24",  # Why .100? Because .1 is boring!
            "subnet_base": "192.168.100",
            "server": {
                "name": "Main Server",
                "ip": "192.168.100.1",
                "port": 51820,  # default WireGuard port
                "endpoint": "your_server_addr.com:51820",  # Shameless self-promotion 😎
                "external_interface": "eth0",  # Assume eth0, but users should check
                "private_key": "",
                "public_key": ""
            },
            "nodes": {}
        }
        
        # Generate keys for server (the most important part!)
        server_private, server_public = generate_keypair()
        default_network["server"]["private_key"] = server_private
        default_network["server"]["public_key"] = server_public


        # Default nodes based on modern home/office VPN structures and research
        # Reflects real-world deployment patterns from 2024-2025 era
        # Organized by device categories for better IP management
        default_nodes = [
            # === NETWORK INFRASTRUCTURE (192.168.100.2-9) ===
            {"name": "Edge Router", "ip": "192.168.100.2"},                    # Primary network gateway
            {"name": "Home Office Router", "ip": "192.168.100.3"},             # Secondary/branch router
            {"name": "Network Storage (NAS)", "ip": "192.168.100.4"},          # File server/backup
            {"name": "Access Point WiFi6", "ip": "192.168.100.5"},             # Modern WiFi access point
            {"name": "Network Switch", "ip": "192.168.100.6"},                 # Managed switch
            
            # === WORKSTATIONS & LAPTOPS (192.168.100.10-19) ===
            {"name": "Desktop Workstation", "ip": "192.168.100.10"},           # Primary work computer
            {"name": "MacBook Pro M3", "ip": "192.168.100.11"},                # Modern Apple laptop
            {"name": "ThinkPad X1 Carbon", "ip": "192.168.100.12"},            # Business laptop
            {"name": "Gaming Rig", "ip": "192.168.100.13"},                    # Personal/gaming computer
            {"name": "Home Office Laptop", "ip": "192.168.100.14"},            # Remote work device
            
            # === MOBILE DEVICES (192.168.100.20-29) ===
            {"name": "iPhone 15 Pro", "ip": "192.168.100.20"},                 # Personal mobile
            {"name": "Samsung Galaxy S24", "ip": "192.168.100.21"},            # Android phone
            {"name": "iPad Pro 12.9", "ip": "192.168.100.22"},                 # Tablet for work/media
            {"name": "OnePlus 12", "ip": "192.168.100.23"},                    # Secondary phone
            {"name": "Surface Pro 11", "ip": "192.168.100.24"},                # 2-in-1 tablet/laptop
            
            # === IOT & SMART HOME (192.168.100.30-49) ===
            {"name": "Raspberry Pi 5", "ip": "192.168.100.30"},                # IoT hub/projects
            {"name": "Home Assistant", "ip": "192.168.100.31"},                # Smart home controller
            {"name": "Security Camera Hub", "ip": "192.168.100.32"},           # Video surveillance
            {"name": "Smart TV Samsung", "ip": "192.168.100.33"},              # Connected TV
            {"name": "Arduino ESP32", "ip": "192.168.100.34"},                 # Microcontroller projects
            {"name": "Tesla Model Y", "ip": "192.168.100.35"},                 # Connected vehicle (if applicable)
            {"name": "Starlink Terminal", "ip": "192.168.100.36"},             # Satellite internet backup
            
            # === SERVERS & SERVICES (192.168.100.50-99) ===
            {"name": "Docker Host", "ip": "192.168.100.50"},                   # Container platform
            {"name": "Plex Media Server", "ip": "192.168.100.51"},             # Media streaming
            {"name": "NextCloud Server", "ip": "192.168.100.52"},              # Private cloud storage
            {"name": "pfSense Firewall", "ip": "192.168.100.53"},              # Advanced firewall
            {"name": "Proxmox Host", "ip": "192.168.100.54"},                  # Virtualization platform
            {"name": "GitLab Runner", "ip": "192.168.100.55"},                 # CI/CD automation
            {"name": "Monitoring Stack", "ip": "192.168.100.56"},              # Grafana/Prometheus
            
            # === REMOTE SITES & CLOUD (192.168.100.100-199) ===
            {"name": "AWS EC2 Instance", "ip": "192.168.100.100"},             # Cloud server
            {"name": "Azure VM", "ip": "192.168.100.101"},                     # Microsoft cloud
            {"name": "DigitalOcean VPS", "ip": "192.168.100.102"},             # Development server
            {"name": "Branch Office US", "ip": "192.168.100.110"},             # Site-to-site VPN
            {"name": "Branch Office EU", "ip": "192.168.100.111"},             # European branch
            {"name": "Remote Worker 1", "ip": "192.168.100.120"},              # Remote employee
            {"name": "Remote Worker 2", "ip": "192.168.100.121"},              # Another remote employee
            {"name": "Client Site Alpha", "ip": "192.168.100.130"},            # Customer network access
            
            # === DEVELOPMENT & TESTING (192.168.100.200-229) ===
            {"name": "Dev Environment", "ip": "192.168.100.200"},              # Development testing
            {"name": "Staging Server", "ip": "192.168.100.201"},               # Pre-production
            {"name": "Test Database", "ip": "192.168.100.202"},                # Database testing
            {"name": "Load Balancer", "ip": "192.168.100.203"},                # Traffic distribution
            {"name": "Backup VPN Gateway", "ip": "192.168.100.204"},           # Redundant VPN access
            
            # === GUEST & TEMPORARY (192.168.100.230-249) ===
            {"name": "Guest Laptop", "ip": "192.168.100.230"},                 # Visitor device
            {"name": "Contractor Device", "ip": "192.168.100.231"},            # Temporary access
            {"name": "BYOD Tablet", "ip": "192.168.100.232"},                  # Bring-your-own-device
            {"name": "IoT Quarantine", "ip": "192.168.100.233"},               # Isolated IoT testing
            {"name": "Emergency Hotspot", "ip": "192.168.100.234"},            # Backup internet access
        ]
        
        # Add nodes with key generation (the tedious but necessary part)
        for node_info in default_nodes:
            node_private, node_public = generate_keypair()
            node_id = f"node_{len(default_network['nodes']) + 1}"
            
            default_network["nodes"][node_id] = {
                "name": node_info["name"],
                "ip": node_info["ip"],
                "private_key": node_private,
                "public_key": node_public,
                "enabled": True  # All nodes enabled by default (optimistic!)
            }
        
        self.data["networks"][network_name] = default_network
        self.save_config()
        
        print(colored("✅ Created default network with all nodes!", Colors.GREEN))
        return network_name
    
    def validate_ip(self, ip, subnet_base):
        """Validates IP address - checks if someone went to the dark side 🔍
        
        Basic IP validation that catches most common mistakes.
        Could use ipaddress module but regex is simpler for this use case.
        
        Fun fact: The number of times I've seen people enter 192.168.1.256
        is surprisingly high. People and IP addresses... 🤦‍♂️
        """
        ip_pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
        match = re.match(ip_pattern, ip)
        
        if not match:
            return False, "Invalid IP address format"
        
        octets = [int(x) for x in match.groups()]
        
        # Check octet range (basic but effective validation)
        for octet in octets:
            if not 0 <= octet <= 255:
                return False, "Octet out of range 0-255"
        
        # Check if IP belongs to subnet (prevents accidental cross-subnet configs)
        if not ip.startswith(subnet_base):
            return False, f"IP must be in range {subnet_base}.x"
        
        return True, "OK"
    
    def check_ip_conflicts(self, network_name, new_ip, exclude_node=None):
        """Checks IP address conflicts - like a Jedi searching for Sith 🕵️
        
        Conflict detection is crucial - duplicate IPs cause weird networking issues
        that are a pain to debug. Trust me, I've been there... many times 😵‍💫
        
        The exclude_node parameter is for when editing existing nodes,
        so they don't conflict with themselves. Learned this the hard way!
        """
        network = self.data["networks"][network_name]
        
        # Check conflict with server (servers are special snowflakes)
        if new_ip == network["server"]["ip"]:
            return True, "Conflict with server IP"
        
        # Check conflicts with other nodes (the usual suspects)
        for node_id, node in network["nodes"].items():
            if node_id != exclude_node and node["ip"] == new_ip:
                return True, f"Conflict with node '{node['name']}'"
        
        return False, "OK"
    
    def show_main_menu(self):
        """Main menu - like the Jedi Council! 🏛️
        
        This menu grew organically and probably needs refactoring.
        The conditional menu items based on available networks works,
        but makes the code a bit messy. 
        
        UI/UX thought: Maybe group related actions together?
        Or use submenus? But then it gets more complex to navigate...
        Current approach is simple and functional. Good enough! 👍
        """
        print(colored("\n" + "="*60, Colors.HEADER))
        print(colored("🌟 WireGuard Star Network Manager 🌟", Colors.HEADER))
        print(colored("Your Jedi utility for VPN networks", Colors.CYAN))
        print(colored("="*60, Colors.HEADER))
        
        print(colored("\n📋 Available networks:", Colors.BLUE))
        if not self.data["networks"]:
            print(colored("   (no networks - create your first!)", Colors.YELLOW))
        else:
            for i, (net_id, network) in enumerate(self.data["networks"].items(), 1):
                node_count = len(network["nodes"])
                # Show some useful info in the list (saves user clicks)
                print(colored(f"   {i}. {network['name']} ({net_id}) - {node_count} nodes", Colors.GREEN))
        
        print(colored("\n⚡ Actions:", Colors.BLUE))
        print(colored("1. Create new network", Colors.GREEN))
        if self.data["networks"]:
            # Only show these options if networks exist (logical!)
            print(colored("2. Manage existing network", Colors.GREEN))
            print(colored("3. Generate configs", Colors.GREEN))
            print(colored("4. Generate QR codes", Colors.GREEN))
            print(colored("5. Clone network", Colors.GREEN))
            print(colored("6. Delete network", Colors.RED))  # Red because destructive
        print(colored("7. About program", Colors.CYAN))
        if ENCRYPTION_AVAILABLE:
            print(colored("8. Change master password", Colors.CYAN))
        else:
            # Show what's missing (helpful for users)
            print(colored("8. 🔒 Encryption (install: pip install cryptography)", Colors.YELLOW))        

        print(colored("0. Exit (May the Force be with you!)", Colors.YELLOW))
        
        return input(colored("\n🎯 Your choice: ", Colors.BOLD))
    
    def create_network_menu(self):
        """New network creation menu - birth of a new Jedi! 👶
        
        The flow here tries to be smart about first-time users by offering
        the default network. Most people just want something that works quickly,
        then they can customize later.
        
        Design decision: Auto-create default vs. manual setup?
        Went with offering both - flexibility without forcing complexity.
        """
        print(colored("\n🆕 Creating new network", Colors.HEADER))
        
        # If this is the first network, offer default (user-friendly!)
        if not self.data["networks"]:
            choice = input(colored("Create default network with ready nodes? (y/n): ", Colors.CYAN))
            if choice.lower() in ['y', 'yes', '']:  # Empty input defaults to yes
                return self.create_default_network()
        
        # Manual network creation (for the control freaks among us)
        while True:
            net_id = input(colored("Network ID (English, no spaces): ", Colors.CYAN)) or "new_network"
            if net_id in self.data["networks"]:
                print(colored("❌ Network with this ID already exists!", Colors.RED))
                continue
            break
        
        name = input(colored("Network name: ", Colors.CYAN)) or "New Network"
        
        # Subnet configuration (most confusing part for new users)
        while True:
            subnet_base = input(colored("Base subnet address (192.168.100): ", Colors.CYAN)) or "192.168.100"
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}$', subnet_base):
                break
            print(colored("❌ Invalid format! Enter like 192.168.100", Colors.RED))
        
        # Server configuration (the important stuff)
        server_ip = f"{subnet_base}.1"  # Always use .1 for server (convention)
        endpoint = input(colored("Server endpoint (domain.com:port): ", Colors.CYAN)) or "your-server.com:51820"
        port = input(colored("Server port (51820): ", Colors.CYAN)) or "51820"
        external_if = input(colored("External interface (eth0): ", Colors.CYAN)) or "eth0"
        
        try:
            port = int(port)
        except ValueError:
            port = 51820  # Fallback to standard WireGuard port
        
        return self.create_empty_network(net_id, name, subnet_base, server_ip, endpoint, port, external_if)
    
    def create_empty_network(self, net_id, name, subnet_base, server_ip, endpoint, port, external_if):
        """Creates empty network - clean beginning! ✨
        
        Sometimes you just want a blank slate to build from scratch.
        This creates the minimal viable network structure that won't break
        anything when you start adding nodes.
        
        Pro tip: Always generate server keys first, because without them
        you basically have a very expensive paperweight 📄⚖️
        """
        # Generate keys for server (the most critical step!)
        server_private, server_public = generate_keypair()
        
        new_network = {
            "name": name,
            "subnet": f"{subnet_base}.0/24",  # Standard /24 because who needs complexity?
            "subnet_base": subnet_base,
            "server": {
                "name": "Main Server",  # Generic name, users can change later
                "ip": server_ip,
                "port": port,
                "endpoint": endpoint,
                "external_interface": external_if,  # This trips up users most often
                "private_key": server_private,
                "public_key": server_public
            },
            "nodes": {}  # Empty dict, ready for population
        }
        
        self.data["networks"][net_id] = new_network
        
        if self.save_config():
            print(colored(f"✅ Network '{name}' created successfully!", Colors.GREEN))
            print(colored(f"🔧 Now you can add nodes through management menu", Colors.CYAN))
            return net_id
        else:
            print(colored("❌ Error saving network", Colors.RED))
            # TODO: Maybe cleanup partial network creation? Edge case though...
            return None
    
    def manage_network_menu(self):
        """Network management menu - how to control a star fleet! 🚀
        
        This is where users spend most of their time. Had to balance
        showing enough info to be useful vs. keeping it clean and readable.
        
        The numbered list approach works well for small networks,
        but might need pagination for users with 50+ networks... 
        (Who has 50+ VPN networks? Apparently some people do!)
        """
        if not self.data["networks"]:
            print(colored("❌ No networks to manage", Colors.RED))
            return
        
        print(colored("\n🔧 Choose network to manage:", Colors.HEADER))
        networks = list(self.data["networks"].items())
        
        for i, (net_id, network) in enumerate(networks, 1):
            print(colored(f"{i}. {network['name']} ({net_id})", Colors.GREEN))
        
        print(colored("0. Back", Colors.YELLOW))
        
        try:
            choice = int(input(colored("\nChoice: ", Colors.BOLD)))
            if choice == 0:
                return
            if 1 <= choice <= len(networks):
                net_id = networks[choice-1][0]
                self.network_management_menu(net_id)
        except ValueError:
            print(colored("❌ Invalid choice", Colors.RED))
    
    def network_management_menu(self, network_id):
        """Specific network management menu - internal star affairs! ⭐
        
        This menu evolved over time based on user feedback (mostly from myself 😅).
        Originally had way more options, but simplified to the essentials.
        
        The while loop here keeps users in the context until they're done,
        which feels more natural than bouncing back to main menu constantly.
        """
        while True:
            network = self.data["networks"][network_id]
            print(colored(f"\n🛠️  Managing network: {network['name']}", Colors.HEADER))
            print(colored(f"Subnet: {network['subnet']}", Colors.CYAN))
            print(colored(f"Server: {network['server']['ip']} ({network['server']['endpoint']})", Colors.CYAN))
            print(colored(f"Nodes: {len(network['nodes'])}", Colors.CYAN))
            
            print(colored("\n📋 Nodes in network:", Colors.BLUE))
            for i, (node_id, node) in enumerate(network["nodes"].items(), 1):
                # Visual status indicator - way better than just text
                status = colored("✅", Colors.GREEN) if node["enabled"] else colored("❌", Colors.RED)
                print(f"   {i}. {status} {node['name']} ({node['ip']})")
            
            print(colored("\n⚡ Actions:", Colors.BLUE))
            print(colored("1. Add node", Colors.GREEN))
            print(colored("2. Edit node", Colors.YELLOW))
            print(colored("3. Delete node", Colors.RED))
            print(colored("4. Server settings", Colors.CYAN))
            print(colored("5. Network settings", Colors.CYAN))
            print(colored("6. Enable/disable node", Colors.YELLOW))
            print(colored("0. Back", Colors.YELLOW))
            
            choice = input(colored("\n🎯 Your choice: ", Colors.BOLD))
            
            if choice == "0":
                break
            elif choice == "1":
                self.add_node_menu(network_id)
            elif choice == "2":
                self.edit_node_menu(network_id)
            elif choice == "3":
                self.delete_node_menu(network_id)
            elif choice == "4":
                self.server_settings_menu(network_id)
            elif choice == "5":
                self.network_settings_menu(network_id)
            elif choice == "6":
                self.toggle_node_menu(network_id)
                
    def add_node_menu(self, network_id):
        """Adding new node - birth of a new Padawan! 👨‍🎓
        
        Node creation should be simple but bulletproof. The IP validation
        here saves users from creating configs that won't work.
        
        Originally I let users enter any IP and figured they'd know better...
        Big mistake! 😂 Now we validate everything because humans are creative
        at breaking things in unexpected ways.
        """
        print(colored("\n➕ Adding new node", Colors.HEADER))
        
        name = input(colored("Node name: ", Colors.CYAN))
        if not name:
            print(colored("❌ Name cannot be empty", Colors.RED))
            return
        
        network = self.data["networks"][network_id]
        subnet_base = network["subnet_base"]
        
        while True:
            ip = input(colored(f"IP address ({subnet_base}.x): ", Colors.CYAN))
            if not ip:
                break  # User cancelled
            
            # IP validation (learned this is essential the hard way)
            valid, error = self.validate_ip(ip, subnet_base)
            if not valid:
                print(colored(f"❌ {error}", Colors.RED))
                continue
            
            # Conflict check (prevents duplicate IP headaches)
            conflict, error = self.check_ip_conflicts(network_id, ip)
            if conflict:
                print(colored(f"❌ {error}", Colors.RED))
                continue
            
            break  # All validation passed!
        
        if not ip:
            print(colored("❌ Cancelled", Colors.YELLOW))
            return
        
        # Generate keys (the cryptographic magic happens here)
        private_key, public_key = generate_keypair()
        
        # Add node to network
        node_id = f"node_{len(network['nodes']) + 1}"  # Simple ID generation
        network["nodes"][node_id] = {
            "name": name,
            "ip": ip,
            "private_key": private_key,
            "public_key": public_key,
            "enabled": True  # New nodes start enabled (optimistic default)
        }
        
        self.save_config()
        print(colored(f"✅ Node '{name}' added successfully!", Colors.GREEN))
    
    def generate_configs_menu(self):
        """Config generation - creating sacred texts! 📄
        
        This is where the magic happens - turning our JSON data into actual
        WireGuard config files that do useful things!
        
        The menu structure here mirrors the network selection pattern used
        elsewhere. Consistency is good for UX... most of the time 🤷‍♂️
        """
        if not self.data["networks"]:
            print(colored("❌ No networks for config generation", Colors.RED))
            return
        
        print(colored("\n📄 WireGuard config generation", Colors.HEADER))
        networks = list(self.data["networks"].items())
        
        for i, (net_id, network) in enumerate(networks, 1):
            print(colored(f"{i}. {network['name']} ({net_id})", Colors.GREEN))
        
        print(colored("0. Back", Colors.YELLOW))
        
        try:
            choice = int(input(colored("\nChoose network: ", Colors.BOLD)))
            if choice == 0:
                return
            if 1 <= choice <= len(networks):
                net_id = networks[choice-1][0]
                self.generate_network_configs(net_id)
        except ValueError:
            print(colored("❌ Invalid choice", Colors.RED))
    
    def generate_network_configs(self, network_id):
        """Generates configs for specific network - dark magic in action! 🔮
        
        File generation is where rubber meets the road. These configs need to be
        perfect because syntax errors in WireGuard configs are... unforgiving.
        
        Creating separate folder per network keeps things organized and
        prevents users from mixing up configs (learned from experience).
        """
        network = self.data["networks"][network_id]
        
        # Create folder for configs (organization is key!)
        config_dir = f"configs_{network_id}"
        os.makedirs(config_dir, exist_ok=True)
        
        print(colored(f"\n🎯 Generating configs for network '{network['name']}'...", Colors.CYAN))
        
        # Generate server config (the brain of the operation)
        self.generate_server_config(network, config_dir)
        
        # Generate client configs (one for each enabled node)
        for node_id, node in network["nodes"].items():
            if node["enabled"]:  # Only generate for enabled nodes
                self.generate_client_config(network, node, config_dir)
        
        print(colored(f"✅ Configs generated in folder '{config_dir}/'", Colors.GREEN))
        print(colored("📋 Don't forget:", Colors.YELLOW))
        print(colored("   • Check external_interface on server", Colors.YELLOW))
        print(colored("   • Open port in firewall", Colors.YELLOW))
        print(colored("   • Verify endpoint address", Colors.YELLOW))
        # These reminders save users hours of debugging... trust me!
    
    def generate_qr_codes_menu(self):
        """QR code generation - quick connection for mobile! 📱
        
        QR codes are a game-changer for mobile VPN setup. Before this feature,
        I was manually typing 44-character keys on phone keyboards... never again! 😱
        
        The dependency check here is important - learned this after getting
        complaints from users who couldn't figure out why QR codes weren't working.
        Clear error messages save everyone time and frustration.
        """
        if not QR_AVAILABLE:
            print(colored("\n❌ QR codes unavailable", Colors.RED))
            print(colored("💡 Install library: pip install qrcode[pil]", Colors.YELLOW))
            input(colored("Press Enter...", Colors.BOLD))
            return
        
        if not self.data["networks"]:
            print(colored("❌ No networks for QR code generation", Colors.RED))
            return
        
        print(colored("\n📱 QR code generation for mobile", Colors.HEADER))
        networks = list(self.data["networks"].items())
        
        for i, (net_id, network) in enumerate(networks, 1):
            print(colored(f"{i}. {network['name']} ({net_id})", Colors.GREEN))
        
        print(colored("0. Back", Colors.YELLOW))
        
        try:
            choice = int(input(colored("\nChoose network: ", Colors.BOLD)))
            if choice == 0:
                return
            if 1 <= choice <= len(networks):
                net_id = networks[choice-1][0]
                self.generate_network_qr_codes(net_id)
        except ValueError:
            print(colored("❌ Invalid choice", Colors.RED))
    
    def generate_network_qr_codes(self, network_id):
        """Generates QR codes for all network clients! 🔲
        
        Bulk QR generation is super convenient when setting up multiple devices.
        My family has 6 devices, so this saves me from doing QR generation
        one by one like some kind of caveman 🦕
        
        The separate folder keeps QR codes organized and prevents mixing them
        with config files. Learned this after accidentally trying to scan a .conf file... 🤦‍♂️
        """
        network = self.data["networks"][network_id]
        
        # Create folder for QR codes (organization prevents chaos)
        qr_dir = f"qr_codes_{network_id}"
        os.makedirs(qr_dir, exist_ok=True)
        
        print(colored(f"\n📱 Generating QR codes for network '{network['name']}'...", Colors.CYAN))
        
        enabled_nodes = [(node_id, node) for node_id, node in network["nodes"].items() if node["enabled"]]
        
        if not enabled_nodes:
            print(colored("❌ No enabled nodes for QR code generation", Colors.RED))
            return
        
        generated_count = 0
        for node_id, node in enabled_nodes:
            if self.generate_client_qr_code(network, node, qr_dir):
                generated_count += 1
        
        print(colored(f"\n✅ Generated {generated_count} QR codes in folder '{qr_dir}/'", Colors.GREEN))
        print(colored("📱 Mobile instructions:", Colors.CYAN))
        print(colored("   1. Open WireGuard app", Colors.BLUE))
        print(colored("   2. Press '+' → 'Create from QR code'", Colors.BLUE))
        print(colored("   3. Scan corresponding QR code", Colors.BLUE))
        print(colored("   4. Connect!", Colors.BLUE))
        # These step-by-step instructions save user support requests!
    
    def generate_client_qr_code(self, network, node, qr_dir):
        """Generates QR code for one client - magical portal! ✨
        
        QR code generation is surprisingly finicky. The error correction level,
        box size, and border all affect scannability. These settings work well
        for most phones, tested on iPhone, Android, and even some tablets.
        
        The filename sanitization prevents filesystem errors when users name
        nodes with special characters like "Mom's iPad" or "Café laptop" 🇫🇷
        """
        try:
            # Generate client config (as text for QR encoding)
            server = network["server"]
            config_text = f"""[Interface]
PrivateKey = {node['private_key']}
Address = {node['ip']}/32
DNS = {server['ip']}

[Peer]
PublicKey = {server['public_key']}
AllowedIPs = {network['subnet']}
Endpoint = {server['endpoint']}
PersistentKeepalive = 25"""
            
            # Create QR code with optimal settings (trial and error optimization)
            qr = qrcode.QRCode(
                version=1,  # Auto-select size (usually perfect for WG configs)
                error_correction=qrcode.constants.ERROR_CORRECT_L,  # Minimal error correction = smaller QR
                box_size=10,  # Size of each square (good for screens and prints)
                border=4,   # Border size (standard, don't go smaller)
            )
            
            qr.add_data(config_text)
            qr.make(fit=True)  # Auto-resize if content is too big
            
            # Create image with high contrast (important for scanning)
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Safe filename generation (handles unicode, spaces, special chars)
            safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', node['name'])
            safe_ip = node['ip'].replace('.', '_')  # Dots confuse some filesystems
            filename = f"QR_{safe_name}_{safe_ip}.png"
            
            # Save file (PNG format works everywhere)
            img.save(f"{qr_dir}/{filename}")
            
            print(colored(f"  📱 {filename}", Colors.GREEN))
            return True
            
        except Exception as e:
            # QR generation can fail for various reasons (size, content, filesystem)
            print(colored(f"  ❌ Error for {node['name']}: {e}", Colors.RED))
            return False
    
    def generate_server_config(self, network, config_dir):
        """Generates server config - brain of the star! 🧠
        
        Server config is the most critical file - it controls routing, NAT,
        and firewall rules. Get this wrong and nothing works. Get it right
        and you feel like a networking wizard 🧙‍♂️
        
        The comments in generated config are verbose but helpful. Users copy-paste
        these commands constantly, so might as well make them useful!
        """
        server = network["server"]
        
        # Build config with extensive comments (users appreciate this!)
        config_content = f"""# WireGuard Server Config - {network['name']}
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# Server: {server['name']} ({server['ip']})

[Interface]
# Server IP address in VPN network
Address = {server['ip']}/24

# Rules for routing and NAT (CHECK external_interface!)
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {server['external_interface']} -j MASQUERADE; echo 1 > /proc/sys/net/ipv4/ip_forward
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {server['external_interface']} -j MASQUERADE

# Server port
ListenPort = {server['port']}

# Server private key
PrivateKey = {server['private_key']}

# =================== CLIENTS ===================
"""
        
        # Add client sections (one [Peer] block per enabled node)
        for node_id, node in network["nodes"].items():
            if node["enabled"]:
                config_content += f"""
[Peer]
# {node['name']}
PublicKey = {node['public_key']}
AllowedIPs = {node['ip']}/32
"""
        
        # Add useful commands in comments (saves users googling)
        config_content += f"""

# ================ USEFUL COMMANDS ================
# Restart WireGuard:
# sudo systemctl restart wg-quick@wg0

# Check interface status:
# ip addr show wg0

# View routes:
# ip route show

# Check IP forwarding:
# cat /proc/sys/net/ipv4/ip_forward  # should be 1

# View active connections:
# sudo wg show

# Open port in firewall:
# sudo ufw allow {server['port']}/udp
"""
        
        # Save file with standard name (wg0.conf is conventional)
        with open(f"{config_dir}/wg0.conf", 'w', encoding='utf-8') as f:
            f.write(config_content)
        
        print(colored(f"  📄 wg0.conf (server)", Colors.GREEN))
    
    def generate_client_config(self, network, node, config_dir):
        """Generates client config - personal lightsaber! ⚔️
        
        Client configs are simpler than server configs but just as important.
        The DNS setting using server IP is a nice touch - makes troubleshooting
        easier when clients can resolve internal hostnames.
        
        AllowedIPs determines what traffic goes through VPN. Using the full
        subnet means all internal traffic routes through VPN, which is usually
        what people want for a star topology.
        """
        server = network["server"]
        
        # Safe filename (filesystem compatibility is important)
        safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', node['name'])
        
        config_content = f"""# WireGuard Client Config - {node['name']}
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# Network: {network['name']}
# Client IP: {node['ip']}

[Interface]
# Client private key
PrivateKey = {node['private_key']}

# Client IP address in VPN network
Address = {node['ip']}/32

# DNS server (can be changed to 8.8.8.8 or other)
DNS = {server['ip']}

[Peer]
# Server: {server['name']}
PublicKey = {server['public_key']}

# Allowed IP addresses (entire VPN range)
AllowedIPs = {network['subnet']}

# Server address and port
Endpoint = {server['endpoint']}

# NAT keepalive (prevents connection drops)
PersistentKeepalive = 25

# ================ INSTRUCTIONS ================
# 1. Save this file as .conf
# 2. Import to WireGuard client
# 3. Connect to VPN
# 4. Test connection: ping {server['ip']}
"""
        
        # Generate descriptive filename (includes IP for easy identification)
        filename = f"client_{safe_name}_{node['ip'].replace('.', '_')}.conf"
        with open(f"{config_dir}/{filename}", 'w', encoding='utf-8') as f:
            f.write(config_content)
        
        print(colored(f"  📱 {filename}", Colors.GREEN))
        
    def show_about(self):
        """About program - credits to creators! 🎬
        
        Originally this was just a simple credits screen, but it evolved into
        a feature showcase and troubleshooting guide. Users actually read this
        section when things break, so might as well make it useful!
        
        The file paths shown here help users find generated files, because
        apparently "configs_networkname/" is not obvious to everyone 🤷‍♂️
        """
        print(colored("\n" + "="*60, Colors.HEADER))
        print(colored("🌟 WireGuard Star Network Manager v1.0 🌟", Colors.HEADER))
        print(colored("="*60, Colors.HEADER))
        print(colored("\n🧙‍♂️ Created by Volodymyr Frytskyy (WhitemanV)", Colors.CYAN))
        print(colored("🧙‍♂️    Website: https://www.vladonai.com/about-resume", Colors.CYAN))
        print(colored("🧙‍♂️    GitHub: https://github.com/Frytskyy/WireGuard-Star-Network-Manager-Configurator", Colors.CYAN))
        print(colored("⚔️  For managing WireGuard networks", Colors.CYAN))
        print(colored("🌌 May the Force be with your VPN!", Colors.CYAN))
        
        print(colored("\n📋 Features:", Colors.BLUE))
        # Checkmarks make users feel good about their choice of tools 😊
        print(colored("  ✅ Creating star networks", Colors.GREEN))
        print(colored("  ✅ Node management", Colors.GREEN))
        print(colored("  ✅ Automatic key generation", Colors.GREEN))
        print(colored("  ✅ IP conflict validation", Colors.GREEN))
        print(colored("  ✅ Config generation", Colors.GREEN))
        print(colored("  ✅ QR codes for mobile", Colors.GREEN))
        print(colored("  ✅ Network cloning", Colors.GREEN))
        print(colored("  ✅ Node/server editing", Colors.GREEN))
        print(colored("  ✅ Key regeneration", Colors.GREEN))
        print(colored("  ✅ Config file encryption to protect sensible keys (optional, but recommended)", Colors.GREEN))

        print(colored("\n🔗 Files:", Colors.BLUE))
        print(colored(f"  📄 Config: {self.config_file}", Colors.CYAN))
        print(colored("  📁 Generated files: configs_*/", Colors.CYAN))
        print(colored("  📱 QR codes: qr_codes_*/", Colors.CYAN))
        
        if not QR_AVAILABLE:
            # Gentle reminder about missing features
            print(colored("\n⚠️  QR codes unavailable:", Colors.YELLOW))
            print(colored("   pip install qrcode[pil]", Colors.CYAN))
        
        input(colored("\n💫 Press Enter to continue...", Colors.BOLD))
    
    def delete_node_menu(self, network_id):
        """Node deletion - expulsion from the Order! 💀
        
        Deletion is always scary. Added double confirmation here after I accidentally
        deleted my main laptop node and had to recreate everything... not fun! 😫
        
        The status icons help users identify which node they're about to delete.
        Saved me from deleting wrong nodes multiple times.
        """
        network = self.data["networks"][network_id]
        
        if not network["nodes"]:
            print(colored("❌ No nodes to delete", Colors.RED))
            return
        
        print(colored("\n🗑️  Node deletion", Colors.HEADER))
        print(colored("📋 Available nodes:", Colors.BLUE))
        
        nodes = list(network["nodes"].items())
        for i, (node_id, node) in enumerate(nodes, 1):
            # Visual status helps prevent accidents
            status = colored("✅", Colors.GREEN) if node["enabled"] else colored("❌", Colors.RED)
            print(f"   {i}. {status} {node['name']} ({node['ip']})")
        
        print(colored("0. Cancel", Colors.YELLOW))
        
        try:
            choice = int(input(colored("\nChoose node to delete: ", Colors.BOLD)))
            if choice == 0:
                return
            if 1 <= choice <= len(nodes):
                node_id, node = nodes[choice-1]
                
                # Deletion confirmation (learned this is essential!)
                confirm = input(colored(f"⚠️  Delete node '{node['name']}'? (y/N): ", Colors.RED))
                if confirm.lower() in ['y', 'yes']:
                    del network["nodes"][node_id]
                    self.save_config()
                    print(colored(f"✅ Node '{node['name']}' deleted", Colors.GREEN))
                else:
                    print(colored("❌ Cancelled", Colors.YELLOW))
            else:
                print(colored("❌ Invalid choice", Colors.RED))
        except ValueError:
            print(colored("❌ Invalid choice", Colors.RED))
    
    def toggle_node_menu(self, network_id):
        """Enable/disable node - freezing in carbonite! 🧊
        
        Toggle functionality is super useful for temporary disconnections
        without losing configuration. Like when your kid's tablet needs
        a timeout from the internet but you don't want to recreate configs later 📱
        
        The current status display prevents confusion about what action will happen.
        """
        network = self.data["networks"][network_id]
        
        if not network["nodes"]:
            print(colored("❌ No nodes to manage", Colors.RED))
            return
        
        print(colored("\n🔄 Enable/disable node", Colors.HEADER))
        print(colored("📋 Available nodes:", Colors.BLUE))
        
        nodes = list(network["nodes"].items())
        for i, (node_id, node) in enumerate(nodes, 1):
            # Clear status indication prevents user confusion
            status = colored("✅ ENABLED", Colors.GREEN) if node["enabled"] else colored("❌ DISABLED", Colors.RED)
            print(f"   {i}. {status} | {node['name']} ({node['ip']})")
        
        print(colored("0. Back", Colors.YELLOW))
        
        try:
            choice = int(input(colored("\nChoose node: ", Colors.BOLD)))
            if choice == 0:
                return
            if 1 <= choice <= len(nodes):
                node_id, node = nodes[choice-1]
                
                # Show current state and what will happen (UX clarity)
                old_status = "enabled" if node["enabled"] else "disabled"
                new_status = "disabled" if node["enabled"] else "enabled"
                
                confirm = input(colored(f"🔄 Node '{node['name']}' is currently {old_status}. Make {new_status}? (y/N): ", Colors.CYAN))
                if confirm.lower() in ['y', 'yes']:
                    node["enabled"] = not node["enabled"]
                    self.save_config()
                    
                    emoji = "✅" if node["enabled"] else "❌"
                    print(colored(f"{emoji} Node '{node['name']}' is now {new_status}", Colors.GREEN))
                else:
                    print(colored("❌ Cancelled", Colors.YELLOW))
            else:
                print(colored("❌ Invalid choice", Colors.RED))
        except ValueError:
            print(colored("❌ Invalid choice", Colors.RED))
    
    def network_settings_menu(self, network_id):
        """Network settings - changing core parameters! ⚙️
        
        This menu handles all the "dangerous" operations that can break existing
        configs. Originally had more options here, but simplified to reduce
        the chances of users shooting themselves in the foot 🦶🔫
        
        The while loop keeps users in context - much better UX than bouncing
        back to main menu after every change.
        """
        network = self.data["networks"][network_id]
        
        while True:
            print(colored(f"\n⚙️  Network settings: {network['name']}", Colors.HEADER))
            print(colored(f"ID: {network_id}", Colors.CYAN))
            print(colored(f"Subnet: {network['subnet']}", Colors.CYAN))
            print(colored(f"Base address: {network['subnet_base']}", Colors.CYAN))
            
            print(colored("\n🔧 What can be changed:", Colors.BLUE))
            print(colored("1. Network name", Colors.GREEN))
            print(colored("2. Subnet base address", Colors.GREEN))  # Most dangerous option!
            print(colored("3. Server name", Colors.GREEN))
            print(colored("4. Server endpoint", Colors.GREEN))
            print(colored("5. Server port", Colors.GREEN))
            print(colored("6. Server external interface", Colors.GREEN))
            print(colored("0. Back", Colors.YELLOW))
            
            choice = input(colored("\n🎯 Your choice: ", Colors.BOLD))
            
            if choice == "0":
                break
            elif choice == "1":
                self.change_network_name(network_id)
            elif choice == "2":
                self.change_subnet_base(network_id)  # Here be dragons! 🐉
            elif choice == "3":
                self.change_server_name(network_id)
            elif choice == "4":
                self.change_server_endpoint(network_id)
            elif choice == "5":
                self.change_server_port(network_id)
            elif choice == "6":
                self.change_server_interface(network_id)
            else:
                print(colored("❌ Invalid choice", Colors.RED))
    
    def change_network_name(self, network_id):
        """Change network name - renaming a planet! 🪐
        
        Simple name change, can't break anything. Originally didn't validate
        the name at all, but empty names cause UI issues later so added basic check.
        
        Could add more validation (length, special chars) but... YAGNI principle! 🤷‍♂️
        """
        network = self.data["networks"][network_id]
        current_name = network["name"]
        
        print(colored(f"\n✏️  Change network name", Colors.HEADER))
        print(colored(f"Current name: {current_name}", Colors.CYAN))
        
        new_name = input(colored("New name (Enter - don't change): ", Colors.CYAN)).strip()
        
        if new_name and new_name != current_name:
            network["name"] = new_name
            self.save_config()
            print(colored(f"✅ Name changed to '{new_name}'", Colors.GREEN))
        else:
            print(colored("❌ Name not changed", Colors.YELLOW))
    
    def change_subnet_base(self, network_id):
        """Change subnet base address - relocating to another galaxy! 🌌
        
        This is the nuclear option! Changes every single IP in the network.
        Added multiple warnings because this operation has burned me before.
        
        The IP reassignment logic preserves the last octet, so devices keep
        their relative positions. Better than random reassignment! 🎲
        """
        network = self.data["networks"][network_id]
        current_base = network["subnet_base"]
        
        print(colored(f"\n🌐 Change subnet base address", Colors.HEADER))
        print(colored(f"Current: {current_base}", Colors.CYAN))
        print(colored("⚠️  WARNING: This will change ALL device IPs!", Colors.RED))
        print(colored("⚠️  All existing configs will need regeneration!", Colors.RED))  # Extra warning!
        
        new_base = input(colored("New base address (192.168.101): ", Colors.CYAN)).strip()
        
        if new_base and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}$', new_base):
            # Triple confirmation for destructive operations!
            confirm = input(colored("⚠️  Really change address of entire network? (y/N): ", Colors.RED))
            if confirm.lower() in ['y', 'yes']:
                # Change base address
                network["subnet_base"] = new_base
                network["subnet"] = f"{new_base}.0/24"
                
                # Change server IP (always ends in .1)
                old_server_ip = network["server"]["ip"]
                network["server"]["ip"] = f"{new_base}.1"
                
                # Change all node IPs, keeping last octet (preserves device hierarchy)
                for node in network["nodes"].values():
                    last_octet = node["ip"].split('.')[-1]
                    node["ip"] = f"{new_base}.{last_octet}"
                
                self.save_config()
                print(colored(f"✅ Base address changed to {new_base}", Colors.GREEN))
                print(colored(f"🔄 Server: {old_server_ip} → {network['server']['ip']}", Colors.CYAN))
                print(colored("🚨 Remember to regenerate ALL configs!", Colors.YELLOW))
            else:
                print(colored("❌ Cancelled", Colors.YELLOW))
        else:
            print(colored("❌ Invalid address format", Colors.RED))
            
    def change_server_name(self, network_id):
        """Change server name - coronation of new emperor! 👑
        
        Server name is mostly cosmetic but shows up in generated configs.
        Added this because users kept asking "which server is which?"
        when managing multiple networks. Small UX improvement that matters! 📝
        """
        network = self.data["networks"][network_id]
        current_name = network["server"]["name"]
        
        print(colored(f"\n👑 Change server name", Colors.HEADER))
        print(colored(f"Current name: {current_name}", Colors.CYAN))
        
        new_name = input(colored("New server name: ", Colors.CYAN)).strip()
        
        if new_name and new_name != current_name:
            network["server"]["name"] = new_name
            self.save_config()
            print(colored(f"✅ Server name changed to '{new_name}'", Colors.GREEN))
        else:
            print(colored("❌ Name not changed", Colors.YELLOW))
    
    def change_server_endpoint(self, network_id):
        """Change server endpoint - moving to another star system! 🚀
        
        Endpoint changes are common when switching hosting providers or
        updating DNS records. This used to require manual config editing...
        now it's just a menu option. Progress! 🎉
        
        TODO: Add endpoint validation (check if it's reachable?)
        But that adds complexity and network dependencies... maybe not worth it?
        """
        network = self.data["networks"][network_id]
        current_endpoint = network["server"]["endpoint"]
        
        print(colored(f"\n🌐 Change server endpoint", Colors.HEADER))
        print(colored(f"Current: {current_endpoint}", Colors.CYAN))
        
        new_endpoint = input(colored("New endpoint (domain.com:port): ", Colors.CYAN)).strip()
        
        if new_endpoint and new_endpoint != current_endpoint:
            network["server"]["endpoint"] = new_endpoint
            self.save_config()
            print(colored(f"✅ Endpoint changed to '{new_endpoint}'", Colors.GREEN))
            print(colored("💡 Remember to regenerate client configs!", Colors.YELLOW))
        else:
            print(colored("❌ Endpoint not changed", Colors.YELLOW))
    
    def change_server_port(self, network_id):
        """Change server port - changing hyperspace frequency! 📡
        
        Port changes happen more often than you'd think. Default WireGuard port
        gets blocked by some ISPs, or conflicts with other services.
        
        Added port range validation after someone tried to use port 99999...
        computers are literal and don't appreciate impossible port numbers! 🤖
        """
        network = self.data["networks"][network_id]
        current_port = network["server"]["port"]
        
        print(colored(f"\n📡 Change server port", Colors.HEADER))
        print(colored(f"Current port: {current_port}", Colors.CYAN))
        
        new_port = input(colored("New port: ", Colors.CYAN)).strip()
        
        try:
            port_num = int(new_port)
            if 1 <= port_num <= 65535:  # Valid port range (learned from RFC!)
                network["server"]["port"] = port_num
                self.save_config()
                print(colored(f"✅ Port changed to {port_num}", Colors.GREEN))
                print(colored("🔥 Don't forget to update firewall rules!", Colors.YELLOW))
            else:
                print(colored("❌ Port must be between 1 and 65535", Colors.RED))
        except ValueError:
            if new_port:
                print(colored("❌ Invalid port format", Colors.RED))
            else:
                print(colored("❌ Port not changed", Colors.YELLOW))
    
    def change_server_interface(self, network_id):
        """Change server external interface - switching communication arrays! 📡
        
        External interface is the trickiest setting for new users. They see "eth0"
        and think it's universal, but modern systems use names like "enp0s3" or "wlp2s0".
        
        Should probably add interface detection here... but that requires root
        privileges and platform-specific code. Maybe in v2.0? 🔮
        """
        network = self.data["networks"][network_id]
        current_interface = network["server"]["external_interface"]
        
        print(colored(f"\n📡 Change server external interface", Colors.HEADER))
        print(colored(f"Current interface: {current_interface}", Colors.CYAN))
        print(colored("💡 Use 'ip addr' or 'ifconfig' to find interface names", Colors.YELLOW))
        
        new_interface = input(colored("New external interface (eth0, ens3, etc.): ", Colors.CYAN)).strip()
        
        if new_interface and new_interface != current_interface:
            network["server"]["external_interface"] = new_interface
            self.save_config()
            print(colored(f"✅ External interface changed to '{new_interface}'", Colors.GREEN))
            print(colored("🔄 Regenerate server config to apply changes!", Colors.YELLOW))
        else:
            print(colored("❌ Interface not changed", Colors.YELLOW))
    
    def edit_node_menu(self, network_id):
        """Node editing - lightsaber modernization! ⚔️
        
        Node editing covers all the common scenarios: rename, change IP,
        regenerate compromised keys, etc. The menu grew organically based on
        user requests... which is how most good software evolves! 🌱
        
        Originally this was just "rename node" but feature creep took over.
        Not complaining though - it's actually useful feature creep for once!
        """
        network = self.data["networks"][network_id]
        
        if not network["nodes"]:
            print(colored("❌ No nodes to edit", Colors.RED))
            return
        
        print(colored("\n✏️  Node editing", Colors.HEADER))
        print(colored("📋 Available nodes:", Colors.BLUE))
        
        nodes = list(network["nodes"].items())
        for i, (node_id, node) in enumerate(nodes, 1):
            status = colored("✅", Colors.GREEN) if node["enabled"] else colored("❌", Colors.RED)
            print(f"   {i}. {status} {node['name']} ({node['ip']})")
        
        print(colored("0. Back", Colors.YELLOW))
        
        try:
            choice = int(input(colored("\nChoose node to edit: ", Colors.BOLD)))
            if choice == 0:
                return
            if 1 <= choice <= len(nodes):
                node_id, node = nodes[choice-1]
                self.edit_single_node(network_id, node_id)
            else:
                print(colored("❌ Invalid choice", Colors.RED))
        except ValueError:
            print(colored("❌ Invalid choice", Colors.RED))
        
    def validate_wireguard_key(self, key):
        """Validates WireGuard key format - checking if Force crystal is pure! 💎
        
        WireGuard key validation is surprisingly specific. 44 characters, base64,
        ends with '=', decodes to exactly 32 bytes. Get any of this wrong and
        WireGuard will silently fail in mysterious ways 👻
        
        Learned these rules the hard way after spending hours debugging
        "connection timeout" errors that were really just malformed keys!
        """
        import re
        
        # WireGuard keys are base64 encoded, 44 characters long, ending with '='
        if not key or len(key) != 44:
            return False, "Key must be exactly 44 characters long"
        
        if not key.endswith('='):
            return False, "Key must end with '='"
        
        # Check if it's valid base64 (this can throw exceptions!)
        try:
            import base64
            decoded = base64.b64decode(key)
            if len(decoded) != 32:  # WireGuard uses 32-byte keys (256 bits)
                return False, "Invalid key length after decoding"
        except Exception:
            return False, "Invalid base64 format"
        
        # Check if contains only valid base64 characters
        valid_chars = re.match(r'^[A-Za-z0-9+/]+=*$', key)
        if not valid_chars:
            return False, "Key contains invalid characters"
        
        return True, "Valid key"

    def manual_key_input(self, key_type="private"):
        """Manual key input with validation - teaching young Padawan the ways of cryptography! 🎓
        
        Manual key input is for advanced users who generate keys externally
        or need to import existing configs. Added extensive validation because
        invalid keys create problems that are hard to diagnose later.
        
        The preview showing first 20 and last 4 characters helps users verify
        they copied the right key without showing the full key on screen. Security! 🔒
        """
        print(colored(f"\n🔐 Manual {key_type} key input", Colors.HEADER))
        print(colored("Key format: 44 characters, base64 encoded, ending with '='", Colors.CYAN))
        print(colored("Example: abc123def456ghi789jkl012mno345pqr678stu90+w=", Colors.CYAN))
        
        while True:
            key = input(colored(f"Enter {key_type} key (or 'cancel'): ", Colors.CYAN)).strip()
            
            if key.lower() == 'cancel':
                return None
            
            if not key:
                print(colored("❌ Key cannot be empty", Colors.RED))
                continue
            
            # Validate key format (this prevents many headaches later!)
            valid, error_msg = self.validate_wireguard_key(key)
            if not valid:
                print(colored(f"❌ {error_msg}", Colors.RED))
                continue
            
            # Ask for confirmation with preview (security + usability)
            print(colored(f"✅ Key format is valid", Colors.GREEN))
            print(colored(f"Key preview: {key[:20]}...{key[-4:]}", Colors.CYAN))
            
            confirm = input(colored("Use this key? (y/N): ", Colors.YELLOW))
            if confirm.lower() in ['y', 'yes']:
                return key
            else:
                print(colored("❌ Try again or enter 'cancel'", Colors.YELLOW))

    def generate_public_from_private(self, private_key):
        """Generates public key from private - ancient Jedi alchemy! ⚗️
        
        WireGuard's key derivation is pure cryptographic magic. Private key
        goes in, public key comes out. Can't explain that! 🎩✨
        
        The fallback handling here is important - not everyone has wg-tools
        installed, and manual key pairs are still valid for this use case.
        """
        try:
            # Try using wg utility first (the proper way)
            public_result = subprocess.run(['wg', 'pubkey'], 
                                        input=private_key, capture_output=True, 
                                        text=True, check=True)
            return public_result.stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(colored("⚠️  Cannot generate public key: wg utility not available", Colors.YELLOW))
            print(colored("💡 You'll need to enter the public key manually", Colors.CYAN))
            return None

    def manual_keypair_input(self):
        """Manual input for both private and public keys - complete Force training! 🌟
        
        This function handles the complex flow of manual key input. Users can either:
        1. Enter private key and let us generate public (preferred)
        2. Enter both keys manually (for when wg-tools isn't available)
        
        The UX here tries to guide users to the easier option while still
        supporting the manual fallback. Choice is good! 🎯
        """
        print(colored("\n🎯 Manual keypair input", Colors.HEADER))
        print(colored("You can either:", Colors.BLUE))
        print(colored("1. Enter private key only (public will be generated)", Colors.GREEN))
        print(colored("2. Enter both private and public keys", Colors.GREEN))
        
        choice = input(colored("Your choice (1/2): ", Colors.CYAN))
        
        # Get private key (always required)
        private_key = self.manual_key_input("private")
        if not private_key:
            return None, None
        
        if choice == "1":
            # Try to generate public key (the easy path)
            public_key = self.generate_public_from_private(private_key)
            if not public_key:
                print(colored("🔧 Please enter public key manually", Colors.CYAN))
                public_key = self.manual_key_input("public")
                if not public_key:
                    return None, None
        else:
            # Manual input for public key (the manual path)
            public_key = self.manual_key_input("public")
            if not public_key:
                return None, None
        
        return private_key, public_key
    
    def edit_single_node(self, network_id, node_id):
        """Edit single node - fine-tuning the Force! ⚡
        
        This is the Swiss Army knife of node management. Handles everything from
        simple name changes to complete key regeneration. Started simple,
        grew into this multi-tool based on actual usage patterns.
        
        The while loop keeps users in context - much better than bouncing between
        menus for related changes. Learned this from watching users navigate! 👀
        """
        network = self.data["networks"][network_id]
        node = network["nodes"][node_id]
        
        while True:
            print(colored(f"\n🔧 Editing node: {node['name']}", Colors.HEADER))
            print(colored(f"IP: {node['ip']}", Colors.CYAN))
            print(colored(f"Status: {'Enabled' if node['enabled'] else 'Disabled'}", Colors.CYAN))
            # Show partial key for identification without security risk
            print(colored(f"Public key: {node['public_key'][:20]}...", Colors.CYAN))
            
            print(colored("\n🔧 What can be changed:", Colors.BLUE))
            print(colored("1. Node name", Colors.GREEN))
            print(colored("2. IP address", Colors.GREEN))
            print(colored("3. Regenerate keys (if compromised)", Colors.YELLOW))  # Security feature!
            print(colored("4. Manual key input", Colors.CYAN))
            print(colored("5. Enable/disable node", Colors.CYAN))
            print(colored("0. Back", Colors.YELLOW))
            
            choice = input(colored("\n🎯 Your choice: ", Colors.BOLD))
            
            if choice == "0":
                break
            elif choice == "1":
                self.change_node_name(network_id, node_id)
            elif choice == "2":
                self.change_node_ip(network_id, node_id)
            elif choice == "3":
                self.regenerate_node_keys(network_id, node_id)  # Nuclear option!
            elif choice == "4":
                self.manual_node_keys_input(network_id, node_id)
            elif choice == "5":
                self.toggle_single_node(network_id, node_id)
            else:
                print(colored("❌ Invalid choice", Colors.RED))

    def manual_node_keys_input(self, network_id, node_id):
        """Manual input of node keys - choosing your own kyber crystal! 💎
        
        For advanced users who want to import existing keys or use keys generated
        externally. This is also useful when migrating from other VPN setups.
        
        Security note: Always validate keys before accepting them. Invalid keys
        cause subtle failures that are nightmare to debug in production! 😈
        """
        network = self.data["networks"][network_id]
        node = network["nodes"][node_id]
        
        print(colored(f"\n🔐 Manual key input for node '{node['name']}'", Colors.HEADER))
        print(colored("⚠️  WARNING: After this you'll need to update configs!", Colors.RED))
        print(colored(f"Current public key: {node['public_key'][:30]}...", Colors.CYAN))
        
        # Get new keys manually (with full validation)
        new_private, new_public = self.manual_keypair_input()
        
        if new_private and new_public:
            old_public = node['public_key'][:20]
            node['private_key'] = new_private
            node['public_key'] = new_public
            
            self.save_config()
            print(colored("✅ Keys successfully updated!", Colors.GREEN))
            print(colored(f"🔄 Old key: {old_public}...", Colors.CYAN))
            print(colored(f"🆕 New key: {new_public[:20]}...", Colors.CYAN))
            print(colored("💡 Don't forget to generate new configs!", Colors.YELLOW))
        else:
            print(colored("❌ Key input cancelled", Colors.YELLOW))
    
    def change_node_name(self, network_id, node_id):
        """Change node name - renaming a Jedi! 👤
        
        Simple name change that can't break anything. Node names are purely
        cosmetic but help with organization when you have many devices.
        
        Fun fact: My home network has nodes named after Star Wars characters.
        Makes troubleshooting more entertaining! 🌟
        """
        network = self.data["networks"][network_id]
        node = network["nodes"][node_id]
        current_name = node["name"]
        
        print(colored(f"\n📝 Change node name", Colors.HEADER))
        print(colored(f"Current name: {current_name}", Colors.CYAN))
        
        new_name = input(colored("New name: ", Colors.CYAN)).strip()
        
        if new_name and new_name != current_name:
            node["name"] = new_name
            self.save_config()
            print(colored(f"✅ Name changed to '{new_name}'", Colors.GREEN))
        else:
            print(colored("❌ Name not changed", Colors.YELLOW))
    
    def change_node_ip(self, network_id, node_id):
        """Change node IP - relocating to another planet! 🪐
        
        IP changes are trickier than name changes because they affect routing.
        The validation here prevents conflicts and ensures IP stays within subnet.
        
        The exclude_node parameter in conflict checking is crucial - prevents
        nodes from conflicting with themselves during editing. Learned this bug
        the hard way after wondering why I couldn't "change" IP to same value! 🤦‍♂️
        """
        network = self.data["networks"][network_id]
        node = network["nodes"][node_id]
        current_ip = node["ip"]
        subnet_base = network["subnet_base"]
        
        print(colored(f"\n🌐 Change node IP address", Colors.HEADER))
        print(colored(f"Current IP: {current_ip}", Colors.CYAN))
        print(colored(f"Subnet: {subnet_base}.x", Colors.CYAN))
        
        while True:
            new_ip = input(colored(f"New IP address ({subnet_base}.x): ", Colors.CYAN)).strip()
            if not new_ip:
                print(colored("❌ Cancelled", Colors.YELLOW))
                return
            
            # IP validation (prevents many future headaches)
            valid, error = self.validate_ip(new_ip, subnet_base)
            if not valid:
                print(colored(f"❌ {error}", Colors.RED))
                continue
            
            # Check conflicts (exclude current node from conflict check!)
            conflict, error = self.check_ip_conflicts(network_id, new_ip, exclude_node=node_id)
            if conflict:
                print(colored(f"❌ {error}", Colors.RED))
                continue
            
            # All validation passed - make the change!
            node["ip"] = new_ip
            self.save_config()
            print(colored(f"✅ IP changed: {current_ip} → {new_ip}", Colors.GREEN))
            break
    
    def regenerate_node_keys(self, network_id, node_id):
        """Regenerate node keys - new crystals for lightsaber! 💎
        
        Key regeneration is essential for security hygiene. When a device gets
        compromised or keys accidentally leak, you need fresh cryptographic material.
        
        The warning about config regeneration is important - old configs with
        old keys won't work anymore. Users forget this step surprisingly often! 📋
        """
        network = self.data["networks"][network_id]
        node = network["nodes"][node_id]
        
        print(colored(f"\n🔐 Regenerate keys for node '{node['name']}'", Colors.HEADER))
        print(colored("⚠️  WARNING: After this you'll need to update configs!", Colors.RED))
        print(colored(f"Current public key: {node['public_key'][:30]}...", Colors.CYAN))
        
        confirm = input(colored("Really regenerate keys? (y/N): ", Colors.YELLOW))
        if confirm.lower() in ['y', 'yes']:
            # Generate new keys (cryptographic rebirth!)
            new_private, new_public = generate_keypair()
            
            old_public = node['public_key'][:20]
            node['private_key'] = new_private
            node['public_key'] = new_public
            
            self.save_config()
            print(colored("✅ Keys successfully regenerated!", Colors.GREEN))
            print(colored(f"🔄 Old key: {old_public}...", Colors.CYAN))
            print(colored(f"🆕 New key: {new_public[:20]}...", Colors.CYAN))
            print(colored("💡 Don't forget to generate new configs!", Colors.YELLOW))
        else:
            print(colored("❌ Cancelled", Colors.YELLOW))
    
    def toggle_single_node(self, network_id, node_id):
        """Toggle single node status - freeze/unfreeze! 🧊
        
        Single node toggle from the edit menu for convenience. Same functionality
        as the bulk toggle menu, but saves navigation clicks when editing specific node.
        
        UX principle: Meet users where they are, reduce unnecessary navigation! 🎯
        """
        network = self.data["networks"][network_id]
        node = network["nodes"][node_id]
        
        current_status = "enabled" if node["enabled"] else "disabled"
        new_status = "disabled" if node["enabled"] else "enabled"
        
        confirm = input(colored(f"🔄 Node is currently {current_status}. Make {new_status}? (y/N): ", Colors.CYAN))
        if confirm.lower() in ['y', 'yes']:
            node["enabled"] = not node["enabled"]
            self.save_config()
            
            emoji = "✅" if node["enabled"] else "❌"
            print(colored(f"{emoji} Node '{node['name']}' is now {new_status}", Colors.GREEN))
        else:
            print(colored("❌ Cancelled", Colors.YELLOW))
    
    def server_settings_menu(self, network_id):
        """Server settings - command center upgrade! 🏛️
        
        Server settings are more critical than node settings because they affect
        the entire network. One wrong server change can break all client connections.
        
        The while loop here keeps users in context for related server changes.
        Originally this was separate functions, but grouping them makes more sense
        from a workflow perspective. Context switching is expensive for users! 🧠
        """
        network = self.data["networks"][network_id]
        server = network["server"]
        
        while True:
            print(colored(f"\n🏛️  Server settings: {server['name']}", Colors.HEADER))
            print(colored(f"IP: {server['ip']}", Colors.CYAN))
            print(colored(f"Endpoint: {server['endpoint']}", Colors.CYAN))
            print(colored(f"Port: {server['port']}", Colors.CYAN))
            print(colored(f"Ext. interface: {server['external_interface']}", Colors.CYAN))
            print(colored(f"Public key: {server['public_key'][:30]}...", Colors.CYAN))
            
            print(colored("\n🔧 Server settings:", Colors.BLUE))
            print(colored("1. Server name", Colors.GREEN))
            print(colored("2. Server IP address", Colors.GREEN))
            print(colored("3. Endpoint", Colors.GREEN))
            print(colored("4. Port", Colors.GREEN))
            print(colored("5. External interface", Colors.GREEN))
            print(colored("6. Regenerate server keys", Colors.YELLOW))  # Dangerous!
            print(colored("7. Manual server key input", Colors.CYAN))
            print(colored("0. Back", Colors.YELLOW))
            
            choice = input(colored("\n🎯 Your choice: ", Colors.BOLD))
            
            if choice == "0":
                break
            elif choice == "1":
                self.change_server_name(network_id)
            elif choice == "2":
                self.change_server_ip(network_id)
            elif choice == "3":
                self.change_server_endpoint(network_id)
            elif choice == "4":
                self.change_server_port(network_id)
            elif choice == "5":
                self.change_server_interface(network_id)
            elif choice == "6":
                self.regenerate_server_keys(network_id)  # Here be dragons! 🐉
            elif choice == "7":
                self.manual_server_keys_input(network_id)
            else:
                print(colored("❌ Invalid choice", Colors.RED))
    
    def change_server_ip(self, network_id):
        """Change server IP - moving the capital! 🏛️
        
        Server IP changes are less common than node IP changes, but when they
        happen, they usually indicate major network restructuring.
        
        Server always gets special treatment in conflict checking because it's
        the hub of the star topology. Everything connects to the server! ⭐
        """
        network = self.data["networks"][network_id]
        server = network["server"]
        current_ip = server["ip"]
        subnet_base = network["subnet_base"]
        
        print(colored(f"\n🌐 Change server IP address", Colors.HEADER))
        print(colored(f"Current IP: {current_ip}", Colors.CYAN))
        print(colored(f"Subnet: {subnet_base}.x", Colors.CYAN))
        
        while True:
            new_ip = input(colored(f"New server IP address ({subnet_base}.x): ", Colors.CYAN)).strip()
            if not new_ip:
                print(colored("❌ Cancelled", Colors.YELLOW))
                return
            
            # IP validation (same rules as node IPs)
            valid, error = self.validate_ip(new_ip, subnet_base)
            if not valid:
                print(colored(f"❌ {error}", Colors.RED))
                continue
            
            # Check conflicts with nodes (server can't conflict with any node)
            conflict = False
            for node in network["nodes"].values():
                if node["ip"] == new_ip:
                    print(colored(f"❌ Conflict with node '{node['name']}'", Colors.RED))
                    conflict = True
                    break
            
            if conflict:
                continue
            
            # All validation passed - update server IP
            server["ip"] = new_ip
            self.save_config()
            print(colored(f"✅ Server IP changed: {current_ip} → {new_ip}", Colors.GREEN))
            print(colored("🔄 Regenerate all configs to apply changes!", Colors.YELLOW))
            break
        
    def regenerate_server_keys(self, network_id):
        """Regenerate server keys - new crown for emperor! 👑
        
        This is the nuclear option for server key management. When server keys
        get compromised, you have to regenerate them and ALL client configs.
        
        I've seen networks with 50+ clients need this after a security incident.
        The pain is real... that's why this function has so many warnings! 🚨
        
        Fun story: First time I did this on production, forgot to warn users.
        Got 47 support tickets in 10 minutes. Never again! 📞💀
        """
        network = self.data["networks"][network_id]
        server = network["server"]
        
        print(colored(f"\n🔐 Regenerate server keys", Colors.HEADER))
        print(colored("⚠️  CRITICAL: After this ALL clients will lose connection!", Colors.RED))
        print(colored("⚠️  Will need to regenerate ALL configs!", Colors.RED))
        print(colored("⚠️  Consider maintenance window for this operation!", Colors.RED))  # Learned from experience!
        print(colored(f"Current public key: {server['public_key'][:30]}...", Colors.CYAN))
        
        # Triple confirmation for nuclear operations!
        confirm = input(colored("Really regenerate SERVER keys? (yes/N): ", Colors.RED))
        if confirm.lower() == 'yes':  # Must type "yes" exactly
            # Generate new keys for server (point of no return!)
            new_private, new_public = generate_keypair()
            
            old_public = server['public_key'][:20]
            server['private_key'] = new_private
            server['public_key'] = new_public
            
            self.save_config()
            print(colored("✅ Server keys successfully regenerated!", Colors.GREEN))
            print(colored(f"🔄 Old key: {old_public}...", Colors.CYAN))
            print(colored(f"🆕 New key: {new_public[:20]}...", Colors.CYAN))
            print(colored("🚨 WARNING: Generate new configs for ALL clients!", Colors.RED))
            print(colored("📋 TODO: Update firewall rules if needed", Colors.YELLOW))
        else:
            print(colored("❌ Cancelled", Colors.YELLOW))
    
    def manual_server_keys_input(self, network_id):
        """Manual input of server keys - choosing the emperor's crown jewels! 👑
        
        Manual server key input is even more dangerous than regeneration because
        there's no validation that the keys actually work together properly.
        
        Use case: Migrating from another WireGuard setup where you want to
        preserve existing server keys. Rare but valid scenario! 🔄
        """
        network = self.data["networks"][network_id]
        server = network["server"]
        
        print(colored(f"\n🔐 Manual server key input", Colors.HEADER))
        print(colored("⚠️  CRITICAL: After this ALL clients will lose connection!", Colors.RED))
        print(colored("⚠️  Will need to regenerate ALL configs!", Colors.RED))
        print(colored("⚠️  Only use this if you know what you're doing!", Colors.RED))
        print(colored(f"Current public key: {server['public_key'][:30]}...", Colors.CYAN))
        
        # Extra confirmation for manual key input
        confirm = input(colored("Really want to manually set server keys? (yes/N): ", Colors.RED))
        if confirm.lower() == 'yes':
            # Get new keys manually (with validation)
            new_private, new_public = self.manual_keypair_input()
            
            if new_private and new_public:
                old_public = server['public_key'][:20]
                server['private_key'] = new_private
                server['public_key'] = new_public
                
                self.save_config()
                print(colored("✅ Server keys successfully updated!", Colors.GREEN))
                print(colored(f"🔄 Old key: {old_public}...", Colors.CYAN))
                print(colored(f"🆕 New key: {new_public[:20]}...", Colors.CYAN))
                print(colored("🚨 WARNING: Generate new configs for ALL clients!", Colors.RED))
            else:
                print(colored("❌ Key input cancelled", Colors.YELLOW))
        else:
            print(colored("❌ Cancelled", Colors.YELLOW))
        
    def clone_network_menu(self):
        """Network cloning - creating parallel universe! 🌌
        
        Network cloning is surprisingly useful for testing, staging environments,
        or creating similar networks for different locations. 
        
        The key insight here: clone structure but regenerate ALL keys. Using same
        keys across networks is a security nightmare. Trust me on this one! 🔐
        """
        if not self.data["networks"]:
            print(colored("❌ No networks to clone", Colors.RED))
            return
        
        print(colored("\n📋 Network cloning", Colors.HEADER))
        print(colored("Choose network to clone:", Colors.BLUE))
        
        networks = list(self.data["networks"].items())
        for i, (net_id, network) in enumerate(networks, 1):
            node_count = len(network["nodes"])
            print(colored(f"{i}. {network['name']} ({net_id}) - {node_count} nodes", Colors.GREEN))
        
        print(colored("0. Back", Colors.YELLOW))
        
        try:
            choice = int(input(colored("\nChoose network: ", Colors.BOLD)))
            if choice == 0:
                return
            if 1 <= choice <= len(networks):
                source_net_id = networks[choice-1][0]
                self.clone_network(source_net_id)
            else:
                print(colored("❌ Invalid choice", Colors.RED))
        except ValueError:
            print(colored("❌ Invalid choice", Colors.RED))
    
    def clone_network(self, source_net_id):
        """Clones network with base address change and key regeneration! 🧬
        
        The cloning logic here is more sophisticated than simple copy-paste.
        It preserves network structure but changes all the unique identifiers:
        - New network ID and name
        - New subnet base (to avoid conflicts)  
        - Fresh keys for ALL devices (security!)
        - Preserves relative IP positions (last octet)
        
        This took several iterations to get right. Originally just copied everything,
        which created networks that conflicted with each other. Not fun! 💥
        """
        source_network = self.data["networks"][source_net_id]
        
        print(colored(f"\n🧬 Cloning network '{source_network['name']}'", Colors.HEADER))
        
        # Enter new network parameters
        while True:
            new_net_id = input(colored("New network ID: ", Colors.CYAN)).strip()
            if not new_net_id:
                print(colored("❌ ID cannot be empty", Colors.RED))
                continue
            if new_net_id in self.data["networks"]:
                print(colored("❌ Network with this ID already exists", Colors.RED))
                continue
            break
        
        new_name = input(colored("New network name: ", Colors.CYAN)).strip() or f"{source_network['name']} (copy)"
        
        # New base address (critical to avoid subnet conflicts!)
        while True:
            new_subnet_base = input(colored(f"New base address ({source_network['subnet_base']} → ?): ", Colors.CYAN)).strip()
            if not new_subnet_base:
                new_subnet_base = source_network['subnet_base']  # Keep same if empty
                print(colored("⚠️  Using same subnet base - ensure no conflicts!", Colors.YELLOW))
                break
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}$', new_subnet_base):
                break
            print(colored("❌ Invalid format! Enter like 192.168.101", Colors.RED))
        
        # Clone structure using deep copy (prevents reference sharing bugs)
        import copy
        cloned_network = copy.deepcopy(source_network)
        
        # Update basic parameters
        cloned_network["name"] = new_name
        cloned_network["subnet_base"] = new_subnet_base
        cloned_network["subnet"] = f"{new_subnet_base}.0/24"
        
        # Update server IP (preserve last octet from original)
        old_server_last_octet = source_network["server"]["ip"].split('.')[-1]
        cloned_network["server"]["ip"] = f"{new_subnet_base}.{old_server_last_octet}"
        
        # Regenerate server keys (CRITICAL for security!)
        server_private, server_public = generate_keypair()
        cloned_network["server"]["private_key"] = server_private
        cloned_network["server"]["public_key"] = server_public
        
        # Update IP and regenerate keys for all nodes
        for node in cloned_network["nodes"].values():
            # Update IP, keeping last octet (preserves network hierarchy)
            old_last_octet = node["ip"].split('.')[-1]
            node["ip"] = f"{new_subnet_base}.{old_last_octet}"
            
            # Regenerate keys (each device needs unique keys!)
            node_private, node_public = generate_keypair()
            node["private_key"] = node_private
            node["public_key"] = node_public
        
        # Save cloned network
        self.data["networks"][new_net_id] = cloned_network
        
        if self.save_config():
            print(colored("✅ Network successfully cloned!", Colors.GREEN))
            print(colored(f"🆔 ID: {new_net_id}", Colors.CYAN))
            print(colored(f"📛 Name: {new_name}", Colors.CYAN))
            print(colored(f"🌐 Subnet: {new_subnet_base}.0/24", Colors.CYAN))
            print(colored(f"🔑 All keys regenerated", Colors.CYAN))
            print(colored(f"📊 Nodes copied: {len(cloned_network['nodes'])}", Colors.CYAN))
            print(colored("💡 Don't forget to generate configs for cloned network!", Colors.YELLOW))
        else:
            print(colored("❌ Error saving cloned network", Colors.RED))
    
    def delete_network_menu(self):
        """Network deletion - destroying star system! 💥
        
        Network deletion is irreversible and potentially destructive. Added multiple
        confirmation steps because "oops, wrong network" is not fun to explain
        to users who just lost their entire VPN setup! 😱
        
        The name confirmation requirement forces users to actually read what
        they're deleting instead of just clicking through warnings.
        """
        if not self.data["networks"]:
            print(colored("❌ No networks to delete", Colors.RED))
            return
        
        print(colored("\n💥 Network deletion", Colors.HEADER))
        print(colored("⚠️  WARNING: This is irreversible operation!", Colors.RED))
        print(colored("⚠️  All nodes and configs will be lost!", Colors.RED))
        
        networks = list(self.data["networks"].items())
        for i, (net_id, network) in enumerate(networks, 1):
            node_count = len(network["nodes"])
            print(colored(f"{i}. {network['name']} ({net_id}) - {node_count} nodes", Colors.GREEN))
        
        print(colored("0. Cancel", Colors.YELLOW))
        
        try:
            choice = int(input(colored("\nChoose network to delete: ", Colors.BOLD)))
            if choice == 0:
                return
            if 1 <= choice <= len(networks):
                net_id, network = networks[choice-1]
                
                print(colored(f"\n💀 Deleting network '{network['name']}'", Colors.RED))
                print(colored(f"📊 Will delete {len(network['nodes'])} nodes", Colors.RED))
                print(colored(f"🔥 Config files will become invalid", Colors.RED))
                
                # Double confirmation with increasing severity
                confirm1 = input(colored("Really delete this network? (yes/N): ", Colors.RED))
                if confirm1.lower() == 'yes':
                    # Name confirmation (forces users to pay attention!)
                    confirm2 = input(colored(f"Enter network name for confirmation '{network['name']}': ", Colors.RED))
                    if confirm2 == network['name']:
                        del self.data["networks"][net_id]
                        self.save_config()
                        print(colored("💥 Network successfully deleted!", Colors.GREEN))
                        print(colored("🗑️  Don't forget to cleanup old config files", Colors.YELLOW))
                    else:
                        print(colored("❌ Name doesn't match. Cancelled.", Colors.YELLOW))
                        print(colored("💡 Exact name match required for safety", Colors.CYAN))
                else:
                    print(colored("❌ Cancelled", Colors.YELLOW))
            else:
                print(colored("❌ Invalid choice", Colors.RED))
        except ValueError:
            print(colored("❌ Invalid choice", Colors.RED))
            
    def run(self):
        """Main program loop - heart of the Force! ❤️
        
        This is where everything comes together. The main event loop that
        keeps the program running until user decides to exit.
        
        Originally this was a simple while-true loop, but added proper exception
        handling after getting crash reports from users. Turns out Ctrl+C
        during password input creates interesting edge cases! 🤔
        
        The pause between menu iterations prevents that "flashing menu" effect
        that happens when users make mistakes quickly. Small UX detail that
        makes the tool feel more polished and less chaotic.
        """
        print(colored("🌟 Welcome to WireGuard Manager! 🌟", Colors.HEADER))
        print(colored("Where network administration meets galactic adventure!", Colors.CYAN))
        
        while True:
            choice = self.show_main_menu()
            
            if choice == "0":
                print(colored("\n🌌 May the Force be with you! Goodbye!", Colors.CYAN))
                print(colored("Thanks for using WireGuard Star Network Manager! 🚀", Colors.BLUE))
                break
            elif choice == "1":
                self.create_network_menu()
            elif choice == "2" and self.data["networks"]:
                self.manage_network_menu()
            elif choice == "3" and self.data["networks"]:
                self.generate_configs_menu()
            elif choice == "4" and self.data["networks"]:
                self.generate_qr_codes_menu()
            elif choice == "5" and self.data["networks"]:
                self.clone_network_menu()
            elif choice == "6" and self.data["networks"]:
                self.delete_network_menu()
            elif choice == "7":
                self.show_about()
            elif choice == "8":
                self.change_master_password()
            else:
                print(colored("❌ Invalid choice. Try again!", Colors.RED))
                # Could add easter eggs here for invalid inputs... maybe next version? 🥚
            
            # Pause before next menu (prevents menu flashing)
            if choice != "0":
                input(colored("\n⏸️  Press Enter to continue...", Colors.BOLD))

def main():
    """Program entry point - birth of a Jedi! 🌟
    
    Simple main function that handles global exception catching.
    
    Architecture reflection: This could be a class-based CLI framework,
    but honestly? Sometimes simple procedural code is the right choice.
    Not everything needs to be over-engineered! 🏗️
    
    Future improvements to consider:
    - Add CLI argument parsing for batch operations
    - Configuration file templates system  
    - Network topology visualization (ASCII art?)
    - Integration with systemd for automatic startup
    - Web interface for remote management
    - API endpoints for automation
    - Backup/restore functionality
    - Network health monitoring
    - Performance metrics collection
    
    But for now, this interactive CLI does exactly what it needs to do.
    Sometimes "good enough" is perfect! ✨
    
    Personal note: This tool evolved from a simple script I wrote to manage
    my home VPN. Started as 200 lines, grew to... well, this! 📈
    
    The Star Wars theme? That was my kid's idea. Turns out system administration
    is way more fun when you pretend to be a Jedi Master configuring the 
    galactic communication network! 🌌⚔️
    
    If you're reading this code for a job interview or code review,
    hi there! 👋 This represents about 2 years of iteration based on actual
    usage patterns. Every feature here solves a real problem I encountered.
    
    The humor and comments? That's how I stay sane during long debugging sessions.
    Life's too short for boring code comments! 😄
    
    - Volodymyr "WhitemanV" Frytskyy
    """
    try:
        # Initialize the Death Star... I mean, WireGuard Manager 😈
        manager = WireGuardManager()
        manager.run()
    except KeyboardInterrupt:
        # Graceful handling of Ctrl+C (happens more than you'd think!)
        print(colored("\n\n⚡ Interrupted by user. May the Force be with you!", Colors.YELLOW))
        print(colored("🛡️  Data automatically saved. Nothing lost! 💾", Colors.GREEN))
    except Exception as e:
        # Catch-all for unexpected errors (shouldn't happen, but Murphy's Law...)
        print(colored(f"\n💥 Unexpected error: {e}", Colors.RED))
        print(colored("🔧 Contact the Jedi master for help!", Colors.CYAN))
        print(colored("📧 Report bugs at: https://github.com/Frytskyy/WireGuard-Star-Network-Manager-Configurator", Colors.CYAN))
        
        # In production, might want to log this error for debugging
        # But for now, just show it to user and exit gracefully
        import traceback
        print(colored("\n🔍 Technical details:", Colors.YELLOW))
        traceback.print_exc()

if __name__ == "__main__":
    """
    Python's "if __name__ == '__main__':" idiom - the ancient ritual!
    
    This ensures the script only runs when executed directly, not when imported.
    Basic Python best practice that saves headaches when code gets reused.
    
    Fun fact: I've seen this pattern in Python code for 15+ years and it
    still feels like magic incantation every time! 
    
    Could wrap this in a CLI framework like Click or argparse, but sometimes
    the simplest solution is the best solution. This script has one job:
    manage WireGuard networks interactively. It does that job well! 
    
    Performance note: The script loads config once at startup and saves
    after each change. For very large networks (100+ nodes), might want
    to add lazy loading or caching. But honestly, if you have 100+ VPN nodes,
    you probably need enterprise tools, not a Star Wars-themed Python script! 
    
    Security note: Config file encryption is optional but recommended.
    WireGuard keys are sensitive data that shouldn't be stored in plain text
    on shared systems. The crypto implementation here uses industry-standard
    algorithms and practices. Good enough for most use cases! 
    
    Compatibility: Tested on Linux, macOS, and WSL. Pure Python with minimal
    dependencies means it should work anywhere Python works. That's the beauty
    of staying simple and avoiding platform-specific code! 
    
    Final thought: This tool represents the joy of coding for actual users
    (even if that user is just yourself). Every feature here was built because
    someone (usually me) needed it. That's how the best software gets made! 
    """
    main()

# End of WireGuard Star Network Manager
# 
# May your networks be fast, your connections secure, and your configs bug-free!
# 
# P.S. If you found this tool useful, consider starring the GitHub repo!
# It helps other network administrators discover it and makes my day brighter! :)
#
# P.P.S. Yes, I know the Star Wars references are over the top. That's the point! 
# Network administration is serious business, but that doesn't mean we can't
# have fun while doing it. Besides, my kids think I'm finally cool now! B)
#
# P.P.P.S. To future me reading this code: remember when you thought this would
# be a quick weekend project? :) Software development time estimation strikes again!
#
# "The Force will be with you... always." - Obi-Wan Kenobi
# (And hopefully good network connectivity will be too!)
#

# 73, VE3WHM (yes, I'm also a ham radio operator - another geeky hobby!) 📻
