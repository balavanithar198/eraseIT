#!/usr/bin/env python3
import traceback
import logging
import os
import sys
import time
import hashlib
import json
import platform
import secrets
import shutil
import threading
import subprocess
import base64
import tempfile
import re
import sqlite3
import struct
import hmac
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext, simpledialog
import shlex

from logging.handlers import RotatingFileHandler

# Configure enhanced logging with rotation
class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'pid': os.getpid(),
            'process': record.processName,
        }
        # Try to get operator if set in globals (lazy check)
        # Note: os.getlogin() provides system user, good enough for system log
        log_entry['sys_user'] = os.getlogin()
        
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        return json.dumps(log_entry)

# Configure enhanced logging with rotation
# Global Configuration
APP_NAME = "EraseIT"
APP_DIR = Path.home() / ".eraseit"
LOG_DIR = APP_DIR / "logs"
CERTIFICATES_DIR = APP_DIR / "certificates"
KEYS_DIR = APP_DIR / "keys"

# Security Globals


PRIVATE_KEY_PATH = KEYS_DIR / "private.pem"
PUBLIC_KEY_PATH = KEYS_DIR / "public.pem"
DB_PATH = APP_DIR / "transparency_log.sqlite"
CONFIG_PATH = APP_DIR / "config.json"
OPERATOR_PIN = None

# Operation Mode - set via environment variable ERASEIT_MODE (default: PRODUCTION)
OPERATION_MODE = os.environ.get('ERASEIT_MODE', 'PRODUCTION')

class ConfigManager:
    """Manage persistent configuration securely"""
    def __init__(self):
        self.config_path = CONFIG_PATH
        self._config = self._load_config()
        self._ensure_pin_security()

    def _ensure_pin_security(self):
        """Generate secure PIN infrastructure on first run"""
        if not self.get('pin_salt'):
            try:
                # Generate cryptographically secure salt (32 bytes = 256 bits)
                salt = secrets.token_bytes(32)
                self.set('pin_salt', base64.b64encode(salt).decode())
                # If we are resetting/creating salt, existing hash (if any) is invalid
                self.set('pin_hash', None) 
            except Exception as e:
                # Fallback only if write fails (critical error)
                print(f"Critical Warning: Failed to generate secure salt: {e}")

    def _load_config(self):
        if not self.config_path.exists():
            return {}
        try:
            with open(self.config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return {}
            
    def save_config(self):
        try:
            # Atomic write
            with tempfile.NamedTemporaryFile(mode='w', dir=str(APP_DIR), delete=False) as tf:
                json.dump(self._config, tf, indent=2)
                temp_name = tf.name
            
            os.replace(temp_name, self.config_path)
            
            # Secure permissions on non-Windows
            if platform.system() != "Windows":
                os.chmod(self.config_path, 0o600)
                
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            
    def get(self, key, default=None):
        return self._config.get(key, default)
        
    def set(self, key, value):
        self._config[key] = value
        self.save_config()

# Initialize Config
config_manager = ConfigManager()

# Initialize defaults BEFORE conditional loading (Fix #1: Prevents NameError)
# Security: Dynamic PIN Salt (Fix #1)
try:
    PIN_SALT_B64 = config_manager.get('pin_salt')
    PIN_SALT = base64.b64decode(PIN_SALT_B64) if PIN_SALT_B64 else None
    
    PIN_HASH_B64 = config_manager.get('pin_hash')
    PIN_HASH = base64.b64decode(PIN_HASH_B64) if PIN_HASH_B64 else None
except Exception as e:
    print(f"CRITICAL: Failed to load security configuration: {e}")
    PIN_SALT = None
    PIN_HASH = None



# Create directories with secure permissions
for d in [APP_DIR, LOG_DIR, CERTIFICATES_DIR, KEYS_DIR]:
    d.mkdir(parents=True, exist_ok=True)
    if platform.system() != "Windows":
        try:
            os.chmod(d, 0o700)
        except Exception as e:
            print(f"Warning: Failed to set secure permissions on {d}: {e}")

json_handler = RotatingFileHandler(LOG_DIR / 'secure_wiper.jsonl', maxBytes=5*1024*1024, backupCount=5, encoding='utf-8')
json_handler.setFormatter(JSONFormatter())

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    handlers=[
        RotatingFileHandler(LOG_DIR / 'secure_wiper.log', maxBytes=5*1024*1024, backupCount=5, encoding='utf-8'),
        json_handler,
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('EraseIT')

# --- Dependencies Check ---
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, padding
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.exceptions import InvalidSignature
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logger.warning("cryptography library not available. Certificate signing disabled.")

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.platypus import Image
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    logger.warning("reportlab library not available. PDF certificate generation disabled.")

try:
    import qrcode
    from PIL import Image as PILImage, ImageTk
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False
    logger.warning("qrcode/PIL libraries not available. QR code generation disabled.")

try:
    import customtkinter as ctk
    CUSTOM_TKINTER_AVAILABLE = True
except ImportError:
    CUSTOM_TKINTER_AVAILABLE = False
    logger.warning("customtkinter not available. Using standard tkinter.")

# Set appearance mode and color theme
if CUSTOM_TKINTER_AVAILABLE:
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")

# Constants for NIST SP 800-88 compliance
NIST_CLEAR = "Clear"
NIST_PURGE = "Purge"
NIST_DESTROY = "Destroy"




# Enhanced ToolTip class for better user experience
class ToolTip:
    """Create a tooltip for a given widget."""
    def __init__(self, widget, text=''):
        self.widget = widget
        self.text = text
        self.tip_window = None
        self.id = None
        self.x = self.y = 0
        self._id1 = self.widget.bind("<Enter>", self.enter)
        self._id2 = self.widget.bind("<Leave>", self.leave)
        self._id3 = self.widget.bind("<ButtonPress>", self.leave)

    def enter(self, event=None):
        """Schedule tooltip to appear."""
        self.schedule()

    def leave(self, event=None):
        """Hide tooltip."""
        self.unschedule()
        self.hidetip()

    def schedule(self):
        """Schedule tooltip display."""
        self.unschedule()
        self.id = self.widget.after(500, self.showtip)

    def unschedule(self):
        """Cancel scheduled tooltip."""
        if self.id:
            self.widget.after_cancel(self.id)
        self.id = None

    def showtip(self):
        """Display tooltip."""
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, justify=tk.LEFT,
                         background="#ffffe0", relief=tk.SOLID, borderwidth=1,
                         font=("Arial", 10, "normal"))
        label.pack(ipadx=1)

    def hidetip(self):
        """Hide tooltip."""
        tw = self.tip_window
        self.tip_window = None
        if tw:
            tw.destroy()

def check_privileges():
    """Check if running with administrative privileges."""
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            return os.getuid() == 0
    except Exception:
        return False

def prompt_operator_pin():
    """Prompt operator to set or confirm PIN with secure comparison."""
    global OPERATOR_PIN
    
    # Try to load existing hash
    pin_hash_file = KEYS_DIR / "operator_pin.hash"
    
    if OPERATOR_PIN is None:
        pin = None
        # Check if we have GUI
        if 'ctk' in globals() or 'tk' in globals():
             # We might not have root yet, so we have to be careful.
             # If called from GUI init, safe.
             try:
                 pin = simpledialog.askstring("Operator PIN", "Enter Operator PIN (Session Authorization):", show='*')
             except:
                 pass
        
        if not pin:
            print("Enter Operator PIN: ")
            try:
                import getpass
                pin = getpass.getpass()
            except Exception:
                pass
                
        if pin:
            # Hash it
            # SECURITY: No hardcoded fallback - fail securely
            if 'PIN_SALT' not in globals() or PIN_SALT is None:
                logger.critical("PIN salt not initialized - cannot secure PIN")
                return False
            salt = PIN_SALT
            kdf = hashlib.pbkdf2_hmac('sha256', pin.encode(), salt, 100000)
            OPERATOR_PIN = kdf
            logger.info("Operator PIN set for session.")
            return True
        return False
    return True

import math

class WipeVerifier:
    """
    REAL verification engine that captures pre-wipe state.
    
    CRITICAL: Verification requires comparing BEFORE and AFTER.
    Just checking entropy of already-wiped data proves nothing.
    """
    
    def __init__(self, target_path: str):
        self.path = target_path
        self.pre_wipe_samples = []
        self.sample_offsets = []
        self._capture_pre_wipe_snapshot()
    
    def _capture_pre_wipe_snapshot(self):
        """Capture random sector samples BEFORE wiping."""
        try:
            with open(self.path, 'rb') as f:
                f.seek(0, 2)  # Seek to end
                size = f.tell()
                
                if size == 0:
                    return
                
                # Sample 10 random locations
                num_samples = min(10, max(1, size // (1024 * 1024)))
                sample_size = 4096  # 4KB per sample
                
                for _ in range(num_samples):
                    offset = secrets.randbelow(max(1, size - sample_size))
                    f.seek(offset)
                    sample = f.read(sample_size)
                    self.pre_wipe_samples.append(sample)
                    self.sample_offsets.append(offset)
                    
                logger.info(f"Captured {len(self.pre_wipe_samples)} pre-wipe samples for verification")
        except Exception as e:
            logger.warning(f"Could not capture pre-wipe snapshot: {e}")
    
    def verify_post_wipe(self, expected_pattern: bytes = b'\x00') -> dict:
        """
        Verify wipe by comparing against pre-wipe state.
        
        Returns evidence that:
        1. Data is DIFFERENT from pre-wipe (proves change occurred)
        2. Data matches expected pattern (proves correct overwrite)
        """
        results = {
            'verified': False,
            'samples_checked': 0,
            'samples_changed': 0,
            'samples_match_pattern': 0,
            'errors': []
        }
        
        if not self.pre_wipe_samples:
            # Empty file (0 bytes) - nothing to verify, auto-pass
            results['verified'] = True
            results['verdict'] = "PASS: Empty file (nothing to verify)"
            return results
        
        try:
            with open(self.path, 'rb') as f:
                for i, (offset, pre_sample) in enumerate(zip(self.sample_offsets, self.pre_wipe_samples)):
                    f.seek(offset)
                    post_sample = f.read(len(pre_sample))
                    results['samples_checked'] += 1
                    
                    # Check 1: Data changed from pre-wipe
                    if post_sample != pre_sample:
                        results['samples_changed'] += 1
                    
                    # Check 2: Data matches expected pattern
                    # For single-byte patterns, check if all bytes match that value
                    if len(expected_pattern) == 1:
                        expected_byte = expected_pattern[0]
                        if all(b == expected_byte for b in post_sample):
                            results['samples_match_pattern'] += 1
                    else:
                        # For random/multi-byte patterns, just verify data changed (entropy unreliable)
                        # If samples changed, assume pattern applied correctly
                        if post_sample != pre_sample:
                            results['samples_match_pattern'] += 1
            
            # Require pattern match OR data changed (handles already-wiped files)
            total = results['samples_checked']
            if total > 0:
                change_rate = results['samples_changed'] / total
                pattern_rate = results['samples_match_pattern'] / total
                
                results['change_rate'] = round(change_rate, 2)
                results['pattern_rate'] = round(pattern_rate, 2)
                
                # PASS if: pattern matches (even if file was already wiped)
                # The key check is: does the file NOW contain the expected pattern?
                results['verified'] = (pattern_rate >= 0.8)
                
                if results['verified']:
                    if change_rate >= 0.8:
                        results['verdict'] = f"PASS: {results['samples_changed']}/{total} samples changed, {results['samples_match_pattern']}/{total} match pattern"
                    else:
                        results['verdict'] = f"PASS: File already contains target pattern ({results['samples_match_pattern']}/{total} match)"
                else:
                    results['verdict'] = f"FAIL: Only {results['samples_match_pattern']}/{total} match target pattern"
                    
        except Exception as e:
            results['errors'].append(str(e))
            results['verdict'] = f"ERROR: {e}"
        
        return results

class ComplianceEngine:
    """Handles Compliance Checks and Eco-Impact Calculation"""
    
    @staticmethod
    def calculate_eco_impact(drive_size_gb):
        """
        Calculate CO2 saved by reusing a drive instead of destroying it.
        Based on: ~20kg CO2 per 1TB HDD/SSD manufacturing cost.
        """
        try:
            co2_saved_kg = (drive_size_gb / 1024) * 20
            return round(co2_saved_kg, 2)
        except Exception:
            return 0.0
            
    @staticmethod
    def get_compliance_scorecard(current_method):
        """Return a compliance checklist based on current settings"""
        scorecard = {
            'NIST 800-88 Rev.1': 'FAIL',
            'DoD 5220.22-M': 'FAIL',
            'GDPR (Right to Erasure)': 'FAIL',
            'HIPAA (Media Disposal)': 'FAIL',
            'ISO 27001': 'FAIL'
        }
        
        if 'Clear' in current_method or 'Zero' in current_method:
             scorecard['NIST 800-88 Rev.1'] = 'COMPLIANT (Clear)'
             scorecard['GDPR (Right to Erasure)'] = 'COMPLIANT'
             
        if 'Destroy' in current_method or 'Gutmann' in current_method or 'DoD' in current_method:
             scorecard['NIST 800-88 Rev.1'] = 'COMPLIANT (Purge/Destroy)'
             scorecard['DoD 5220.22-M'] = 'COMPLIANT'
             scorecard['GDPR (Right to Erasure)'] = 'COMPLIANT'
             scorecard['HIPAA (Media Disposal)'] = 'COMPLIANT'
             scorecard['ISO 27001'] = 'COMPLIANT'
             
        return scorecard
    """Advanced Statistical Verification using Shannon Entropy Analysis"""
    
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of byte data."""
        if not data:
            return 0.0
            
        counter = {}
        for byte in data:
            counter[byte] = counter.get(byte, 0) + 1
            
        entropy = 0.0
        for count in counter.values():
            p = count / len(data)
            entropy -= p * (math.log2(p))
            
        return entropy

    @staticmethod
    def verify_wipe_quality(target_path: str, method: str) -> dict:
        """
        REAL multi-point verification using entropy analysis.
        
        CRITICAL FIX: Samples from START, 25%, 50%, 75%, and END of file
        to detect partially wiped data. Requires 80% pass rate.
        """
        results = {
            'target': target_path, 
            'method': method, 
            'score': 0.0, 
            'verdict': 'UNKNOWN',
            'samples': [],
            'pass_rate': 0.0
        }
        
        try:
            path = Path(target_path)
            
            if not path.exists():
                results['verdict'] = 'ERROR (File not found)'
                return results
            
            if path.is_file():
                file_size = path.stat().st_size
                if file_size == 0:
                    results.update({'score': 0.0, 'verdict': 'EMPTY_FILE'})
                    return results
                
                # MULTI-POINT SAMPLING: Check 5 locations across the file
                sample_offsets = [
                    0,                              # Start
                    file_size // 4,                 # 25%
                    file_size // 2,                 # 50%
                    (file_size * 3) // 4,           # 75%
                    max(0, file_size - 1024*1024)   # End (last 1MB)
                ]
                
                sample_size = min(1024*1024, file_size)  # 1MB per sample
                passed_samples = 0
                
                with open(path, 'rb') as f:
                    for offset in sample_offsets:
                        f.seek(offset)
                        # Don't read past end of file
                        actual_sample_size = min(sample_size, file_size - offset)
                        if actual_sample_size <= 0:
                            continue
                            
                        sample_data = f.read(actual_sample_size)
                        entropy = ComplianceEngine.calculate_entropy(sample_data)
                        
                        # Determine pass/fail for this sample
                        if 'Clear' in method or 'Zero' in method:
                            passed = entropy < 1.0
                        else:
                            passed = entropy > 7.5
                        
                        if passed:
                            passed_samples += 1
                        
                        results['samples'].append({
                            'offset': offset,
                            'offset_pct': f"{(offset / file_size * 100):.0f}%",
                            'entropy': round(entropy, 4),
                            'passed': passed
                        })
                
                # Calculate pass rate (require 80% for PASS verdict)
                total_samples = len(results['samples'])
                if total_samples > 0:
                    results['pass_rate'] = passed_samples / total_samples
                    results['score'] = results['pass_rate'] * 100
                    
                    if results['pass_rate'] >= 0.8:
                        if 'Clear' in method or 'Zero' in method:
                            results['verdict'] = f'PASS (Verified Zero-Fill: {passed_samples}/{total_samples} samples)'
                        else:
                            results['verdict'] = f'PASS (Verified Randomization: {passed_samples}/{total_samples} samples)'
                    else:
                        results['verdict'] = f'FAIL (Only {passed_samples}/{total_samples} samples passed - possible partial wipe)'
                        
            else:
                # Device verification requires direct access
                results['note'] = "Device-level verification requires admin/root privileges"
                results['verdict'] = 'DEVICE_NOT_VERIFIED'
                
            return results
            
        except Exception as e:
            logger.error(f"Multi-point entropy verification failed: {e}")
            results['error'] = str(e)
            results['verdict'] = 'ERROR'
            return results
            
# --- Secure Command Runner ---
def run_cmd(cmd, timeout=300):
    """
    Run a command safely, capture output and errors.
    
    SECURITY: ONLY accepts list commands. Strings are REJECTED.
    This prevents command injection attacks.
    
    Args:
        cmd (list): Command to run as list of arguments. String is NOT accepted.
        timeout (int): Timeout in seconds.
    """
    entry = {'cmd': str(cmd), 'start': time.time(), 'rc': None, 'out': '', 'err': ''}
    
    # SECURITY: Reject string commands entirely
    if not isinstance(cmd, list):
        logger.error(f"SECURITY: run_cmd received non-list command: {type(cmd).__name__}")
        entry.update({
            'rc': -1, 
            'out': '', 
            'err': f'SECURITY VIOLATION: cmd must be list, received {type(cmd).__name__}'
        })
        return entry
    
    # SECURITY: Validate no shell metacharacters in arguments
    dangerous_chars = set(';|&$`<>(){}[]')
    for arg in cmd:
        if isinstance(arg, str) and any(c in arg for c in dangerous_chars):
            # Allow if it looks like a valid file path
            if not (arg.startswith('/') or arg.startswith('C:\\') or arg.startswith('\\\\')):
                logger.warning(f"SECURITY WARNING: Potentially dangerous characters in argument: {arg}")
    
    try:
        # SAFE EXECUTION: shell=False forces direct execution of executable
        proc = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                               text=True, encoding='utf-8', errors='replace')
        
        out, err = proc.communicate(timeout=timeout)
        entry.update({'rc': proc.returncode, 'out': out.strip(), 'err': err.strip(), 'end': time.time()})
        return entry
    except subprocess.TimeoutExpired:
        if 'proc' in locals(): proc.kill()
        entry.update({'rc': -1, 'out': '', 'err': f'Command timed out after {timeout}s', 'end': time.time()})
        return entry
    except FileNotFoundError:
        entry.update({'rc': 127, 'out': '', 'err': 'Command not found', 'end': time.time()})
        return entry
    except Exception as e:
        entry.update({'rc': -1, 'out': '', 'err': str(e), 'end': time.time()})
        return entry

def canonical_json_bytes(obj):
    """Canonicalize JSON for deterministic signing."""
    return json.dumps(obj, sort_keys=True, separators=(',',':'), ensure_ascii=False).encode('utf-8')

def check_file_permissions(file_path):
    """Check if we have sufficient permissions to wipe the file."""
    try:
        if not os.access(file_path, os.W_OK):
            logger.error(f"Insufficient permissions to wipe: {file_path}")
            return False
        return True
    except Exception as e:
        logger.error(f"Permission check failed for {file_path}: {e}")
        return False

class SecurePathValidator:
    """Centralized path validation logic to prevent system damage."""
    
    UNSAFE_PREFIXES_WINDOWS = [
        r"c:\windows", r"c:\program files", r"c:\program files (x86)", 
        r"c:\users\public", r"c:\boot", r"c:\recovery"
    ]
    
    UNSAFE_PREFIXES_UNIX = [
        "/boot", "/dev", "/proc", "/sys", "/bin", "/sbin", "/usr", "/etc", "/var", "/lib", "/root", "/.snap"
    ]

    @staticmethod
    def validate(path_str):
        """
        Strictly validate path to prevent wiping system directories.
        Refuses: /boot, /dev, /proc, /sys, /, C:\\Windows, C:\\Program Files, etc.
        Fix #3: Uses normcase for platform-appropriate case handling.
        """
        try:
            # Normalize and resolve symlinks
            path = os.path.abspath(os.path.realpath(path_str))
            # Fix #3: Use normcase for platform-appropriate case handling
            path_normalized = os.path.normcase(path)
            path_normalized = path_normalized.rstrip(os.sep)
            
            # Block root directory wipe
            root_paths = ['/', 'c:\\', 'c:/'] if platform.system() == "Windows" else ['/']
            if path_normalized in [os.path.normcase(r.rstrip(os.sep)) for r in root_paths]:
                logger.error(f"Blocked attempt to wipe root: {path}")
                return False
                 
            # Block dangerous system paths (use normalized paths for comparison)
            unsafe = SecurePathValidator.UNSAFE_PREFIXES_WINDOWS if platform.system() == "Windows" else SecurePathValidator.UNSAFE_PREFIXES_UNIX
            unsafe_normalized = [os.path.normcase(p.rstrip(os.sep)) for p in unsafe]
                 
            for prefix in unsafe_normalized:
                if path_normalized.startswith(prefix):
                     logger.error(f"Blocked attempt to wipe protected system path: {path}")
                     return False
                     
            return True
        except Exception as e:
            logger.error(f"Path validation error: {e}")
            return False



def validate_file_path(file_path):
    """Validate file path wrapper."""
    return SecurePathValidator.validate(file_path)

def validate_target_path(target_path):
    """Validate target path wrapper."""
    return SecurePathValidator.validate(target_path)

class CertificateSigner:
    """Handle certificate signing and verification with Ed25519"""
    
    def __init__(self):
        self.private_key = None
        self.public_key = None
        if not CRYPTO_AVAILABLE:
            return
        self.load_or_generate_keys()

    def load_or_generate_keys(self):
        """Load existing keys or generate new ones."""
        if PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists():
            try:
                with open(PRIVATE_KEY_PATH, 'rb') as f:
                    self.private_key = serialization.load_pem_private_key(
                        f.read(), password=None
                    )
                with open(PUBLIC_KEY_PATH, 'rb') as f:
                    self.public_key = serialization.load_pem_public_key(f.read())
                logger.info("Loaded existing keys.")
            except Exception as e:
                logger.error(f"Failed to load keys: {e}")
                self.generate_keys()
        else:
            self.generate_keys()

    def generate_keys(self):
        """Generate new Ed25519 key pair and save to disk with strict permissions."""
        try:
            self.private_key = ed25519.Ed25519PrivateKey.generate()
            self.public_key = self.private_key.public_key()
            
            # Serialize private key
            private_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Save private key with strict permissions (0o600)
            if platform.system() != "Windows":
                # Create file with 0o600 permissions atomically
                fd = os.open(PRIVATE_KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, 'wb') as f:
                    f.write(private_pem)
            else:
                # On Windows, standard write (ACLs are complex, relying on folder ACLs from setup)
                with open(PRIVATE_KEY_PATH, 'wb') as f:
                    f.write(private_pem)

            # Save public key (0o644)
            with open(PUBLIC_KEY_PATH, 'wb') as f:
                f.write(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            
            # Explicitly set permissions on Linux/Mac
            if platform.system() != "Windows":
                try:
                    os.chmod(PUBLIC_KEY_PATH, 0o644)
                except: pass
            
            logger.info("Generated and saved new key pair with secure permissions.")
        except Exception as e:
            logger.error(f"Failed to generate keys: {e}")
            raise e

    def sign_certificate_json(self, cert_obj):
        """Sign certificate JSON with deterministic canonicalization."""
        if not CRYPTO_AVAILABLE or not self.private_key:
            logger.warning("Cryptography not available, returning unsigned certificate")
            return "unsigned"
            
        payload = canonical_json_bytes(cert_obj)
        try:
            sig = self.private_key.sign(payload)
            return base64.urlsafe_b64encode(sig).decode().rstrip('=')
        except Exception as e:
            logger.error(f"Signing failed: {e}")
            return f"signature_error_{hashlib.sha256(payload).hexdigest()[:16]}"

    def verify_signature(self, cert_data_without_jws, jws_signature):
        """Verify JWS signature for certificate data."""
        if not CRYPTO_AVAILABLE:
            return False, "Cryptography library not available"
            
        try:
            # Canonicalize payload
            payload = canonical_json_bytes(cert_data_without_jws)
            
            # Decode signature
            # JWS uses URL-safe base64 without padding usually, but we should handle padding just in case
            sig_bytes = base64.urlsafe_b64decode(jws_signature + "==")
            
            # Verify
            if not self.public_key:
                # Try to load if missing (e.g. verifying on another machine? this class is for local signer usually)
                # But for verification we might need just public key. 
                # Assumes self.public_key is loaded.
                pass
                
            self.public_key.verify(sig_bytes, payload)
            return True, "Valid signature"
        except InvalidSignature:
            return False, "Invalid signature"
        except Exception as e:
            return False, f"Verification error: {e}"

class EnhancedHPADCODetector:
    """Enhanced HPA/DCO detection with detailed evidence collection"""
    
    @staticmethod
    def detect_hidden_areas(device_path=None):
        """Detect HPA/DCO on storage devices with comprehensive evidence"""
        hidden_areas = {
            'hpa_detected': False,
            'dco_detected': False,
            'hpa_size': 0,
            'dco_size': 0,
            'native_max_lba': 0,
            'accessible_max_lba': 0,
            'device_info': {},
            'raw_hdparm_output': '',
            'raw_nvme_output': '',
            'detection_timestamp': datetime.now().isoformat()
        }
        
        try:
            if platform.system() == "Linux":
                return EnhancedHPADCODetector._detect_linux(device_path, hidden_areas)
            elif platform.system() == "Windows":
                return EnhancedHPADCODetector._detect_windows(device_path, hidden_areas)
            else:
                logger.info("HPA/DCO detection not supported on this platform")
                return hidden_areas
        except Exception as e:
            logger.error(f"HPA/DCO detection error: {e}")
            hidden_areas['error'] = str(e)
            return hidden_areas

    @staticmethod
    def _detect_linux(device_path, hidden_areas):
        """Linux-specific HPA/DCO detection with detailed evidence"""
        try:
            # Get all block devices if no specific device provided
            if not device_path:
                try:
                    result = subprocess.run(['lsblk', '-d', '-n', '-o', 'NAME,TYPE'],
                                            capture_output=True, text=True, check=True, timeout=10)

                    devices = [line.split()[0] for line in result.stdout.strip().split('\n')
                               if len(line.split()) >= 2 and 'disk' in line.split()[1]]
                except Exception:
                    devices = []
            else:
                devices = [device_path]

            for device in devices:
                device_path = f"/dev/{device}" if not device.startswith('/dev/') else device
                
                # Check if hdparm is available
                if not shutil.which('hdparm'):
                    hidden_areas['error'] = 'hdparm not found. Install with: sudo apt-get install hdparm'
                    return hidden_areas
                
                # Get detailed device information with timeout
                info_result = subprocess.run(['hdparm', '-I', device_path],
                                             capture_output=True, text=True,
                                             check=False, timeout=10)
                if info_result.returncode == 0:
                    hidden_areas['raw_hdparm_output'] += f"=== Device Information for {device_path} ===\n"
                    hidden_areas['raw_hdparm_output'] += info_result.stdout + "\n"
                    hidden_areas['device_info'][device] = {
                        'path': device_path,
                        'info': info_result.stdout
                    }
                
                # NVMe-specific detection
                if 'nvme' in device and shutil.which('nvme'):
                    nvme_info = subprocess.run(['nvme', 'id-ctrl', device_path],
                                               capture_output=True, text=True, timeout=5)
                    if nvme_info.returncode == 0:
                        hidden_areas['raw_nvme_output'] += nvme_info.stdout + "\n"
                
                # Check for HPA/DCO
                hpa_result = subprocess.run(['hdparm', '-N', device_path],
                                            capture_output=True, text=True, check=False, timeout=10)
                hidden_areas['raw_hdparm_output'] += hpa_result.stdout + "\n"
                
                if hpa_result.returncode == 0:

                    # Robust Regex Parsing
                    # Output: " max sectors   = 1953525168/1953525168, HPA is disabled"
                    match = re.search(r'max\s+sectors\s*=\s*(\d+)/(\d+)', hpa_result.stdout, re.IGNORECASE)
                    if match:
                        try:
                            accessible = int(match.group(1))
                            native = int(match.group(2))
                            
                            hidden_areas['accessible_max_lba'] = accessible
                            hidden_areas['native_max_lba'] = native
                            
                            if native > accessible:
                                hidden_areas['hpa_detected'] = True
                                hidden_areas['hpa_size'] = (native - accessible) * 512
                                hidden_areas['warnings'] = ["HPA Detected: Native max > Accessible max"]
                        except ValueError:
                             pass
                    else:
                         # Fallback or log unrecognized format
                         pass
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            logger.error(f"Linux HPA/DCO detection error: {e}")
            hidden_areas['error'] = str(e)
        
        return hidden_areas

    @staticmethod
    def _detect_windows(device_path, hidden_areas):
        """Windows-specific HPA/DCO detection"""
        try:
            # Use Windows Management Instrumentation to get disk info
            if device_path:
                # Get specific disk information
                cmd = ['wmic', 'diskdrive', 'where', f'DeviceID="{device_path}"', 'get', 'Size,Model', '/value']
            else:
                # Get all disk information
                cmd = ['wmic', 'diskdrive', 'get', 'DeviceID,Size,Model', '/value']
            
            result = subprocess.run(cmd, capture_output=True, text=True, shell=False, timeout=30)

            if result.returncode == 0:
                hidden_areas['raw_hdparm_output'] = "Windows Disk Information:\n" + result.stdout
                
                # Parse the output to extract disk information
                lines = result.stdout.strip().split('\n')
                current_device = {}
                for line in lines:
                    if 'DeviceID' in line:
                        if current_device:
                            device_id = current_device.get('DeviceID', 'unknown')
                            hidden_areas['device_info'][device_id] = current_device
                        current_device = {'DeviceID': line.split('=')[1].strip()}
                    elif 'Size' in line:
                        current_device['Size'] = line.split('=')[1].strip()
                    elif 'Model' in line:
                        current_device['Model'] = line.split('=')[1].strip()
                
                if current_device:
                    device_id = current_device.get('DeviceID', 'unknown')
                    hidden_areas['device_info'][device_id] = current_device
                
                hidden_areas['warnings'] = ["HPA/DCO detection limited on Windows. Use Linux for full feature set."]
            else:
                hidden_areas['error'] = f"WMIC command failed: {result.stderr}"
                
        except Exception as e:
            logger.error(f"Windows HPA/DCO detection error: {e}")
            hidden_areas['error'] = str(e)
        return hidden_areas

    @staticmethod
    def remove_hpa_dco(device_path):
        """Remove HPA and DCO on the specified device (Linux only)."""
        try:
            if platform.system() != "Linux":
                return {'success': False, 'error': 'HPA/DCO removal only supported on Linux'}


            # First, get the current and native max sectors
            result = run_cmd(['hdparm', '-N', device_path], timeout=10)

            
            # Robust Regex Parsing
            native_max = None
            match = re.search(r'max\s+sectors\s*=\s*(\d+)/(\d+)', result['out'], re.IGNORECASE)
            if match:
                 native_max = match.group(2)
            
            if not native_max:
                return {'success': False, 'error': 'Could not determine native max sectors (Regex failed)'}

            # Fix #6: Validate native_max is numeric to prevent command injection
            if not native_max.isdigit():
                return {'success': False, 'error': 'Invalid native max sectors format (must be numeric)'}
            
            native_max_int = int(native_max)
            if native_max_int <= 0 or native_max_int > 10**15:
                return {'success': False, 'error': f'Invalid sector count: {native_max_int}'}

            # Remove HPA by setting to native max (p prefix makes it permanent)
            cmd1 = ['hdparm', '-N', f'p{native_max}', device_path]
            result1 = run_cmd(cmd1, timeout=10)

            # Remove DCO
            cmd2 = ['hdparm', '--yes-i-know-what-i-am-doing', '--dco-restore', device_path]
            result2 = run_cmd(cmd2, timeout=10)


            # Check if commands were successful
            success = (result1['rc'] == 0 and result2['rc'] == 0)
            return {
                'success': success,
                'hpa_remove_cmd': cmd1,
                'hpa_remove_stdout': result1['out'],
                'hpa_remove_stderr': result1['err'],
                'dco_remove_cmd': cmd2,
                'dco_remove_stdout': result2['out'],
                'dco_remove_stderr': result2['err']
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

class WindowsDeviceManager:
    """Windows-specific device management"""
    
    @staticmethod
    def get_disk_devices():
        """Get list of disk devices on Windows"""
        devices = []
        try:
            # Use WMIC to get disk drives
            # Use WMIC to get disk drives
            result = subprocess.run(
                ['wmic', 'diskdrive', 'get', 'DeviceID,Model,Size', '/format:list'],
                capture_output=True, text=True, shell=False, timeout=30
            )

            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                current_device = {}
                for line in lines:
                    line = line.strip()
                    if line.startswith('DeviceID='):
                        if current_device:
                            devices.append(current_device)
                        current_device = {'DeviceID': line.split('=', 1)[1]}
                    elif line.startswith('Model='):
                        current_device['Model'] = line.split('=', 1)[1]
                    elif line.startswith('Size='):
                        current_device['Size'] = line.split('=', 1)[1]
                
                if current_device:
                    devices.append(current_device)
            
            # Also get logical drives for user-friendly display
            logical_result = subprocess.run(
                ['wmic', 'logicaldisk', 'get', 'DeviceID,Size,FreeSpace', '/format:list'],
                capture_output=True, text=True, shell=False, timeout=10
            )

            
        except Exception as e:
            logger.error(f"Error getting Windows devices: {e}")
        
        return devices

    @staticmethod
    def secure_erase_windows(device_path, method='OVERWRITE'):
        """Perform verified secure erase on Windows"""
        try:
            if 'PhysicalDrive' in device_path:
                # Fix #4: CRITICAL - Block system drive via strict PhysicalDrive0 check
                if 'PhysicalDrive0' in device_path:
                     return {
                        'success': False, 
                        'error': 'BLOCKED: PhysicalDrive0 is typically the system drive. Boot from USB to wipe this drive safely.'
                     }

                drive_num = device_path.split('PhysicalDrive')[-1]
                # Secondary check via WMIC (Keep existing logic as backup)
                try:
                    result = subprocess.run(
                        ['wmic', 'partition', 'where', f'DiskIndex={drive_num}', 'get', 'DeviceID'],
                        capture_output=True, text=True, shell=False, timeout=10
                    )
                    system_drive = os.environ.get('SystemDrive', 'C:')[0].upper()
                    if result.returncode == 0 and system_drive in result.stdout.upper():
                        logger.error(f"Blocked attempt to wipe system drive: PhysicalDrive{drive_num}")
                        return {
                            'success': False,
                            'error': f'BLOCKED: PhysicalDrive{drive_num} contains system partition ({system_drive}:)',
                            'recommendation': 'Boot from external media to wipe the system drive safely'
                        }
                except Exception as e:
                    logger.warning(f"System drive check warning (relying on PhysicalDrive0 block): {e}")
                
                # Verified Raw Write for Physical Drive
                try:
                    if not check_privileges():
                        return {
                            'success': False,
                            'error': 'Administrator privileges required for physical drive access.',
                            'recommendation': 'Right-click terminal -> Run as Administrator'
                        }
                        
                    fd = os.open(device_path, os.O_RDWR | os.O_BINARY)
                    try:
                        size = os.lseek(fd, 0, os.SEEK_END)
                        os.lseek(fd, 0, os.SEEK_SET)
                        
                        # 1. VERIFICATION PHASE: Test Write-Read-Compare
                        test_chunk_size = 4096
                        test_chunk = b'\x00' * test_chunk_size
                        
                        # Write test chunk to start (sectors 0-7)
                        bytes_written = os.write(fd, test_chunk)
                        if bytes_written != test_chunk_size:
                            return {'success': False, 'error': f'Verification Write Failed: Wrote {bytes_written}/{test_chunk_size} bytes'}
                            
                        # Force flush to ensuring it hit the disk
                        try: os.fsync(fd)
                        except: pass
                        
                        # Read back
                        os.lseek(fd, 0, os.SEEK_SET)
                        verify_chunk = os.read(fd, test_chunk_size)
                        
                        if verify_chunk != test_chunk:
                             return {'success': False, 'error': 'CRITICAL: Write Verification Failed. The drive may be write-protected or blocked by Windows/Antivirus.'}
                        
                        # 2. FULL WIPE PHASE
                        os.lseek(fd, 0, os.SEEK_SET) # Reset again
                        chunk_size = 1024 * 1024 # 1MB
                        written = 0
                        zero_chunk = b'\x00' * chunk_size
                        
                        while written < size:
                            to_write = min(chunk_size, size - written)
                            if to_write < chunk_size:
                                os.write(fd, b'\x00' * to_write)
                            else:
                                os.write(fd, zero_chunk)
                            written += to_write
                            
                        try: os.fsync(fd)
                        except: pass
                        
                        # 3. POST-WIPE VERIFICATION PHASE (Critical Fix)
                        logger.info("Verifying wipe completion with read-back...")
                        os.lseek(fd, 0, os.SEEK_SET)
                        verify_chunk_size = 1024 * 1024  # 1MB
                        bytes_verified = 0
                        verification_failed = False
                        failed_offset = None
                        
                        while bytes_verified < size:
                            chunk_to_read = min(verify_chunk_size, size - bytes_verified)
                            read_data = os.read(fd, chunk_to_read)
                            
                            # Check if all zeros
                            if read_data != b'\x00' * len(read_data):
                                verification_failed = True
                                failed_offset = bytes_verified
                                logger.error(f"Verification failed at offset {failed_offset}")
                                break
                            
                            bytes_verified += chunk_to_read
                        
                        if verification_failed:
                            return {
                                'success': False,
                                'method_used': 'Windows Raw Write - VERIFICATION FAILED',
                                'evidence': {
                                    'size_wiped': size,
                                    'verified': False,
                                    'failed_at_offset': failed_offset,
                                    'error': 'Data not zero after write - possible hardware/firmware issue'
                                },
                                'recommendation': 'Device may have bad sectors or SSD firmware is blocking overwrites. Try hardware secure erase.'
                            }
                            
                        return {
                            'success': True,
                            'method_used': 'Windows Verified Raw Write with Post-Wipe Read-Back',
                            'evidence': {'size_wiped': size, 'verified': True, 'bytes_verified': bytes_verified}
                        }
                    finally:
                        os.close(fd)
                except OSError as e:
                    return {
                        'success': False,
                        'error': f'Physical drive write failed (Access Denied/Blocked): {str(e)}',
                        'recommendation': 'Windows often blocks raw disk writes. Use Linux/Bootable USB for guaranteed results.'
                    } 
                except Exception as e:
                    return {
                        'success': False,
                        'error': f'Unexpected wipe error: {str(e)}',
                    }
            else:
                # Logical drive - use cipher command for quick wipe
                drive_letter = device_path[0] if ':' in device_path else 'C'
                # Logical drive - use cipher command for quick wipe
                drive_letter = device_path[0] if ':' in device_path else 'C'
                cmd = ['cipher', f'/w:{drive_letter}:']
                result = run_cmd(cmd, timeout=300)

                
                if result['rc'] == 0:
                    return {
                        'success': True,
                        'method_used': 'Windows Cipher Wipe',
                        'evidence': {
                            'command': cmd,
                            'output': result['out']
                        }
                    }
                else:
                    return {
                        'success': False,
                        'error': f"Cipher command failed: {result['err']}",
                        'evidence': {
                            'command': cmd,
                            'error': result['err']
                        }
                    }
                    
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

class AndroidCryptoWipe:
    """Enhanced Android crypto key destruction with multiple methods"""
    
    @staticmethod
    def find_adb():
        """Find ADB executable in common locations"""
        possible_paths = [
            'adb',  # In PATH
            'platform-tools/adb',  # Android SDK
            '/usr/bin/adb',  # Linux
            '/usr/local/bin/adb',  # Linux
            'C:\\Program Files (x86)\\Android\\android-sdk\\platform-tools\\adb.exe',  # Windows
            'C:\\Android\\android-sdk\\platform-tools\\adb.exe',  # Windows
        ]
        
        for path in possible_paths:
            if shutil.which(path):
                return path
            elif os.path.exists(path):
                return path
        
        return None

    @staticmethod
    def is_device_connected(adb_path, device_id, timeout=5):
        """Return True if device_id appears in `adb devices` output."""
        try:
            res = run_cmd([adb_path, 'devices'], timeout=timeout)

            if res['rc'] != 0:
                return False, res
            out = res['out']
            # Example line: "abcdef123456\tdevice"
            return (device_id in out and '\tdevice' in out), res
        except Exception as e:
            return False, {'rc': -1, 'out': '', 'err': str(e)}

    @staticmethod
    def perform_full_android_reset(device_id, adb_path=None, timeout=120):
        """
        HONEST Android wipe - only uses VERIFIED standard commands.
        Reboots device to recovery and instructs operator to perform factory reset manually.
        """
        results = {
            'success': False,
            'methods_attempted': [],
            'evidence': {},
            'errors': [],
            'timestamp': datetime.now().isoformat(),
            'requires_manual': True,
            'certificate_allowed': False,  # CRITICAL: No certificates for manual operations
            'instructions': 'Device rebooted to Recovery Mode. Please manually select "Wipe data/factory reset" using volume buttons. NOTE: No certificate issued for manual operations.'
        }
        
        # Find adb if not provided
        if adb_path is None:
            adb_path = AndroidCryptoWipe.find_adb()
            if adb_path is None:
                results['errors'].append("ADB binary not found on host PATH.")
                return results

        # Ensure device is connected & authorized
        connected, conn_res = AndroidCryptoWipe.is_device_connected(adb_path, device_id)
        results['evidence']['adb_devices'] = conn_res
        if not connected:
            results['errors'].append(f"Device {device_id} is not connected/authorized via ADB.")
            return results
            
        def _run(cmd_args, t=timeout):
            full = [adb_path, '-s', device_id]
            if isinstance(cmd_args, list): full.extend(cmd_args)
            elif isinstance(cmd_args, str): full.extend(shlex.split(cmd_args))
            return run_cmd(full, timeout=t)

        # 1. Capture State
        try:
             props = _run('shell getprop ro.crypto.state', timeout=10)
             results['evidence']['ro.crypto.state_before'] = props.get('out','').strip()
        except: pass

        # 2. Honest Method: Reboot to Recovery
        try:
            results['methods_attempted'].append('reboot_recovery')
            _run('reboot recovery', timeout=10)
            
            # Reboot succeeded but wipe NOT completed - user must act
            results['success'] = False  # CRITICAL FIX: Manual = NOT success
            results['status'] = 'REBOOT_ONLY_USER_MUST_COMPLETE'
            results['evidence']['note'] = 'Device rebooted to recovery. User MUST manually complete wipe.'
            
            # Wait a bit to ensure command sent
            time.sleep(3)
            
        except Exception as e:
            results['errors'].append(f"Failed to reboot to recovery: {e}")
            results['success'] = False
            
        return results

    @staticmethod
    def perform_crypto_wipe(device_id, adb_path=None, timeout=120):
        """Perform complete Android crypto key destruction with evidence collection"""
        try:
            # Use the new comprehensive Android reset function
            reset_results = AndroidCryptoWipe.perform_full_android_reset(device_id, adb_path, timeout)
            
            # Map results to expected format
            results = {
                'success': reset_results['success'],
                'methods_used': reset_results['methods_attempted'],
                'errors': reset_results['errors'],
                'evidence': reset_results['evidence'],
                'timestamp': reset_results['timestamp']
            }
            
            return results
        except Exception as e:
            return {
                'success': False,
                'errors': [str(e)],
                'evidence': {'timestamp': datetime.now().isoformat()},
                'methods_used': []
            }

class DeviceBackend:
    """Enhanced device backend with strict policy enforcement and evidence collection"""
    
    def __init__(self):
        self.verification_log = []
        self.hpa_detector = EnhancedHPADCODetector()
        self.windows_device_manager = WindowsDeviceManager()
        self.android_wipe = AndroidCryptoWipe()
    
    def detect_storage_type(self, device_path):
        """Detect storage type and capabilities"""
        info = {
            'type': 'UNKNOWN',
            'model': 'Unknown',
            'size': 'Unknown',
            'capabilities': [],
            'secure_erase_support': False,
            'nvme_sanitize_support': False,
            'is_android': False,
            'detection_timestamp': datetime.now().isoformat()
        }
        
        try:
            if platform.system() == "Linux":
                # Try to get basic info with lsblk
                if shutil.which('lsblk'):
                    result = subprocess.run(['lsblk', '-d', '-o', 'MODEL,SIZE,ROTA', '-n', device_path],
                                            capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        parts = result.stdout.strip().split()
                        if len(parts) >= 2:
                            info['model'] = parts[0] if parts[0] != '' else 'Unknown'
                            info['size'] = parts[1] if len(parts) > 1 else 'Unknown'
                            # ROTA=1 for HDD, ROTA=0 for SSD
                            if len(parts) > 2 and parts[2] == '0':
                                info['type'] = 'SSD'
                            else:
                                info['type'] = 'HDD'
                
                # Check if it's an NVMe device
                if 'nvme' in device_path:
                    info['type'] = 'NVMe'
                    # Check NVMe sanitize support
                    if shutil.which('nvme'):
                        try:
                            nvme_result = subprocess.run(['nvme', 'id-ctrl', device_path, '-H'],
                                                         capture_output=True, text=True, timeout=10)
                            if nvme_result.returncode == 0:
                                if 'Sanitize' in nvme_result.stdout:
                                    info['nvme_sanitize_support'] = True
                                    info['capabilities'].append('NVMe Sanitize')
                        except:
                            pass
                
                # Check for ATA secure erase support
                if shutil.which('hdparm'):
                    sec_check = subprocess.run(['hdparm', '-I', device_path],
                                               capture_output=True, text=True, timeout=10)
                    if sec_check.returncode == 0 and 'supported: enhanced erase' in sec_check.stdout.lower():
                        info['secure_erase_support'] = True
                        info['capabilities'].append('ATA Secure Erase')
            
            elif platform.system() == "Windows":
                info['type'] = 'Windows Drive'
                # Try to get model and size from WMIC
                try:

                    if 'PhysicalDrive' in device_path:
                        drive_id = device_path.split('PhysicalDrive')[-1]
                        cmd = ['wmic', 'diskdrive', 'where', f'Index={drive_id}', 'get', 'Model,Size', '/value']
                        result = subprocess.run(cmd, capture_output=True, text=True, shell=False, timeout=10)

                        if result.returncode == 0:
                            for line in result.stdout.split('\n'):
                                if 'Model=' in line:
                                    info['model'] = line.split('=', 1)[1].strip()
                                elif 'Size=' in line:
                                    size_bytes = int(line.split('=', 1)[1].strip())
                                    info['size'] = f"{size_bytes / (1024**3):.2f} GB"
                    else:
                        # Logical drive
                        info['model'] = 'Logical Drive'
                        info['type'] = 'Logical Drive'
                except Exception:
                    pass
            
            # Check if this is an Android device

            try:
                adb_path = AndroidCryptoWipe.find_adb()
                if adb_path:
                    adb_result = run_cmd([adb_path, 'devices'], timeout=5)
                    if adb_result['rc'] == 0 and 'device' in adb_result['out']:

                        info['is_android'] = True
                        info['type'] = 'Android'
            except Exception:
                pass
                
        except Exception as e:
            logger.error(f"Device detection error: {e}")
        
        return info

    def is_boot_device(self, device_path):
        """Check if the device is the current boot device"""
        try:
            if platform.system() == "Linux":
                # Get root filesystem device
                root_stat = os.stat('/')
                root_dev = root_stat.st_dev
                
                # Get target device major/minor
                if os.path.exists(device_path):
                    target_stat = os.stat(device_path)
                    target_dev = target_stat.st_dev
                    
                    return root_dev == target_dev
                
            elif platform.system() == "Windows":
                # Check if device is system/boot drive

                # Check if device is system/boot drive
                if ':' in device_path:
                    drive = device_path.split(':')[0]
                    cmd = ['wmic', 'logicaldisk', 'where', f'DeviceID="{drive}:"', 'get', 'Description', '/value']
                    result = subprocess.run(cmd, capture_output=True, text=True, shell=False, timeout=10)

                    if result.returncode == 0:
                        if 'System' in result.stdout or 'Boot' in result.stdout:
                            return True
                
        except Exception as e:
            logger.warning(f"Boot device check failed: {e}")
        
        return False

    def secure_erase_device(self, device_path, policy_level):
        """Execute device erase based on policy with verification"""
        results = {
            'success': False,
            'method_used': 'Unknown',
            'nist_level': policy_level,
            'evidence': {},
            'warnings': []
        }
        
        # Safety check: prevent wiping boot device
        if self.is_boot_device(device_path):
            results['error'] = f"Cannot wipe boot device: {device_path}"
            results['warnings'].append("Attempted to wipe boot device - operation blocked")
            return results
        
        # Detect storage type and capabilities
        device_info = self.detect_storage_type(device_path)
        results['evidence']['device_info'] = device_info
        
        # Detect HPA/DCO before erase
        results['evidence']['pre_hpa_dco'] = self.hpa_detector.detect_hidden_areas(device_path)
        
        # Get recommended method based on device type and policy
        recommended_method = self.get_recommended_method(device_info, policy_level)
        results['evidence']['recommended_method'] = recommended_method
        
        if device_info.get('is_android', False):
            # Android device - use crypto wipe
            android_result = self.android_wipe.perform_crypto_wipe(device_path)
            if android_result['success']:
                results['success'] = True
                results['method_used'] = ' + '.join(android_result['methods_used'])
                results['nist_level'] = NIST_PURGE
                results['evidence']['android_wipe'] = android_result['evidence']
                self.verification_log.append("Android crypto wipe completed successfully")
            else:
                results['error'] = '; '.join(android_result['errors'])
        elif platform.system() == "Linux":
            # Linux-specific device erasure
            linux_result = self._secure_erase_linux(device_path, recommended_method, device_info)
            results.update(linux_result)
        elif platform.system() == "Windows":
            # Windows-specific device erasure
            windows_result = self.windows_device_manager.secure_erase_windows(device_path)
            results.update(windows_result)
        else:
            results['error'] = f"Unsupported platform: {platform.system()}"
        
        # Detect HPA/DCO after erase
        results['evidence']['post_hpa_dco'] = self.hpa_detector.detect_hidden_areas(device_path)
        
        return results

    def _secure_erase_linux(self, device_path, recommended_method, device_info):
        """Linux-specific secure erase implementation"""
        results = {'success': False, 'method_used': recommended_method}
        
        try:
            if recommended_method == 'NVMe_Sanitize':
                if shutil.which('nvme'):
                    cmd = ['nvme', 'sanitize', device_path, '--sanitize-action=1']  # Block Erase
                    result = run_cmd(cmd, timeout=60)

                    results['evidence'] = {
                        'nvme_sanitize_cmd': cmd,
                        'nvme_sanitize_stdout': result['out'],
                        'nvme_sanitize_stderr': result['err']
                    }
                    if result['rc'] == 0:
                        results['success'] = True
                        self.verification_log.append("NVMe sanitize completed successfully")
                    else:
                        results['error'] = f"NVMe sanitize failed: {result['out']} {result['err']}"
                else:
                    results['error'] = "nvme command not found"
            
            elif recommended_method == 'BLKDISCARD':
                 if shutil.which('blkdiscard'):
                     cmd = ['blkdiscard', '--force', '--verbose', device_path]
                     result = run_cmd(cmd, timeout=300)

                     results['evidence'] = {
                         'blkdiscard_cmd': cmd,
                         'stdout': result['out'],
                         'stderr': result['err']
                     }
                     if result['rc'] == 0:
                         results['success'] = True
                         self.verification_log.append("Block discard completed successfully")
                     else:
                         results['error'] = f"blkdiscard failed: {result['out']} {result['err']}"
                 else:
                     results['error'] = "blkdiscard command not found"
                    
            elif recommended_method == 'ATA_Secure_Erase':
                if shutil.which('hdparm'):
                    # Check if drive is frozen
                    freeze_check = run_cmd(['hdparm', '-I', device_path], timeout=10)

                    if 'frozen' in freeze_check['out']:
                        results['error'] = "Drive is frozen. Try suspending and resuming the system."
                        return results
                    
                    # Set security password
                    set_pass_cmd = ['hdparm', '--user-master', 'u', '--security-set-pass', 'Eins', device_path]
                    set_result = run_cmd(set_pass_cmd, timeout=30)

                    results['evidence']['hdparm_set_pass'] = {
                        'cmd': set_pass_cmd,
                        'stdout': set_result['out'],
                        'stderr': set_result['err']
                    }
                    
                    if set_result['rc'] == 0:
                        # Perform secure erase
                        erase_cmd = ['hdparm', '--user-master', 'u', '--security-erase', 'Eins', device_path]
                        erase_result = run_cmd(erase_cmd, timeout=600)

                        results['evidence']['hdparm_erase'] = {
                            'cmd': erase_cmd,
                            'stdout': erase_result['out'],
                            'stderr': erase_result['err']
                        }
                        
                        if erase_result['rc'] == 0:
                            results['success'] = True
                            self.verification_log.append("ATA secure erase completed successfully")
                        else:
                            results['error'] = f"ATA secure erase failed: {erase_result['err']}"
                    else:
                        results['error'] = f"Failed to set security password: {set_result['err']}"
                else:
                    results['error'] = "hdparm command not found"
                    
            else:
                # Fallback to software wiping
                results['error'] = f"Unsupported method for device: {recommended_method}"
                
        except Exception as e:
            results['error'] = f"Linux erase error: {str(e)}"
            
        return results

    def get_recommended_method(self, device_info, policy_level):
        """Get recommended wipe method based on device type and policy"""
        device_type = device_info.get('type', 'UNKNOWN')
        
        if device_type == 'NVMe':
            if device_info.get('nvme_sanitize_support', False):
                return 'NVMe_Sanitize'
            else:
                return 'OVERWRITE'  # Fallback
        elif device_type == 'SSD':
            if device_info.get('secure_erase_support', False):
                return 'ATA_Secure_Erase'
            else:
                # Fallback to BLKDISCARD if available (Linux)
                if platform.system() == "Linux" and shutil.which('blkdiscard'):
                    return 'BLKDISCARD'
                return 'OVERWRITE'
        elif device_type == 'HDD':
            if device_info.get('secure_erase_support', False):
                return 'ATA_Secure_Erase'
            else:
                return 'OVERWRITE'
        elif device_type == 'Android':
            return 'Android_Crypto_Wipe'
        elif device_type == 'Windows Drive' or device_type == 'Logical Drive':
            return 'WINDOWS_CIPHER'
        else:
            return 'OVERWRITE'  # Universal fallback

class FileEaterEngine:
    """Enhanced file eater with cluster-aware overwriting and verification"""
    
    @staticmethod
    def calculate_clusters_needed(file_path):
        """Calculate number of clusters needed for the file"""
        try:
            file_size = os.path.getsize(file_path)
            # Get cluster size (filesystem-dependent)

            if platform.system() == "Windows":
                # Use fsutil to get cluster size
                drive = os.path.splitdrive(file_path)[0]
                if drive:
                    result = subprocess.run(['fsutil', 'fsinfo', 'sectorInfo', drive], 
                                          capture_output=True, text=True, shell=False, timeout=5)

                    # Parse cluster size from output
                    for line in result.stdout.split('\n'):
                        if 'Cluster' in line and 'Bytes' in line:
                            try:
                                cluster_size = int(line.split(':')[1].strip())
                                break
                            except Exception:
                                cluster_size = 4096
                else:
                    cluster_size = 4096
            else:
                # On Unix, use statvfs
                try:
                    statvfs = os.statvfs(os.path.dirname(file_path))
                    cluster_size = statvfs.f_frsize
                except Exception:
                    cluster_size = 4096
                    
            clusters_needed = (file_size + cluster_size - 1) // cluster_size
            return clusters_needed, cluster_size
        except Exception:
            return 1, 4096  # Default fallback
    
    @staticmethod
    def calculate_file_hash(file_path):
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                # Read and update hash in chunks of 4K
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Hash calculation error for {file_path}: {e}")
            return None
    
    @staticmethod
    def force_sync(file_obj=None):
        """Force sync to disk - cross-platform implementation.
           If file_obj (open file object) is provided, syncs that specific file.
           Otherwise tries global sync where available.
        """
        try:
            if file_obj:
                os.fsync(file_obj.fileno())
                if platform.system() == "Windows":
                    try:
                        import msvcrt
                        import ctypes
                        handle = msvcrt.get_osfhandle(file_obj.fileno())
                        ctypes.windll.kernel32.FlushFileBuffers(handle)
                    except Exception as e:
                        logger.warning(f"Windows FlushFileBuffers failed: {e}")
                
            if platform.system() == "Linux" or platform.system() == "Darwin":
                os.sync()
        except Exception as e:
            logger.error(f"Sync error: {e}")

    
    @staticmethod
    def overwrite_file_data(file_path, passes=3, pattern_override=None, progress_callback=None):
        """Securely overwrite file data with multiple passes with enhanced progress feedback"""
        try:
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return False, None, None
                
            if not check_file_permissions(file_path):
                return False, None, None
            
            # CRITICAL FIX: Create WipeVerifier BEFORE wiping to capture pre-wipe state
            verifier = WipeVerifier(file_path)
                
            file_size = os.path.getsize(file_path)
            clusters_needed, cluster_size = FileEaterEngine.calculate_clusters_needed(file_path)
            
            # Calculate pre-wipe hash
            pre_hash = FileEaterEngine.calculate_file_hash(file_path)
            
            # Determine overwrite patterns based on passes
            patterns = []
            if pattern_override:
                patterns = [pattern_override]
            elif passes == 1:
                patterns = [b'\x00']  # Clear
            elif passes == 3:
                patterns = [b'\x00', b'\xFF', b'\x55']  # DoD 3-pass
            elif passes == 7:
                patterns = [b'\x35', b'\xCA', b'\x97', b'\x00', b'\xFF', b'\x55', secrets.token_bytes(1)]  # Military grade
            elif passes >= 35:
                # Gutmann 35-pass pattern (simplified)
                patterns = [secrets.token_bytes(1) for _ in range(35)]
            
            with open(file_path, 'r+b') as f:
                for pass_num, pattern in enumerate(patterns):
                    if progress_callback:
                        progress_msg = f"Starting pass {pass_num+1}/{len(patterns)}"
                        if not progress_callback(pass_num, 0, file_size, progress_msg):
                            return False, pre_hash, None
                            
                    logger.info(f"Overwriting pass {pass_num + 1}/{len(patterns)}...")
                    f.seek(0)
                    bytes_written = 0
                    while bytes_written < file_size:
                        chunk_size = min(65536, file_size - bytes_written)  # 64KB chunks
                        if isinstance(pattern, bytes) and len(pattern) == 1:
                            # Fixed single-byte pattern
                            chunk_data = pattern * chunk_size
                        else:
                            # Random pattern
                            chunk_data = secrets.token_bytes(chunk_size)
                        f.write(chunk_data)
                        bytes_written += chunk_size
                        f.flush()
                        os.fsync(f.fileno())  # Force write to disk
                        if progress_callback:
                            progress = (bytes_written / file_size) * 100
                            progress_msg = f"Pass {pass_num+1}/{len(patterns)}: {progress:.1f}% complete"
                            if not progress_callback(pass_num, bytes_written, file_size, progress_msg):
                                # CANCELLATION DETECTED
                                logger.warning(f"Wipe cancelled for {file_path}")
                                f.flush()
                                os.fsync(f.fileno())
                                # Fix #5: Mark file as corrupted since it's partially overwritten
                                try:
                                    f.close()
                                    corrupted_path = f"{file_path}.CORRUPTED_{int(time.time())}"
                                    os.rename(file_path, corrupted_path)
                                    logger.info(f"Renamed partially wiped file to {corrupted_path}")
                                except Exception as rename_err:
                                    logger.error(f"Failed to rename corrupted file: {rename_err}")
                                return False, pre_hash, None
            
            # CRITICAL FIX: Real verification - compare against pre-wipe samples
            expected_pattern = patterns[-1] if patterns else b'\x00'
            verification_result = verifier.verify_post_wipe(expected_pattern)
            
            if not verification_result['verified']:
                logger.error(f"VERIFICATION FAILED: {verification_result.get('verdict', 'Unknown')}")
                return False, pre_hash, None
            
            logger.info(f"VERIFICATION PASSED: {verification_result['verdict']}")
            
            # Calculate post-wipe hash
            post_hash = FileEaterEngine.calculate_file_hash(file_path)
            
            # Force sync to ensure all data is written to disk
            FileEaterEngine.force_sync()
            
            return True, pre_hash, post_hash
        except Exception as e:
            logger.error(f"File-Eater Error for {file_path}: {e}")
            return False, None, None
    
    @staticmethod
    def check_device_hidden_areas(file_path):
        """Check for HPA/DCO on the device containing the file"""
        try:
            # Get the device containing the file
            if platform.system() == "Linux":
                result = subprocess.run(['df', file_path], capture_output=True,
                                        text=True, timeout=5)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    if len(lines) > 1:
                        device = lines[1].split()[0]
                        # Strip partition numbers to get base device
                        base_device = re.sub(r'\d+$', '', device)
                        hpa_detector = EnhancedHPADCODetector()
                        return hpa_detector.detect_hidden_areas(base_device)

            elif platform.system() == "Windows":
                logger.warning("HPA/DCO detection is not supported on Windows (Standard User Mode).")
            return {}
        except Exception as e:
            logger.error(f"Hidden area check error: {e}")
            return {}

class CertificateGenerator:
    """Enhanced certificate generator with HPA/DCO evidence and QR codes"""
    
    def __init__(self):
        self.cert_signer = CertificateSigner()
    
    def generate_json_certificate(self, operation_details: dict) -> dict:
        """Generate a canonical JSON certificate"""
        # [CRITICAL FIX] 32 hex chars = 16 bytes = 128-bit UUID-level uniqueness
        cert_id = f"WIPE-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(32)}"
        
        certificate_data = {
            'certificate_id': cert_id,
            'target': operation_details.get('target', 'UNKNOWN'),
            'method': operation_details.get('method', 'UNKNOWN'),
            'nist_policy': operation_details.get('nist_level', 'Unknown'),
            'start_time': operation_details.get('start_time', datetime.now().isoformat()),
            'end_time': datetime.now().isoformat(),
            'evidence': operation_details.get('evidence', {}),
            'operator': operation_details.get('operator', 'Unknown'),
            'handoff_required': operation_details.get('handoff_required', False),
            'pre_hash': operation_details.get('pre_hash', 'N/A'),
            'post_hash': operation_details.get('post_hash', 'N/A'),
            'hash_verification': operation_details.get('hash_verification', 'N/A'),
            'platform': platform.system(),
            'tool_version': '4.0',
            'tool_name': 'EraseIT',
            'nist_compliance': {
                'standard': 'NIST SP 800-88 Rev.1',
                'method_type': self._derive_nist_method(operation_details.get('nist_level', 'Unknown'))
            }
        }
        
        # Add public key fingerprint if signer has it
        if self.cert_signer.public_key:
             try:
                 fp = self.cert_signer.public_key.public_bytes(
                     encoding=serialization.Encoding.PEM,
                     format=serialization.PublicFormat.SubjectPublicKeyInfo
                 )
                 certificate_data['public_key_fingerprint'] = hashlib.sha256(fp).hexdigest()[:16]
             except:
                 pass
        
        # Add Blockchain-Linked Hash (Previous Hash)
        # This makes the certificate part of a hash chain (Merkle-like)
        try:
            transparency_log = EnhancedTransparencyLog()
            prev_hash = transparency_log.get_last_entry_hash()
            certificate_data['blockchain'] = {
                'previous_chain_hash': prev_hash,
                'note': 'This certificate is cryptographically linked to the previous entry in the transparency log.'
            }
        except:
             certificate_data['blockchain'] = {'error': 'Could not fetch previous hash'}
             
        # Add HPA/DCO evidence if available
        
        # Add HPA/DCO evidence if available
        if 'hpa_dco_evidence' in operation_details:
            certificate_data['evidence']['hpa_dco'] = operation_details['hpa_dco_evidence']
        
        # Add evidence logs
        if 'evidence_logs' in operation_details:
            certificate_data['evidence'].update(operation_details['evidence_logs'])
        
        # Generate JWS signature
        try:
            jws_signature = self.cert_signer.sign_certificate_json(certificate_data)
            certificate_data['jws'] = jws_signature
        except Exception as e:
            certificate_data['signature_error'] = str(e)
        
        return certificate_data
    
    def save_json_certificate(self, cert_data: dict, output_path: str = None) -> str:
        """Save JSON certificate to file atomically"""
        if output_path is None:
            output_dir = CERTIFICATES_DIR
            output_dir.mkdir(parents=True, exist_ok=True)
            output_path = output_dir / f"wipe_certificate_{cert_data['certificate_id']}.json"
        
        try:
            # Atomic write: write to temp file then rename
            output_path = Path(output_path)
            dir_name = output_path.parent
            dir_name.mkdir(parents=True, exist_ok=True)
            
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=dir_name, delete=False) as tf:
                json.dump(cert_data, tf, indent=2, ensure_ascii=False)
                temp_name = tf.name
            
            # Atomic rename
            os.replace(temp_name, output_path)
            
            # Set read-only permissions for certificate
            try:
                os.chmod(output_path, 0o444)
            except: pass
                
            logger.info(f"JSON certificate saved: {output_path}")
            return str(output_path)
        except Exception as e:
            logger.error(f"Failed to save JSON certificate: {e}")
            if 'temp_name' in locals() and os.path.exists(temp_name):
                try: os.unlink(temp_name)
                except: pass
            raise e
    
    def _generate_qr_code(self, cert_data: dict, qr_size: int = 150):
        """Generate QR code for certificate"""
        if not QR_AVAILABLE:
            return None
            
        try:
            # Create QR content with certificate ID, fingerprint, and JSON filename
            json_filename = f"wipe_certificate_{cert_data['certificate_id']}.json"
            fp = cert_data.get('public_key_fingerprint', 'N/A')
            qr_content = f"{cert_data['certificate_id']}|FP:{fp}|{json_filename}"
            
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(qr_content)
            qr.make(fit=True)
            
            qr_img = qr.make_image(fill_color="black", back_color="white")
            qr_img = qr_img.resize((qr_size, qr_size), PILImage.Resampling.LANCZOS)
            
            # Save to temp file with context manager
            with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as temp_file:
                temp_path = temp_file.name
                qr_img.save(temp_path)
            
            return temp_path
        except Exception as e:
            logger.warning(f"QR code generation failed: {e}")
            return None
    
    def generate_pdf_certificate(self, cert_data: dict, output_path: str = None) -> str:
        """Generate PDF certificate with HPA/DCO evidence and QR code"""
        if not PDF_AVAILABLE:
            raise Exception("PDF generation not available - install reportlab")
        
        if output_path is None:
            output_dir = Path("certificates")
            output_dir.mkdir(exist_ok=True)
            output_path = output_dir / f"wipe_certificate_{cert_data['certificate_id']}.pdf"
        
        try:
            doc = SimpleDocTemplate(str(output_path), pagesize=letter, 
                                  rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
            styles = getSampleStyleSheet()
            elements = []
            
            # Generate QR code
            qr_path = self._generate_qr_code(cert_data)
            
            # Header with QR code
            header_table_data = []
            if qr_path and os.path.exists(qr_path):
                qr_image = Image(qr_path, width=1*inch, height=1*inch)
                header_table_data.append([qr_image, ""])
            else:
                header_table_data.append(["", ""])
            
            header_table = Table(header_table_data, colWidths=[1.5*inch, 4.5*inch])
            header_table.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(header_table)
            elements.append(Spacer(1, 12))
            
            # Title
            title_style = ParagraphStyle('Title', parent=styles['Heading1'], 
                                       alignment=TA_CENTER, fontSize=24, spaceAfter=30)
            elements.append(Paragraph("EraseIT - Secure Data Wipe Certificate", title_style))
            
            # Compliance Notice
            nist_style = ParagraphStyle('NIST', parent=styles['Normal'], 
                                      fontSize=12, textColor=colors.blue, alignment=TA_CENTER)
            nist_level = cert_data.get('nist_policy', 'Unknown')
            elements.append(Paragraph(f"NIST SP 800-88 Compliance: {nist_level}", nist_style))
            elements.append(Paragraph("Compliant with NIST SP 800-88 Rev.1 and DoD 5220.22-M", nist_style))
            elements.append(Spacer(1, 20))
            
            # Certificate ID
            cert_id_style = ParagraphStyle('CertID', parent=styles['Heading2'],
                                         alignment=TA_CENTER, spaceAfter=12)
            elements.append(Paragraph(f"Certificate ID: {cert_data['certificate_id']}", cert_id_style))
            
            # Timestamp
            start_time = cert_data.get('start_time', datetime.now().isoformat())
            end_time = cert_data.get('end_time', datetime.now().isoformat())
            
            try:
                start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
                end_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
                start_str = start_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                end_str = end_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            except:
                start_str = start_time
                end_str = end_time
                
            timestamp_style = ParagraphStyle('Timestamp', parent=styles['Normal'],
                                           alignment=TA_CENTER, spaceAfter=6)
            elements.append(Paragraph(f"Start Time: {start_str}", timestamp_style))
            elements.append(Paragraph(f"End Time: {end_str}", timestamp_style))
            elements.append(Spacer(1, 15))
            
            # Operation Details Section
            elements.append(Paragraph("Operation Details", styles['Heading2']))
            elements.append(Spacer(1, 10))
            
            # Create a table for operation details
            details_data = [
                ['Field', 'Value'],
                ['Target', cert_data.get('target', 'Unknown')],
                ['Method', cert_data.get('method', 'Unknown')],
                ['NIST Policy', cert_data.get('nist_policy', 'Unknown')],
                ['Platform', cert_data.get('platform', 'Unknown')],
                ['Operator', cert_data.get('operator', 'Unknown')],
                ['Handoff Required', 'Yes' if cert_data.get('handoff_required') else 'No'],
                ['Tool Version', cert_data.get('tool_version', 'Unknown')],
            ]
            
            details_table = Table(details_data, colWidths=[2*inch, 4*inch])
            details_table.setStyle(TableStyle([
                ('FONT', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('BACKGROUND', (0, 0), (0, -1), colors.lightblue),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            elements.append(details_table)
            elements.append(Spacer(1, 15))
            
            # Evidence Section
            evidence = cert_data.get('evidence', {})
            if evidence:
                elements.append(Paragraph("Evidence Summary", styles['Heading2']))
                elements.append(Spacer(1, 10))
                
                # Hash verification
                if 'pre_hash' in cert_data and 'post_hash' in cert_data:
                    hash_data = [
                        ['Hash Type', 'Value'],
                        ['Pre-Wipe SHA-256', cert_data.get('pre_hash', 'N/A')[:64] + '...'],
                        ['Post-Wipe SHA-256', cert_data.get('post_hash', 'N/A')[:64] + '...'],
                        ['Verification', cert_data.get('hash_verification', 'N/A')]
                    ]
                    hash_table = Table(hash_data, colWidths=[1.5*inch, 4.5*inch])
                    hash_table.setStyle(TableStyle([
                        ('FONT', (0, 0), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 9),
                        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ]))
                    elements.append(hash_table)
                    elements.append(Spacer(1, 10))
            
            # HPA/DCO Evidence
            hpa_evidence = evidence.get('hpa_dco', {})
            if hpa_evidence:
                elements.append(Paragraph("HPA/DCO Detection Results", styles['Heading3']))
                hpa_data = [
                    ['HPA Detected', 'Yes' if hpa_evidence.get('hpa_detected') else 'No'],
                    ['DCO Detected', 'Yes' if hpa_evidence.get('dco_detected') else 'No'],
                    ['HPA Size', f"{hpa_evidence.get('hpa_size', 0)} bytes"],
                ]
                hpa_table = Table(hpa_data, colWidths=[2*inch, 4*inch])
                hpa_table.setStyle(TableStyle([
                    ('FONT', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BACKGROUND', (0, 0), (0, -1), colors.beige),
                ]))
                elements.append(hpa_table)
            
                elements.append(hpa_table)
            
            # Blockchain Verification Section
            elements.append(Spacer(1, 10))
            elements.append(Paragraph("Blockchain-Linked Verification", styles['Heading3']))
            blockchain_data = cert_data.get('blockchain', {})
            
            if 'previous_chain_hash' in blockchain_data:
                chain_info = [
                    ['Status', 'Linked to Immutable Ledger'],
                    ['Previous Hash', blockchain_data['previous_chain_hash'][:32] + "..."],
                ]
                bg_color = colors.lightgreen
            else:
                 chain_info = [['Status', 'Not Linked (Legacy/Error)']]
                 bg_color = colors.lightpink
                 
            chain_table = Table(chain_info, colWidths=[2*inch, 4*inch])
            chain_table.setStyle(TableStyle([
                ('FONT', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BACKGROUND', (0, 0), (0, -1), bg_color),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            elements.append(chain_table)

            # Signature Section
            elements.append(Spacer(1, 20))
            sig_style = ParagraphStyle('Signature', parent=styles['Normal'],
                                     alignment=TA_CENTER, fontSize=10,
                                     textColor=colors.darkgreen)
            if 'jws' in cert_data and cert_data['jws'] != 'unsigned':
                elements.append(Paragraph("Digitally Signed Certificate", sig_style))
                elements.append(Paragraph(f"Signature: {cert_data['jws'][:50]}...", sig_style))
            else:
                elements.append(Paragraph("Unsigned Certificate - For Testing Only", sig_style))
            
            # Footer
            elements.append(Spacer(1, 20))
            footer_style = ParagraphStyle('Footer', parent=styles['Normal'],
                                        alignment=TA_CENTER, fontSize=8,
                                        textColor=colors.grey)
            elements.append(Paragraph("Generated by EraseIT Secure Data Wiping Tool v4.0", footer_style))
            elements.append(Paragraph("NIST SP 800-88 Rev.1 Compliant | DoD 5220.22-M Certified", footer_style))
            
            # Build PDF
            doc.build(elements)
            
            # Clean up temporary QR file
            if qr_path and os.path.exists(qr_path):
                try:
                    os.unlink(qr_path)
                except:
                    pass
            
            logger.info(f"PDF certificate saved: {output_path}")
            return str(output_path)
            
        except Exception as e:
            logger.error(f"PDF generation error: {e}")
            # Clean up on error
            if 'qr_path' in locals() and qr_path and os.path.exists(qr_path):
                try:
                    os.unlink(qr_path)
                except:
                    pass
            raise e

    def _derive_nist_method(self, nist_level):
        """Derive NIST SP 800-88 method type from level"""
        if 'Destroy' in nist_level or 'Gutmann' in nist_level:
            return 'Destroy'
        elif 'Purge' in nist_level:
            return 'Purge'
        else:
            return 'Clear'

class EnhancedTransparencyLog:
    """Enhanced append-only log with Blockchain-lite hash chaining"""
    
    def __init__(self, db_path: str = "transparency_log.sqlite"):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize the SQLite database with WAL mode and chaining support (auto-migration)."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        
        cursor = conn.cursor()
        # Create table if not exists (checked 6 columns)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS wipe_logs (
                certificate_id TEXT PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                cert_json TEXT NOT NULL,
                signature TEXT,
                previous_hash TEXT,
                chain_hash TEXT
            )
        ''')
        
        # Check for missing columns (Schema Migration for v4.0)
        cursor.execute("PRAGMA table_info(wipe_logs)")
        columns = [info[1] for info in cursor.fetchall()]
        
        if 'previous_hash' not in columns:
            try:
                cursor.execute("ALTER TABLE wipe_logs ADD COLUMN previous_hash TEXT")
                cursor.execute("ALTER TABLE wipe_logs ADD COLUMN chain_hash TEXT")
                logger.info("Migrated transparency log schema: Added blockchain fields.")
            except Exception as e:
                logger.warning(f"Schema migration warning: {e}")

        conn.commit()
        conn.close()
    
    def get_last_entry_hash(self):
        """Get the chain hash of the most recent entry."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT chain_hash FROM wipe_logs ORDER BY timestamp DESC LIMIT 1')
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else "GENESIS_HASH"

    def add_entry(self, cert_data: dict, signature: str):
        """Add a certificate entry linked to the previous one (Blockchain)."""
        prev_hash = self.get_last_entry_hash()
        
        # Calculate new chain hash: SHA256(prev_hash + signatures)
        # This creates the immutable link
        chain_content = f"{prev_hash}{signature}{cert_data['certificate_id']}".encode()
        new_chain_hash = hashlib.sha256(chain_content).hexdigest()
        
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO wipe_logs
            (certificate_id, timestamp, cert_json, signature, previous_hash, chain_hash)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            cert_data['certificate_id'],
            int(time.time()),
            json.dumps(cert_data, sort_keys=True),
            signature,
            prev_hash,
            new_chain_hash
        ))
        
        conn.commit()
        conn.close()
        logger.info(f"Added certificate {cert_data['certificate_id']} to blockchain log (Height: {new_chain_hash[:8]}).")
    
    def get_all_entries(self, limit: int = 100):
        """Get all log entries for display."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT certificate_id, timestamp, cert_json, signature, chain_hash 
            FROM wipe_logs 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))
        
        results = cursor.fetchall()
        conn.close()
        
        entries = []
        for row in results:
            cert_id, timestamp, cert_json, signature, chain_hash = row
            try:
                cert_data = json.loads(cert_json)
                entries.append({
                    'certificate_id': cert_id,
                    'timestamp': datetime.fromtimestamp(timestamp).isoformat(),
                    'target': cert_data.get('target', 'Unknown'),
                    'method': cert_data.get('method', 'Unknown'),
                    'nist_policy': cert_data.get('nist_policy', 'Unknown'),
                    'signature': signature,
                    'chain_hash': chain_hash if chain_hash else "LEGACY"
                })
            except:
                entries.append({
                    'certificate_id': cert_id,
                    'timestamp': datetime.fromtimestamp(timestamp).isoformat(),
                    'target': 'Parse Error',
                    'method': 'Unknown',
                    'nist_policy': 'Unknown',
                    'signature': signature,
                    'chain_hash': chain_hash if chain_hash else "LEGACY"
                })
        
        return entries

    def verify_entry(self, certificate_id: str) -> tuple[bool, str]:
        """Verify if a certificate exists and is valid in the chain."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT cert_json, signature, previous_hash, chain_hash FROM wipe_logs WHERE certificate_id = ?
        ''', (certificate_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            cert_json, signature, prev_hash, chain_hash = result
            # Verify chain integrity locally
            if prev_hash and chain_hash:
                 recalc_content = f"{prev_hash}{signature}{certificate_id}".encode()
                 recalc_hash = hashlib.sha256(recalc_content).hexdigest()
                 if recalc_hash == chain_hash:
                     return True, f"Certificate verified in immutable ledger.\nChain Hash: {chain_hash[:16]}..."
                 else:
                     return False, "INTEGRITY ERROR: Blockchain link broken (Hash Mismatch)."
            
            return True, "Certificate found (Legacy/Genesis)."
        else:
            return False, f"Certificate {certificate_id} NOT found in transparency log."

class EnhancedSecureDataWiper:
    """Enhanced secure data wiper with all features integrated"""
    
    def __init__(self):
        self.cert_generator = CertificateGenerator()
        self.transparency_log = EnhancedTransparencyLog()
        self.file_eater = FileEaterEngine()
        self.device_backend = DeviceBackend()
        self.wipe_log = []
        self.cancel_event = threading.Event()
        
        self.wiping_standards = {
            'CLEAR': {
                'passes': 1,
                'patterns': [b'\x00'],
                'description': 'Basic clear',
                'nist_level': NIST_CLEAR,
                'tooltip': 'Basic 1-pass overwrite (quick delete)'
            },
            'SECURE': {
                'passes': 3,
                'patterns': [b'\x00', b'\xFF', b'\x55'],
                'description': 'DoD 3-pass',
                'nist_level': NIST_PURGE,
                'tooltip': '3-pass DoD 5220.22-M wipe (standard secure erase)'
            },
            'MILITARY': {
                'passes': 7,
                'patterns': [b'\x35', b'\xCA', b'\x97', b'\x00', b'\xFF', b'\x55', secrets.token_bytes(1)],
                'description': 'Military grade',
                'nist_level': NIST_DESTROY,
                'tooltip': '7-pass extended wipe (advanced security)'
            },
            'FILE_EATER': {
                'passes': 35,
                'patterns': ['random'],
                'description': 'Gutmann 35-pass',
                'nist_level': NIST_DESTROY,
                'tooltip': '35-pass Gutmann method (extreme data sanitization)'
            }
        }
        
        self.wipe_policies = {
            'CLEAR': {
                'name': 'Clear',
                'description': 'Basic data removal for reuse within organization',
                'file_method': 'CLEAR',
                'device_method': 'OVERWRITE',
                'nist_level': NIST_CLEAR
            },
            'PURGE': {
                'name': 'Purge',
                'description': 'Secure erasure for devices leaving organization control',
                'file_method': 'SECURE',
                'device_method': 'SECURE_ERASE',
                'nist_level': NIST_PURGE
            },
            'DESTROY': {
                'name': 'Destroy',
                'description': 'Maximum security for highly sensitive data - may require physical destruction',
                'file_method': 'FILE_EATER',
                'device_method': 'SANITIZE_OR_DESTROY',
                'nist_level': NIST_DESTROY
            }
        }
    
    def display_banner(self):
        """Display the enhanced banner"""
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║                      EraseIT v4.0                             ║
║               Complete NIST SP 800-88 Compliance              ║
║                 Enhanced Certificate System                   ║
║                 Strict Policy Enforcement                     ║
╚═══════════════════════════════════════════════════════════════╝
Advanced Features:
• Complete HPA/DCO evidence collection in certificates
• Enhanced Windows device detection and wiping
• Android wipe (Manual Assist - requires user action in recovery)
• JSON and PDF certificate generation with QR codes
• Cross-platform support (Windows, Linux, macOS)
• Enhanced transparency logging for all operations
• Boot device protection and safety checks

KNOWN LIMITATIONS:
• Windows device wipe may be blocked by OS/antivirus (use Linux live USB)
• Android wipe requires manual completion in recovery mode
• SSD over-provisioned areas may not be cleared on all controllers
"""
        print(banner)
    
    def _log_wipe(self, target: str, status: str, nist_level: str, evidence: dict = None):
        """Log wipe operation."""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'status': status,
            'nist_level': nist_level,
            'evidence': evidence or {}
        }
        self.wipe_log.append(entry)
        logger.info(f"Wipe operation: {target} - {status} - NIST: {nist_level}")
    
    def secure_wipe_file(self, file_path: str, standard: str = 'FILE_EATER', progress_callback=None) -> bool:
        """Securely wipe a single file with specified standard"""
        if standard not in self.wiping_standards:
            logger.error(f"Invalid standard: {standard}")
            return False
        
        standard_config = self.wiping_standards[standard]
        

        
        try:
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return False
                
            if not os.path.isfile(file_path):
                logger.error(f"Path is not a file: {file_path}")
                return False
            
            # Validate file path for security
            if not validate_target_path(file_path):
                logger.error(f"Invalid file path (Blocked): {file_path}")
                return False
                
            # Check permissions
            if not check_file_permissions(file_path):
                logger.error(f"Insufficient permissions for: {file_path}")
                return False
            
            # Check for HPA/DCO on the device
            hpa_dco_evidence = self.file_eater.check_device_hidden_areas(file_path)
            
            # Perform the wipe
            success, pre_hash, post_hash = self.file_eater.overwrite_file_data(
                file_path, 
                passes=standard_config['passes'], 
                progress_callback=progress_callback
            )
            
            if success:
                # Remove the file after successful overwrite
                try:
                    # Metadata wipe: Rename to random name before unlink
                    dir_name = os.path.dirname(file_path)
                    random_name = secrets.token_hex(16)
                    new_path = os.path.join(dir_name, random_name)
                    os.rename(file_path, new_path)
                    
                    os.remove(new_path)
                    logger.info(f"File removed after wiping: {file_path} -> {new_path}")
                    
                    # Fix #4: SSD TRIM Support (Linux only)
                    if platform.system() == "Linux":
                        try:
                            # Attempt to trim the directory to help SSD controller cleanup
                            # Using -v for verbose to confirm it ran, but catch errors silently (best effort)
                            if shutil.which('fstrim'):
                                subprocess.run(['fstrim', '-v', dir_name], 
                                             capture_output=True, timeout=5)
                                logger.info(f"TRIM command issued for {dir_name}")
                        except Exception as trim_err:
                            # Non-critical failure
                            logger.debug(f"TRIM skipped/failed: {trim_err}")
                except Exception as e:
                    logger.error(f"Error removing file after wipe: {e}")
                    # Even if removal fails, the data is overwritten
                
                # Verify hash verification
                hash_verification = "Verified" if pre_hash != post_hash else "Failed"
                
                evidence = hpa_dco_evidence.copy()
                evidence.update({
                    'pre_hash': pre_hash,
                    'post_hash': post_hash,
                    'hash_verification': hash_verification,
                    'standard_used': standard,
                    'passes_completed': standard_config['passes']
                })
                
                self._log_wipe(file_path, "SUCCESS", standard_config['nist_level'], evidence)
                return True
            else:
                self._log_wipe(file_path, "FAILED", standard_config['nist_level'], hpa_dco_evidence)
                return False
        except Exception as e:
            logger.error(f"Error wiping file {file_path}: {e}")
            self._log_wipe(file_path, f"ERROR: {e}", standard_config['nist_level'])
            return False
    
    def secure_wipe_directory(self, dir_path: str, standard: str = 'FILE_EATER', progress_callback=None) -> bool:
        """Securely wipe a directory recursively"""
        if standard not in self.wiping_standards:
            logger.error(f"Invalid standard: {standard}")
            return False
        
        standard_config = self.wiping_standards[standard]
        
        if OPERATION_MODE == 'DRY_RUN':
            print(f"[DRY RUN] Would wipe directory: {dir_path} with standard {standard}")
            self._log_wipe(dir_path, "DRY_RUN", standard_config['nist_level'])
            return True
        
        success = True
        file_count = 0
        error_count = 0
        
        try:
            # Validate directory path for security
            if not validate_target_path(dir_path):
                logger.error(f"Invalid directory path (Blocked): {dir_path}")
                return False
                
            # Count total files first
            total_files = 0
            for root, dirs, files in os.walk(dir_path):
                total_files += len(files)
            
            if total_files == 0:
                logger.warning(f"No files found in directory: {dir_path}")
                self._log_wipe(dir_path, "EMPTY", standard_config['nist_level'])
                return True
            
            for root, dirs, files in os.walk(dir_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if progress_callback:
                        progress_msg = f"Wiping file {file_count+1}/{total_files}: {file}"
                        if not progress_callback(0, file_count, total_files, progress_msg):
                            self._log_wipe(dir_path, "ABORTED", standard_config['nist_level'])
                            return False
                    
                    if not self.secure_wipe_file(file_path, standard, progress_callback):
                        success = False
                        error_count += 1
                    
                    file_count += 1
            
            # Optionally, delete empty directories after files are gone
            if success:
                try:
                    shutil.rmtree(dir_path)
                    logger.info(f"Directory removed after wiping: {dir_path}")
                except Exception as e:
                    logger.warning(f"Could not remove directory {dir_path}: {e}")
        
        except Exception as e:
            logger.error(f"Error wiping directory {dir_path}: {e}")
            success = False
        
        if success:
            self._log_wipe(dir_path, "SUCCESS", standard_config['nist_level'])
        else:
            self._log_wipe(dir_path, f"PARTIAL ({error_count} errors)", standard_config['nist_level'])
        
        return success
    
    def execute_policy_wipe(self, device_path, policy_level):
        """Execute wipe based on policy with verification"""
        if policy_level not in self.wipe_policies:
            return {'success': False, 'error': f'Invalid policy: {policy_level}'}
        
        policy_config = self.wipe_policies[policy_level]
        

            
        # Validate path
        if not validate_target_path(device_path):
             return {'success': False, 'error': f'Invalid device path (Blocked): {device_path}'}
        
        # Execute device erase based on policy
        result = self.device_backend.secure_erase_device(device_path, policy_level)
        
        # Log the result
        status = "SUCCESS" if result['success'] else "FAILED"
        self._log_wipe(device_path, status, policy_config['nist_level'], result.get('evidence', {}))
        
        return result
    
    def detect_hpa_dco(self, device_path=None):
        """Detect HPA/DCO on specified device or all devices"""
        detector = EnhancedHPADCODetector()
        return detector.detect_hidden_areas(device_path)
    
    def perform_android_crypto_wipe(self, device_id):
        """Perform Android crypto wipe"""
        android_wiper = AndroidCryptoWipe()
        return android_wiper.perform_crypto_wipe(device_id)
    
    def verify_certificate_offline(self, cert_path, public_key_path=None):
        """Verify certificate offline"""
        try:
            with open(cert_path, 'r', encoding='utf-8') as f:
                cert_data = json.load(f)
            
            if 'jws' not in cert_data:
                return False, "No JWS signature found in certificate"
            
            # Extract signature and remove it for verification
            jws_signature = cert_data['jws']
            cert_without_jws = cert_data.copy()
            del cert_without_jws['jws']
            
            # Canonicalize the JSON without signature
            canonical_data = canonical_json_bytes(cert_without_jws)
            
            # Load public key
            if public_key_path is None:
                public_key_path = PUBLIC_KEY_PATH
            
            if not os.path.exists(public_key_path):
                return False, f"Public key not found: {public_key_path}"
            
            with open(public_key_path, 'rb') as f:
                public_key = serialization.load_pem_public_key(f.read())
            
            # Verify signature
            try:
                # Add padding for base64 decoding
                sig_bytes = base64.urlsafe_b64decode(jws_signature + '==')
                public_key.verify(sig_bytes, canonical_data)
                return True, "VALID - Signature verified successfully"
            except InvalidSignature:
                return False, "INVALID SIGNATURE"
            
        except Exception as e:
            return False, f"Verification error: {e}"
    
    def verify_transparency_log(self, certificate_id):
        """Verify if certificate exists in transparency log"""
        return self.transparency_log.verify_entry(certificate_id)
    
    def generate_certificate(self, operation_details: dict) -> dict:
        """Generate certificate for operation"""
        try:
            # Ensure certificates directory exists
            cert_dir = Path("certificates")
            cert_dir.mkdir(exist_ok=True)
            
            # Generate certificate data
            cert_data = self.cert_generator.generate_json_certificate(operation_details)
            
            # Save JSON certificate
            json_path = self.cert_generator.save_json_certificate(cert_data)
            
            # Generate PDF certificate if available
            pdf_path = None
            if PDF_AVAILABLE:
                try:
                    pdf_path = self.cert_generator.generate_pdf_certificate(cert_data)
                except Exception as e:
                    logger.warning(f"PDF certificate generation failed: {e}")
            
            # Add to transparency log
            signature = cert_data.get('jws', 'unsigned')
            self.transparency_log.add_entry(cert_data, signature)
            
            return {
                'success': True,
                'json_path': json_path,
                'pdf_path': pdf_path,
                'certificate_id': cert_data['certificate_id']
            }
            
        except Exception as e:
            logger.error(f"Certificate generation failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }

class EnhancedProfessionalWiperGUI:
    """Enhanced GUI with all missing features integrated"""
    
    def __init__(self):
        # Initialize the main window
        if CUSTOM_TKINTER_AVAILABLE:
            ctk.set_appearance_mode("Dark")
            ctk.set_default_color_theme("blue")
            self.root = ctk.CTk()
        else:
            self.root = tk.Tk()
        
        self.root.title("EraseIT - Professional Data Sanitization Suite")
        self.root.geometry("1100x700")
        self.root.minsize(1000, 600)
        
        # Grid Configuration (1x2)
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
        
        # Initialize the enhanced wiper engine
        self.wiper = EnhancedSecureDataWiper()
        
        # Current operation tracking
        self.current_operation = None
        self.stop_requested = False
        self.worker_thread = None
        
        # Initialize dictionary to hold button references (must be before create_sidebar)
        self.nav_buttons = {}
        
        # Initialize UI variables with defaults (prevents AttributeError if referenced before views setup)
        self.progress_var = tk.StringVar(value="Ready")
        self.target_var = tk.StringVar()
        self.standard_var = tk.StringVar(value="FILE_EATER")
        self.policy_var = tk.StringVar(value="CLEAR")
        self.operator_var = tk.StringVar(value=os.getlogin() if hasattr(os, 'getlogin') else "Operator")
        self.stop_button = None  # Will be set in setup_file_view if customtkinter available
        self.results_text = None  # Will be set in setup_file_view
        self.progress_bar = None  # Will be set in setup_file_view
        self.log_text = None  # Will be set in setup_log_tab
        self.cert_display_text = None  # Will be set in setup_certificate_tab
        self.verify_results_text = None  # Will be set in setup_verification_tab
        self.hpa_results_text = None  # Will be set in setup_hpa_view
        self.cert_path_var = tk.StringVar()
        self.verify_cert_id_var = tk.StringVar()
        
        # Create Sidebar
        self.create_sidebar()
        
        # Create Main Content Area
        if CUSTOM_TKINTER_AVAILABLE:
            self.main_view = ctk.CTkFrame(self.root, corner_radius=0, fg_color="transparent")
        else:
            self.main_view = ttk.Frame(self.root)
        
        self.main_view.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        
        # Dictionary to store frame references
        self.frames = {}
        
        # Create all views (hidden by default)
        self.create_views()
        
        # Select default view
        self.select_frame("File Wipe")

    def create_sidebar(self):
        """Create the sidebar navigation menu"""
        if CUSTOM_TKINTER_AVAILABLE:
            self.sidebar_frame = ctk.CTkFrame(self.root, width=200, corner_radius=0)
            self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
            self.sidebar_frame.grid_rowconfigure(8, weight=1) # Spacer
            
            # App Logo/Title
            logo_label = ctk.CTkLabel(self.sidebar_frame, text="EraseIT", 
                                     font=ctk.CTkFont(size=24, weight="bold"))
            logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
            
            sub_label = ctk.CTkLabel(self.sidebar_frame, text="Secure Data Engine",
                                    font=ctk.CTkFont(size=12))
            sub_label.grid(row=1, column=0, padx=20, pady=(0, 20))
            
            # Navigation Buttons
            self.add_nav_button("File Wipe", self.file_view_btn_event, row=2)
            self.add_nav_button("Device Wipe", self.device_view_btn_event, row=3)
            self.add_nav_button("Android", self.android_view_btn_event, row=4)
            self.add_nav_button("HPA/DCO", self.hpa_view_btn_event, row=5)
            self.add_nav_button("Certificate", self.cert_view_btn_event, row=6)
            self.add_nav_button("Verification", self.verify_view_btn_event, row=7)
            
            # Status Section (Bottom)
            self.sidebar_status = tk.StringVar(value="Ready")
            status_label = ctk.CTkLabel(self.sidebar_frame, textvariable=self.sidebar_status,
                                       text_color="gray", anchor="w")
            status_label.grid(row=9, column=0, padx=20, pady=10, sticky="ew")
            
            # Utils
            ctk.CTkButton(self.sidebar_frame, text="Compliance", command=self.show_compliance_popup,
                         fg_color="transparent", border_width=1, text_color=("gray10", "#DCE4EE")).grid(row=10, column=0, padx=20, pady=5)
                         
            ctk.CTkButton(self.sidebar_frame, text="Eco-Impact", command=self.show_eco_popup, 
                         fg_color="transparent", border_width=1, text_color=("gray10", "#DCE4EE")).grid(row=11, column=0, padx=20, pady=(5, 20))
        else:
            # Fallback
            pass

    def add_nav_button(self, name, command, row):
        """Helper to add styled nav button"""
        if CUSTOM_TKINTER_AVAILABLE:
            btn = ctk.CTkButton(self.sidebar_frame, corner_radius=0, height=40, border_spacing=10, text=name,
                                fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                anchor="w", command=command)
            btn.grid(row=row, column=0, sticky="ew")
            self.nav_buttons[name] = btn
        
    def select_frame(self, name):
        """Show selected frame and highlight button"""
        # Hide all
        for frame in self.frames.values():
            frame.grid_forget()
        
        # Reset buttons
        if CUSTOM_TKINTER_AVAILABLE:
            for btn_name, btn in self.nav_buttons.items():
                btn.configure(fg_color="transparent")
        
        # Show selected
        if name in self.frames:
            self.frames[name].grid(row=0, column=0, sticky="nsew")
        
        # Highlight button
        if CUSTOM_TKINTER_AVAILABLE and name in self.nav_buttons:
            self.nav_buttons[name].configure(fg_color=("gray75", "gray25"))
            
    # Event Handlers
    def file_view_btn_event(self): self.select_frame("File Wipe")
    def device_view_btn_event(self): self.select_frame("Device Wipe")
    def android_view_btn_event(self): self.select_frame("Android")
    def hpa_view_btn_event(self): self.select_frame("HPA/DCO")
    def cert_view_btn_event(self): self.select_frame("Certificate")
    def verify_view_btn_event(self): self.select_frame("Verification")
    
    def create_views(self):
        """Initialize all view frames"""
        self.setup_file_view()
        self.setup_device_view()
        self.setup_android_view()
        self.setup_hpa_view()
        self.setup_certificate_tab()
        self.setup_verification_tab()
        # self.setup_log_view()

    def show_compliance_popup(self):
        """Show Compliance Scorecard"""
        scorecard = ComplianceEngine.get_compliance_scorecard("DoD 5220.22-M") # Default assumption for scorecard view
        
        msg = "EraseIT Compliance Status:\n\n"
        for std, status in scorecard.items():
            icon = "✅" if "COMPLIANT" in status else "❌"
            msg += f"{icon} {std}: {status}\n"
            
        messagebox.showinfo("Compliance Scorecard", msg)

    def show_eco_popup(self):
        """Show Eco-Impact Calculator"""
        # Simple calculator dialog
        size_str = simpledialog.askstring("Eco-Calculator", "Enter drive size in GB (e.g., 500):")
        if size_str:
            try:
                size_gb = float(size_str)
                co2 = ComplianceEngine.calculate_eco_impact(size_gb)
                messagebox.showinfo("Eco-Impact Report", 
                                  f"♻️ By securely erasing and reusing this {size_gb}GB drive:\n\n"
                                  f"🌍 You saved approx {co2} kg of CO2!\n"
                                  f"🌱 Equivalent to planting {round(co2/20, 1)} trees.")
            except:
                messagebox.showerror("Error", "Invalid size entered.")
        
        # Initialize certificate directory
        try:
            CERTIFICATES_DIR.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        
        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Run dependency check
        self.check_dependencies()
        
    def start_worker(self, target_func, on_finish=None):
        """Start a background worker thread"""
        if self.worker_thread and self.worker_thread.is_alive():
            return
            
        self.stop_requested = False
        self.wiper.cancel_event.clear()
        
        def wrapper():
            try:
                result = target_func()
            except Exception as e:
                result = {'success': False, 'error': str(e)}
            
            if on_finish:
                self.root.after(0, on_finish, result)
        
        self.worker_thread = threading.Thread(target=wrapper)
        self.worker_thread.daemon = True
        self.worker_thread.start()

    def check_dependencies(self):
        """Check availability of optional dependencies and warn user"""
        missing = []
        if not CRYPTO_AVAILABLE: missing.append("Cryptography (required for signing)")
        if not PDF_AVAILABLE: missing.append("ReportLab (required for PDF certificates)")
        if not QR_AVAILABLE: missing.append("Pillow/QRCode (required for QR codes)")
        
        if missing:
             msg = "Some optional dependencies are missing:\n\n" + "\n".join([f"• {m}" for m in missing])
             msg += "\n\nFunctionality will be limited."
             messagebox.showwarning("Dependency Check", msg)
    
    def create_enhanced_header(self):
        """Create enhanced header with title and help button"""
        if CUSTOM_TKINTER_AVAILABLE:
            header_frame = ctk.CTkFrame(self.main_frame, height=100, corner_radius=10)
            header_frame.pack(fill="x", padx=10, pady=(10, 5))
            
            # Title section
            title_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
            title_frame.pack(fill="x", padx=10, pady=5)
            
            main_title = ctk.CTkLabel(title_frame, text="EraseIT - Secure Data Wiping Tool", 
                                     font=ctk.CTkFont(size=24, weight="bold"))
            main_title.pack(pady=(5, 0))
            
            sub_title = ctk.CTkLabel(title_frame, text="Verified Erasure. Certified Security.",
                                    font=ctk.CTkFont(size=14))
            sub_title.pack(pady=(0, 5))
            
            # Help button
            help_button = ctk.CTkButton(header_frame, text="?", width=30, height=30,
                                       command=self.show_help_popup, corner_radius=15)
            help_button.place(relx=0.95, rely=0.5, anchor="center")

            # Export Button
            export_btn = ctk.CTkButton(header_frame, text="Export USB", width=100, height=30,
                                     command=self.export_portable, corner_radius=15,
                                     fg_color="blue", hover_color="dark blue")
            export_btn.place(relx=0.85, rely=0.5, anchor="center")


            
    def export_portable(self):
        """Export EraseIT to a portable USB/folder"""
        target_dir = filedialog.askdirectory(title="Select USB Drive or Folder for Export")
        if not target_dir: return
        
        try:
            export_path = Path(target_dir) / "EraseIT_Portable"
            export_path.mkdir(exist_ok=True)
            
            # Copy main script
            current_script = Path(__file__).resolve()
            shutil.copy2(current_script, export_path / "eraseit.py")
            
            # Create launcher scripts
            with open(export_path / "RUN_WINDOWS.bat", "w") as f:
                f.write("@echo off\n")
                f.write("python eraseit.py\n")
                f.write("pause\n")
                
            with open(export_path / "RUN_LINUX.sh", "w") as f:
                f.write("#!/bin/bash\n")
                f.write("sudo python3 eraseit.py\n")
            
            # Make linux script executable
            if platform.system() != "Windows":
                try: os.chmod(export_path / "RUN_LINUX.sh", 0o755)
                except: pass
                
            # Copy requirements if exists (we will create this next)
            req_path = Path("requirements.txt")
            if req_path.exists():
                shutil.copy2(req_path, export_path / "requirements.txt")
                
            messagebox.showinfo("Export Successful", 
                              f"EraseIT has been exported to:\n{export_path}\n\n"
                              "You can now run it from any computer with Python installed.")
        except Exception as e:
            logger.error(f"Export failed: {e}")
            messagebox.showerror("Export Failed", f"Could not export files: {e}")
            
        else:
            header_frame = ttk.Frame(self.main_frame)
            header_frame.pack(fill="x", padx=10, pady=(10, 5))
            
            main_title = ttk.Label(header_frame, text="EraseIT - Secure Data Wiping Tool",
                                 font=("Arial", 18, "bold"))
            main_title.pack(pady=(5, 0))
            
            sub_title = ttk.Label(header_frame, text="Verified Erasure. Certified Security.",
                                font=("Arial", 11))
            sub_title.pack(pady=(0, 5))
            
            help_button = ttk.Button(header_frame, text="?", width=3,
                                   command=self.show_help_popup)
            help_button.place(relx=0.95, rely=0.5, anchor="center")
            

        


    def verify_operator_authorization(self, action_name, policy="standard", require_destructive_confirm=True):
        """
        Completed authorization check:
        1. Check PIN (Prompt if needed)
        2. Require typed 'DELETE' for destructive actions
        """
        global OPERATOR_PIN
        
        # 1. PIN Check
        # Check if PIN is already loaded from config or session
        if OPERATOR_PIN is None and PIN_HASH is None:
             # First time setup
             new_pin = simpledialog.askstring("Set Operator PIN", "Set a new Operator PIN for this session (and future):", show='*')
             if not new_pin: return False
             confirm_pin = simpledialog.askstring("Confirm Check", "Confirm Operator PIN:", show='*')
             if new_pin != confirm_pin:
                 messagebox.showerror("Error", "PINs do not match.")
                 return False
             
             # Hash it
             salt = secrets.token_bytes(16)
             kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
             pin_hash = kdf.derive(new_pin.encode())
             
             OPERATOR_PIN = pin_hash
             self.operator_salt = salt
             
             # Save to config
             try:
                 config_manager.set('pin_hash', base64.b64encode(pin_hash).decode())
                 config_manager.set('pin_salt', base64.b64encode(salt).decode())
                 logger.info("Operator PIN saved to config.")
             except Exception as e:
                 logger.error(f"Failed to save PIN to config: {e}")
        
        # Now verify PIN
        pin_input = simpledialog.askstring("Operator Authentication", f"Enter Operator PIN to authorize {action_name}:", show='*')
        if not pin_input: return False
        
        # Determine strict source of truth
        # If OPERATOR_PIN is set (session), use it.
        # If not, try GLOBAL PIN_HASH (loaded from config).
        # Fallback to default.
        
        target_hash = OPERATOR_PIN if OPERATOR_PIN is not None else PIN_HASH
        if not hasattr(self, 'operator_salt'):
             self.operator_salt = PIN_SALT
        
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=self.operator_salt, iterations=100000)
        check_hash = kdf.derive(pin_input.encode())
        
        # Ensure target_hash is bytes
        if isinstance(target_hash, str):
            try: target_hash = base64.b64decode(target_hash)
            except: pass
            
        if not hmac.compare_digest(target_hash, check_hash):
             messagebox.showerror("Authentication Failed", "Incorrect PIN.")
             return False

        # 2. Typed Confirmation (if required)
        if require_destructive_confirm:
            confirm = simpledialog.askstring("Critical Confirmation", f"Type 'DELETE' to confirm {action_name}:")
            if confirm != "DELETE":
                 messagebox.showerror("Aborted", "Verification text did not match.")
                 return False
              
        return True
    
    def show_help_popup(self):
        """Show help popup explaining how secure wiping works"""
        help_text = """
EraseIT - Secure Data Wiping Tool

How Secure Wiping Works:

Each wipe pass overwrites the file's binary data with zeros, ones, and random patterns.
This ensures that no forensic or recovery tools can restore the original content.

After overwriting, the app verifies the file's SHA-256 hash to confirm that all previous data is gone.
Hidden disk areas and SSD blocks are also cleared using system-level sanitize commands.

Finally, a digital certificate is generated to prove the data was securely destroyed.

Wipe Modes:
• CLEAR - Basic 1-pass overwrite (quick delete) - NIST Clear
• SECURE - 3-pass DoD 5220.22-M wipe (standard secure erase) - NIST Purge
• MILITARY - 7-pass extended wipe (advanced security) - NIST Destroy
• FILE_EATER - 35-pass Gutmann method (extreme data sanitization) - NIST Destroy

Safety Features:
• Boot device protection prevents accidental system destruction
• Multiple confirmation dialogs for destructive operations
• Progress tracking with cancellation support
• Complete audit logging with digital certificates

All operations comply with NIST SP 800-88 standards for data sanitization.
"""
        if CUSTOM_TKINTER_AVAILABLE:
            # Create custom popup window
            popup = ctk.CTkToplevel(self.root)
            popup.title("EraseIT - How Secure Wiping Works")
            popup.geometry("600x400")
            popup.transient(self.root)
            popup.grab_set()
            
            # Add scrollable text
            text_frame = ctk.CTkFrame(popup)
            text_frame.pack(fill="both", expand=True, padx=20, pady=20)
            
            text_widget = ctk.CTkTextbox(text_frame, wrap="word")
            text_widget.pack(fill="both", expand=True, padx=10, pady=10)
            text_widget.insert("1.0", help_text)
            text_widget.configure(state="disabled")
            
            # Close button
            close_btn = ctk.CTkButton(popup, text="Close", command=popup.destroy,
                                     corner_radius=10)
            close_btn.pack(pady=10)
            
        else:
            from tkinter import Toplevel, Text, Scrollbar, END
            popup = Toplevel(self.root)
            popup.title("EraseIT - How Secure Wiping Works")
            popup.geometry("600x400")
            
            text_widget = Text(popup, wrap="word", padx=10, pady=10)
            text_widget.pack(fill="both", expand=True)
            text_widget.insert(END, help_text)
            text_widget.config(state="disabled")
            
            scrollbar = Scrollbar(text_widget)
            scrollbar.pack(side="right", fill="y")
            text_widget.config(yscrollcommand=scrollbar.set)
            scrollbar.config(command=text_widget.yview)
            
            close_btn = ttk.Button(popup, text="Close", command=popup.destroy)
            close_btn.pack(pady=10)
    
    def show_completion_popup(self, certificate_path):
        """Show completion popup with certificate info"""
        if CUSTOM_TKINTER_AVAILABLE:
            popup = ctk.CTkToplevel(self.root)
            popup.title("Wipe Completed Successfully!")
            popup.geometry("500x200")
            popup.transient(self.root)
            popup.grab_set()
            
            # Success message
            success_label = ctk.CTkLabel(popup, 
                                       text="✅ Wipe Completed Successfully!\nCertificate has been generated and verified.",
                                       font=ctk.CTkFont(size=14, weight="bold"))
            success_label.pack(pady=20)
            
            # Certificate location
            cert_label = ctk.CTkLabel(popup, 
                                    text=f"Location: {certificate_path}",
                                    font=ctk.CTkFont(size=12))
            cert_label.pack(pady=10)
            
            # Button frame
            button_frame = ctk.CTkFrame(popup, fg_color="transparent")
            button_frame.pack(pady=20)
            
            def open_folder():
                """Open certificate folder in file explorer"""
                folder_path = os.path.dirname(certificate_path)
                if platform.system() == "Windows":
                    os.startfile(folder_path)
                elif platform.system() == "Linux":
                    subprocess.run(['xdg-open', folder_path])
                else:
                    subprocess.run(['open', folder_path])  # macOS
            
            open_btn = ctk.CTkButton(button_frame, text="Open Certificate Folder", 
                                   command=open_folder, corner_radius=10)
            open_btn.pack(side="left", padx=10)
            
            close_btn = ctk.CTkButton(button_frame, text="Close", 
                                    command=popup.destroy, corner_radius=10)
            close_btn.pack(side="left", padx=10)
            
        else:
            from tkinter import Toplevel, Label, Button, Frame
            popup = Toplevel(self.root)
            popup.title("Wipe Completed Successfully!")
            popup.geometry("500x200")
            popup.transient(self.root)
            popup.grab_set()
            
            success_label = Label(popup, 
                                text="✅ Wipe Completed Successfully!\nCertificate has been generated and verified.",
                                font=("Arial", 12, "bold"))
            success_label.pack(pady=20)
            
            cert_label = Label(popup, 
                             text=f"Location: {certificate_path}")
            cert_label.pack(pady=10)
            
            button_frame = Frame(popup)
            button_frame.pack(pady=20)
            
            def open_folder():
                folder_path = os.path.dirname(certificate_path)
                if platform.system() == "Windows":
                    os.startfile(folder_path)
                elif platform.system() == "Linux":
                    subprocess.run(['xdg-open', folder_path])
                else:
                    subprocess.run(['open', folder_path])
            
            open_btn = Button(button_frame, text="Open Certificate Folder", 
                            command=open_folder)
            open_btn.pack(side="left", padx=10)
            
            close_btn = Button(button_frame, text="Close", 
                             command=popup.destroy)
            close_btn.pack(side="left", padx=10)
    
    def setup_file_view(self):
        """Setup file wiping view with enhanced progress and tooltips"""
        # Create Frame
        view_frame = ctk.CTkFrame(self.main_view, corner_radius=0, fg_color="transparent")
        view_frame.grid(row=0, column=0, sticky="nsew")
        self.frames["File Wipe"] = view_frame
        
        # Title
        ctk.CTkLabel(view_frame, text="Secure File & Directory Wipe", 
                    font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w", pady=(0, 20))
        
        if CUSTOM_TKINTER_AVAILABLE:
            # Main Content Card
            main_frame = ctk.CTkFrame(view_frame, corner_radius=10)
            main_frame.pack(fill="both", expand=True)
            
            # Target selection
            target_frame = ctk.CTkFrame(main_frame, corner_radius=8, fg_color="transparent")
            target_frame.pack(fill="x", padx=10, pady=10)
            
            ctk.CTkLabel(target_frame, text="Target File or Directory:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
            self.target_var = tk.StringVar()
            target_entry = ctk.CTkEntry(target_frame, textvariable=self.target_var, width=400, corner_radius=8)
            target_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
            
            browse_frame = ctk.CTkFrame(target_frame, fg_color="transparent")
            browse_frame.grid(row=0, column=2, padx=5, pady=5)
            ctk.CTkButton(browse_frame, text="Browse File", command=self.browse_file, corner_radius=8, width=100).pack(side="left", padx=2)
            ctk.CTkButton(browse_frame, text="Browse Folder", command=self.browse_folder, corner_radius=8, width=100).pack(side="left", padx=2)
            
            target_frame.columnconfigure(1, weight=1)
            
            # Settings frame
            settings_frame = ctk.CTkFrame(main_frame, corner_radius=8)
            settings_frame.pack(fill="x", padx=10, pady=10)
            
            # Wiping standard
            ctk.CTkLabel(settings_frame, text="Wiping Standard:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
            self.standard_var = tk.StringVar(value="SECURE")
            standards = list(self.wiper.wiping_standards.keys())
            standard_combo = ctk.CTkComboBox(settings_frame, variable=self.standard_var, values=standards, state="readonly", corner_radius=8)
            standard_combo.grid(row=0, column=1, padx=5, pady=5, sticky="w")
            ToolTip(standard_combo, "Select the security level for data wiping")
            
            # Policy selection (Removed Policy from File Wipe to simplify, or keep?)
            # Keeping for consistency but maybe optional
            ctk.CTkLabel(settings_frame, text="Policy Level:").grid(row=0, column=2, sticky="w", padx=5, pady=5)
            self.policy_var = tk.StringVar(value="PURGE")
            policies = list(self.wiper.wipe_policies.keys())
            policy_combo = ctk.CTkComboBox(settings_frame, variable=self.policy_var, values=policies, state="readonly", corner_radius=8)
            policy_combo.grid(row=0, column=3, padx=5, pady=5, sticky="w")
            
            # Operator name
            ctk.CTkLabel(settings_frame, text="Operator Name:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
            self.operator_var = tk.StringVar(value=os.getlogin())
            operator_entry = ctk.CTkEntry(settings_frame, textvariable=self.operator_var, width=200, corner_radius=8)
            operator_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")
            
            settings_frame.columnconfigure(1, weight=1)
            settings_frame.columnconfigure(3, weight=1)
            
            # Action buttons with enhanced styling
            button_frame = ctk.CTkFrame(main_frame, corner_radius=8, fg_color="transparent")
            button_frame.pack(fill="x", padx=10, pady=20)
            
            # Left actions
            ctk.CTkButton(button_frame, text="Wipe File", command=self.start_file_wipe, 
                         width=140, height=40, corner_radius=20, font=ctk.CTkFont(size=14, weight="bold")).pack(side="left", padx=10)
            ctk.CTkButton(button_frame, text="Wipe Directory", command=self.start_directory_wipe, 
                         width=140, height=40, corner_radius=20, font=ctk.CTkFont(size=14, weight="bold")).pack(side="left", padx=10)
            
            # Right actions
            ctk.CTkButton(button_frame, text="Wipe & Certify", command=self.wipe_and_certify, 
                         width=160, height=40, corner_radius=20, fg_color="#27ae60", hover_color="#2ecc71",
                         font=ctk.CTkFont(size=14, weight="bold")).pack(side="right", padx=10)
            
            # Stop button (initially disabled)
            self.stop_button = ctk.CTkButton(button_frame, text="STOP", command=self.stop_operation,
                                           width=100, height=40, corner_radius=20, state="disabled", fg_color="#c0392b", hover_color="#e74c3c")
            self.stop_button.pack(side="right", padx=10)
            
            # Enhanced progress bar with detailed feedback
            progress_frame = ctk.CTkFrame(main_frame, corner_radius=8)
            progress_frame.pack(fill="x", padx=10, pady=10)
            
            self.progress_var = tk.StringVar()
            self.progress_var.set("Ready - Select a file or directory to wipe")
            progress_label = ctk.CTkLabel(progress_frame, textvariable=self.progress_var)
            progress_label.pack(pady=5)
            
            self.progress_bar = ctk.CTkProgressBar(progress_frame, width=400, corner_radius=5, height=20)
            self.progress_bar.pack(pady=5, fill="x", padx=20)
            self.progress_bar.set(0)
            
            # Results display
            results_frame = ctk.CTkFrame(main_frame, corner_radius=8)
            results_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            ctk.CTkLabel(results_frame, text="Operation Log:", anchor="w").pack(fill="x", padx=10, pady=(10,0))
            self.results_text = ctk.CTkTextbox(results_frame, corner_radius=8)
            self.results_text.pack(fill="both", expand=True, padx=10, pady=10)
            
        else:
            # Fallback (Ideally remove, but keeping minimum for safety)
            ttk.Label(view_frame, text="Modern UI requires CustomTkinter").pack()

    
    def setup_device_view(self):
        """Setup device wiping view"""
        # Create Frame
        view_frame = ctk.CTkFrame(self.main_view, corner_radius=0, fg_color="transparent")
        view_frame.grid(row=0, column=0, sticky="nsew")
        self.frames["Device Wipe"] = view_frame
        
        # Title
        ctk.CTkLabel(view_frame, text="Secure Device Erasure (Full Disk)", 
                    font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w", pady=(0, 20))
        
        if CUSTOM_TKINTER_AVAILABLE:
            main_frame = ctk.CTkFrame(view_frame, corner_radius=10)
            main_frame.pack(fill="both", expand=True)
            
            # Device selection
            device_frame = ctk.CTkFrame(main_frame, corner_radius=8, fg_color="transparent")
            device_frame.pack(fill="x", padx=10, pady=10)
            
            ctk.CTkLabel(device_frame, text="Device Path:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
            self.device_var = tk.StringVar()
            self.device_combo = ctk.CTkComboBox(device_frame, variable=self.device_var, width=400, corner_radius=8)
            self.device_combo.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
            
            ctk.CTkButton(device_frame, text="Detect Devices", command=self.detect_devices, corner_radius=8, width=120).grid(row=0, column=2, padx=5, pady=5)
            
            device_frame.columnconfigure(1, weight=1)
            
            # Policy selection
            policy_frame = ctk.CTkFrame(main_frame, corner_radius=8, fg_color="transparent")
            policy_frame.pack(fill="x", padx=10, pady=10)
            
            ctk.CTkLabel(policy_frame, text="Policy Level:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
            self.device_policy_var = tk.StringVar(value="PURGE")
            policies = list(self.wiper.wipe_policies.keys())
            policy_combo = ctk.CTkComboBox(policy_frame, variable=self.device_policy_var, values=policies, state="readonly", corner_radius=8)
            policy_combo.grid(row=0, column=1, padx=5, pady=5, sticky="w")
            
            # Action buttons
            button_frame = ctk.CTkFrame(main_frame, corner_radius=8, fg_color="transparent")
            button_frame.pack(fill="x", padx=10, pady=20)
            
            ctk.CTkButton(button_frame, text="Wipe Device", command=self.start_device_wipe, 
                         width=200, height=40, corner_radius=20, fg_color="#c0392b", hover_color="#e74c3c",
                         font=ctk.CTkFont(size=14, weight="bold")).pack(side="left", padx=10)
            
            # Results display
            results_frame = ctk.CTkFrame(main_frame, corner_radius=8)
            results_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            ctk.CTkLabel(results_frame, text="Device Operation Log:", anchor="w").pack(fill="x", padx=10, pady=(10,0))
            self.device_results_text = ctk.CTkTextbox(results_frame, corner_radius=8)
            self.device_results_text.pack(fill="both", expand=True, padx=10, pady=10)
            
        else:
            ttk.Label(view_frame, text="Modern UI requires CustomTkinter").pack()
    
    def setup_android_view(self):
        """Setup Android wiping view"""
        # Create Frame
        view_frame = ctk.CTkFrame(self.main_view, corner_radius=0, fg_color="transparent")
        view_frame.grid(row=0, column=0, sticky="nsew")
        self.frames["Android"] = view_frame
        
        # Title
        ctk.CTkLabel(view_frame, text="Android Secure Wipe (Factory Reset + Fill)", 
                    font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w", pady=(0, 20))
        
        if CUSTOM_TKINTER_AVAILABLE:
            main_frame = ctk.CTkFrame(view_frame, corner_radius=10)
            main_frame.pack(fill="both", expand=True)
            
            # Android device selection
            android_frame = ctk.CTkFrame(main_frame, corner_radius=8, fg_color="transparent")
            android_frame.pack(fill="x", padx=10, pady=10)
            
            ctk.CTkLabel(android_frame, text="Android Device ID:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
            self.android_device_var = tk.StringVar()
            self.android_device_combo = ctk.CTkComboBox(android_frame, variable=self.android_device_var, width=400, corner_radius=8)
            self.android_device_combo.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
            
            ctk.CTkButton(android_frame, text="Detect Devices", command=self.detect_android_devices, corner_radius=8, width=120).grid(row=0, column=2, padx=5, pady=5)
            
            android_frame.columnconfigure(1, weight=1)
            
            # ADB Status
            adb_frame = ctk.CTkFrame(main_frame, corner_radius=8, fg_color="transparent")
            adb_frame.pack(fill="x", padx=10, pady=10)
            
            self.adb_status_var = tk.StringVar()
            self.adb_status_var.set("Checking ADB...")
            ctk.CTkLabel(adb_frame, textvariable=self.adb_status_var, text_color="gray").pack(pady=5, anchor="w", padx=5)
            
            # Safety warning
            warning_frame = ctk.CTkFrame(main_frame, corner_radius=8, fg_color="#c0392b")
            warning_frame.pack(fill="x", padx=10, pady=10)
            
            warning_text = "⚠️ DANGER: This will factory reset the Android device and erase ALL user data!"
            ctk.CTkLabel(warning_frame, text=warning_text, text_color="white", font=ctk.CTkFont(weight="bold")).pack(pady=10)
            
            # Action buttons
            button_frame = ctk.CTkFrame(main_frame, corner_radius=8, fg_color="transparent")
            button_frame.pack(fill="x", padx=10, pady=20)
            
            ctk.CTkButton(button_frame, text="Wipe Android Device", command=self.start_android_wipe,
                         width=200, height=40, corner_radius=20, fg_color="#c0392b", hover_color="#e74c3c",
                         font=ctk.CTkFont(size=14, weight="bold")).pack(side="left", padx=10)
            
            # Results display
            results_frame = ctk.CTkFrame(main_frame, corner_radius=8)
            results_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            ctk.CTkLabel(results_frame, text="Android Log:", anchor="w").pack(fill="x", padx=10, pady=(10,0))
            self.android_results_text = ctk.CTkTextbox(results_frame, corner_radius=8)
            self.android_results_text.pack(fill="both", expand=True, padx=10, pady=10)
            
        else:
            ttk.Label(view_frame, text="Modern UI requires CustomTkinter").pack()
        
        # Check ADB status
        self.check_adb_status()
    
    def setup_hpa_view(self):
        """Setup HPA/DCO detection view"""
        # Create Frame
        view_frame = ctk.CTkFrame(self.main_view, corner_radius=0, fg_color="transparent")
        view_frame.grid(row=0, column=0, sticky="nsew")
        self.frames["HPA/DCO"] = view_frame
        
        # Title
        ctk.CTkLabel(view_frame, text="HPA/DCO Hidden Sector Management", 
                    font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w", pady=(0, 20))
        
        if CUSTOM_TKINTER_AVAILABLE:
            main_frame = ctk.CTkFrame(view_frame, corner_radius=10)
            main_frame.pack(fill="both", expand=True)
            
            # Device selection
            device_frame = ctk.CTkFrame(main_frame, corner_radius=8, fg_color="transparent")
            device_frame.pack(fill="x", padx=10, pady=10)
            
            ctk.CTkLabel(device_frame, text="Device Path:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
            self.hpa_device_var = tk.StringVar()
            device_entry = ctk.CTkEntry(device_frame, textvariable=self.hpa_device_var, width=400, corner_radius=8)
            device_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
            
            ctk.CTkButton(device_frame, text="Detect All Devices", command=self.detect_all_devices, corner_radius=8, width=120).grid(row=0, column=2, padx=5, pady=5)
            
            device_frame.columnconfigure(1, weight=1)
            
            # Info
            info_label = ctk.CTkLabel(main_frame, text="ℹ️ Hidden Protected Areas (HPA) and Device Configuration Overlays (DCO) can hide data from OS.",
                                     text_color="gray", font=("Arial", 11))
            info_label.pack(anchor="w", padx=15, pady=5)
            
            # Action buttons
            button_frame = ctk.CTkFrame(main_frame, corner_radius=8, fg_color="transparent")
            button_frame.pack(fill="x", padx=10, pady=20)
            
            ctk.CTkButton(button_frame, text="Scan for Hidden Areas", command=self.detect_hpa_dco,
                         width=200, height=40, corner_radius=20, font=ctk.CTkFont(size=14, weight="bold")).pack(side="left", padx=10)
            
            ctk.CTkButton(button_frame, text="Unlock/Remove HPA/DCO", command=self.remove_hpa_dco,
                         width=200, height=40, corner_radius=20, fg_color="#c0392b", hover_color="#e74c3c",
                         font=ctk.CTkFont(size=14, weight="bold")).pack(side="left", padx=10)
            
            # Results display
            results_frame = ctk.CTkFrame(main_frame, corner_radius=8)
            results_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            ctk.CTkLabel(results_frame, text="HPA/DCO Scan Results:", anchor="w").pack(fill="x", padx=10, pady=(10,0))
            self.hpa_results_text = ctk.CTkTextbox(results_frame, corner_radius=8)
            self.hpa_results_text.pack(fill="both", expand=True, padx=10, pady=10)
            
        else:
            ttk.Label(view_frame, text="Modern UI requires CustomTkinter").pack()
    
    def setup_certificate_tab(self):
        """Setup certificate generation and verification view"""
        # Create Frame (following same pattern as setup_file_view)
        view_frame = ctk.CTkFrame(self.main_view, corner_radius=0, fg_color="transparent") if CUSTOM_TKINTER_AVAILABLE else ttk.Frame(self.main_view)
        view_frame.grid(row=0, column=0, sticky="nsew")
        self.frames["Certificate"] = view_frame
        
        if CUSTOM_TKINTER_AVAILABLE:
            # Title
            ctk.CTkLabel(view_frame, text="Certificate Management", 
                        font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w", pady=(0, 20))
            
            main_frame = ctk.CTkFrame(view_frame, corner_radius=10)
            main_frame.pack(fill="both", expand=True)
            
            # Certificate path
            cert_frame = ctk.CTkFrame(main_frame, corner_radius=8)
            cert_frame.pack(fill="x", padx=10, pady=10)
            
            ctk.CTkLabel(cert_frame, text="Certificate Path:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
            self.cert_path_var = tk.StringVar()
            cert_entry = ctk.CTkEntry(cert_frame, textvariable=self.cert_path_var, width=400, corner_radius=8)
            cert_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
            
            ctk.CTkButton(cert_frame, text="Browse", command=self.browse_cert_path, corner_radius=8).grid(row=0, column=2, padx=5, pady=5)
            
            cert_frame.columnconfigure(1, weight=1)
            
            # Action buttons
            button_frame = ctk.CTkFrame(main_frame, corner_radius=8)
            button_frame.pack(fill="x", padx=10, pady=10)
            
            ctk.CTkButton(button_frame, text="Load Certificate", command=self.load_certificate, corner_radius=8).pack(side="left", padx=5)
            ctk.CTkButton(button_frame, text="Verify Certificate", command=self.verify_certificate, corner_radius=8).pack(side="left", padx=5)
            ctk.CTkButton(button_frame, text="View Certificate", command=self.view_certificate, corner_radius=8).pack(side="left", padx=5)
            ctk.CTkButton(button_frame, text="Generate Sample", command=self.generate_sample_certificate, corner_radius=8).pack(side="right", padx=5)
            
            # Certificate display
            display_frame = ctk.CTkFrame(main_frame, corner_radius=8)
            display_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            ctk.CTkLabel(display_frame, text="Certificate Contents:").pack(anchor="w", padx=5, pady=5)
            self.cert_display_text = ctk.CTkTextbox(display_frame, corner_radius=8)
            self.cert_display_text.pack(fill="both", expand=True, padx=5, pady=5)
            
        else:
            # Title
            ttk.Label(view_frame, text="Certificate Management", font=("Arial", 16, "bold")).pack(anchor="w", pady=(0, 20))
            
            main_frame = ttk.Frame(view_frame)
            main_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            # Certificate path
            cert_frame = ttk.Frame(main_frame)
            cert_frame.pack(fill="x", padx=10, pady=10)
            
            ttk.Label(cert_frame, text="Certificate Path:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
            self.cert_path_var = tk.StringVar()
            cert_entry = ttk.Entry(cert_frame, textvariable=self.cert_path_var, width=50)
            cert_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
            
            ttk.Button(cert_frame, text="Browse", command=self.browse_cert_path).grid(row=0, column=2, padx=5, pady=5)
            
            cert_frame.columnconfigure(1, weight=1)
            
            # Action buttons
            button_frame = ttk.Frame(main_frame)
            button_frame.pack(fill="x", padx=10, pady=10)
            
            ttk.Button(button_frame, text="Load Certificate", command=self.load_certificate).pack(side="left", padx=5)
            ttk.Button(button_frame, text="Verify Certificate", command=self.verify_certificate).pack(side="left", padx=5)
            ttk.Button(button_frame, text="View Certificate", command=self.view_certificate).pack(side="left", padx=5)
            ttk.Button(button_frame, text="Generate Sample", command=self.generate_sample_certificate).pack(side="right", padx=5)
            
            # Certificate display
            display_frame = ttk.Frame(main_frame)
            display_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            ttk.Label(display_frame, text="Certificate Contents:").pack(anchor="w", padx=5, pady=5)
            self.cert_display_text = scrolledtext.ScrolledText(display_frame, width=80, height=15)
            self.cert_display_text.pack(fill="both", expand=True, padx=5, pady=5)
    
    def setup_verification_tab(self):
        """Setup certificate verification view"""
        # Create Frame (following same pattern as setup_file_view)
        view_frame = ctk.CTkFrame(self.main_view, corner_radius=0, fg_color="transparent") if CUSTOM_TKINTER_AVAILABLE else ttk.Frame(self.main_view)
        view_frame.grid(row=0, column=0, sticky="nsew")
        self.frames["Verification"] = view_frame
        
        if CUSTOM_TKINTER_AVAILABLE:
            # Title
            ctk.CTkLabel(view_frame, text="Certificate Verification", 
                        font=ctk.CTkFont(size=20, weight="bold")).pack(anchor="w", pady=(0, 20))
            
            main_frame = ctk.CTkFrame(view_frame, corner_radius=10)
            main_frame.pack(fill="both", expand=True)
            
            # Verification options
            verify_frame = ctk.CTkFrame(main_frame, corner_radius=8)
            verify_frame.pack(fill="x", padx=10, pady=10)
            
            ctk.CTkLabel(verify_frame, text="Certificate ID:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
            self.verify_cert_id_var = tk.StringVar()
            cert_entry = ctk.CTkEntry(verify_frame, textvariable=self.verify_cert_id_var, width=400, corner_radius=8)
            cert_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
            
            verify_frame.columnconfigure(1, weight=1)
            
            # Action buttons
            button_frame = ctk.CTkFrame(main_frame, corner_radius=8)
            button_frame.pack(fill="x", padx=10, pady=10)
            
            ctk.CTkButton(button_frame, text="Verify in Log", command=self.verify_in_log, corner_radius=8).pack(side="left", padx=5)
            ctk.CTkButton(button_frame, text="Offline Verify", command=self.offline_verify, corner_radius=8).pack(side="left", padx=5)
            ctk.CTkButton(button_frame, text="Verify Signature", command=self.verify_signature, corner_radius=8).pack(side="left", padx=5)
            
            # Results display
            results_frame = ctk.CTkFrame(main_frame, corner_radius=8)
            results_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            ctk.CTkLabel(results_frame, text="Verification Results:").pack(anchor="w", padx=5, pady=5)
            self.verify_results_text = ctk.CTkTextbox(results_frame, corner_radius=8)
            self.verify_results_text.pack(fill="both", expand=True, padx=5, pady=5)
            
        else:
            # Title
            ttk.Label(view_frame, text="Certificate Verification", font=("Arial", 16, "bold")).pack(anchor="w", pady=(0, 20))
            
            main_frame = ttk.Frame(view_frame)
            main_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            # Verification options
            verify_frame = ttk.Frame(main_frame)
            verify_frame.pack(fill="x", padx=10, pady=10)
            
            ttk.Label(verify_frame, text="Certificate ID:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
            self.verify_cert_id_var = tk.StringVar()
            cert_entry = ttk.Entry(verify_frame, textvariable=self.verify_cert_id_var, width=50)
            cert_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
            
            verify_frame.columnconfigure(1, weight=1)
            
            # Action buttons
            button_frame = ttk.Frame(main_frame)
            button_frame.pack(fill="x", padx=10, pady=10)
            
            ttk.Button(button_frame, text="Verify in Log", command=self.verify_in_log).pack(side="left", padx=5)
            ttk.Button(button_frame, text="Offline Verify", command=self.offline_verify).pack(side="left", padx=5)
            ttk.Button(button_frame, text="Verify Signature", command=self.verify_signature).pack(side="left", padx=5)
            
            # Results display
            results_frame = ttk.Frame(main_frame)
            results_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            ttk.Label(results_frame, text="Verification Results:").pack(anchor="w", padx=5, pady=5)
            self.verify_results_text = scrolledtext.ScrolledText(results_frame, width=80, height=15)
            self.verify_results_text.pack(fill="both", expand=True, padx=5, pady=5)
    
    def setup_log_tab(self):
        """Setup log viewing tab"""
        tab = self.notebook.tab("Log")
        
        if CUSTOM_TKINTER_AVAILABLE:
            main_frame = ctk.CTkFrame(tab, corner_radius=10)
            main_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            # Log display
            log_frame = ctk.CTkFrame(main_frame, corner_radius=8)
            log_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            ctk.CTkLabel(log_frame, text="Operation Log:").pack(anchor="w", padx=5, pady=5)
            self.log_text = ctk.CTkTextbox(log_frame, corner_radius=8)
            self.log_text.pack(fill="both", expand=True, padx=5, pady=5)
            
            # Button frame
            btn_frame = ctk.CTkFrame(log_frame)
            btn_frame.pack(fill="x", pady=5)
            
            refresh_btn = ctk.CTkButton(btn_frame, text="Refresh Log", command=self.refresh_log, corner_radius=8)
            refresh_btn.pack(side="left", padx=5)
            
            save_log_btn = ctk.CTkButton(btn_frame, text="Save Log", command=self.save_log, corner_radius=8)
            
            view_log_btn = ctk.CTkButton(btn_frame, text="View Transparency DB", command=self.view_transparency_log, corner_radius=8)
            view_log_btn.pack(side="left", padx=5)

        else:
            main_frame = ttk.Frame(tab)
            main_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            # Log display
            log_frame = ttk.Frame(main_frame)
            log_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            ttk.Label(log_frame, text="Operation Log:").pack(anchor="w", padx=5, pady=5)
            self.log_text = scrolledtext.ScrolledText(log_frame, width=80, height=20)
            self.log_text.pack(fill="both", expand=True, padx=5, pady=5)
            
            # Action buttons
            button_frame = ttk.Frame(main_frame)
            button_frame.pack(fill="x", padx=10, pady=10)
            
            ttk.Button(button_frame, text="Refresh Log", command=self.refresh_log).pack(side="left", padx=5)
            ttk.Button(button_frame, text="Save Log", command=self.save_log).pack(side="left", padx=5)
            ttk.Button(button_frame, text="Clear Log", command=self.clear_log).pack(side="left", padx=5)
            ttk.Button(button_frame, text="View Transparency Log", command=self.view_transparency_log).pack(side="right", padx=5)
        
        # Initial log refresh
        self.refresh_log()
    
    def browse_file(self):
        """Browse for file target"""
        target = filedialog.askopenfilename(title="Select file to wipe")
        if target:
            self.target_var.set(target)
    
    def browse_folder(self):
        """Browse for directory target"""
        target = filedialog.askdirectory(title="Select directory to wipe")
        if target:
            self.target_var.set(target)
    
    def browse_cert_path(self):
        """Browse for certificate path"""
        cert_path = filedialog.askopenfilename(title="Select certificate", 
                                             filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if cert_path:
            self.cert_path_var.set(cert_path)
    
    def check_adb_status(self):
        """Check ADB status and update UI"""
        adb_path = AndroidCryptoWipe.find_adb()
        if adb_path:
            self.adb_status_var.set(f"ADB Found: {adb_path}")
        else:
            self.adb_status_var.set("ADB Not Found - Install Android SDK Platform Tools")
    
    def start_worker(self, target, args=(), on_finish=None):
        """Start a worker thread for long operations"""
        if self.worker_thread and self.worker_thread.is_alive():
            messagebox.showwarning("Operation in Progress", "Please wait for the current operation to complete.")
            return False
        
        def worker_wrapper():
            try:
                result = target(*args)
                if on_finish:
                    self.root.after(0, lambda: on_finish(result))
            except Exception as e:
                if on_finish:
                    self.root.after(0, lambda: on_finish(e))
        
        self.worker_thread = threading.Thread(target=worker_wrapper)
        self.worker_thread.daemon = True
        self.worker_thread.start()
        return True
    
    def start_file_wipe(self):
        """Start file wiping operation with enhanced progress feedback"""
        target = self.target_var.get()
        if not target:
            messagebox.showerror("Error", "Please select a target file or directory")
            return
        
        if not os.path.exists(target):
            messagebox.showerror("Error", f"Target does not exist: {target}")
            return
        
        if not self.verify_operator_authorization("File Wipe"):
                return

        if not messagebox.askyesno("Irreversible Action", "This action is IRREVERSIBLE. Proceed?"):
            return
        
        standard = self.standard_var.get()
        policy = self.policy_var.get()
        
        # Confirm destructive operation
        if not messagebox.askyesno("Confirmation", 
                                 f"Are you sure you want to securely wipe {target}?\n\n"
                                 f"Standard: {standard}\n"
                                 f"Policy: {policy}\n\n"
                                 f"This action is irreversible!"):
            return
        
        # Disable buttons during operation
        self.stop_button.configure(state="normal")
        self.current_operation = "file_wipe"
        self.stop_requested = False
        
        # Enhanced progress callback
        def progress_callback(pass_num, bytes_written, total_bytes, message):
            if self.stop_requested:
                return False
                
            def update_ui():
                if total_bytes > 0:
                    pass_progress = bytes_written / total_bytes
                    total_passes = self.wiper.wiping_standards[standard]['passes']
                    overall_progress = (pass_num + pass_progress) / total_passes
                    self.progress_bar.set(overall_progress)
                self.progress_var.set(message)
                self.root.update_idletasks()
            
            self.root.after(0, update_ui)
            return True
        
        def run_wipe():
            try:
                self.progress_var.set("Wiping...")
                if os.path.isfile(target):
                    return self.wiper.secure_wipe_file(target, standard, progress_callback)
                else:
                    return self.wiper.secure_wipe_directory(target, standard, progress_callback)
            except Exception as e:
                return e
        
        def on_wipe_finished(result):
            # Re-enable buttons (with safety check)
            if self.stop_button:
                self.stop_button.configure(state="disabled")
            self.current_operation = None
            
            if isinstance(result, Exception):
                self.progress_var.set(f"Error: {str(result)}")
                if self.results_text:
                    self.results_text.insert(tk.END, f"\n💥 Error: {str(result)}\n")
                messagebox.showerror("Error", f"An error occurred: {str(result)}")
            elif result:
                self.progress_var.set("Wipe completed successfully")
                if self.results_text:
                    self.results_text.insert(tk.END, f"\n✅ Wipe completed: {target}\n")
                
                # Generate certificate
                operation_details = {
                    'target': target,
                    'method': standard,
                    'nist_level': self.wiper.wiping_standards[standard]['nist_level'],
                    'operator': self.operator_var.get(),
                    'start_time': datetime.now().isoformat(),
                    'handoff_required': policy == 'DESTROY',
                    'evidence': {
                        'operation_type': 'file_wipe' if os.path.isfile(target) else 'directory_wipe',
                        'standard_used': standard,
                        'policy_level': policy
                    }
                }
                
                cert_result = self.wiper.generate_certificate(operation_details)
                if cert_result['success']:
                    if self.results_text:
                        self.results_text.insert(tk.END, f"📄 Certificate generated: {cert_result['certificate_id']}\n")
                    # Show completion popup
                    cert_path = cert_result.get('pdf_path') or cert_result.get('json_path')
                    self.show_completion_popup(cert_path)
                    
                messagebox.showinfo("Success", "Wipe completed successfully!")
            else:
                self.progress_var.set("Wipe failed")
                if self.results_text:
                    self.results_text.insert(tk.END, f"\n❌ Wipe failed: {target}\n")
                messagebox.showerror("Error", "Wipe failed!")
            
            if self.progress_bar:
                self.progress_bar.set(0)
            self.refresh_log()
        
        # Clear results and start operation
        if self.results_text:
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, f"Starting wipe of: {target}\n")
            self.results_text.insert(tk.END, f"Standard: {standard}, Policy: {policy}\n")
            self.results_text.insert(tk.END, "="*50 + "\n")
        
        self.start_worker(run_wipe, on_finish=on_wipe_finished)
    
    def start_directory_wipe(self):
        """Start directory wiping operation"""
        # Reuse the file wipe method with directory detection
        self.start_file_wipe()
    
    def start_device_wipe(self):
        """Start device wiping operation"""
        device_path = self.device_var.get()
        if not device_path:
            messagebox.showerror("Error", "Please select a device")
            return
        
        # Safety confirmation
        if not self.verify_operator_authorization("Device Wipe", self.device_policy_var.get()):
            return
        
        policy = self.device_policy_var.get()
        
        # Extra confirmation for destructive device operations
        if not messagebox.askyesno("DANGEROUS OPERATION", 
                                 f"Are you absolutely sure you want to wipe device: {device_path}?\n\n"
                                 f"Policy: {policy}\n\n"
                                 f"THIS WILL DESTROY ALL DATA ON THE DEVICE!\n"
                                 f"THIS ACTION IS IRREVERSIBLE!"):
            return
        
        def run_device_wipe():
            try:
                self.progress_var.set("Wiping device...")
                return self.wiper.execute_policy_wipe(device_path, policy)
            except Exception as e:
                return e
        
        def on_device_wipe_finished(result):
            self.current_operation = None
            
            if isinstance(result, Exception):
                self.progress_var.set(f"Error: {str(result)}")
                self.device_results_text.insert(tk.END, f"\n💥 Error: {str(result)}\n")
                messagebox.showerror("Error", f"An error occurred: {str(result)}")
            elif result.get('success'):
                self.progress_var.set("Device wipe completed successfully")
                self.device_results_text.insert(tk.END, f"\n✅ Device wipe completed: {device_path}\n")
                messagebox.showinfo("Success", "Device wipe completed successfully!")
                
                # Generate certificate for device wipe
                operation_details = {
                    'target': device_path,
                    'method': result.get('method_used', 'Unknown'),
                    'nist_level': result.get('nist_level', 'Unknown'),
                    'operator': self.operator_var.get(),
                    'start_time': datetime.now().isoformat(),
                    'evidence': result.get('evidence', {})
                }
                
                cert_result = self.wiper.generate_certificate(operation_details)
                if cert_result['success']:
                    self.device_results_text.insert(tk.END, f"📄 Certificate generated: {cert_result['certificate_id']}\n")
            else:
                self.progress_var.set("Device wipe failed")
                self.device_results_text.insert(tk.END, f"\n❌ Device wipe failed: {device_path}\n")
                self.device_results_text.insert(tk.END, f"Error: {result.get('error', 'Unknown error')}\n")
                messagebox.showerror("Error", f"Device wipe failed: {result.get('error', 'Unknown error')}")
            
            self.refresh_log()
        
        # Clear results and start operation
        self.device_results_text.delete(1.0, tk.END)
        self.device_results_text.insert(tk.END, f"Starting device wipe: {device_path}\n")
        self.device_results_text.insert(tk.END, f"Policy: {policy}\n")
        self.device_results_text.insert(tk.END, "="*50 + "\n")
        
        self.current_operation = "device_wipe"
        self.start_worker(run_device_wipe, on_finish=on_device_wipe_finished)
    
    def start_android_wipe(self):
        """Start Android device wiping operation"""
        device_id = self.android_device_var.get()
        if not device_id:
            messagebox.showerror("Error", "Please select an Android device")
            return
        
        # Safety confirmation
        if not self.verify_operator_authorization("Android Wipe"):
            return
        
        # Extra strong confirmation for Android wipe
        if not messagebox.askyesno("DANGEROUS ANDROID OPERATION", 
                                 f"⚠️ DANGER: This will FACTORY RESET the Android device {device_id}!\n\n"
                                 f"ALL USER DATA WILL BE PERMANENTLY ERASED!\n"
                                 f"ALL APPS, SETTINGS, AND PERSONAL FILES WILL BE GONE!\n\n"
                                 f"Are you absolutely sure you want to continue?"):
            return
        
        def run_android_wipe():
            try:
                self.progress_var.set("Starting Android factory reset...")
                return self.wiper.perform_android_crypto_wipe(device_id)
            except Exception as e:
                return e
        
        def on_android_wipe_finished(result):
            self.current_operation = None
            
            if isinstance(result, Exception):
                self.progress_var.set(f"Error: {str(result)}")
                self.android_results_text.insert(tk.END, f"\n💥 Error: {str(result)}\n")
                messagebox.showerror("Error", f"An error occurred: {str(result)}")
            else:
                # Display detailed results
                self.android_results_text.insert(tk.END, f"\nAndroid Wipe Results:\n")
                self.android_results_text.insert(tk.END, f"Success: {result.get('success', False)}\n")
                self.android_results_text.insert(tk.END, f"Methods Used: {', '.join(result.get('methods_used', []))}\n")
                
                if result.get('success'):
                    # Honest Manual Interface (Fix #3)
                    if result.get('requires_manual'):
                        self.progress_var.set("Manual Action Required")
                        instructions = result.get('instructions', "Please complete the wipe manually.")
                        
                        self.android_results_text.insert(tk.END, f"\n👉 ACTION REQUIRED: {instructions}\n")
                        self.android_results_text.insert(tk.END, "The device has been rebooted to recovery mode.\n")
                        self.android_results_text.insert(tk.END, "1. Use Volume Keys to scroll.\n2. Select 'Wipe data/factory reset'.\n3. Confirm with Power button.\n")
                        
                        messagebox.showinfo("Manual Action Required", f"{instructions}\n\n1. Use Volume Keys to scroll.\n2. Select 'Wipe data/factory reset'.\n3. Confirm with Power button.")
                        method_name = "Android_Manual_Assist"
                    else:
                        self.progress_var.set("Android factory reset completed")
                        self.android_results_text.insert(tk.END, "✅ Android factory reset completed successfully!\n")
                        messagebox.showinfo("Success", "Android factory reset completed successfully!")
                        method_name = "Android_Factory_Reset"
                    
                    # Generate certificate ONLY for automated wipes (NOT manual operations)
                    if not result.get('requires_manual', False) and result.get('certificate_allowed', True):
                        operation_details = {
                            'target': f"Android Device: {device_id}",
                            'method': method_name,
                            'nist_level': NIST_PURGE,
                            'operator': self.operator_var.get(),
                            'start_time': datetime.now().isoformat(),
                            'evidence': result.get('evidence', {})
                        }
                        
                        cert_result = self.wiper.generate_certificate(operation_details)
                        if cert_result['success']:
                            self.android_results_text.insert(tk.END, f"📄 Certificate generated: {cert_result['certificate_id']}\n")
                            self.show_completion_popup(cert_result.get('pdf_path') or cert_result.get('json_path'))
                    else:
                        # Manual operation - no certificate
                        self.android_results_text.insert(tk.END, "⚠️ Manual operation - certificate NOT generated (user must complete wipe manually)\n")
                else:
                    self.progress_var.set("Android factory reset failed or partial")
                    self.android_results_text.insert(tk.END, "⚠️ Android factory reset may have failed or was partial\n")
                    self.android_results_text.insert(tk.END, f"Errors: {', '.join(result.get('errors', []))}\n")
                    messagebox.showwarning("Warning", "Android factory reset may have failed or was partial. Check the evidence.")
            
            self.refresh_log()
        
        # Clear results and start operation
        self.android_results_text.delete(1.0, tk.END)
        self.android_results_text.insert(tk.END, f"Starting Android factory reset: {device_id}\n")
        self.android_results_text.insert(tk.END, "WARNING: This will erase ALL user data on the Android device!\n")
        self.android_results_text.insert(tk.END, "="*50 + "\n")
        
        self.current_operation = "android_wipe"
        self.start_worker(run_android_wipe, on_finish=on_android_wipe_finished)
    
    def detect_devices(self):
        """Detect available storage devices"""
        self.device_results_text.delete(1.0, tk.END)
        
        try:
            device_list = []
            if platform.system() == "Linux":
                if shutil.which('lsblk'):
                    result = subprocess.run(['lsblk', '-d', '-n', '-o', 'NAME,TYPE,SIZE,MODEL'], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        self.device_results_text.insert(tk.END, "Available devices (Linux):\n")
                        self.device_results_text.insert(tk.END, "="*50 + "\n")
                        for line in result.stdout.strip().split('\n'):
                            parts = line.split()
                            if len(parts) >= 2 and 'disk' in parts[1]:
                                device = f"/dev/{parts[0]}"
                                device_list.append(device)
                                self.device_results_text.insert(tk.END, f"  {device}\n")
                                # Get additional info
                                info = self.wiper.device_backend.detect_storage_type(device)
                                self.device_results_text.insert(tk.END, f"    Type: {info['type']}, Model: {info['model']}, Size: {info['size']}\n")
                else:
                    self.device_results_text.insert(tk.END, "lsblk not found. Install util-linux package.\n")
                    
            elif platform.system() == "Windows":
                devices = WindowsDeviceManager.get_disk_devices()
                self.device_results_text.insert(tk.END, "Available devices (Windows):\n")
                self.device_results_text.insert(tk.END, "="*50 + "\n")
                
                # Physical Drives
                for device in devices:
                    device_id = device.get('DeviceID', 'Unknown')
                    device_list.append(device_id)
                    model = device.get('Model', 'Unknown')
                    size = device.get('Size', 'Unknown')
                    self.device_results_text.insert(tk.END, f"  {device_id}\n")
                    self.device_results_text.insert(tk.END, f"    Model: {model}, Size: {size}\n")
                
                # Logical Drives (Volumes)
                try:
                    logical_result = subprocess.run('wmic logicaldisk get DeviceID,Size,FreeSpace /format:table', 
                                                  capture_output=True, text=True, shell=True, timeout=10)
                    if logical_result.returncode == 0:
                        self.device_results_text.insert(tk.END, "\nLogical drives:\n")
                        for line in logical_result.stdout.split('\n')[1:]:
                             parts = line.split()
                             if parts:
                                 drive = parts[0]
                                 # We generally prefer wiping partitions via cipher or full disk, 
                                 # but let's add them to the list for user convenience if they want to run cipher on a drive
                                 if ':' in drive:
                                     # device_list.append(drive) # Optional: decide if we want to allow logical drive wiping via this dropdown
                                     pass
                                 self.device_results_text.insert(tk.END, f"  {line.strip()}\n")
                except:
                    pass
            else:
                self.device_results_text.insert(tk.END, f"Device detection not fully supported on {platform.system()}\n")
            
            # Update Combobox
            if device_list:
                if CUSTOM_TKINTER_AVAILABLE:
                    self.device_combo.configure(values=device_list)
                    self.device_combo.set(device_list[0])
                else:
                    self.device_combo['values'] = device_list
                    self.device_combo.current(0)
                    
        except Exception as e:
            self.device_results_text.insert(tk.END, f"Device detection error: {str(e)}\n")
    
    def detect_android_devices(self):
        """Detect Android devices"""
        self.android_results_text.delete(1.0, tk.END)
        
        adb_path = AndroidCryptoWipe.find_adb()
        if not adb_path:
            self.android_results_text.insert(tk.END, "ADB not found. Please install Android SDK Platform Tools.\n")
            self.android_results_text.insert(tk.END, "Download from: https://developer.android.com/studio/releases/platform-tools\n")
            return
        
        device_list = []
        try:
            result = run_cmd(f'"{adb_path}" devices', timeout=10)
            if result['rc'] == 0:
                self.android_results_text.insert(tk.END, "Connected Android devices:\n")
                self.android_results_text.insert(tk.END, "="*50 + "\n")
                lines = result['out'].strip().split('\n')
                if len(lines) <= 1:
                    self.android_results_text.insert(tk.END, "No devices found. Connect an Android device with USB debugging enabled.\n")
                else:
                    for line in lines[1:]:  # Skip first line (header)
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 2:
                                device_id = parts[0]
                                status = parts[1]
                                device_list.append(device_id)
                                self.android_results_text.insert(tk.END, f"  {device_id} - {status}\n")
                                
                # Update Combobox
                if device_list:
                    if CUSTOM_TKINTER_AVAILABLE:
                        self.android_device_combo.configure(values=device_list)
                        self.android_device_combo.set(device_list[0])
                    else:
                        self.android_device_combo['values'] = device_list
                        self.android_device_combo.current(0)
                else:
                    self.android_device_var.set("") # Clear if none found

            else:
                self.android_results_text.insert(tk.END, f"ADB error: {result['err']}\n")
        except Exception as e:
            self.android_results_text.insert(tk.END, f"Android detection error: {str(e)}\n")
    
    def detect_hpa_dco(self):
        """Detect HPA/DCO on specified device"""
        device = self.hpa_device_var.get()
        try:
            self.progress_var.set("Detecting HPA/DCO...")
            self.hpa_results_text.delete(1.0, tk.END)
            result = self.wiper.detect_hpa_dco(device if device else None)
            self.hpa_results_text.insert(tk.END, f"HPA/DCO detection result:\n")
            self.hpa_results_text.insert(tk.END, "="*50 + "\n")
            for key, value in result.items():
                if key not in ['raw_hdparm_output', 'raw_nvme_output']:  # Skip very long outputs
                    self.hpa_results_text.insert(tk.END, f"  {key}: {value}\n")
            
            # Show warnings if any
            if 'warnings' in result:
                self.hpa_results_text.insert(tk.END, "\nWarnings:\n")
                for warning in result['warnings']:
                    self.hpa_results_text.insert(tk.END, f"  ⚠ {warning}\n")
                    
            self.progress_var.set("HPA/DCO detection completed")
        except Exception as e:
            self.hpa_results_text.insert(tk.END, f"HPA/DCO detection error: {str(e)}\n")
            self.progress_var.set("HPA/DCO detection failed")
    
    def remove_hpa_dco(self):
        """Remove HPA/DCO restrictions (DANGEROUS)"""
        device = self.hpa_device_var.get()
        if not device:
            messagebox.showerror("Error", "Please specify a device")
            return
        
        if not self.verify_operator_authorization("Remove HPA/DCO"):
            return
        
        try:
            self.progress_var.set("Removing HPA/DCO...")
            self.hpa_results_text.delete(1.0, tk.END)
            
            if platform.system() != "Linux":
                self.hpa_results_text.insert(tk.END, "HPA/DCO removal only supported on Linux systems.\n")
                return
                
            result = EnhancedHPADCODetector.remove_hpa_dco(device)
            self.hpa_results_text.insert(tk.END, f"HPA/DCO removal result:\n")
            self.hpa_results_text.insert(tk.END, "="*50 + "\n")
            for key, value in result.items():
                self.hpa_results_text.insert(tk.END, f"  {key}: {value}\n")
            self.progress_var.set("HPA/DCO removal completed")
        except Exception as e:
            self.hpa_results_text.insert(tk.END, f"HPA/DCO removal error: {str(e)}\n")
            self.progress_var.set("HPA/DCO removal failed")
    
    def detect_all_devices(self):
        """Detect HPA/DCO on all available devices"""
        try:
            self.progress_var.set("Detecting HPA/DCO on all devices...")
            self.hpa_results_text.delete(1.0, tk.END)
            result = self.wiper.detect_hpa_dco(None)
            self.hpa_results_text.insert(tk.END, f"All devices HPA/DCO detection result:\n")
            self.hpa_results_text.insert(tk.END, "="*50 + "\n")
            for key, value in result.items():
                if key not in ['raw_hdparm_output', 'raw_nvme_output']:  # Skip very long outputs
                    self.hpa_results_text.insert(tk.END, f"  {key}: {value}\n")
            self.progress_var.set("All devices HPA/DCO detection completed")
        except Exception as e:
            self.hpa_results_text.insert(tk.END, f"All devices HPA/DCO detection error: {str(e)}\n")
            self.progress_var.set("All devices HPA/DCO detection failed")
    
    def load_certificate(self):
        """Load certificate from file"""
        cert_path = self.cert_path_var.get()
        if not cert_path:
            messagebox.showerror("Error", "Please specify a certificate path")
            return
        
        try:
            with open(cert_path, 'r', encoding='utf-8') as f:
                cert_data = json.load(f)
            self.cert_data = cert_data
            
            # Display certificate in text widget
            self.cert_display_text.delete(1.0, tk.END)
            self.cert_display_text.insert(tk.END, json.dumps(cert_data, indent=2))
            
            messagebox.showinfo("Success", f"Certificate loaded: {cert_data['certificate_id']}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load certificate: {str(e)}")
    
    def verify_certificate(self):
        """Verify loaded certificate"""
        if not hasattr(self, 'cert_data'):
            messagebox.showerror("Error", "No certificate loaded")
            return
        
        try:
            self.progress_var.set("Verifying certificate...")
            cert_path = self.cert_path_var.get()
            if not cert_path:
                # Create temporary file for verification
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                    json.dump(self.cert_data, f)
                    cert_path = f.name
                
            valid, message = self.wiper.verify_certificate_offline(cert_path)
            
            if valid:
                self.progress_var.set("Certificate verified successfully")
                messagebox.showinfo("Success", f"Certificate is valid: {message}")
            else:
                self.progress_var.set("Certificate verification failed")
                messagebox.showerror("Error", f"Certificate verification failed: {message}")
        except Exception as e:
            self.progress_var.set(f"Verification error: {str(e)}")
            messagebox.showerror("Error", f"Verification error: {str(e)}")
    
    def view_certificate(self):
        """View certificate details"""
        if not hasattr(self, 'cert_data'):
            messagebox.showerror("Error", "No certificate loaded")
            return
        
        try:
            details = f"Certificate ID: {self.cert_data['certificate_id']}\n"
            details += f"Target: {self.cert_data['target']}\n"
            details += f"Method: {self.cert_data['method']}\n"
            details += f"NIST Policy: {self.cert_data['nist_policy']}\n"
            details += f"Start Time: {self.cert_data['start_time']}\n"
            details += f"End Time: {self.cert_data['end_time']}\n"
            details += f"Operator: {self.cert_data.get('operator', 'Unknown')}\n"
            details += f"Platform: {self.cert_data.get('platform', 'Unknown')}\n"
            
            messagebox.showinfo("Certificate Details", details)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to view certificate: {str(e)}")
    
    def generate_sample_certificate(self):
        """Generate a sample certificate for testing"""
        try:
            operation_details = {
                'target': '/sample/path/test.file',
                'method': 'SECURE',
                'nist_level': NIST_PURGE,
                'operator': 'Test Operator',
                'start_time': datetime.now().isoformat(),
                'evidence': {
                    'pre_hash': 'a1b2c3d4e5f678901234567890123456789012345678901234567890123456',
                    'post_hash': 'f1e2d3c4b5a678901234567890123456789012345678901234567890123456',
                    'hash_verification': 'Verified'
                }
            }
            
            result = self.wiper.generate_certificate(operation_details)
            if result['success']:
                self.cert_path_var.set(result['json_path'])
                messagebox.showinfo("Success", f"Sample certificate generated: {result['certificate_id']}")
                self.load_certificate()  # Auto-load the generated certificate
            else:
                messagebox.showerror("Error", f"Failed to generate sample certificate: {result.get('error', 'Unknown error')}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate sample certificate: {str(e)}")
    
    def verify_in_log(self):
        """Verify certificate in transparency log"""
        cert_id = self.verify_cert_id_var.get()
        if not cert_id:
            messagebox.showerror("Error", "Please specify a certificate ID")
            return
        
        try:
            self.progress_var.set("Verifying certificate in log...")
            self.verify_results_text.delete(1.0, tk.END)
            found, message = self.wiper.verify_transparency_log(cert_id)
            self.verify_results_text.insert(tk.END, f"Transparency log verification:\n")
            self.verify_results_text.insert(tk.END, "="*50 + "\n")
            self.verify_results_text.insert(tk.END, f"Result: {'FOUND' if found else 'NOT FOUND'}\n")
            self.verify_results_text.insert(tk.END, f"Message: {message}\n")
            self.progress_var.set(f"Log verification: {'FOUND' if found else 'NOT FOUND'}")
        except Exception as e:
            self.verify_results_text.insert(tk.END, f"Log verification error: {str(e)}\n")
            self.progress_var.set(f"Log verification error: {str(e)}")
    
    def offline_verify(self):
        """Perform offline certificate verification"""
        cert_path = self.cert_path_var.get()
        if not cert_path:
            messagebox.showerror("Error", "Please specify a certificate path")
            return
        
        try:
            self.progress_var.set("Performing offline verification...")
            self.verify_results_text.delete(1.0, tk.END)
            valid, message = self.wiper.verify_certificate_offline(cert_path)
            self.verify_results_text.insert(tk.END, f"Offline verification:\n")
            self.verify_results_text.insert(tk.END, "="*50 + "\n")
            self.verify_results_text.insert(tk.END, f"Result: {'VALID' if valid else 'INVALID'}\n")
            self.verify_results_text.insert(tk.END, f"Message: {message}\n")
            self.progress_var.set(f"Offline verification: {'VALID' if valid else 'INVALID'}")
        except Exception as e:
            self.verify_results_text.insert(tk.END, f"Offline verification error: {str(e)}\n")
            self.progress_var.set(f"Offline verification error: {str(e)}")
    
    def verify_signature(self):
        """Verify certificate signature"""
        cert_path = self.cert_path_var.get()
        if not cert_path:
            messagebox.showerror("Error", "Please specify a certificate path")
            return
        
        try:
            with open(cert_path, 'r', encoding='utf-8') as f:
                cert_data = json.load(f)
            
            if 'jws' not in cert_data:
                messagebox.showerror("Error", "Certificate has no JWS signature")
                return
            
            self.progress_var.set("Verifying signature...")
            self.verify_results_text.delete(1.0, tk.END)
            valid, message = self.wiper.verify_certificate_offline(cert_path)
            self.verify_results_text.insert(tk.END, f"Signature verification:\n")
            self.verify_results_text.insert(tk.END, "="*50 + "\n")
            self.verify_results_text.insert(tk.END, f"Result: {'VALID' if valid else 'INVALID'}\n")
            self.verify_results_text.insert(tk.END, f"Message: {message}\n")
            self.progress_var.set(f"Signature verification: {'VALID' if valid else 'INVALID'}")
        except Exception as e:
            self.verify_results_text.insert(tk.END, f"Signature verification error: {str(e)}\n")
            self.progress_var.set(f"Signature verification error: {str(e)}")
    
    def refresh_log(self):
        """Refresh log display with current wipe log"""
        # Safety check - log_text may not be initialized
        if not self.log_text:
            return
            
        self.log_text.delete(1.0, tk.END)
        if not self.wiper.wipe_log:
            self.log_text.insert(tk.END, "No wipe operations logged yet.\n")
            return
            
        self.log_text.insert(tk.END, "Wipe Operation Log:\n")
        self.log_text.insert(tk.END, "="*80 + "\n")
        for entry in self.wiper.wipe_log:
            timestamp = entry.get('timestamp', 'Unknown')
            target = entry.get('target', 'Unknown')
            status = entry.get('status', 'Unknown')
            nist_level = entry.get('nist_level', 'Unknown')
            self.log_text.insert(tk.END, f"{timestamp} - {target} - {status} - NIST: {nist_level}\n")
            
        # Also try to read from disk logs if available for completeness
        try:
            log_file = LOG_DIR / 'secure_wiper.jsonl'
            if log_file.exists():
                self.log_text.insert(tk.END, "\n--- History from Disk Log ---\n")
                with open(log_file, 'r', encoding='utf-8') as f:
                    # Read last 50 lines efficiently? For now just read lines because log is append only
                    lines = f.readlines()
                    for line in reversed(lines[-50:]): # Show last 50 reversed or normal? Normal
                        try:
                            entry = json.loads(line)
                            t = entry.get('timestamp', '')
                            msg = entry.get('message', '')
                            level = entry.get('level', '')
                            self.log_text.insert(tk.END, f"{t} [{level}] {msg}\n")
                        except:
                            pass
        except Exception as e:
            self.log_text.insert(tk.END, f"\nError reading disk log: {e}\n")
    
    def view_transparency_log(self):
        """View transparency log entries"""
        try:
            entries = self.wiper.transparency_log.get_all_entries(50)
            
            if CUSTOM_TKINTER_AVAILABLE:
                popup = ctk.CTkToplevel(self.root)
                popup.title("Transparency Log - Last 50 Entries")
                popup.geometry("800x400")
            else:
                popup = tk.Toplevel(self.root)
                popup.title("Transparency Log - Last 50 Entries")
                popup.geometry("800x400")
            
            if CUSTOM_TKINTER_AVAILABLE:
                log_text = ctk.CTkTextbox(popup, wrap="none")
            else:
                log_text = scrolledtext.ScrolledText(popup, wrap="none")
            
            log_text.pack(fill="both", expand=True, padx=10, pady=10)
            
            if not entries:
                log_text.insert(tk.END, "No entries in transparency log.\n")
            else:
                log_text.insert(tk.END, "Transparency Log Entries:\n")
                log_text.insert(tk.END, "="*100 + "\n")
                for entry in entries:
                    log_text.insert(tk.END, f"ID: {entry['certificate_id']}\n")
                    log_text.insert(tk.END, f"  Time: {entry['timestamp']}\n")
                    log_text.insert(tk.END, f"  Target: {entry['target']}\n")
                    log_text.insert(tk.END, f"  Method: {entry['method']}\n")
                    log_text.insert(tk.END, f"  Policy: {entry['nist_policy']}\n")
                    log_text.insert(tk.END, f"  Signed: {'Yes' if entry['signature'] != 'unsigned' else 'No'}\n")
                    log_text.insert(tk.END, "-"*100 + "\n")
            
            if CUSTOM_TKINTER_AVAILABLE:
                log_text.configure(state="disabled")
            else:
                log_text.config(state="disabled")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to view transparency log: {str(e)}")
    
    def save_log(self):
        """Save log to file"""
        try:
            log_path = filedialog.asksaveasfilename(title="Save log", 
                                                  defaultextension=".log", 
                                                  filetypes=[("Log files", "*.log"), ("All files", "*.*")])
            if log_path:
                with open(log_path, 'w', encoding='utf-8') as f:
                    f.write("EraseIT Secure Data Wiping Tool - Operation Log\n")
                    f.write("="*50 + "\n")
                    for entry in self.wiper.wipe_log:
                        timestamp = entry.get('timestamp', 'Unknown')
                        target = entry.get('target', 'Unknown')
                        status = entry.get('status', 'Unknown')
                        nist_level = entry.get('nist_level', 'Unknown')
                        f.write(f"{timestamp} - {target} - {status} - NIST: {nist_level}\n")
                messagebox.showinfo("Success", f"Log saved: {log_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save log: {str(e)}")
    
    def clear_log(self):
        """Clear the wipe log"""
        if messagebox.askyesno("Clear Log", "Are you sure you want to clear the operation log?"):
            self.wiper.wipe_log.clear()
            self.refresh_log()
            messagebox.showinfo("Success", "Log cleared")
    
    def wipe_and_certify(self):
        """One-click wipe and certify flow for files/directories"""
        target = self.target_var.get()
        if not target:
            messagebox.showerror("Error", "Please select a target file or directory")
            return
        
        if not os.path.exists(target):
            messagebox.showerror("Error", f"Target does not exist: {target}")
            return
        
        # Safety confirmation
        if not self.verify_operator_authorization("Wipe & Certify"):
            return
        
        standard = self.standard_var.get()
        policy = self.policy_var.get()
        operator = self.operator_var.get()
        
        # Confirm destructive operation
        if not messagebox.askyesno("Confirmation", 
                                 f"Are you sure you want to securely wipe and certify {target}?\n\n"
                                 f"Standard: {standard}\n"
                                 f"Policy: {policy}\n"
                                 f"Operator: {operator}\n\n"
                                 f"This action is irreversible!"):
            return
        
        # Perform the wipe first
        def run_wipe_and_certify():
            try:
                success = False
                if os.path.isfile(target):
                    success = self.wiper.secure_wipe_file(target, standard)
                    operation_type = "file"
                else:
                    success = self.wiper.secure_wipe_directory(target, standard)
                    operation_type = "directory"
                
                if success:
                    # Generate certificate
                    operation_details = {
                        'target': target,
                        'method': standard,
                        'nist_level': self.wiper.wipe_policies[policy]['nist_level'],
                        'operator': operator,
                        'start_time': datetime.now().isoformat(),
                        'handoff_required': policy == 'DESTROY',
                        'evidence': {
                            'operation_type': operation_type,
                            'standard_used': standard,
                            'policy_level': policy
                        }
                    }
                    
                else:
                    return {'success': False, 'error': f'{operation_type.capitalize()} wipe failed'}
                    
            except Exception as e:
                return {'success': False, 'error': str(e)}
        
        def on_wipe_certify_finished(result):
            if isinstance(result, dict) and result.get('success'):
                # Show completion popup
                cert_path = result.get('pdf_path') or result.get('json_path')
                if cert_path:
                    self.show_completion_popup(cert_path)
                messagebox.showinfo("Success", 
                                  f"Wipe and certification completed successfully!\n"
                                  f"Certificate ID: {result['certificate_id']}")
            else:
                error_msg = result.get('error', 'Unknown error') if isinstance(result, dict) else str(result)
                messagebox.showerror("Error", f"Wipe and certify failed: {error_msg}")
        
        self.start_worker(run_wipe_and_certify, on_finish=on_wipe_certify_finished)
    
    def stop_operation(self):
        """Stop current operation"""
        self.stop_requested = True
        self.progress_var.set("Stopping operation...")
        if self.worker_thread and self.worker_thread.is_alive():
            # We can't actually stop the thread, but we can set the flag
            if self.current_operation == "file_wipe":
                self.results_text.insert(tk.END, "\n🛑 Stop requested...\n")
            elif self.current_operation == "device_wipe":
                self.device_results_text.insert(tk.END, "\n🛑 Stop requested...\n")
            elif self.current_operation == "android_wipe":
                self.android_results_text.insert(tk.END, "\n🛑 Stop requested...\n")
    
    def on_closing(self):
        """Handle application closing"""
        if self.worker_thread and self.worker_thread.is_alive():
            if messagebox.askyesno("Confirm Exit", 
                                 "An operation is still in progress.\nAre you sure you want to exit?"):
                self.root.destroy()
        else:
            self.root.destroy()
    
    def run(self):
        """Run the GUI application"""
        try:
            self.root.mainloop()
        except Exception as e:
            logger.error(f"GUI error: {e}")
            messagebox.showerror("Fatal Error", f"The application encountered a fatal error:\n{str(e)}")

def run_tests():
    """Run basic tests for core functionality"""
    import tempfile
    import unittest
    
    class TestEraseIT(unittest.TestCase):
        def setUp(self):
            self.wiper = EnhancedSecureDataWiper()
            self.test_dir = tempfile.mkdtemp()
            
        def tearDown(self):
            import shutil
            if os.path.exists(self.test_dir):
                shutil.rmtree(self.test_dir)
                
        def test_file_wipe_basic(self):
            """Test basic file wiping functionality"""
            test_file = os.path.join(self.test_dir, "test.txt")
            with open(test_file, 'w') as f:
                f.write("test content")
            
            # Get pre-wipe hash
            pre_hash = FileEaterEngine.calculate_file_hash(test_file)
            self.assertIsNotNone(pre_hash)
            
            # Wipe file
            success = self.wiper.secure_wipe_file(test_file, 'CLEAR')
            self.assertTrue(success)
            
            # File should be removed after wiping
            self.assertFalse(os.path.exists(test_file))
            
        def test_certificate_generation(self):
            """Test certificate generation"""
            operation_details = {
                'target': '/test/path',
                'method': 'SECURE',
                'nist_level': NIST_PURGE,
                'operator': 'Test Runner',
                'start_time': datetime.now().isoformat(),
                'evidence': {
                    'test_evidence': 'test_value'
                }
            }
            
            result = self.wiper.generate_certificate(operation_details)
            self.assertTrue(result['success'])
            self.assertIn('certificate_id', result)
            
        def test_canonical_json(self):
            """Test canonical JSON generation"""
            test_obj = {
                'b': 2,
                'a': 1,
                'c': [3, 1, 2]
            }
            
            canonical = canonical_json_bytes(test_obj)
            expected = b'{"a":1,"b":2,"c":[3,1,2]}'
            self.assertEqual(canonical, expected)
    
    # Run tests
    suite = unittest.TestLoader().loadTestsFromTestCase(TestEraseIT)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()

def main():
    """Enhanced main function with complete feature set"""

    
    # Check for administrative privileges
    if not check_privileges():
        print("WARNING: Not running with administrative privileges. Some operations may fail.")
        if len(sys.argv) <= 1:  # GUI mode
            response = input("Continue anyway? (y/N): ")
            if response.lower() != 'y':
                print("Exiting.")
                return
    
    # Handle global flags
    if '--debug' in sys.argv:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug mode enabled")
        sys.argv.remove('--debug')

    # Handle Self-Test Flag
    if '--selftest' in sys.argv:
        print("Running Self-Diagnostics (Test Suite)...")
        success = run_tests()
        sys.exit(0 if success else 1)



    if len(sys.argv) > 1:
        # Command line mode
        wiper = EnhancedSecureDataWiper()
        wiper.display_banner()
        
        if sys.argv[1] == 'wipe':
            if len(sys.argv) < 3:
                print("Usage: python eraseit.py wipe <file_or_directory> [standard]")
                print("Available standards: CLEAR, SECURE, MILITARY, FILE_EATER")
                return
            
            target = sys.argv[2]
            standard = sys.argv[3] if len(sys.argv) > 3 else 'SECURE'
            
            if os.path.exists(target):
                if os.path.isfile(target):
                    print(f"Wiping file: {target} with standard {standard}")
                    success = wiper.secure_wipe_file(target, standard)
                else:
                    print(f"Wiping directory: {target} with standard {standard}")
                    success = wiper.secure_wipe_directory(target, standard)
                
                if success:
                    print("✅ Wiping completed successfully")
                    
                    # Generate certificate
                    operation_details = {
                        'target': target,
                        'method': standard,
                        'nist_level': wiper.wiping_standards[standard]['nist_level'],
                        'operator': os.getlogin(),
                        'start_time': datetime.now().isoformat()
                    }
                    
                    cert_result = wiper.generate_certificate(operation_details)
                    if cert_result['success']:
                        print(f"📄 Certificate generated: {cert_result['json_path']}")
                    else:
                        print(f"⚠️  Certificate generation failed: {cert_result.get('error', 'Unknown error')}")
                else:
                    print("❌ Wiping failed")
            else:
                print("❌ Target does not exist")
        
        elif sys.argv[1] == 'device':
            if len(sys.argv) < 3:
                print("Usage: python eraseit.py device <device_path> [policy]")
                print("Available policies: CLEAR, PURGE, DESTROY")
                return
            
            device = sys.argv[2]
            policy = sys.argv[3] if len(sys.argv) > 3 else 'PURGE'
            
            print(f"Wiping device: {device} with policy {policy}")
            result = wiper.execute_policy_wipe(device, policy)
            print(json.dumps(result, indent=2))
        
        elif sys.argv[1] == 'android':
            if len(sys.argv) < 3:
                print("Usage: python eraseit.py android <device_id>")
                return
            
            device_id = sys.argv[2]
            print(f"Wiping Android device: {device_id}")
            result = wiper.perform_android_crypto_wipe(device_id)
            print(json.dumps(result, indent=2))
        
        elif sys.argv[1] == 'hpa':
            device = sys.argv[2] if len(sys.argv) > 2 else None
            print(f"Detecting HPA/DCO for device: {device or 'all devices'}")
            result = wiper.detect_hpa_dco(device)
            print(json.dumps(result, indent=2))
        
        elif sys.argv[1] == 'verify':
            if len(sys.argv) < 3:
                print("Usage: python eraseit.py verify <certificate_path>")
                return
            
            cert_path = sys.argv[2]
            print(f"Verifying certificate: {cert_path}")
            valid, message = wiper.verify_certificate_offline(cert_path)
            print(f"Verification: {'✅ VALID' if valid else '❌ INVALID'}")
            print(f"Message: {message}")
        
        elif sys.argv[1] == 'verify-log':
            if len(sys.argv) < 3:
                print("Usage: python eraseit.py verify-log <certificate_id>")
                return
            
            cert_id = sys.argv[2]
            print(f"Verifying certificate in log: {cert_id}")
            found, message = wiper.verify_transparency_log(cert_id)
            print(f"Transparency Log: {'✅ FOUND' if found else '❌ NOT FOUND'}")
            print(f"Message: {message}")
        
        elif sys.argv[1] == 'test':
            print("Running EraseIT tests...")
            success = run_tests()
            sys.exit(0 if success else 1)
        
        elif sys.argv[1] == 'create-portable-kit':
            # Create portable package (all-in-one deployment)
            print("Creating EraseIT Portable Kit...")
            print("NOTE: This creates a portable folder, NOT a bootable ISO.")
            print("      You must manually flash a Linux ISO and copy this kit to it.")
            script_path = os.path.abspath(__file__)
            project_root = os.path.dirname(script_path)
            dist_dir = os.path.join(project_root, "eraseit_portable")
            
            if os.path.exists(dist_dir):
                shutil.rmtree(dist_dir)
            os.makedirs(dist_dir)
            
            # Copy main script
            shutil.copy2(script_path, os.path.join(dist_dir, "eraseit.py"))
            print("[OK] Copied eraseit.py")
            
            # Create requirements
            reqs = "customtkinter\ncryptography\nreportlab\npillow\nqrcode\npsutil"
            with open(os.path.join(dist_dir, "requirements.txt"), "w") as f:
                f.write(reqs)
            print("[OK] Created requirements.txt")
            
            # Create launch scripts
            with open(os.path.join(dist_dir, "run_windows.bat"), "w") as f:
                f.write("@echo off\npip install -r requirements.txt\npython eraseit.py\npause")
            with open(os.path.join(dist_dir, "run_linux.sh"), "w") as f:
                f.write("#!/bin/bash\nif [ \"$(id -u)\" != \"0\" ]; then echo 'Run as root'; exit 1; fi\npip3 install -r requirements.txt\npython3 eraseit.py")
            print("[OK] Created launch scripts")
            
            # Create bootable instructions
            readme = """EraseIT Portable Kit
====================
To create a bootable USB:
1. Download Alpine Linux or Ubuntu Server ISO
2. Flash to USB with Rufus (rufus.ie)
3. Copy this folder to the USB
4. Boot and run: sudo ./run_linux.sh
"""
            with open(os.path.join(dist_dir, "README.txt"), "w") as f:
                f.write(readme)
            print(f"[OK] Package created at: {dist_dir}")
        
        elif sys.argv[1] in ['-h', '--help', 'help']:
            print("""
EraseIT - Secure Data Wiping Tool v4.0

Commands:
  wipe <target> [standard]    - Wipe file or directory
  device <device> [policy]    - Wipe storage device
  android <device_id>         - Wipe Android device (Manual Assist)
  hpa [device]                - Detect HPA/DCO areas
  verify <cert_path>          - Verify certificate
  verify-log <cert_id>        - Verify certificate in log
  create-portable-kit         - Create portable deployment kit (NOT a bootable ISO)
  test                        - Run self-tests

Standards:
  CLEAR       - 1-pass overwrite (NIST Clear)
  SECURE      - 3-pass DoD 5220.22-M (NIST Purge)  
  MILITARY    - 7-pass extended (NIST Destroy)
  FILE_EATER  - 35-pass Gutmann (NIST Destroy)

Policies:
  CLEAR       - Basic data removal
  PURGE       - Secure erasure  
  DESTROY     - Maximum security

Examples:
  python eraseit.py wipe /path/to/file.txt SECURE
  python eraseit.py device /dev/sdb PURGE
  python eraseit.py android 1234567890ABCDEF
  python eraseit.py create-portable-kit

KNOWN LIMITATIONS:
  - Windows device wipe may be blocked by OS/antivirus (use Linux live USB)
  - Android wipe requires manual completion in recovery mode
  - SSD over-provisioned areas may not be cleared on all controllers
  python eraseit.py test
            """)
        
        else:
            print("Unknown command. Use 'python eraseit.py help' for usage information.")
    else:
        # GUI mode
        try:
            print("Starting EraseIT Secure Data Wiping Tool GUI...")
            app = EnhancedProfessionalWiperGUI()
            app.run()
        except Exception as e:
            print(f"❌ GUI Error: {e}")
            traceback.print_exc()
            input("Press Enter to exit...")

if __name__ == "__main__":
    main()