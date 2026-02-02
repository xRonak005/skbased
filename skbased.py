
import json
import random
import re
import uuid
import requests
import time
import threading
import queue
import sys
import os
from datetime import datetime
from colorama import init, Fore, Style
import warnings
from flask import Flask, request, jsonify

# Suppress SSL warnings
warnings.filterwarnings('ignore')

# Initialize colorama
init(autoreset=True)

# Global flag to indicate if Flask server is running
FLASK_SERVER_RUNNING = threading.Event()
FLASK_APP_INSTANCE = None # To hold the Flask app instance for potential shutdown

# ============================================
# RESPONSE CATEGORIZATION KEYWORDS
# ============================================
CHARGED_KEYWORDS = [
    "success",  # API response field
    "succeeded",  # Charge status
    "true",  # Boolean success
]

APPROVED_BUT_FAILED_KEYWORDS = [
    "security code is invalid",  # CVV wrong
    "doesn't not supported this type of purchase",  # Card type not supported
    "card is not supported",  # Card not supported
    "3d secure required",  # 3D Secure needed
    "requires_action",  # Additional action needed
    "insufficient funds",  # No money
]

DECLINED_DEAD_KEYWORDS = [
    "card was declined",  # Generic decline
    "card number is incorrect",  # Wrong card number
    "expiration year is invalid",  # Wrong expiry
    "expiration month is invalid",  # Wrong expiry month
    "invalid card",  # Invalid card
    "invalid account",  # Invalid account
]

# ============================================
# ENHANCED PROXY MANAGER
# ============================================
class ProxyManager:
    def __init__(self, proxy_file=None):
        self.proxies = []
        self.current_index = 0
        self.lock = threading.Lock()
        
        if proxy_file and os.path.exists(proxy_file):
            self.load_proxies(proxy_file)
    
    def load_proxies(self, proxy_file):
        """Load proxies from file"""
        try:
            with open(proxy_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and ':' in line and not line.startswith('#'):
                        self.proxies.append(line)
            
            print(f"{Fore.GREEN}✅ Loaded {len(self.proxies)} proxies")
            
        except Exception as e:
            print(f"{Fore.RED}❌ Error loading proxies: {e}")
    
    def get_next_proxy(self):
        """Get next proxy with rotation"""
        with self.lock:
            if not self.proxies:
                return None
            
            proxy_str = self.proxies[self.current_index]
            self.current_index = (self.current_index + 1) % len(self.proxies)
            
            # Parse proxy format: host:port:username:password
            parts = proxy_str.split(':')
            
            if len(parts) == 4:  # host:port:user:pass
                host, port, user, password = parts
                proxy_dict = {
                    'http': f'http://{user}:{password}@{host}:{port}',
                    'https': f'http://{user}:{password}@{host}:{port}'
                }
                return proxy_dict
            
            elif len(parts) == 2:  # host:port
                host, port = parts
                proxy_dict = {
                    'http': f'http://{host}:{port}',
                    'https': f'http://{host}:{port}'
                }
                return proxy_dict
            
            return None

    def get_specific_proxy(self, proxy_str):
        """Get a specific proxy dictionary from a string (host:port:user:pass or host:port)"""
        if not proxy_str:
            return None
        
        parts = proxy_str.split(':')
        if len(parts) == 4:  # host:port:user:pass
            host, port, user, password = parts
            proxy_dict = {
                'http': f'http://{user}:{password}@{host}:{port}',
                'https': f'http://{user}:{password}@{host}:{port}'
            }
            return proxy_dict
        elif len(parts) == 2:  # host:port
            host, port = parts
            proxy_dict = {
                'http': f'http://{host}:{port}',
                'https': f'http://{host}:{port}'
            }
            return proxy_dict
        return None

# ============================================
# ENHANCED RESPONSE CATEGORIZER
# ============================================
class ResponseCategorizer:
    @staticmethod
    def categorize_response(error_message, response_data):
        """
        Categorize response based on exact keywords
        Returns: (category, subcategory)
        """
        error_lower = error_message.lower() if error_message else ""
        
        # Check for CHARGED (successful)
        if isinstance(response_data, dict):
            # Check API success field
            if response_data.get('success') is True:
                return "CHARGED", "API_SUCCESS_TRUE"
            if response_data.get('ok') is True:
                return "CHARGED", "OK_TRUE"
            
            # Check charge status
            if response_data.get('status') == 'succeeded':
                return "CHARGED", "STATUS_SUCCEEDED"
            if response_data.get('paid') is True:
                return "CHARGED", "PAID_TRUE"
            
            # Check data object
            data = response_data.get('data', {})
            if data.get('status') == 'succeeded':
                return "CHARGED", "DATA_STATUS_SUCCEEDED"
            if data.get('paid') is True:
                return "CHARGED", "DATA_PAID_TRUE"
        
        # Check for APPROVED_BUT_FAILED (CVV wrong, 3D Secure, etc)
        for keyword in APPROVED_BUT_FAILED_KEYWORDS:
            if keyword in error_lower:
                if "security code" in error_lower or "cvv" in error_lower:
                    return "APPROVED_BUT_FAILED", "INVALID_CVV"
                elif "insufficient" in error_lower:
                    return "APPROVED_BUT_FAILED", "INSUFFICIENT_FUNDS"
                elif "3d" in error_lower or "secure" in error_lower:
                    return "APPROVED_BUT_FAILED", "3D_SECURE_REQUIRED"
                elif "not supported" in error_lower:
                    return "APPROVED_BUT_FAILED", "CARD_NOT_SUPPORTED"
                elif "requires_action" in error_lower:
                    return "APPROVED_BUT_FAILED", "REQUIRES_ACTION"
                else:
                    return "APPROVED_BUT_FAILED", "OTHER_APPROVED_FAILURE"
        
        # Check for DECLINED_DEAD
        for keyword in DECLINED_DEAD_KEYWORDS:
            if keyword in error_lower:
                if "declined" in error_lower:
                    return "DECLINED_DEAD", "CARD_DECLINED"
                elif "incorrect" in error_lower:
                    return "DECLINED_DEAD", "INCORRECT_CARD_NUMBER"
                elif "invalid" in error_lower and ("year" in error_lower or "month" in error_lower):
                    return "DECLINED_DEAD", "INVALID_EXPIRY"
                elif "invalid" in error_lower:
                    return "DECLINED_DEAD", "INVALID_CARD"
                else:
                    return "DECLINED_DEAD", "OTHER_DECLINE"
        
        # Default to unknown
        return "UNKNOWN", "UNKNOWN_ERROR"

# ============================================
# STRIPE CHECKER WITH EXACT CATEGORIZATION
# ============================================
class ExactStripeChecker:
    def __init__(self, sk, pk, proxy_manager=None):
        self.sk = sk
        self.pk = pk
        self.proxy_manager = proxy_manager
        self.currency = 'aud'
        self.amount = 200  # $2.00 in cents
        self.categorizer = ResponseCategorizer()
        
        # Test connection only if not running from Flask (to avoid repeated calls)
        # This check is simplified; for a robust solution, consider a global flag or explicit parameter
        if not FLASK_SERVER_RUNNING.is_set(): # Only test connection if Flask is not already running
            self.test_connection()
    
    def test_connection(self):
        """Test Stripe connection"""
        print(f"{Fore.CYAN}🔍 Testing Stripe connection...")
        try:
            headers = {"Authorization": f"Bearer {self.sk}"}
            response = requests.get(
                "https://api.stripe.com/v1/account",
                headers=headers,
                timeout=15,
                verify=False
            )
            
            if response.status_code == 200:
                account = response.json()
                print(f"{Fore.GREEN}✅ Connected to: {account.get('email', 'Unknown')}")
                print(f"{Fore.CYAN}💰 Currency: {account.get('default_currency', 'aud').upper()}")
                return True
            else:
                print(f"{Fore.RED}❌ Connection failed: HTTP {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            print(f"{Fore.RED}❌ Connection error: {e}")
            return False
    
    def create_token(self, cc, mm, yy, cvv, proxy=None):
        """Create Stripe token"""
        headers = {
            'authority': 'api.stripe.com',
            'accept': 'application/json',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://js.stripe.com',
            'referer': 'https://js.stripe.com/',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        session_ids = {
            'guid': str(uuid.uuid4()),
            'muid': str(uuid.uuid4()),
            'sid': str(uuid.uuid4())
        }
        
        data = {
            "guid": session_ids['guid'],
            "muid": session_ids['muid'],
            "sid": session_ids['sid'],
            "referrer": "http://localhost:8081",
            "time_on_page": str(random.randint(10000, 120000)),
            "card[number]": cc,
            "card[cvc]": cvv,
            "card[exp_month]": mm,
            "card[exp_year]": yy,
            "payment_user_agent": "stripe.js/250b377966; stripe-js-v3/250b377966; card-element",
            "key": self.pk
        }
        
        try:
            response = requests.post(
                "https://api.stripe.com/v1/tokens",
                data=data,
                headers=headers,
                proxies=proxy,
                timeout=15,
                verify=False
            )
            
            if response.status_code == 200:
                result = response.json()
                if 'id' in result:
                    return {
                        'success': True,
                        'token_id': result['id'],
                        'raw_response': result
                    }
            
            result = response.json() if response.content else {}
            error_msg = result.get('error', {}).get('message', f'HTTP {response.status_code}')
            
            return {
                'success': False,
                'error': error_msg,
                'raw_response': result
            }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def create_charge(self, token_id, proxy=None):
        """Create charge"""
        headers = {
            "Authorization": f"Bearer {self.sk}",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        data = {
            "amount": str(self.amount),
            "currency": self.currency,
            "source": token_id,
            "description": "Payment"
        }
        
        try:
            response = requests.post(
                "https://api.stripe.com/v1/charges",
                data=data,
                headers=headers,
                proxies=proxy,
                timeout=20,
                verify=False
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    'success': True,
                    'charge_id': result.get('id'),
                    'status': result.get('status'),
                    'paid': result.get('paid'),
                    'raw_response': result
                }
            
            result = response.json() if response.content else {}
            error_msg = result.get('error', {}).get('message', f'HTTP {response.status_code}')
            
            return {
                'success': False,
                'error': error_msg,
                'raw_response': result
            }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def process_card_exact(self, card_line, proxy=None):
        """Process card with exact categorization"""
        try:
            # Parse card
            parts = card_line.strip().split('|')
            if len(parts) < 4:
                return {
                    'card': card_line,
                    'status': 'INVALID_FORMAT',
                    'error': 'Invalid format'
                }
            
            cc = re.sub(r'\s+', '', parts[0])
            mm = re.sub(r'\D+', '', parts[1])
            yy = re.sub(r'\D+', '', parts[2])
            cvv = re.sub(r'\s+', '', parts[3])
            
            # Format year
            if len(yy) == 4:
                yy = yy[2:]
            
            # Create token
            token_result = self.create_token(cc, mm, yy, cvv, proxy)
            
            if not token_result['success']:
                category, subcategory = self.categorizer.categorize_response(
                    token_result.get('error'), 
                    token_result.get('raw_response', {})
                )
                return {
                    'card': f"{cc}|{mm}|{yy}|{cvv}",
                    'status': category,
                    'substatus': subcategory,
                    'error': token_result.get('error'),
                    'stage': 'TOKEN_CREATION',
                    'raw_response': token_result.get('raw_response')
                }
            
            # Create charge
            charge_result = self.create_charge(token_result['token_id'], proxy)
            
            if charge_result['success']:
                # Check if actually charged (succeeded)
                if charge_result.get('status') == 'succeeded' or charge_result.get('paid') is True:
                    return {
                        'card': f"{cc}|{mm}|{yy}|{cvv}",
                        'status': 'CHARGED',
                        'substatus': 'SUCCESSFUL_CHARGE',
                        'charge_id': charge_result.get('id'), # Use 'id' for charge_id
                        'stage': 'CHARGE',
                        'raw_response': charge_result.get('raw_response')
                    }
                else:
                    # Created but not succeeded
                    category, subcategory = self.categorizer.categorize_response(
                        f"Status: {charge_result.get('status')}", 
                        charge_result.get('raw_response', {})
                    )
                    return {
                        'card': f"{cc}|{mm}|{yy}|{cvv}",
                        'status': category,
                        'substatus': subcategory,
                        'error': f"Charge status: {charge_result.get('status')}",
                        'stage': 'CHARGE',
                        'raw_response': charge_result.get('raw_response')
                    }
            else:
                category, subcategory = self.categorizer.categorize_response(
                    charge_result.get('error'), 
                    charge_result.get('raw_response', {})
                )
                return {
                    'card': f"{cc}|{mm}|{yy}|{cvv}",
                    'status': category,
                    'substatus': subcategory,
                    'error': charge_result.get('error'),
                    'stage': 'CHARGE',
                    'raw_response': charge_result.get('raw_response')
                }
                
        except Exception as e:
            return {
                'card': card_line,
                'status': 'EXCEPTION',
                'substatus': 'PROCESSING_ERROR',
                'error': str(e)
            }

# ============================================
# WORKER SYSTEM
# ============================================
def exact_worker(checker, card_queue, results_queue, proxy_manager, worker_id, stats):
    """Worker thread with exact categorization"""
    while True:
        try:
            card_line = card_queue.get_nowait()
        except queue.Empty:
            break
        
        # Get proxy
        proxy = None
        if proxy_manager:
            proxy = proxy_manager.get_next_proxy()
        
        # Process card
        result = checker.process_card_exact(card_line, proxy)
        
        # Update stats
        with stats['lock']:
            stats['processed'] += 1
            status = result.get('status', 'UNKNOWN')
            
            if status == 'CHARGED':
                stats['charged'] += 1
                stats['live'] += 1
            elif status == 'APPROVED_BUT_FAILED':
                stats['approved_failed'] += 1
                stats['live'] += 1
            elif status == 'DECLINED_DEAD':
                stats['declined_dead'] += 1
            else:
                stats['other'] += 1
        
        # Send result
        results_queue.put((worker_id, result))
        
        card_queue.task_done()

# ============================================
# MAIN PROCESSING
# ============================================
def exact_mass_check(config):
    """Mass check with exact categorization"""
    # This function is now designed to be called both from CLI and Flask.
    # When called from Flask, it will process a single card and return the result.
    # When called from CLI, it will process a list of cards and print progress.

    is_cli_mode = not config.get('is_flask_call', False)

    if is_cli_mode:
        print(f"\n{Fore.GREEN}{'═' * 70}")
        print(f"{Fore.YELLOW}🎯 EXACT STRIPE CHECKER")
        print(f"{Fore.GREEN}{'═' * 70}")
        
        # Load cards
        print(f"{Fore.CYAN}📥 Loading cards...")
        
        cards = []
        try:
            with open(config['combo_file'], 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or 'Scraped at:' in line or '📅' in line:
                        continue
                    
                    # Extract card
                    pattern = r'(\d{13,19})[\|:\s]+(\d{1,2})[\|:\s]+(\d{2,4})[\|:\s]+(\d{3,4})'
                    match = re.search(pattern, line)
                    
                    if match:
                        cc, mm, yy, cvv = match.groups()
                        
                        if not (mm.isdigit() and 1 <= int(mm) <= 12):
                            continue
                        
                        if len(yy) == 4:
                            yy = yy[2:]
                        
                        if not (cvv.isdigit() and len(cvv) in [3, 4]):
                            continue
                        
                        cards.append(f"{cc}|{mm}|{yy}|{cvv}")
        except Exception as e:
            print(f"{Fore.RED}❌ Error loading cards: {e}")
            return
        
        if not cards:
            print(f"{Fore.RED}❌ No valid cards found!")
            return
        
        print(f"{Fore.GREEN}✅ Loaded {len(cards)} cards")
    else: # Flask mode
        cards = [config['card_line']] # Only one card to process
        print(f"{Fore.CYAN}Processing single card from API: {config['card_line']}")

    # Initialize proxy manager
    proxy_manager = None
    if config.get('proxy_file') and os.path.exists(config['proxy_file']):
        proxy_manager = ProxyManager(config['proxy_file'])
    
    # Initialize checker
    checker = ExactStripeChecker(
        sk=config['sk'],
        pk=config['pk'],
        proxy_manager=proxy_manager
    )
    checker.amount = config['amount']
    
    if is_cli_mode:
        print(f"{Fore.CYAN}💰 Amount: ${config['amount']/100:.2f} AUD")
        print(f"{Fore.CYAN}🧵 Threads: {config['threads']}")
        if proxy_manager and proxy_manager.proxies:
            print(f"{Fore.CYAN}🔄 Proxies: {len(proxy_manager.proxies)} (rotating)")
        
        # Create results directory
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        results_dir = f"results_exact_{timestamp}"
        os.makedirs(results_dir, exist_ok=True)
        
        # Create output files
        charged_file = os.path.join(results_dir, 'CHARGED.txt')
        approved_failed_file = os.path.join(results_dir, 'APPROVED_BUT_FAILED.txt')
        declined_dead_file = os.path.join(results_dir, 'DECLINED_DEAD.txt')
        other_file = os.path.join(results_dir, 'OTHER.txt')
        raw_file = os.path.join(results_dir, 'raw_responses.json')
        
        # Create queues
        card_queue = queue.Queue()
        results_queue = queue.Queue()
        
        # Add cards to queue
        for card in cards:
            card_queue.put(card)
        
        total_cards = len(cards)
        
        # Stats
        stats = {
            'total': total_cards,
            'processed': 0,
            'charged': 0,
            'approved_failed': 0,
            'declined_dead': 0,
            'live': 0,
            'other': 0,
            'lock': threading.Lock(),
            'start_time': time.time(),
            'raw_responses': []
        }
        
        # Start workers
        print(f"\n{Fore.YELLOW}🚀 Starting {config['threads']} workers...")
        threads = []
        for i in range(min(config['threads'], total_cards)):
            t = threading.Thread(
                target=exact_worker,
                args=(checker, card_queue, results_queue, proxy_manager, i, stats),
                daemon=True
            )
            t.start()
            threads.append(t)
        
        print(f"\n{Fore.CYAN}{'─' * 70}")
        print(f"{Fore.YELLOW}📊 PROCESSING {total_cards} CARDS")
        print(f"{Fore.CYAN}{'─' * 70}")
        
        last_update = time.time()
        
        try:
            while stats['processed'] < total_cards:
                try:
                    worker_id, result = results_queue.get(timeout=0.5)
                    
                    # Save raw response
                    raw_response = {
                        'timestamp': datetime.now().isoformat(),
                        'card': result.get('card'),
                        'status': result.get('status'),
                        'substatus': result.get('substatus'),
                        'error': result.get('error'),
                        'stage': result.get('stage'),
                        'raw': result.get('raw_response')
                    }
                    stats['raw_responses'].append(raw_response)
                    
                    # Save to appropriate file
                    status = result.get('status', 'UNKNOWN')
                    card_display = result['card'].split('|')[0] if 'card' in result else 'Unknown'
                    
                    if status == 'CHARGED':
                        with open(charged_file, 'a', encoding='utf-8') as f:
                            f.write(f"{result['card']} | Charge: {result.get('charge_id', 'N/A')}\n")
                        print(f"{Fore.GREEN}[{stats['processed']}/{total_cards}] ✅ CHARGED: {card_display[:6]}**** | ID: {result.get('charge_id', 'N/A')}")
                        
                    elif status == 'APPROVED_BUT_FAILED':
                        substatus = result.get('substatus', '')
                        with open(approved_failed_file, 'a', encoding='utf-8') as f:
                            f.write(f"{result['card']} | Type: {substatus} | Error: {result.get('error', 'N/A')}\n")
                        
                        # Color code based on substatus
                        if 'INVALID_CVV' in substatus:
                            print(f"{Fore.CYAN}[{stats['processed']}/{total_cards}] 🔥 APPROVED (WRONG CVV): {card_display[:6]}****")
                        elif 'INSUFFICIENT_FUNDS' in substatus:
                            print(f"{Fore.MAGENTA}[{stats['processed']}/{total_cards}] 🔥 APPROVED (NO FUNDS): {card_display[:6]}****")
                        elif '3D_SECURE' in substatus:
                            print(f"{Fore.BLUE}[{stats['processed']}/{total_cards}] 🔥 APPROVED (3D SECURE): {card_display[:6]}****")
                        else:
                            print(f"{Fore.YELLOW}[{stats['processed']}/{total_cards}] 🔥 APPROVED: {card_display[:6]}**** | {substatus}")
                        
                    elif status == 'DECLINED_DEAD':
                        with open(declined_dead_file, 'a', encoding='utf-8') as f:
                            f.write(f"{result['card']} | Error: {result.get('error', 'N/A')}\n")
                        print(f"{Fore.RED}[{stats['processed']}/{total_cards}] ❌ DEAD: {card_display[:6]}**** | {result.get('error', '')[:50]}")
                        
                    else:
                        with open(other_file, 'a', encoding='utf-8') as f:
                            f.write(f"{result.get('card', 'Unknown')} | Status: {status} | Error: {result.get('error', 'N/A')}\n")
                        print(f"{Fore.MAGENTA}[{stats['processed']}/{total_cards}] ⚠️ {status}: {card_display[:6]}**** | {result.get('error', '')[:50]}")
                    
                    # Update display
                    current_time = time.time()
                    if current_time - last_update >= 2 or stats['processed'] == total_cards:
                        elapsed = current_time - stats['start_time']
                        speed = stats['processed'] / elapsed if elapsed > 0 else 0
                        remaining = (total_cards - stats['processed']) / speed if speed > 0 else 0
                        
                        progress = (stats['processed'] / total_cards) * 100
                        bar_length = 50
                        filled = int(bar_length * stats['processed'] // total_cards)
                        bar = '█' * filled + '░' * (bar_length - filled)
                        
                        sys.stdout.write(f"\r{Fore.CYAN}{bar} {progress:.1f}%")
                        sys.stdout.write(f"\n{Fore.YELLOW}📊 Charged: {stats['charged']} | Approved-Failed: {stats['approved_failed']} | Dead: {stats['declined_dead']} | Other: {stats['other']} | Total: {stats['processed']}/{total_cards}")
                        sys.stdout.write(f"\n{Fore.CYAN}⚡ Speed: {speed:.1f} cards/sec | ⏱️ Elapsed: {elapsed:.0f}s | ⏳ Remaining: {remaining:.0f}s")
                        sys.stdout.write(f"\n{Fore.CYAN}{'─' * 70}\n")
                        sys.stdout.flush() # Ensure output is printed immediately
                        
                        last_update = current_time
                        
                except queue.Empty:
                    alive_threads = sum(1 for t in threads if t.is_alive())
                    if alive_threads == 0:
                        break
                    time.sleep(0.1)
                    
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}⚠️ Stopped by user")
        
        # Wait for threads
        for t in threads:
            t.join(timeout=1)
        
        # Save raw responses
        print(f"\n{Fore.CYAN}💾 Saving raw responses...")
        with open(raw_file, 'w', encoding='utf-8') as f:
            json.dump(stats['raw_responses'], f, indent=2, ensure_ascii=False)
        
        # Final stats
        elapsed = time.time() - stats['start_time']
        
        print(f"\n{Fore.GREEN}{'═' * 70}")
        print(f"{Fore.YELLOW}🎯 EXACT CHECK COMPLETED")
        print(f"{Fore.GREEN}{'═' * 70}")
        
        print(f"{Fore.CYAN}📈 EXACT RESULTS:")
        print(f"{Fore.WHITE}   Total Cards: {stats['total']}")
        print(f"{Fore.GREEN}   ✅ CHARGED (Success): {stats['charged']}")
        print(f"{Fore.YELLOW}   🔥 APPROVED BUT FAILED (Live): {stats['approved_failed']}")
        print(f"{Fore.RED}   ❌ DECLINED DEAD: {stats['declined_dead']}")
        print(f"{Fore.MAGENTA}   ⚠️ OTHER: {stats['other']}")
        print(f"{Fore.CYAN}   🔥 TOTAL LIVE CARDS: {stats['charged'] + stats['approved_failed']}")
        
        if elapsed > 0:
            print(f"{Fore.CYAN}   ⚡ Average Speed: {stats['total']/elapsed:.1f} cards/sec")
        
        if stats['total'] > 0:
            live_rate = ((stats['charged'] + stats['approved_failed']) / stats['total']) * 100
            charge_rate = (stats['charged'] / stats['total']) * 100
            print(f"{Fore.CYAN}   📊 Live Rate: {live_rate:.1f}%")
            print(f"{Fore.CYAN}   🎯 Charge Rate: {charge_rate:.1f}%")
        
        print(f"\n{Fore.YELLOW}💾 FILES SAVED:")
        print(f"{Fore.CYAN}   📁 Directory: {results_dir}")
        print(f"{Fore.GREEN}   ✅ CHARGED: {charged_file}")
        print(f"{Fore.YELLOW}   🔥 APPROVED_BUT_FAILED: {approved_failed_file}")
        print(f"{Fore.RED}   ❌ DECLINED_DEAD: {declined_dead_file}")
        print(f"{Fore.MAGENTA}   ⚠️ OTHER: {other_file}")
        print(f"{Fore.CYAN}   📋 RAW: {raw_file}")
        print(f"{Fore.GREEN}{'═' * 70}")
    
    else: # Flask mode: process single card
        card_line = config['card_line']
        specific_proxy = None
        if config.get('proxy'):
            # Create a temporary ProxyManager to parse the specific proxy string
            temp_proxy_manager = ProxyManager()
            specific_proxy = temp_proxy_manager.get_specific_proxy(config['proxy'])
            if not specific_proxy:
                return {'error': 'Invalid proxy format provided in URL.'}

        result = checker.process_card_exact(card_line, specific_proxy)
        return result


# ============================================
# MENU SYSTEM
# ============================================
def exact_main_menu():
    """Exact categorization main menu"""
    print(f"""
{Fore.CYAN}{'═' * 70}
{Fore.MAGENTA}╔══════════════════════════════════════════════════════════════════╗
{Fore.MAGENTA}║{Fore.YELLOW}        EXACT STRIPE CATEGORIZER v1.0                      {Fore.MAGENTA}║
{Fore.MAGENTA}║{Fore.CYAN}  Charged ✅ | Approved-Failed 🔥 | Declined-Dead ❌        {Fore.MAGENTA}║
{Fore.MAGENTA}╚══════════════════════════════════════════════════════════════════╝
{Fore.CYAN}{'═' * 70}
    """)
    
    while True:
        print(f"\n{Fore.YELLOW}📋 EXACT CATEGORIZER MENU")
        print(f"{Fore.CYAN}1. Start Exact Categorizer (CLI Mode)")
        print(f"{Fore.CYAN}2. Clean Combo File")
        print(f"{Fore.CYAN}3. Test Connection")
        if FLASK_SERVER_RUNNING.is_set():
            print(f"{Fore.GREEN}4. API Server is RUNNING (http://{FLASK_APP_HOST}:{FLASK_APP_PORT})")
            print(f"{Fore.RED}5. Stop API Server")
            print(f"{Fore.CYAN}6. Exit")
        else:
            print(f"{Fore.CYAN}4. Start API Server (Flask Mode)")
            print(f"{Fore.CYAN}5. Exit")
        
        choice = input(f"\n{Fore.GREEN}Select option: {Fore.WHITE}").strip()
        
        if choice == '1':
            start_exact_checker_cli()
        elif choice == '2':
            clean_file()
        elif choice == '3':
            test_stripe()
        elif choice == '4':
            if FLASK_SERVER_RUNNING.is_set():
                print(f"{Fore.YELLOW}API server is already running.")
            else:
                start_flask_server_threaded()
        elif choice == '5':
            if FLASK_SERVER_RUNNING.is_set(): # If API is running, this option is "Stop API Server"
                stop_flask_server()
            else: # If API is not running, this option is "Exit"
                print(f"{Fore.YELLOW}👋 Goodbye!")
                break
        elif choice == '6' and FLASK_SERVER_RUNNING.is_set(): # This option is "Exit" when API is running
            print(f"{Fore.YELLOW}👋 Goodbye!")
            break
        else:
            print(f"{Fore.RED}❌ Invalid choice!")

def start_exact_checker_cli():
    """Start exact checker in CLI mode"""
    print(f"\n{Fore.GREEN}{'═' * 70}")
    print(f"{Fore.YELLOW}🚀 EXACT CHECKER SETUP (CLI MODE)")
    print(f"{Fore.GREEN}{'═' * 70}")
    
    # Get SK
    sk = input(f"\n{Fore.CYAN}[1/6] Stripe SK (sk_live_...): {Fore.WHITE}").strip()
    if not sk.startswith('sk_'):
        print(f"{Fore.RED}❌ Invalid SK")
        return
    
    # Get PK
    pk = input(f"\n{Fore.CYAN}[2/6] Stripe PK (pk_live_...): {Fore.WHITE}").strip()
    if not pk.startswith('pk_'):
        print(f"{Fore.RED}❌ Invalid PK")
        return
    
    # Get combo file
    combo_file = input(f"\n{Fore.CYAN}[3/6] Card file: {Fore.WHITE}").strip()
    if not os.path.exists(combo_file):
        print(f"{Fore.RED}❌ File not found")
        return
    
    # Get proxy file
    proxy_file = input(f"\n{Fore.CYAN}[4/6] Proxy file (optional): {Fore.WHITE}").strip()
    if proxy_file and not os.path.exists(proxy_file):
        print(f"{Fore.YELLOW}⚠️ Proxy file not found, continuing without proxies.")
        proxy_file = None
    
    # Get threads
    try:
        threads = int(input(f"\n{Fore.CYAN}[5/6] Threads (1-50): {Fore.WHITE}").strip() or "20")
        threads = max(1, min(50, threads))
    except ValueError:
        threads = 20
        print(f"{Fore.YELLOW}⚠️ Invalid input for threads, defaulting to {threads}")
    
    # Get amount
    try:
        amount = float(input(f"\n{Fore.CYAN}[6/6] Amount AUD (e.g., 2.00): {Fore.WHITE}").strip() or "2.00")
        amount_cents = int(amount * 100)
    except ValueError:
        amount_cents = 200
        print(f"{Fore.YELLOW}⚠️ Invalid input for amount, defaulting to ${amount_cents/100:.2f}")
    
    config = {
        'sk': sk,
        'pk': pk,
        'combo_file': combo_file,
        'proxy_file': proxy_file,
        'threads': threads,
        'amount': amount_cents,
        'is_flask_call': False # Indicate CLI mode
    }
    
    exact_mass_check(config)

def clean_file():
    """Clean combo file"""
    input_file = input(f"\n{Fore.CYAN}Input file: {Fore.WHITE}").strip()
    if not os.path.exists(input_file):
        print(f"{Fore.RED}❌ File not found")
        return
    
    output_file = input(f"\n{Fore.CYAN}Output file (default: cleaned_exact.txt): {Fore.WHITE}").strip() or "cleaned_exact.txt"
    
    valid_cards = []
    
    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or 'Scraped at:' in line:
                    continue
                
                pattern = r'(\d{13,19})[\|:\s]+(\d{1,2})[\|:\s]+(\d{2,4})[\|:\s]+(\d{3,4})'
                match = re.search(pattern, line)
                
                if match:
                    cc, mm, yy, cvv = match.groups()
                    
                    if not (mm.isdigit() and 1 <= int(mm) <= 12):
                        continue
                    
                    if len(yy) == 4:
                        yy = yy[2:]
                    
                    if not (cvv.isdigit() and len(cvv) in [3, 4]):
                        continue
                    
                    valid_cards.append(f"{cc}|{mm}|{yy}|{cvv}")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            for card in valid_cards:
                f.write(f"{card}\n")
        
        print(f"{Fore.GREEN}✅ Saved {len(valid_cards)} cards to {output_file}")
        
    except Exception as e:
        print(f"{Fore.RED}❌ Error: {e}")

def test_stripe():
    """Test Stripe connection"""
    sk = input(f"\n{Fore.CYAN}Enter SK: {Fore.WHITE}").strip()
    
    if not sk.startswith('sk_'):
        print(f"{Fore.RED}❌ Invalid SK")
        return
    
    try:
        headers = {"Authorization": f"Bearer {sk}"}
        response = requests.get(
            "https://api.stripe.com/v1/account",
            headers=headers,
            timeout=10,
            verify=False
        )
        
        if response.status_code == 200:
            account = response.json()
            print(f"\n{Fore.GREEN}✅ CONNECTED!")
            print(f"{Fore.CYAN}📧 {account.get('email', 'N/A')}")
            print(f"{Fore.CYAN}🌍 {account.get('country', 'N/A')}")
            print(f"{Fore.CYAN}💰 {account.get('default_currency', 'N/A').upper()}")
        else:
            print(f"{Fore.RED}❌ Failed: HTTP {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"{Fore.RED}❌ Error: {e}")

# ============================================
# FLASK INTEGRATION
# ============================================
app = Flask(__name__)
FLASK_APP_HOST = "0.0.0.0"
FLASK_APP_PORT = 5000

@app.route('/skbased', methods=['GET'])
def skbased_check():
    cc_full = request.args.get('cc')
    sk = request.args.get('sk')
    pk = request.args.get('pk')
    proxy_str = request.args.get('proxy') # host:port:user:pass or host:port
    
    if not all([cc_full, sk, pk]):
        return jsonify({'error': 'Missing parameters: cc, sk, pk are required.'}), 400
    
    # Validate SK and PK format
    if not sk.startswith('sk_'):
        return jsonify({'error': 'Invalid Stripe SK format.'}), 400
    if not pk.startswith('pk_'):
        return jsonify({'error': 'Invalid Stripe PK format.'}), 400

    # Parse CC format from query parameter (e.g., 4000000000000000|12|24|123)
    # The `process_card_exact` expects 'cc|mm|yy|cvv'
    card_parts = cc_full.split('|')
    if len(card_parts) != 4:
        return jsonify({'error': 'Invalid card format. Expected cc|mm|yy|cvv.'}), 400
    
    cc, mm, yy, cvv = card_parts
    
    # Basic validation of card components
    if not (cc.isdigit() and 13 <= len(cc) <= 19):
        return jsonify({'error': 'Invalid card number format.'}), 400
    if not (mm.isdigit() and 1 <= int(mm) <= 12):
        return jsonify({'error': 'Invalid month format.'}), 400
    if not (yy.isdigit() and (len(yy) == 2 or len(yy) == 4)):
        return jsonify({'error': 'Invalid year format.'}), 400
    if not (cvv.isdigit() and len(cvv) in [3, 4]):
        return jsonify({'error': 'Invalid CVV format.'}), 400

    # Default amount for API calls
    amount_cents = 200 # $2.00 AUD
    
    config = {
        'sk': sk,
        'pk': pk,
        'card_line': cc_full, # Pass the full card line for processing
        'proxy': proxy_str, # Pass the proxy string directly
        'amount': amount_cents,
        'is_flask_call': True # Indicate Flask mode
    }
    
    try:
        # Instantiate checker without a file-based ProxyManager for API calls
        # The specific proxy for the request will be passed directly to process_card_exact
        checker = ExactStripeChecker(sk=sk, pk=pk)
        checker.amount = amount_cents # Ensure amount is set
        
        specific_proxy_dict = None
        if proxy_str:
            temp_proxy_manager = ProxyManager() # Use a temporary instance to parse
            specific_proxy_dict = temp_proxy_manager.get_specific_proxy(proxy_str)
            if not specific_proxy_dict:
                return jsonify({'error': 'Invalid proxy format provided in URL. Expected host:port or host:port:user:pass.'}), 400

        result = checker.process_card_exact(cc_full, specific_proxy_dict)
        
        # Clean up raw_response for API output if it's too verbose or contains sensitive info
        # For this example, we'll return it as is, but in production, you might filter it.
        
        return jsonify(result), 200
    except Exception as e:
        print(f"{Fore.RED}❌ API Error: {e}")
        return jsonify({'error': f'An internal server error occurred: {str(e)}'}), 500

def run_flask_app():
    """Function to run the Flask app, intended for a separate thread."""
    global FLASK_SERVER_RUNNING, FLASK_APP_INSTANCE
    FLASK_SERVER_RUNNING.set()
    FLASK_APP_INSTANCE = app # Store the app instance
    try:
        app.run(host=FLASK_APP_HOST, port=FLASK_APP_PORT, debug=False, use_reloader=False) # use_reloader=False is crucial for threading
    except Exception as e:
        print(f"{Fore.RED}❌ Flask server thread error: {e}")
    finally:
        FLASK_SERVER_RUNNING.clear()
        FLASK_APP_INSTANCE = None

def start_flask_server_threaded():
    """Starts the Flask API server in a separate thread."""
    if FLASK_SERVER_RUNNING.is_set():
        print(f"{Fore.YELLOW}API server is already running.")
        return

    print(f"\n{Fore.GREEN}{'═' * 70}")
    print(f"{Fore.YELLOW}🚀 STARTING FLASK API SERVER IN BACKGROUND")
    print(f"{Fore.GREEN}{'═' * 70}")
    
    # You can prompt for host/port here if you want to make them configurable
    # For now, using global defaults.
    
    server_thread = threading.Thread(target=run_flask_app, daemon=True)
    server_thread.start()
    
    # Give the server a moment to start up
    time.sleep(1) 
    
    if FLASK_SERVER_RUNNING.is_set():
        print(f"{Fore.GREEN}🌐 API server running on http://{FLASK_APP_HOST}:{FLASK_APP_PORT}")
        print(f"{Fore.CYAN}Endpoint: /skbased?cc=CARD|MM|YY|CVV&sk=sk_live_...&pk=pk_live_...&proxy=host:port:user:pass")
        print(f"{Fore.YELLOW}You can now use the menu while the API runs in the background.")
    else:
        print(f"{Fore.RED}❌ Failed to start Flask server.")

def stop_flask_server():
    """Stops the Flask API server."""
    global FLASK_SERVER_RUNNING, FLASK_APP_INSTANCE
    if not FLASK_SERVER_RUNNING.is_set():
        print(f"{Fore.YELLOW}API server is not running.")
        return

    print(f"{Fore.YELLOW}Attempting to stop Flask API server...")
    try:
        # This is a common way to shut down a Flask app running in a thread.
        # It sends a request to a special endpoint that triggers a shutdown.
        requests.post(f'http://{FLASK_APP_HOST}:{FLASK_APP_PORT}/shutdown')
        FLASK_SERVER_RUNNING.clear()
        FLASK_APP_INSTANCE = None
        print(f"{Fore.GREEN}Flask API server stopped.")
    except Exception as e:
        print(f"{Fore.RED}❌ Error stopping Flask server: {e}")

# Add a shutdown route for the Flask app
@app.route('/shutdown', methods=['POST'])
def shutdown():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()
    return 'Server shutting down...'

# ============================================
# MAIN
# ============================================
if __name__ == "__main__":
    try:
        # Start the Flask API server by default in a separate thread
        start_flask_server_threaded()
        
        # Then display the main menu
        exact_main_menu()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}👋 Stopped by user")
    except Exception as e:
        print(f"\n{Fore.RED}❌ An unexpected error occurred: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Ensure Flask server is stopped if it was running
        if FLASK_SERVER_RUNNING.is_set():
            stop_flask_server()

