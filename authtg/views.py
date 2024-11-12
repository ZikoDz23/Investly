from django.shortcuts import render, redirect
from django.http import JsonResponse
from web3 import Web3
from tronpy import Tron
from tronpy.providers import HTTPProvider
from tronpy.keys import PrivateKey
import requests
from decimal import Decimal
import qrcode
from io import BytesIO
from django.core.files.base import ContentFile
import base64
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.conf import settings
from .models import UserProfile


# Set up Ethereum (ETH) connection
eth_web3 = Web3(Web3.HTTPProvider('https://mainnet.infura.io/v3/bf28a0864caa4fa7bc364c205bec19b3'))

# Set up Tron (TRX) connection
provider = HTTPProvider(api_key='7833f328-2e25-44d6-abab-014630652408') 
tron_client = Tron(provider=provider)


# ERC20_ABI for standard ERC-20 tokens
ERC20_ABI = [
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function"
    }
]



def get_usd_price(symbol):
    url = "https://pro-api.coinmarketcap.com/v1/cryptocurrency/quotes/latest"
    headers = {
        "Accepts": "application/json",
        "X-CMC_PRO_API_KEY": settings.COINMARKETCAP_API_KEY,
    }
    # Map the symbol to CoinMarketCap's IDs if necessary (e.g., Ethereum is 'ETH', Tether is 'USDT')
    symbol_map = {
        "ethereum": "ETH",
        "tether": "USDT",
        "tron": "TRX",
    }
    coin_symbol = symbol_map.get(symbol.lower(), symbol.upper())  # Defaults to symbol if not mapped
    
    params = {
        "symbol": coin_symbol,
        "convert": "USD"
    }
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        
        # Access the price from the API response
        if coin_symbol in data["data"]:
            return Decimal(data["data"][coin_symbol]["quote"]["USD"]["price"])
        else:
            raise ValueError(f"Price data for '{symbol}' not found in CoinMarketCap API response.")
    except requests.RequestException as e:
        # Handle network-related errors
        raise ValueError(f"Failed to fetch price for '{symbol}': {str(e)}")
    except (ValueError, KeyError) as e:
        # Handle JSON structure issues or missing data
        raise ValueError(f"Failed to fetch price for '{symbol}': {str(e)}")



def fetch_eth_balance(address):
    balance = eth_web3.eth.get_balance(address)
    return eth_web3.from_wei(balance, 'ether')

def fetch_erc20_balance(address, contract_address):
    contract = eth_web3.eth.contract(address=Web3.to_checksum_address(contract_address), abi=ERC20_ABI)
    balance = contract.functions.balanceOf(address).call()
    decimals = contract.functions.decimals().call()
    return Decimal(balance) / Decimal(10 ** decimals)

def fetch_trx_balance(address):
    try:
        # Fetch balance if the account exists
        return Decimal(tron_client.get_account_balance(address))
    except Exception as e:
        # If account is not found on-chain, return a balance of 0
        if "account not found" in str(e).lower():
            return Decimal(0)
        else:
            raise e

def fetch_trc20_balance(address, contract_address):
    contract = tron_client.get_contract(contract_address)
    balance = contract.functions.balanceOf(address)
    return Decimal(balance) / Decimal(10 ** 6)

 # Assuming UserProfile is created as outlined before

@login_required
def import_wallet(request):
    user_profile = request.user.userprofile

    # Check if the wallet is already associated with the user profile
    if user_profile.wallet_address:
        return redirect('main_page')

    if request.method == 'POST':
        private_key = request.POST.get('private_key')
        if private_key:
            try:
                # Ethereum and Tron wallet setup
                eth_account = eth_web3.eth.account.from_key(private_key)
                trx_account = PrivateKey(bytes.fromhex(private_key))
                trx_address = trx_account.public_key.to_base58check_address()
                
                

                # Fetch balances for Ethereum and Tron
                eth_balance = fetch_eth_balance(eth_account.address)
                usdt_eth_balance = fetch_erc20_balance(eth_account.address, '0xdac17f958d2ee523a2206206994597c13d831ec7')
                trx_balance = fetch_trx_balance(trx_address)
                usdt_trx_balance = fetch_trc20_balance(trx_address, 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t')

                # Convert balances to USD
                eth_to_usd = float(Decimal(eth_balance) * get_usd_price("ethereum"))
                usdt_eth_to_usd = float(Decimal(usdt_eth_balance) * get_usd_price("tether"))
                trx_to_usd = float(Decimal(trx_balance) * get_usd_price("tron"))
                usdt_trx_to_usd = float(Decimal(usdt_trx_balance) * get_usd_price("tether"))

                # Calculate total balance in USD
                total_balance_usd = eth_to_usd + usdt_eth_to_usd + trx_to_usd + usdt_trx_to_usd

                # Organize assets for display
                assets = [
                    {"name": "ETH", "balance": float(eth_balance), "usd_value": eth_to_usd},
                    {"name": "USDT_ERC20", "balance": float(usdt_eth_balance), "usd_value": usdt_eth_to_usd},
                    {"name": "TRX", "balance": float(trx_balance), "usd_value": trx_to_usd},
                    {"name": "USDT_TRC20", "balance": float(usdt_trx_balance), "usd_value": usdt_trx_to_usd}
                ]

                # Save wallet information in the user's profile
                user_profile.wallet_address = eth_account.address  # Assuming Ethereum address is the main identifier
                user_profile.eth_address = eth_account.address
                user_profile.tron_address = trx_address
                user_profile.private_key_encrypted = private_key  # You would encrypt and store this securely
                user_profile.save()

                # Store assets in session for use on the main page
                request.session['total_balance_usd'] = total_balance_usd
                request.session['assets'] = assets

                # Redirect to the main page
                return redirect('main_page')
            
            except Exception as e:
                return JsonResponse({'error': str(e)}, status=500)

    return render(request, 'import_wallet.html')


def main_page(request):
    total_balance_usd = request.session.get('total_balance_usd', 0)
    assets = request.session.get('assets', [])
    return render(request, 'main_page.html', {'total_balance_usd': total_balance_usd, 'assets': assets})


def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        year_of_birth = request.POST.get('year_of_birth')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        terms_accepted = request.POST.get('terms_accepted')

        # Basic validations
        if not terms_accepted:
            messages.error(request, "You must accept the terms and conditions.")
            return redirect('register')

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect('register')

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return redirect('register')

        # Create the user
        user = User.objects.create_user(username=username, email=email, password=password)
        user.save()
        
        messages.success(request, "Registration successful! Please log in.")
        return redirect('login')
    
    return render(request, 'register.html')


def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            user_profile = user.userprofile
            
            # Check if wallet data exists in UserProfile
            if user_profile.wallet_address and user_profile.private_key_encrypted:
                # Fetch wallet details automatically on login
                try:
                    private_key = user_profile.private_key_encrypted  # Assume decryption process here
                    
                    # Ethereum and Tron wallet setup
                    eth_account = eth_web3.eth.account.from_key(private_key)
                    trx_account = PrivateKey(bytes.fromhex(private_key))
                    trx_address = trx_account.public_key.to_base58check_address()

                    # Fetch balances for Ethereum and Tron
                    eth_balance = fetch_eth_balance(eth_account.address)
                    usdt_eth_balance = fetch_erc20_balance(eth_account.address, '0xdac17f958d2ee523a2206206994597c13d831ec7')
                    trx_balance = fetch_trx_balance(trx_address)
                    usdt_trx_balance = fetch_trc20_balance(trx_address, 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t')

                    # Convert balances to USD
                    eth_to_usd = float(Decimal(eth_balance) * get_usd_price("ethereum"))
                    usdt_eth_to_usd = float(Decimal(usdt_eth_balance) * get_usd_price("tether"))
                    trx_to_usd = float(Decimal(trx_balance) * get_usd_price("tron"))
                    usdt_trx_to_usd = float(Decimal(usdt_trx_balance) * get_usd_price("tether"))

                    # Calculate total balance in USD
                    total_balance_usd = eth_to_usd + usdt_eth_to_usd + trx_to_usd + usdt_trx_to_usd

                    # Organize assets for display
                    assets = [
                        {"name": "ETH", "balance": float(eth_balance), "usd_value": eth_to_usd},
                        {"name": "USDT_ERC20", "balance": float(usdt_eth_balance), "usd_value": usdt_eth_to_usd},
                        {"name": "TRX", "balance": float(trx_balance), "usd_value": trx_to_usd},
                        {"name": "USDT_TRC20", "balance": float(usdt_trx_balance), "usd_value": usdt_trx_to_usd}
                    ]

                    # Store wallet data in the session
                    request.session['total_balance_usd'] = total_balance_usd
                    request.session['assets'] = assets

                    # Redirect to the main page with wallet loaded
                    return redirect('main_page')
                
                except Exception as e:
                    messages.error(request, f"Failed to load wallet: {str(e)}")
                    return redirect('login')

            # If no wallet, redirect to the import wallet page
            return redirect('import_wallet')
        else:
            messages.error(request, "Invalid username or password.")
            return redirect('login')
    
    return render(request, 'login.html')


def logout_view(request):
    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect('login')


def redirect_root(request):
    if request.user.is_authenticated:
        return redirect('main_page')  # Redirect to main page if logged in
    else:
        return redirect('login')



def send_eth(private_key, receiver_address, amount):
    account = eth_web3.eth.account.from_key(private_key)
    nonce = eth_web3.eth.get_transaction_count(account.address)
    transaction = {
        'to': receiver_address,
        'value': eth_web3.to_wei(amount, 'ether'),
        'gas': 21000,
        'gasPrice': eth_web3.to_wei('50', 'gwei'),
        'nonce': nonce,
        'chainId': 1
    }
    signed_tx = eth_web3.eth.account.sign_transaction(transaction, private_key)
    tx_hash = eth_web3.eth.send_raw_transaction(signed_tx.raw_transaction)
    return eth_web3.to_hex(tx_hash)

def send_erc20(private_key, receiver_address, amount, token_address):
    account = eth_web3.eth.account.from_key(private_key)
    contract = eth_web3.eth.contract(address=Web3.to_checksum_address(token_address), abi=ERC20_ABI)
    decimals = contract.functions.decimals().call()
    amount_in_wei = int(amount * (10 ** decimals))
    nonce = eth_web3.eth.get_transaction_count(account.address)
    transaction = contract.functions.transfer(receiver_address, amount_in_wei).build_transaction({
        'chainId': 1,
        'gas': 100000,
        'gasPrice': eth_web3.to_wei('50', 'gwei'),
        'nonce': nonce
    })
    signed_tx = eth_web3.eth.account.sign_transaction(transaction, private_key)
    tx_hash = eth_web3.eth.send_raw_transaction(signed_tx.raw_transaction)
    return eth_web3.to_hex(tx_hash)

from decimal import Decimal

def send_trx(private_key, receiver_address, amount):
    # Initialize the account from the private key
    account = PrivateKey(bytes.fromhex(private_key))
    sender_address = account.public_key.to_base58check_address()  # Derive the sender's address from the public key

    # Convert the amount to SUN using Decimal (1 TRX = 1e6 SUN)
    amount_in_sun = int(Decimal(amount) * Decimal(1e6))  # Convert amount to SUN

    # Prepare the transaction for transferring TRX
    txn = (
        tron_client.trx.transfer(sender_address, receiver_address, amount_in_sun)
        .memo("Sending TRX")
        .fee_limit(1_000_000)  # Set the fee limit in SUN
        .build()
        .sign(account)  # Sign with the account's private key
    )
    
    # Broadcast the transaction and get the transaction ID (hash)
    tx_hash = txn.broadcast().txid
    return tx_hash


def send_trc20(private_key, receiver_address, amount, token_address):
    # Initialize the account from the private key
    account = PrivateKey(bytes.fromhex(private_key))
    sender_address = account.public_key.to_base58check_address()  # Derive sender's address from the public key
    
    # Convert the amount to SUN (TRC20 uses 1 TRX = 1e6 SUN)
    amount_in_sun = int(Decimal(amount) * Decimal('1e6'))

    # Fetch the TRC20 contract for the given token address
    contract = tron_client.get_contract(token_address)

    # Prepare and sign the transaction for transferring TRC20 tokens
    txn = (
        contract.functions.transfer(receiver_address, amount_in_sun)
        .with_owner(sender_address)  # Set sender's address as the owner of the transaction
        .fee_limit(1_000_000)  # Set the transaction fee limit in SUN
        .build()
        .sign(account)  # Sign with the account's private key
    )
    
    # Broadcast the transaction and get the transaction ID
    tx_hash = txn.broadcast().txid
    return tx_hash

def update_session_balances(request, eth_account_address, trx_address):
    # Re-fetch balances for Ethereum and Tron assets
    eth_balance = fetch_eth_balance(eth_account_address)
    usdt_eth_balance = fetch_erc20_balance(eth_account_address, '0xdac17f958d2ee523a2206206994597c13d831ec7')
    trx_balance = fetch_trx_balance(trx_address)
    usdt_trx_balance = fetch_trc20_balance(trx_address, 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t')

    # Convert balances to USD
    eth_to_usd = float(Decimal(eth_balance) * get_usd_price("ethereum"))
    usdt_eth_to_usd = float(Decimal(usdt_eth_balance) * get_usd_price("tether"))
    trx_to_usd = float(Decimal(trx_balance) * get_usd_price("tron"))
    usdt_trx_to_usd = float(Decimal(usdt_trx_balance) * get_usd_price("tether"))

    # Calculate total balance in USD
    total_balance_usd = eth_to_usd + usdt_eth_to_usd + trx_to_usd + usdt_trx_to_usd

    # Update assets data
    assets = [
        {"name": "ETH", "balance": float(eth_balance), "usd_value": eth_to_usd},
        {"name": "USDT_ERC20", "balance": float(usdt_eth_balance), "usd_value": usdt_eth_to_usd},
        {"name": "TRX", "balance": float(trx_balance), "usd_value": trx_to_usd},
        {"name": "USDT_TRC20", "balance": float(usdt_trx_balance), "usd_value": usdt_trx_to_usd}
    ]

    # Store the updated balances and assets in the session
    request.session['total_balance_usd'] = total_balance_usd
    request.session['assets'] = assets




@login_required
def send_asset(request, asset_type):
    user_profile = request.user.userprofile
    private_key = user_profile.private_key_encrypted  # Assume this is decrypted securely

    # Get Ethereum and Tron accounts based on the private key
    eth_account = eth_web3.eth.account.from_key(private_key)
    trx_account = PrivateKey(bytes.fromhex(private_key))
    trx_address = trx_account.public_key.to_base58check_address()

    # Fetch balances for the specific asset type
    eth_balance = fetch_eth_balance(eth_account.address)
    usdt_eth_balance = fetch_erc20_balance(eth_account.address, '0xdac17f958d2ee523a2206206994597c13d831ec7')
    trx_balance = fetch_trx_balance(trx_address)
    usdt_trx_balance = fetch_trc20_balance(trx_address, 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t')

    # Define fee requirements for each asset type
    fee_reserve = {
        "eth": Decimal('0.001'),           # ETH reserve for gas
        "usdt_erc20": Decimal('0.001'),    # ETH reserve for ERC20 gas
        "trx": Decimal('1'),               # TRX reserve for TRX transaction fees
        "usdt_trc20": Decimal('29'),        # TRX reserve for TRC20 transaction fees
    }

    # Available balances after reserving fees
    balances = {
        "eth": max(Decimal(eth_balance) - fee_reserve["eth"], Decimal(0)),
        "usdt_erc20": Decimal(usdt_eth_balance),  # USDT ERC20 relies on ETH balance for gas
        "trx": max(Decimal(trx_balance) - fee_reserve["trx"], Decimal(0)),
        "usdt_trc20": max(Decimal(usdt_trx_balance) - fee_reserve["usdt_trc20"], Decimal(0)),
    }

    # Validate the asset type
    if asset_type not in balances:
        messages.error(request, "Invalid asset type.")
        return redirect('select_asset')

    # Retrieve the max amount available for the specified asset, after reserving for fees
    max_amount = balances[asset_type]

    if request.method == 'POST':
        receiver_address = request.POST.get('receiver_address')
        amount = request.POST.get('amount')

        try:
            amount = Decimal(amount)
        except:
            messages.error(request, "Invalid amount entered.")
            return redirect('send_asset', asset_type=asset_type)

        if amount > max_amount:
            messages.error(request, f"Amount exceeds available balance of {max_amount} {asset_type.upper()}, taking transaction fees into account.")
            return redirect('send_asset', asset_type=asset_type)

        try:
            # Handle sending based on asset type
            if asset_type == "eth":
                tx_hash = send_eth(private_key, receiver_address, amount)
            elif asset_type == "usdt_erc20":
                usdt_erc20_address = '0xdac17f958d2ee523a2206206994597c13d831ec7'
                tx_hash = send_erc20(private_key, receiver_address, amount, usdt_erc20_address)
            elif asset_type == "trx":
                tx_hash = send_trx(private_key, receiver_address, amount)
            elif asset_type == "usdt_trc20":
                usdt_trc20_address = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'
                tx_hash = send_trc20(private_key, receiver_address, amount, usdt_trc20_address)
            else:
                raise ValueError("Unsupported asset type")

            # Update balances in session after sending the asset
            update_session_balances(request, eth_account.address, trx_address)

            # Success message with transaction details
            messages.success(request, f"Successfully sent {amount} {asset_type.upper()} to {receiver_address}. Transaction ID: {tx_hash}")
            return redirect('main_page')

        except Exception as e:
            messages.error(request, f"An error occurred: {e}")
            return redirect('send_asset', asset_type=asset_type)

    return render(request, 'send_asset.html', {
        'asset_type': asset_type,
        'max_amount': max_amount,
    })





@login_required
def select_asset(request):
    # Fetch available assets and balances from session (or directly from user profile if preferred)
    assets = request.session.get('assets', [])
    return render(request, 'send.html', {'assets': assets})

def select_network(request):
    # Render a page with options to choose either "ETH" or "TRON"
    return render(request, 'select_network.html')




def receive_address(request, network):
    user_profile = request.user.userprofile

    # Select the appropriate address based on the network
    if network.lower() == 'eth':
        address = user_profile.eth_address  # Use Ethereum address from UserProfile
    elif network.lower() == 'tron':
        address = user_profile.tron_address  # Use TRON address from UserProfile
    else:
        return redirect('select_network')

    # Generate QR code
    qr = qrcode.make(address)
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    qr_code_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')

    # Render the template with the QR code and address
    return render(request, 'receive_address.html', {
        'network': network.upper(),
        'address': address,
        'qr_code_base64': qr_code_base64,
    })


@login_required
def asset_detail(request, name):
    # Retrieve assets from session or database
    assets = request.session.get('assets', [])
    
    # Find the specific asset by name
    asset_info = next((asset for asset in assets if asset["name"].lower() == name.lower()), None)
    
    if not asset_info:
        # If asset is not found, redirect or show an error
        return redirect('main_page')

    # Render the asset detail page with balance information
    return render(request, 'asset_detail.html', {
        'name': asset_info["name"],
        'balance': asset_info["balance"],
        'usd_value': asset_info["usd_value"],
    })


@login_required
def profile(request):
    """
    Renders the profile page for the authenticated user, including wallet and profile information.
    """
    # Fetch the authenticated user's profile
    user_profile, created = UserProfile.objects.get_or_create(user=request.user)

    # Context to pass to the template
    context = {
        "username": request.user.username,
        "wallet_address": user_profile.wallet_address,
        "eth_address": user_profile.eth_address,
        "tron_address": user_profile.tron_address,
        # Additional options for the profile page menu
        
    }

    return render(request, "profile.html", context)

import hashlib
import hmac
import time
from django.conf import settings
from django.shortcuts import redirect
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import HttpResponseBadRequest

def verify_telegram_auth(data, bot_token):
    """Verifies Telegram authentication data using SHA-256 HMAC."""
    auth_data = {k: v for k, v in data.items() if k != 'hash'}
    sorted_data_string = "\n".join(f"{k}={auth_data[k]}" for k in sorted(auth_data.keys()))
    secret_key = hashlib.sha256(bot_token.encode()).digest()
    calculated_hash = hmac.new(secret_key, sorted_data_string.encode(), hashlib.sha256).hexdigest()
    return calculated_hash == data.get('hash')

def telegram_login_callback(request):
    data = request.GET
    bot_token = settings.TELEGRAM_BOT_TOKEN

    # Verify the request is from Telegram
    if not verify_telegram_auth(data, bot_token):
        return HttpResponseBadRequest("Invalid Telegram authentication")

    # Check if the authentication data is not expired (more than 1 day old)
    auth_date = int(data.get('auth_date'))
    if time.time() - auth_date > 86400:
        return HttpResponseBadRequest("Authentication expired")

    # Extract user details from the Telegram data
    telegram_id = data.get('id')
    first_name = data.get('first_name')
    last_name = data.get('last_name', '')
    username = data.get('username')

    # Find or create a user in Django based on Telegram ID
    user, created = User.objects.get_or_create(username=f"telegram_{telegram_id}")
    if created:
        user.first_name = first_name
        user.last_name = last_name
        user.save()

    # Ensure that a UserProfile is created for the user
    user_profile, profile_created = UserProfile.objects.get_or_create(user=user)

    # Log the user in
    login(request, user)

    # Check if the wallet is already imported
    if user_profile.wallet_address and user_profile.private_key_encrypted:
        # Attempt to load wallet details automatically
        try:
            private_key = user_profile.private_key_encrypted  # Decrypt if necessary

            # Initialize Ethereum and Tron accounts
            eth_account = Web3().eth.account.from_key(private_key)
            trx_account = PrivateKey(bytes.fromhex(private_key))
            trx_address = trx_account.public_key.to_base58check_address()

            # Fetch Ethereum and Tron balances
            eth_balance = fetch_eth_balance(eth_account.address)
            usdt_eth_balance = fetch_erc20_balance(eth_account.address, '0xdac17f958d2ee523a2206206994597c13d831ec7')
            trx_balance = fetch_trx_balance(trx_address)
            usdt_trx_balance = fetch_trc20_balance(trx_address, 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t')

            # Convert balances to USD
            eth_to_usd = float(Decimal(eth_balance) * get_usd_price("ethereum"))
            usdt_eth_to_usd = float(Decimal(usdt_eth_balance) * get_usd_price("tether"))
            trx_to_usd = float(Decimal(trx_balance) * get_usd_price("tron"))
            usdt_trx_to_usd = float(Decimal(usdt_trx_balance) * get_usd_price("tether"))

            # Calculate total balance in USD
            total_balance_usd = eth_to_usd + usdt_eth_to_usd + trx_to_usd + usdt_trx_to_usd

            # Organize assets for display
            assets = [
                {"name": "ETH", "balance": float(eth_balance), "usd_value": eth_to_usd},
                {"name": "USDT_ERC20", "balance": float(usdt_eth_balance), "usd_value": usdt_eth_to_usd},
                {"name": "TRX", "balance": float(trx_balance), "usd_value": trx_to_usd},
                {"name": "USDT_TRC20", "balance": float(usdt_trx_balance), "usd_value": usdt_trx_to_usd}
            ]

            # Store wallet data in the session
            request.session['total_balance_usd'] = total_balance_usd
            request.session['assets'] = assets

            # Redirect to the main page with wallet loaded
            return redirect('main_page')

        except Exception as e:
            messages.error(request, f"Failed to load wallet: {str(e)}")
            return redirect('login')

    # If no wallet, redirect to the import wallet page
    messages.info(request, "Please import your wallet to continue.")
    return redirect('import_wallet')
