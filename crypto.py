import argparse
import binascii
import datetime
import glob
import hashlib
import json
import os
import sys

import rsa

LEDGER_FILEPATH = 'test/ledger.txt'
SPECIAL_ID = 'ashitaka'


def hash_string(message):
    """Produce SHA-256 hash as hex string of given string."""
    return hash_bytes(message.encode('ascii')).decode('ascii')


def hash_bytes(byte_string):
    """Produce SHA-256 hash in hex of given byte string."""
    hasher = hashlib.sha256()
    hasher.update(byte_string)
    hex_hash = binascii.hexlify(hasher.digest())
    return hex_hash


def sign_string(message, private_key):
    """Get encrypted hash of message string."""
    message_bytes = message.encode('ascii')
    hex_hash_bytes = hash_bytes(message_bytes)
    encoded_signature = rsa.sign(hex_hash_bytes, private_key, 'SHA-256')
    hex_signature_string = binascii.hexlify(encoded_signature).decode('ascii')
    return hex_signature_string


def verify_signature(message, signature, public_key):
    """Verify signature of message string given signature string."""
    message_bytes = message.encode('ascii')
    hex_hash_bytes = hash_bytes(message_bytes)
    signature_bytes = signature.encode('ascii')
    signature_encoded = binascii.a2b_hex(signature_bytes)
    rsa.verify(hex_hash_bytes, signature_encoded, public_key)


def get_keys_from_file(infilepath):
    """Get RSA keyset from file."""
    with open(infilepath, 'r') as infile:
        data = infile.read()
        public_key = rsa.PublicKey.load_pkcs1(data)
        private_key = rsa.PrivateKey.load_pkcs1(data)
    return public_key, private_key



def add_transaction_to_ledger(transaction):
    """Write transaction record to ledger from transaction object."""
    transaction.pop('signature', None)
    with open(LEDGER_FILEPATH, 'a') as outfile:
        outfile.write(json.dumps(transaction, sort_keys=True) + '\n')


def genesis(outfilepath):
    """Generate genesis block in specified file."""
    # TODO: disallow writing to bad place, for example, 'crypto.py'
    with open(outfilepath, 'w') as outfile:
        outfile.write("Now watch closely, everyone.\n"
            "I'm going to show you how to kill a god.\n"
            "A god of life and death.\n"
            "The trick is not to fear him.")


def generate(outfilepath):
    """Generate a new wallet i.e. RSA public/private keyset."""
    # TODO: disallow writing to bad place, for example, 'crypto.py'
    public_key, private_key = rsa.newkeys(1024)
    public_key_bytes = public_key.save_pkcs1(format='PEM')
    private_key_bytes = private_key.save_pkcs1(format='PEM')
    public_key_string = public_key_bytes.decode('ascii')
    private_key_string = private_key_bytes.decode('ascii')
    with open(outfilepath, 'w') as outfile:
        outfile.write(public_key_string)
        outfile.write(private_key_string)



def address(wallet_filepath):
    """Return address of wallet."""
    with open(wallet_filepath, 'r') as infile:
        data = infile.read()
        public_key = rsa.PublicKey.load_pkcs1(data)
        public_key_bytes = public_key.save_pkcs1(format='PEM')

        hex_hash_string = hash_bytes(public_key_bytes).decode('ascii')
        wallet_address = hex_hash_string[:16]
    return wallet_address


def fund(dest_wallet_addr, amount, outfilepath):
    """Add some amount of value to a wallet."""
    return transfer(SPECIAL_ID, dest_wallet_addr, amount, outfilepath)


def transfer(src_wallet_filepath, dest_wallet_addr, amount, outfilepath):
    """Transfer some amount of value from one wallet to another."""
    transaction = {
        'from': SPECIAL_ID,
        'to': dest_wallet_addr,
        'amount': amount,
        'date': datetime.datetime.now().ctime()
    }
    if src_wallet_filepath == SPECIAL_ID:
        transaction['signature'] = 'Save the forest'
    else:
        transaction['from'] = address(src_wallet_filepath)
        _, private_key = get_keys_from_file(src_wallet_filepath)
        transaction_string = json.dumps(transaction, sort_keys=True)
        transaction['signature'] = sign_string(transaction_string, private_key)

    with open(outfilepath, 'w') as outfile:
        outfile.write(json.dumps(transaction, indent=4, sort_keys=True))


def balance(wallet_addr):
    """Compute the available balance of a wallet."""
    balance = 0

    filepaths_to_check = glob.glob('block_*[1-9]*.txt')  # except block_0.txt
    if os.path.isfile(LEDGER_FILEPATH):
        filepaths_to_check.append(LEDGER_FILEPATH)

    for filepath in filepaths_to_check:
        with open(filepath, 'r') as infile:
            for line in infile.readlines():
                if line[0] != '{':
                    continue

                transaction = json.loads(line)
                amount = transaction['amount']
                # If you want to send money to yourself, go for it
                if transaction['from'] == wallet_addr:
                    balance -= amount
                if transaction['to'] == wallet_addr:
                    balance += amount
    return balance


def verify(wallet_filepath, transaction_filepath):
    """Verify transaction with given wallet credentials."""
    def is_valid_transaction(transaction):
        if transaction['from'] == SPECIAL_ID:
            return True

        wallet_addr = address(wallet_filepath)
        if not (0 < transaction['amount'] <= balance(wallet_addr)):
            return False

        public_key, _ = get_keys_from_file(wallet_filepath)
        signature = transaction.pop('signature', None)
        transaction_string = json.dumps(transaction, sort_keys=True)
        try:
            verify_signature(transaction_string, signature, public_key)
        except rsa.pkcs1.VerificationError as e:
            return False
        return True
    
    with open(transaction_filepath, 'r') as infile:
        transaction = json.load(infile)
    if wallet_filepath == SPECIAL_ID or is_valid_transaction(transaction):
        add_transaction_to_ledger(transaction)


def mine(difficulty):
    """Clear ledger by finding nonce and creating block."""
    def is_ledger_empty():
        with open(LEDGER_FILEPATH, 'r') as infile:
            return infile.read().strip() == ''

    def get_previous_block_number():
        block_filepaths = glob.glob('block_*.txt')
        max_block_number = -1
        for filepath in block_filepaths:
            block_number = int(filepath[len('block_'):-len('.txt')])
            if block_number > max_block_number:
                max_block_number = block_number
        return max_block_number

    def get_block_hash(block_filepath):
        with open(block_filepath, 'r') as infile:
            prev_block = infile.read()
            prev_block_hash = hash_string(prev_block)
        return prev_block_hash

    def get_ledger_contents():
        with open(LEDGER_FILEPATH, 'r') as infile:
            return infile.read().strip()

    def add_nonce(next_block_contents, difficulty):
        for nonce in range(2**64-1):
            new_block = next_block_contents + str(nonce)
            new_block_hash = hash_string(new_block)
            if new_block_hash[:difficulty] == '0' * difficulty:
                return new_block
        return None

    def write_block(filepath, contents):
        with open(filepath, 'w') as outfile:
            outfile.write(contents)

    def clear_ledger():
        open(LEDGER_FILEPATH, 'w').close()

    if not is_ledger_empty():
        prev_block_number = get_previous_block_number()
        prev_block_filepath = 'block_{}.txt'.format(prev_block_number)
        prev_block_hash = get_block_hash(prev_block_filepath)
        ledger_contents = get_ledger_contents()
        
        next_block_number = prev_block_number + 1
        next_block_filepath = 'block_{}.txt'.format(next_block_number)
        next_block_contents = prev_block_hash + '\n' + ledger_contents + '\n'
        next_block_contents = add_nonce(next_block_contents, difficulty)
        
        write_block(next_block_filepath, next_block_contents)
        clear_ledger()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action')
    parser.add_argument('--wallet', nargs='?', default=None, help='Wallet filepath')
    parser.add_argument('--address', nargs='?', default=None, help='Wallet address')
    parser.add_argument('--transaction', nargs='?', default=None, help='Transaction filepath')
    parser.add_argument('--src', nargs='?', default=None, help='Source wallet filepath')
    parser.add_argument('--dest', nargs='?', default=None, help='Destination wallet address')
    parser.add_argument('--out', nargs='?', default=None, help='Out file path')
    parser.add_argument('--amount', nargs='?', default=None, type=int, help='Amount to be transferred')
    parser.add_argument('--difficulty', nargs='?', default=None, type=int, help='Difficulty setting for mining')
    args = parser.parse_args()

    action = args.action
    if action == 'genesis':
        if args.out == None:
            parser.error('--out must be specified')
        genesis(outfilepath=args.out)
    elif action == 'generate':
        if args.out == None:
            parser.error('--out must be specified')
        generate(outfilepath=args.out)
    elif action == 'address':
        if args.wallet == None:
            parser.error('--wallet must be specified')
        addr = address(wallet_filepath=args.wallet)
        print(addr)
    elif action == 'fund':
        if args.dest == None:
            parser.error('--dest must be specified')
        if args.out == None:
            parser.error('--out must be specified')
        if args.amount == None:
            parser.error('--amount must be specified')
        fund(args.dest, args.amount, args.out)
    elif action == 'transfer':
        if args.src == None:
            parser.error('--src must be specified')
        if args.dest == None:
            parser.error('--dest must be specified')
        if args.out == None:
            parser.error('--out must be specified')
        if args.amount == None:
            parser.error('--amount must be specified')
        transfer(args.src, args.dest, args.amount, args.out)
    elif action == 'balance':
        if args.address == None:
            parser.error('--address must be specified')
        print(balance(wallet_addr=args.address))
    elif action == 'verify':
        if args.wallet == None:
            parser.error('--wallet must be specified')
        if args.transaction == None:
            parser.error('--transaction must be specified')
        verify(wallet_filepath=args.wallet, transaction_filepath=args.transaction)
    elif action == 'mine':
        if args.difficulty == None:
            parser.error('--difficulty must be specified')
        mine(difficulty=args.difficulty)
