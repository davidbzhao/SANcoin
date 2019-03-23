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
    """Generate genesis block in specified file.

    Args:
        outfilepath (str): Location to write genesis block
    """
    with open(outfilepath, 'w') as outfile:
        outfile.write("Now watch closely, everyone.\n"
                      "I'm going to show you how to kill a god.\n"
                      "A god of life and death.\n"
                      "The trick is not to fear him.")


def generate(outfilepath):
    """Generate a new wallet i.e. RSA public/private keyset.

    Args:
        outfilepath (str): Location to write wallet file  

    Returns:
        str: The wallet address.
    """
    public_key, private_key = rsa.newkeys(1024)
    public_key_bytes = public_key.save_pkcs1(format='PEM')
    private_key_bytes = private_key.save_pkcs1(format='PEM')
    public_key_string = public_key_bytes.decode('ascii')
    private_key_string = private_key_bytes.decode('ascii')
    with open(outfilepath, 'w') as outfile:
        outfile.write(public_key_string)
        outfile.write(private_key_string)
    return address(outfilepath)


def address(wallet_filepath):
    """Compute the shortened hash of wallet's public key.

    Args:
        wallet_filepath (str): Path to wallet  

    Returns:
        str: The wallet address.
    """
    if not os.path.isfile(wallet_filepath):
        return None

    with open(wallet_filepath, 'r') as infile:
        data = infile.read()
        public_key = rsa.PublicKey.load_pkcs1(data)
        public_key_bytes = public_key.save_pkcs1(format='PEM')

        hex_hash_string = hash_bytes(public_key_bytes).decode('ascii')
        wallet_address = hex_hash_string[:16]
    return wallet_address


def fund(dest_wallet_addr, amount, outfilepath):
    """Add some amount of value to a wallet.

    Args:
        dest_wallet_addr (str): Address of receiving wallet
        amount (int): Address of wallet
        outfilepath (str): Location to write transaction file  

    Returns:
        obj: The transaction object.
    """
    return transfer(SPECIAL_ID, dest_wallet_addr, amount, outfilepath)


def transfer(src_wallet_filepath, dest_wallet_addr, amount, outfilepath):
    """Transfer some amount of value from one wallet to another.

    Args:
        src_wallet_filepath (str): Path to sending wallet
        dest_wallet_addr (str): Address of receiving wallet
        amount (int): Address of wallet
        outfilepath (str): Location to write transaction file  

    Returns:
        obj: The transaction object.
    """
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
    return transaction


def balance(wallet_addr):
    """Compute the available balance of a wallet.

    Args:
        wallet_addr (str): Address of wallet

    Returns:
        int: The current value of wallet.
    """
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
    """Verify transaction with given wallet credentials.

    Args:
        wallet_filepath (str): Path to wallet
        transaction_filepath (str): Path to transaction  

    Returns:
        bool: If the transaction was successfully verified.
    """
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

    if not os.path.isfile(wallet_filepath) and wallet_filepath != SPECIAL_ID:
        return False
    if not os.path.isfile(transaction_filepath):
        return False
    with open(transaction_filepath, 'r') as infile:
        transaction = json.load(infile)
    if wallet_filepath == SPECIAL_ID or is_valid_transaction(transaction):
        add_transaction_to_ledger(transaction)
        return True
    return False


def validate():
    """Check the hashes of each block in the chain.

    Returns:
        int: The number of the first block that has an inconsistent hash.

        If there is no faulty blocks, then return -1. An inconsistent hash
        is one that does not match the hash of the previous block.
    """
    def compute_hash_of_block(block_number):
        block_filepath = 'block_{}.txt'.format(block_number)
        with open(block_filepath, 'r') as infile:
            computed_hash = hash_string(infile.read())
        return computed_hash

    def get_recorded_hash_in_block(block_number):
        block_filepath = 'block_{}.txt'.format(block_number)
        with open(block_filepath, 'r') as infile:
            recorded_hash = infile.readline().strip()
        return recorded_hash

    def does_block_exist(block_number):
        block_filepath = 'block_{}.txt'.format(block_number)
        return os.path.isfile(block_filepath)

    block_number = 0
    while True:
        if block_number > 0:
            if not does_block_exist(block_number):
                break
            recorded_hash = get_recorded_hash_in_block(block_number)
            computed_hash = compute_hash_of_block(block_number - 1)
            if computed_hash != recorded_hash:
                return block_number
        block_number += 1
    return -1


def mine(difficulty):
    """Clear ledger by finding nonce and creating block.

    Args:
        difficulty (int): The number of leading zeros the nonce
        must have.

    Returns:
        str: The hash of the newly-created block.
    """
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
        for nonce in range(2**64 - 1):
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

    if is_ledger_empty():
        return None

    prev_block_number = get_previous_block_number()
    prev_block_filepath = 'block_{}.txt'.format(prev_block_number)
    prev_block_hash = get_block_hash(prev_block_filepath)
    ledger_contents = get_ledger_contents()

    next_block_number = prev_block_number + 1
    next_block_filepath = 'block_{}.txt'.format(next_block_number)
    next_block_contents = prev_block_hash + '\n' + ledger_contents + '\n'
    next_block_contents = add_nonce(next_block_contents, difficulty)
    next_block_hash = hash_string(next_block_contents)

    write_block(next_block_filepath, next_block_contents)
    clear_ledger()
    return next_block_hash


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action')
    parser.add_argument('--wallet', nargs='?',
                        default=None, help='Wallet filepath')
    parser.add_argument('--address', nargs='?',
                        default=None, help='Wallet address')
    parser.add_argument('--transaction', nargs='?',
                        default=None, help='Transaction filepath')
    parser.add_argument('--src', nargs='?', default=None,
                        help='Source wallet filepath')
    parser.add_argument('--dest', nargs='?', default=None,
                        help='Destination wallet address')
    parser.add_argument('--out', nargs='?', default=None, help='Out file path')
    parser.add_argument('--amount', nargs='?', default=None,
                        type=int, help='Amount to be transferred')
    parser.add_argument('--difficulty', nargs='?', default=None,
                        type=int, help='Difficulty setting for mining')
    args = parser.parse_args()

    action = args.action
    if action == 'genesis':
        if args.out == None:
            parser.error('--out must be specified')
        genesis(outfilepath=args.out)
        print('[SUCCESS] In the beginning God created the heaven and the earth... and we created a cryptocurrency.')
    elif action == 'generate':
        if args.out == None:
            parser.error('--out must be specified')
        wallet_addr = generate(outfilepath=args.out)
        print('[SUCCESS] A wild WALLET ({}) has appeared!'.format(wallet_addr))
    elif action == 'address':
        if args.wallet == None:
            parser.error('--wallet must be specified')
        addr = address(wallet_filepath=args.wallet)
        if addr:
            print(addr)
        else:
            print('[FAILURE] Wallet ({}) not found'.format(args.wallet))
    elif action == 'fund':
        if args.dest == None:
            parser.error('--dest must be specified')
        if args.out == None:
            parser.error('--out must be specified')
        if args.amount == None:
            parser.error('--amount must be specified')
        transaction = fund(args.dest, args.amount, args.out)
        print(
            '[SUCCESS] [{date}] {from} ---({amount} SAN)--> {to}'.format(**transaction))
    elif action == 'transfer':
        if args.src == None:
            parser.error('--src must be specified')
        if args.dest == None:
            parser.error('--dest must be specified')
        if args.out == None:
            parser.error('--out must be specified')
        if args.amount == None:
            parser.error('--amount must be specified')
        transaction = transfer(args.src, args.dest, args.amount, args.out)
        print(
            '[SUCCESS] [{date}] {from} ---({amount} SAN)--> {to}'.format(**transaction))
    elif action == 'balance':
        if args.address == None:
            parser.error('--address must be specified')
        print(balance(wallet_addr=args.address))
    elif action == 'verify':
        if args.wallet == None:
            parser.error('--wallet must be specified')
        if args.transaction == None:
            parser.error('--transaction must be specified')
        verified = verify(wallet_filepath=args.wallet,
                          transaction_filepath=args.transaction)
        if verified:
            print('[SUCCESS] LGTM! The transaction ({}) is now part of the ledger ({})'.format(
                args.transaction, LEDGER_FILEPATH))
        else:
            print('[FAILURE] Uh oh! The transaction ({}) could not be verified with the wallet ({})'.format(
                args.transaction, args.wallet))
    elif action == 'mine':
        if args.difficulty == None:
            parser.error('--difficulty must be specified')
        block_hash = mine(difficulty=args.difficulty)
        if block_hash:
            print('[SUCCESS] The hash ({}...{}) does indeed start with {} zeros'.format(
                block_hash[:8],
                block_hash[-8:],
                args.difficulty
            ))
        else:
            print(
                '[FAILURE] The ledger was empty, let\'s all save some electricity and not go mining.')
    elif action == 'validate':
        broken_block_number = validate()
        if broken_block_number == -1:
            print('[SUCCESS] Blocks are chained.')
        else:
            print('[FAILURE] The hash in block #{} does not equal the hash of the previous block.'.format(
                broken_block_number))
