import argparse
import binascii
import datetime
import hashlib
import json

import rsa


LEDGER_FILEPATH = 'test/ledger.txt'
SPECIAL_ID = 'ashitaka'


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
    with open(LEDGER_FILEPATH, 'a') as outfile:
        outfile.write('{} transferred {} to {} on {}\n'.format(
            transaction['from'],
            transaction['amount'],
            transaction['to'],
            transaction['date']
            ))


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


def balance(wallet_filepath):
    """Compute the available balance of a wallet."""
    return 1000000


def verify(wallet_filepath, transaction_filepath):
    """Verify transaction with given wallet credentials."""
    def is_valid_transaction(transaction):        
        if not (0 < transaction['amount'] <= balance(wallet_filepath)):
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


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action')
    parser.add_argument('--wallet', nargs='?', default=None, help='Wallet filepath')
    parser.add_argument('--transaction', nargs='?', default=None, help='Transaction filepath')
    parser.add_argument('--src', nargs='?', default=None, help='Source wallet filepath')
    parser.add_argument('--dest', nargs='?', default=None, help='Destination wallet address')
    parser.add_argument('--out', nargs='?', default=None, help='Out file path')
    parser.add_argument('--amount', nargs='?', default=None, type=int, help='Amount to be transferred')
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
        if args.wallet == None:
            parser.error('--wallet must be specified')
        balance(wallet_filepath=args.wallet)
    elif action == 'verify':
        if args.wallet == None:
            parser.error('--wallet must be specified')
        if args.transaction == None:
            parser.error('--transaction must be specified')
        verify(wallet_filepath=args.wallet, transaction_filepath=args.transaction)
