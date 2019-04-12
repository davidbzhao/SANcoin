import argparse
import binascii
import hashlib
import rsa


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

        hasher = hashlib.sha256()
        hasher.update(public_key_bytes)
        hex_hash = binascii.hexlify(hasher.digest())
        hex_hash_string = hex_hash.decode('ascii')
        wallet_address = hex_hash_string[:16]
    return wallet_address        


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action')
    parser.add_argument('--wallet', nargs='?', default=None, help='Wallet file path')
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
        pass