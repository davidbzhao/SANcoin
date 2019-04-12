import argparse
import rsa

def genesis(out):
    """Generate genesis block in specified file."""
    # TODO: disallow writing to bad place, for example, 'crypto.py'
    with open(out, 'w') as outfile:
        outfile.write("Now watch closely, everyone.\n"
            "I'm going to show you how to kill a god.\n"
            "A god of life and death.\n"
            "The trick is not to fear him.")


def generate(out):
    """Generate a new wallet i.e. RSA public/private keyset."""
    # TODO: disallow writing to bad place, for example, 'crypto.py'
    public_key, private_key = rsa.newkeys(1024)
    public_key_bytes = public_key.save_pkcs1(format='PEM')
    private_key_bytes = private_key.save_pkcs1(format='PEM')
    public_key_string = public_key_bytes.decode('ascii')
    private_key_string = private_key_bytes.decode('ascii')
    with open(out, 'w') as outfile:
        outfile.write(public_key_string)
        outfile.write(private_key_string)



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action')
    parser.add_argument('--out', nargs='?', default=None)
    args = parser.parse_args()

    action = args.action
    if action == 'genesis':
        if args.out == None:
            parser.error('--out must be specified')
        genesis(out=args.out)
    elif action == 'generate':
        if args.out == None:
            parser.error('--out must be specified')
        generate(out=args.out)