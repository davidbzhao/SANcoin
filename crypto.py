import argparse

def genesis(out):
    """Generate genesis block in specified file."""
    # TODO: disallow writing to bad place, for example, 'crypto.py'
    with open(out, 'w') as outfile:
        outfile.write("Now watch closely, everyone.\n"
            "I'm going to show you how to kill a god.\n"
            "A god of life and death.\n"
            "The trick is not to fear him.")


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