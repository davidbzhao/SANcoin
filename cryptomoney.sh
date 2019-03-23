#!/bin/bash

# the first command-line parameter is in $1, the second in $2, etc.

case "$1" in

    name) echo "SAN"
	  # additional parameters provided: (none)
	  ;;

    genesis) python3 crypto.py genesis --out block_0.txt
	     # additional parameters provided: (none)
             ;;

    generate) python3 crypto.py generate --out $2
	      # additional parameters provided: the wallet file name
              ;;

    address) python3 crypto.py address --wallet $2
	     # additional parameters provided: the file name of the wallet
	     ;;

    fund) python3 crypto.py fund --dest $2 --amount $3 --out $4
	  # additional parameters provided: destination wallet
	  # address, the amount, and the transaction file name
          ;;

    transfer) python3 crypto.py transfer --src $2 --dest $3 --amount $4 --out $5
	      # additional parameters provided: source wallet file
	      # name, destination address, amount, and the transaction
	      # file name
	      ;;

    balance) python3 crypto.py balance --address $2
	     # additional parameters provided: wallet address
	     ;;

    verify) python3 crypto.py verify --wallet $2 --transaction $3
	    # additional parameters provided: wallet file name,
	    # transaction file name
	    ;;

    mine) python3 crypto.py mine --difficulty $2
		 # additional parameters provided: difficulty
		 ;;
    
    validate) python3 crypto.py validate
	      # additional parameters provided: (none)
	      ;;

    *) echo Unknown function: $1
       ;;

esac