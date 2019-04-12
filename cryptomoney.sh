#!/bin/bash

# the first command-line parameter is in $1, the second in $2, etc.

case "$1" in

    name) echo "SAN"
	  # additional parameters provided: (none)
	  ;;

    genesis) python3 crypto.py genesis --out block_0.txt
	     # additional parameters provided: (none)
             ;;

    generate) echo "generate"
	      # additional parameters provided: the wallet file name
              ;;

    address) echo "address"
	     # additional parameters provided: the file name of the wallet
	     ;;

    fund) echo "fund"
	  # additional parameters provided: destination wallet
	  # address, the amount, and the transaction file name
          ;;

    transfer) echo "transfer"
	      # additional parameters provided: source wallet file
	      # name, destination address, amount, and the transaction
	      # file name
	      ;;

    balance) echo "balance"
	     # additional parameters provided: wallet address
	     ;;

    verify) echo "verify"
	    # additional parameters provided: wallet file name,
	    # transaction file name
	    ;;

    mine) echo "mine"
		 # additional parameters provided: difficulty
		 ;;
    
    validate) echo "validate"
	      # additional parameters provided: (none)
	      ;;

    *) echo Unknown function: $1
       ;;

esac