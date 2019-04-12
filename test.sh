#!/bin/bash

rm test/*
mkdir test
./cryptomoney.sh genesis block_0.txt
./cryptomoney.sh generate test/alice.wallet
./cryptomoney.sh generate test/bob.wallet
ALICE=$(./cryptomoney.sh address test/alice.wallet)
BOB=$(./cryptomoney.sh address test/bob.wallet)
./cryptomoney.sh fund $ALICE 200 test/transaction1.txt
./cryptomoney.sh fund $BOB 100 test/transaction2.txt
./cryptomoney.sh transfer test/alice.wallet $BOB 25 test/transaction3.txt
./cryptomoney.sh balance $ALICE
./cryptomoney.sh balance $BOB
./cryptomoney.sh verify ashitaka test/transaction1.txt
./cryptomoney.sh verify test/alice.wallet test/transaction2.txt
./cryptomoney.sh verify test/alice.wallet test/transaction3.txt
