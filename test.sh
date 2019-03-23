#!/bin/bash

mkdir -p test
rm test/*
rm block_*
./cryptomoney.sh name
./cryptomoney.sh genesis block_0.txt
./cryptomoney.sh generate test/alice.wallet
./cryptomoney.sh generate test/bob.wallet
./cryptomoney.sh generate test/charlie.wallet
./cryptomoney.sh generate test/david.wallet
ALICE=$(./cryptomoney.sh address test/alice.wallet)
BOB=$(./cryptomoney.sh address test/bob.wallet)
CHARLIE=$(./cryptomoney.sh address test/charlie.wallet)
DAVID=$(./cryptomoney.sh address test/david.wallet)
ECHO=$(./cryptomoney.sh address test/echo.wallet)

./cryptomoney.sh fund $ALICE 200 test/transaction1.1.txt
./cryptomoney.sh fund $BOB 100 test/transaction1.2.txt
./cryptomoney.sh fund $BOB 100 test/transaction1.3.txt
./cryptomoney.sh fund $CHARLIE 0 test/transaction1.4.txt
./cryptomoney.sh fund $CHARLIE 1000 test/transaction1.5.txt
./cryptomoney.sh fund $DAVID 200 test/transaction1.6.txt

# A200 B200 C1000 D200
./cryptomoney.sh transfer test/alice.wallet $BOB 25 test/transaction2.1.txt
# A175 B225 C1000 D200
./cryptomoney.sh transfer test/alice.wallet $CHARLIE 25 test/transaction2.2.txt
# A150 B225 C1025 D200
./cryptomoney.sh transfer test/alice.wallet $DAVID 2500 test/transaction2.3.txt
./cryptomoney.sh transfer test/alice.wallet $DAVID -25 test/transaction2.4.txt
./cryptomoney.sh transfer test/alice.wallet $DAVID 0 test/transaction2.5.txt
# A150 B225 C1025 D200

./cryptomoney.sh balance $ALICE
./cryptomoney.sh balance $BOB
./cryptomoney.sh balance $CHARLIE
./cryptomoney.sh balance $DAVID

./cryptomoney.sh verify ashitaka test/transaction1.1.txt
./cryptomoney.sh verify test/alice.wallet test/transaction1.2.txt  # wrong source wallet
./cryptomoney.sh verify test/anything.wallet test/transaction1.3.txt  # nonexistent wallet
./cryptomoney.sh verify ashitaka test/transaction1.3.txt
./cryptomoney.sh verify ashitaka test/transaction1.4.txt
./cryptomoney.sh verify ashitaka test/transaction1.5.txt
./cryptomoney.sh verify ashitaka test/transaction1.6.txt
./cryptomoney.sh verify ashitaka test/transaction1.7.txt  # nonexistent transaction

./cryptomoney.sh verify test/bob.wallet test/transaction2.1.txt  # wrong wallet
./cryptomoney.sh verify test/anything.wallet test/transaction2.1.txt  # nonexistent wallet
./cryptomoney.sh verify test/bob.wallet test/transaction2.11235.txt  # nonexistent transaction
./cryptomoney.sh verify test/alice.wallet test/transaction2.1.txt
./cryptomoney.sh verify test/alice.wallet test/transaction2.2.txt
./cryptomoney.sh verify test/alice.wallet test/transaction2.3.txt
./cryptomoney.sh verify test/alice.wallet test/transaction2.4.txt
./cryptomoney.sh verify test/alice.wallet test/transaction2.5.txt

./cryptomoney.sh mine 4

./cryptomoney.sh balance $ALICE
./cryptomoney.sh balance $BOB
./cryptomoney.sh balance $CHARLIE
./cryptomoney.sh balance $DAVID

./cryptomoney.sh validate

# A150 B225 C1025 D200

### Send money to self
./cryptomoney.sh transfer test/alice.wallet $ALICE 0 test/transaction3.1.txt
./cryptomoney.sh transfer test/alice.wallet $ALICE 150 test/transaction3.2.txt
./cryptomoney.sh transfer test/alice.wallet $ALICE 125 test/transaction3.3.txt
./cryptomoney.sh transfer test/alice.wallet $ALICE 1000 test/transaction3.4.txt
./cryptomoney.sh transfer test/alice.wallet $ALICE -1000 test/transaction3.5.txt

./cryptomoney.sh verify test/alice.wallet test/transaction3.1.txt
./cryptomoney.sh verify test/alice.wallet test/transaction3.2.txt
./cryptomoney.sh verify test/alice.wallet test/transaction3.3.txt
./cryptomoney.sh verify test/alice.wallet test/transaction3.4.txt
./cryptomoney.sh verify test/alice.wallet test/transaction3.5.txt

./cryptomoney.sh mine 5

# A150 B225 C1025 D200
head -n 1 block_2.txt
sha256sum block_1.txt
