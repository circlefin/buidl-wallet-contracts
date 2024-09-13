.PHONY: build test anvil anvil-test clean abigen

FOUNDRY := docker run -m 12g --rm foundry
ANVIL 	:= docker run -d -p 8545:8545 --name anvil --rm foundry

build:
	docker build -f Dockerfile -m 12g -t foundry .

test:
	forge test -vv

anvil:
	docker rm -f anvil 2> /dev/null || true
	@${ANVIL} "anvil --host 0.0.0.0 --code-size-limit 250000 --balance 1000000"

anvil-test: anvil
	pip3 install -r requirements.txt
	python3 test/anvil/ExampleUSDCTest.py

clean:
	@${FOUNDRY} "forge clean"

abigen:
	@sh abigen.sh go_abigen
	@sh abigen.sh ts_abigen
