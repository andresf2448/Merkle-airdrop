
.PHONY: install

i_foundry:; forge init --force

i_chainlink:; forge install smartcontractkit/chainlink-brownie-contracts

i_solmate:; forge install transmissions11/solmate

i_foundry_dev:; forge install Cyfrin/foundry-devops

i_openzeppelin:; forge install openzeppelin/openzeppelin-contracts

i_chainlinkKit:; forge install smartcontractkit/ccip

i_chainlinkLocal:; forge install smartcontractkit/chainlink-local

#  Merkle Tree Generation with Foundry and Murky
i_murky:; forge install dmfxyz/murky
