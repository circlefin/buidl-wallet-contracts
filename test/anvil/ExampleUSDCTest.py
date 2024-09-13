import unittest
from BaseTest import BaseTest

class ExampleUsdcTest(BaseTest):
    def test_minting(self):
        usdc_minter_credentials = self.generate_new_credentials()

        # Deploy USDC Contract
        usdc_contract = self.deploy_usdc_contract(usdc_minter_credentials)
        temp_credentials = self.generate_new_credentials()

        # Mint 10 USDC to temporary address
        self.build_contract_transaction(
            usdc_contract.functions.mint(temp_credentials.address, 10),
            usdc_minter_credentials
        )

        # Verify the mint was success
        assert usdc_contract.functions.balanceOf(temp_credentials.address).call() == 10

if __name__ == '__main__':
    unittest.main()
