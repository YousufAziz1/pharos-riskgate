from web3 import Web3

def validate_evm_address(address: str) -> str:
    """
    Validates an EVM address and returns the checksummed version.
    Raises ValueError if the address is invalid.
    """
    if not address or not isinstance(address, str):
        raise ValueError("Address must be a non-empty string.")
    
    clean_address = address.strip()
    if not Web3.is_address(clean_address):
        raise ValueError(f"Invalid EVM address: {address}")
        
    return Web3.to_checksum_address(clean_address)
