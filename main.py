import hashlib
import time
import json
from collections import OrderedDict
from ecdsa import SigningKey, VerifyingKey, SECP256k1

class Transaction:
    def __init__(self, sender, recipient, amount):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.signature = ""

    def calculate_hash(self):
        return hashlib.sha256(f"{self.sender}{self.recipient}{self.amount}".encode()).hexdigest()

    def sign_transaction(self, signing_key):
        if signing_key.verifying_key.to_string().hex() != self.sender:
            raise ValueError("You cannot sign transactions for other wallets!")
        self.signature = signing_key.sign(self.calculate_hash().encode()).hex()

    def is_valid(self):
        if self.sender == "0": 
            return True
        if not self.signature or len(self.signature) == 0:
            raise ValueError("No signature in this transaction")
        verifying_key = VerifyingKey.from_string(bytes.fromhex(self.sender), curve=SECP256k1)
        return verifying_key.verify(bytes.fromhex(self.signature), self.calculate_hash().encode())

class Block:
    def __init__(self, index, previous_hash, timestamp, transactions, nonce=0):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_content = f"{self.index}{self.previous_hash}{self.timestamp}{[t.__dict__ for t in self.transactions]}{self.nonce}"
        return hashlib.sha256(block_content.encode()).hexdigest()

    def mine_block(self, difficulty):
        while self.hash[:difficulty] != "0" * difficulty:
            self.nonce += 1
            self.hash = self.calculate_hash()

    def has_valid_transactions(self):
        for tx in self.transactions:
            if not tx.is_valid():
                return False
        return True

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.difficulty = 4
        self.pending_transactions = []
        self.mining_reward = 100

    def create_genesis_block(self):
        return Block(0, "0", time.time(), [])

    def get_latest_block(self):
        return self.chain[-1]

    def mine_pending_transactions(self, mining_reward_address):
        reward_tx = Transaction("0", mining_reward_address, self.mining_reward)
        self.pending_transactions.append(reward_tx)

        block = Block(len(self.chain), self.get_latest_block().hash, time.time(), self.pending_transactions)
        block.mine_block(self.difficulty)

        print(f"Block mined! Hash: {block.hash}")
        self.chain.append(block)

        self.pending_transactions = []

    def add_transaction(self, transaction):
        if not transaction.sender or not transaction.recipient:
            raise ValueError("Transaction must include sender and recipient")
        if not transaction.is_valid():
            raise ValueError("Cannot add invalid transaction to the chain")
        self.pending_transactions.append(transaction)

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if not current_block.has_valid_transactions():
                return False

            if current_block.hash != current_block.calculate_hash():
                print("Current Hashes do not match")
                return False

            if current_block.previous_hash != previous_block.hash:
                print("Previous Hashes do not match")
                return False

        return True


def create_wallet():
    private_key = SigningKey.generate(curve=SECP256k1)
    public_key = private_key.verifying_key
    return private_key, public_key


if __name__ == "__main__":

    private_key_1, public_key_1 = create_wallet()
    private_key_2, public_key_2 = create_wallet()

    my_blockchain = Blockchain()

    tx1 = Transaction(public_key_1.to_string().hex(), public_key_2.to_string().hex(), 10)
    tx1.sign_transaction(private_key_1)
    my_blockchain.add_transaction(tx1)


    print("Mining pending transactions...")
    my_blockchain.mine_pending_transactions(public_key_1.to_string().hex())

    print(f"Is blockchain valid? {my_blockchain.is_chain_valid()}")

    for block in my_blockchain.chain:
        print(f"Block {block.index} [Hash: {block.hash}, Previous Hash: {block.previous_hash}, Transactions: {json.dumps([t.__dict__ for t in block.transactions], indent=2)}]")
