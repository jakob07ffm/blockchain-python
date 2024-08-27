import hashlib
import time

class Block:
    def __init__(self, index, previous_hash, timestamp, data, nonce=0):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.data = data
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = f"{self.index}{self.previous_hash}{self.timestamp}{self.data}{self.nonce}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def mine_block(self, difficulty):
        while self.hash[:difficulty] != "0" * difficulty:
            self.nonce += 1
            self.hash = self.calculate_hash()

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.difficulty = 4 

    def create_genesis_block(self):
        return Block(0, "0", time.time(), "Genesis Block")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, new_block):
        new_block.previous_hash = self.get_latest_block().hash
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.hash != current_block.calculate_hash():
                print("Current Hashes do not match")
                return False

            if current_block.previous_hash != previous_block.hash:
                print("Previous Hashes do not match")
                return False

        return True

if __name__ == "__main__":
    my_blockchain = Blockchain()


    print("Mining block 1...")
    my_blockchain.add_block(Block(1, my_blockchain.get_latest_block().hash, time.time(), "Block 1 Data"))

    print("Mining block 2...")
    my_blockchain.add_block(Block(2, my_blockchain.get_latest_block().hash, time.time(), "Block 2 Data"))


    print(f"Is blockchain valid? {my_blockchain.is_chain_valid()}")

    for block in my_blockchain.chain:
        print(f"Block {block.index} [Hash: {block.hash}, Previous Hash: {block.previous_hash}, Data: {block.data}]")
