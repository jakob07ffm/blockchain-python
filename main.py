import hashlib
import time
import json
import pickle
import random
import sqlite3
import requests
from collections import OrderedDict
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from flask import Flask, jsonify, request, abort
from threading import Thread
from queue import Queue

class BlockchainDB:
    def __init__(self, db_name="blockchain.db"):
        self.conn = sqlite3.connect(db_name)
        self.create_tables()

    def create_tables(self):
        with self.conn:
            self.conn.execute('''CREATE TABLE IF NOT EXISTS blocks
                                 (index INTEGER PRIMARY KEY, previous_hash TEXT, timestamp REAL, 
                                 merkle_root TEXT, nonce INTEGER, hash TEXT, difficulty INTEGER)''')
            self.conn.execute('''CREATE TABLE IF NOT EXISTS transactions
                                 (tx_id TEXT PRIMARY KEY, sender TEXT, recipient TEXT, amount REAL, 
                                 fee REAL, signature TEXT, block_index INTEGER, FOREIGN KEY(block_index) REFERENCES blocks(index))''')

    def save_block(self, block):
        with self.conn:
            self.conn.execute('''INSERT INTO blocks (index, previous_hash, timestamp, merkle_root, nonce, hash, difficulty)
                                 VALUES (?, ?, ?, ?, ?, ?, ?)''', 
                                 (block.index, block.previous_hash, block.timestamp, block.merkle_root, block.nonce, block.hash, block.difficulty))
            for tx in block.transactions:
                self.conn.execute('''INSERT INTO transactions (tx_id, sender, recipient, amount, fee, signature, block_index)
                                     VALUES (?, ?, ?, ?, ?, ?, ?)''', 
                                     (tx.calculate_hash(), tx.sender, tx.recipient, tx.amount, tx.fee, tx.signature, block.index))

    def load_blocks(self):
        cursor = self.conn.cursor()
        cursor.execute('''SELECT * FROM blocks ORDER BY index''')
        blocks = cursor.fetchall()
        return blocks

    def get_transactions_by_address(self, address):
        cursor = self.conn.cursor()
        cursor.execute('''SELECT * FROM transactions WHERE sender = ? OR recipient = ?''', (address, address))
        transactions = cursor.fetchall()
        return transactions

class MerkleTree:
    def __init__(self, transactions):
        self.transactions = transactions
        self.root = self.build_merkle_tree(transactions)

    def build_merkle_tree(self, transactions):
        if len(transactions) == 1:
            return self.calculate_hash(transactions[0])

        new_level = []
        for i in range(0, len(transactions), 2):
            left = transactions[i]
            right = transactions[i + 1] if i + 1 < len(transactions) else left
            new_level.append(self.calculate_hash(left + right))

        return self.build_merkle_tree(new_level)

    @staticmethod
    def calculate_hash(data):
        return hashlib.sha256(data.encode()).hexdigest()

class SmartContract:
    def __init__(self, script):
        self.script = script

    def execute(self, variables):
        exec(self.script, {}, variables)

class Transaction:
    def __init__(self, sender, recipient, amount, fee=0, contract=None):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.fee = fee
        self.contract = contract  
        self.signature = ""

    def calculate_hash(self):
        return hashlib.sha256(f"{self.sender}{self.recipient}{self.amount}{self.fee}{self.contract}".encode()).hexdigest()

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

    def execute_contract(self):
        if self.contract:
            variables = {'amount': self.amount, 'sender': self.sender, 'recipient': self.recipient}
            self.contract.execute(variables)
            self.recipient = variables['recipient']
            self.amount = variables['amount']

class Block:
    def __init__(self, index, previous_hash, timestamp, transactions, nonce=0, difficulty=4):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.merkle_root = MerkleTree([t.calculate_hash() for t in transactions]).root
        self.nonce = nonce
        self.hash = self.calculate_hash()
        self.difficulty = difficulty

    def calculate_hash(self):
        block_content = f"{self.index}{self.previous_hash}{self.timestamp}{self.merkle_root}{self.nonce}{self.difficulty}"
        return hashlib.sha256(block_content.encode()).hexdigest()

    def mine_block(self):
        while self.hash[:self.difficulty] != "0" * self.difficulty:
            self.nonce += 1
            self.hash = self.calculate_hash()

    def has_valid_transactions(self):
        for tx in self.transactions:
            if not tx.is_valid():
                return False
            if tx.contract:
                tx.execute_contract()
        return True

class Wallet:
    def __init__(self):
        self.private_key, self.public_key = self.create_wallet()
        self.balance = 0
        self.history = []

    @staticmethod
    def create_wallet():
        private_key = SigningKey.generate(curve=SECP256k1)
        public_key = private_key.verifying_key
        return private_key, public_key

    def sign_transaction(self, transaction):
        transaction.sign_transaction(self.private_key)

    def add_to_history(self, transaction):
        self.history.append(transaction)

class MultiSigWallet(Wallet):
    def __init__(self, owners, required_signatures):
        self.owners = owners
        self.required_signatures = required_signatures
        self.signatures = []
        self.balance = 0
        self.history = []

    def sign_transaction(self, transaction, signing_key):
        if signing_key.verifying_key.to_string().hex() not in self.owners:
            raise ValueError("This key is not an owner of the wallet!")
        signature = signing_key.sign(transaction.calculate_hash().encode()).hex()
        if signature not in self.signatures:
            self.signatures.append(signature)

        if len(self.signatures) >= self.required_signatures:
            transaction.signature = ','.join(self.signatures)

class Blockchain:
    def __init__(self, db_name="blockchain.db"):
        self.chain = [self.create_genesis_block()]
        self.difficulty = 4
        self.pending_transactions = []
        self.mining_reward = 100
        self.network = P2PNetwork()
        self.wallets = {}
        self.db = BlockchainDB(db_name)

    def create_genesis_block(self):
        return Block(0, "0", time.time(), [])

    def get_latest_block(self):
        return self.chain[-1]

    def add_wallet(self, wallet_address, wallet):
        self.wallets[wallet_address] = wallet

    def get_wallet_balance(self, wallet_address):
        balance = 0
        transactions = self.db.get_transactions_by_address(wallet_address)
        for tx in transactions:
            if tx[1] == wallet_address:
                balance -= (tx[3] + tx[4])
            if tx[2] == wallet_address:
                balance += tx[3]
        return balance

    def add_transaction(self, transaction):
        if not transaction.sender or not transaction.recipient:
            raise ValueError("Transaction must include sender and recipient")
        if not transaction.is_valid():
            raise ValueError("Cannot add invalid transaction to the chain")
        self.pending_transactions.append(transaction)
        self.network.broadcast_transaction(transaction)

    def mine_pending_transactions(self, mining_reward_address):
        reward_tx = Transaction("0", mining_reward_address, self.mining_reward, 0)
        self.pending_transactions.append(reward_tx)

        block = Block(len(self.chain), self.get_latest_block().hash, time.time(), self.pending_transactions, difficulty=self.difficulty)
        block.mine_block()

        self.chain.append(block)
        self.db.save_block(block)
        self.pending_transactions = []

        self.network.broadcast_block(block)

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.hash != current_block.calculate_hash():
                return False
            if current_block.previous_hash != previous_block.hash:
                return False
            if not current_block.has_valid_transactions():
                return False
        return True

    def resolve_conflicts(self):
        longest_chain = self.chain
        for node in self.network.nodes:
            if len(node.blockchain.chain) > len(longest_chain) and node.blockchain.is_chain_valid():
                longest_chain = node.blockchain.chain

        if longest_chain != self.chain:
            self.chain = longest_chain
            self.pending_transactions = []

    def save_chain(self):
        with open("blockchain.pkl", "wb") as f:
            pickle.dump(self.chain, f)

    @staticmethod
    def load_chain():
        with open("blockchain.pkl", "rb") as f:
            return pickle.load(f)

class Node:
    def __init__(self, blockchain):
        self.blockchain = blockchain
        self.pending_transactions = Queue()

    def receive_transaction(self, transaction):
        self.pending_transactions.put(transaction)
        self.blockchain.add_transaction(transaction)

    def mine(self, mining_reward_address):
        while not self.pending_transactions.empty():
            transaction = self.pending_transactions.get()
            self.blockchain.add_transaction(transaction)

        self.blockchain.mine_pending_transactions(mining_reward_address)

class BlockchainExplorer:
    def __init__(self, blockchain):
        self.blockchain = blockchain

    def find_transaction(self, transaction_hash):
        for block in self.blockchain.chain:
            for transaction in block.transactions:
                if transaction.calculate_hash() == transaction_hash:
                    return transaction
        return None

    def get_block_by_index(self, index):
        if index < len(self.blockchain.chain):
            return self.blockchain.chain[index]
        return None

    def get_transactions_by_address(self, address):
        return self.blockchain.db.get_transactions_by_address(address)

class BlockchainAPI:
    def __init__(self, blockchain):
        self.blockchain = blockchain
        self.app = Flask(__name__)
        self.setup_routes()

    def setup_routes(self):
        @self.app.route('/mine', methods=['POST'])
        def mine():
            data = request.get_json()
            if not data or not 'address' in data:
                return jsonify({'message': 'Invalid data'}), 400

            mining_reward_address = data['address']
            self.blockchain.mine_pending_transactions(mining_reward_address)
            return jsonify({'message': 'Block mined successfully'}), 200

        @self.app.route('/transactions/new', methods=['POST'])
        def new_transaction():
            data = request.get_json()
            required_fields = ['sender', 'recipient', 'amount', 'signature']

            if not all(k in data for k in required_fields):
                return jsonify({'message': 'Invalid data'}), 400

            transaction = Transaction(data['sender'], data['recipient'], data['amount'], data.get('fee', 0))
            transaction.signature = data['signature']

            if not transaction.is_valid():
                return jsonify({'message': 'Invalid transaction'}), 400

            self.blockchain.add_transaction(transaction)
            return jsonify({'message': 'Transaction added successfully'}), 201

        @self.app.route('/chain', methods=['GET'])
        def full_chain():
            chain_data = [block.__dict__ for block in self.blockchain.chain]
            return jsonify(chain_data), 200

        @self.app.route('/explorer/transaction/<tx_hash>', methods=['GET'])
        def find_transaction(tx_hash):
            transaction = self.blockchain.db.get_transactions_by_address(tx_hash)
            if transaction:
                return jsonify(transaction), 200
            return jsonify({'message': 'Transaction not found'}), 404

        @self.app.route('/explorer/address/<address>', methods=['GET'])
        def get_transactions_by_address(address):
            transactions = self.blockchain.db.get_transactions_by_address(address)
            return jsonify(transactions), 200

        @self.app.route('/explorer/block/<int:index>', methods=['GET'])
        def get_block_by_index(index):
            block = self.blockchain.db.load_blocks()[index]
            if block:
                return jsonify(block), 200
            return jsonify({'message': 'Block not found'}), 404

    def run(self, host='0.0.0.0', port=5000):
        self.app.run(host=host, port=port)


if __name__ == "__main__":

    wallet1 = Wallet()
    wallet2 = Wallet()

    blockchain = Blockchain()
    node1 = Node(blockchain)
    node2 = Node(blockchain)

  
    blockchain.add_wallet(wallet1.public_key.to_string().hex(), wallet1)
    blockchain.add_wallet(wallet2.public_key.to_string().hex(), wallet2)


    tx1 = Transaction(wallet1.public_key.to_string().hex(), wallet2.public_key.to_string().hex(), 10, 1)
    wallet1.sign_transaction(tx1)

    tx2 = Transaction(wallet2.public_key.to_string().hex(), wallet1.public_key.to_string().hex(), 5, 1)
    wallet2.sign_transaction(tx2)


    node1.receive_transaction(tx1)
    node2.receive_transaction(tx2)

    node1.mine(wallet1.public_key.to_string().hex())


    blockchain.save_chain()
    loaded_blockchain = Blockchain.load_chain()

    explorer = BlockchainExplorer(loaded_blockchain)
    found_tx = explorer.find_transaction(tx1.calculate_hash())
    found_block = explorer.get_block_by_index(1)

    if found_tx:
        print("Transaction found:", json.dumps(found_tx.__dict__, indent=2))
    if found_block:
        print("Block found:", json.dumps(found_block.__dict__, indent=2))

    api = BlockchainAPI(blockchain)
    api.run()
