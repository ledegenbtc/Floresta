#!/usr/bin/env python3
"""
Query wallet data from Floresta's Electrum server.
Usage: python scripts/query_wallet.py [port]
"""

import socket
import json
import hashlib
import sys

def get_scripthash(script_hex: str) -> str:
    """Calculate Electrum scripthash from scriptPubKey hex"""
    script_bytes = bytes.fromhex(script_hex)
    sha256_hash = hashlib.sha256(script_bytes).digest()
    return sha256_hash[::-1].hex()

def electrum_request(method: str, params: list, port: int = 50001):
    """Send request to Electrum server"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect(('127.0.0.1', port))
        request = {"id": 1, "method": method, "params": params}
        sock.send((json.dumps(request) + '\n').encode())
        response = sock.recv(65536).decode()
        return json.loads(response)
    finally:
        sock.close()

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 50001

    # Endereço de teste do descriptor WSH multisig
    # Primeiro endereço derivado (index 0)
    # Você pode adicionar mais endereços aqui
    test_scripts = [
        # Adicione os scriptPubKeys dos seus endereços aqui
        # Formato: "00142b6a2924aa9b1b115d1ac3098b0ba0e6ed510f2a"
    ]

    if not test_scripts:
        print("Para usar este script, adicione os scriptPubKeys dos seus endereços.")
        print("\nOu teste a conexão com o servidor Electrum:")
        try:
            result = electrum_request("server.version", ["query_wallet", "1.4"], port)
            print(f"Servidor Electrum respondeu: {result}")
        except Exception as e:
            print(f"Erro ao conectar: {e}")
            print(f"Verifique se o florestad está rodando na porta {port}")
        return

    total_balance = 0
    all_history = []
    all_utxos = []

    for script_hex in test_scripts:
        scripthash = get_scripthash(script_hex)
        print(f"\n{'='*60}")
        print(f"Script: {script_hex[:20]}...")
        print(f"Scripthash: {scripthash[:20]}...")

        # Balance
        try:
            balance = electrum_request("blockchain.scripthash.get_balance", [scripthash], port)
            if "result" in balance:
                confirmed = balance["result"].get("confirmed", 0)
                unconfirmed = balance["result"].get("unconfirmed", 0)
                total_balance += confirmed + unconfirmed
                print(f"Saldo: {confirmed} sats (confirmado) + {unconfirmed} sats (pendente)")
        except Exception as e:
            print(f"Erro ao consultar saldo: {e}")

        # History
        try:
            history = electrum_request("blockchain.scripthash.get_history", [scripthash], port)
            if "result" in history:
                txs = history["result"]
                all_history.extend(txs)
                print(f"Transações: {len(txs)}")
                for tx in txs:
                    print(f"  - {tx['tx_hash'][:16]}... (altura: {tx.get('height', 'mempool')})")
        except Exception as e:
            print(f"Erro ao consultar histórico: {e}")

        # UTXOs
        try:
            utxos = electrum_request("blockchain.scripthash.listunspent", [scripthash], port)
            if "result" in utxos:
                all_utxos.extend(utxos["result"])
                print(f"UTXOs: {len(utxos['result'])}")
                for utxo in utxos["result"]:
                    print(f"  - {utxo['tx_hash'][:16]}...:{utxo['tx_pos']} = {utxo['value']} sats")
        except Exception as e:
            print(f"Erro ao consultar UTXOs: {e}")

    print(f"\n{'='*60}")
    print(f"TOTAL:")
    print(f"  Saldo: {total_balance} sats ({total_balance/100_000_000:.8f} BTC)")
    print(f"  Transações: {len(all_history)}")
    print(f"  UTXOs: {len(all_utxos)}")

if __name__ == "__main__":
    main()
