# crypto/merkle.py
# SHA-256 Merkle Tree implementation.
# Tamper-evident audit log backbone.
# Leaf prefix 0x00, internal node prefix 0x01
# to prevent second preimage attacks.

import hashlib
import json


def _hash_leaf(data: bytes) -> str:
    """Hash a leaf node with 0x00 prefix."""
    return hashlib.sha256(b'\x00' + data).hexdigest()


def _hash_pair(left: str, right: str) -> str:
    """Hash two child nodes into a parent with 0x01 prefix."""
    combined = bytes.fromhex(left) + bytes.fromhex(right)
    return hashlib.sha256(b'\x01' + combined).hexdigest()


def build_tree(leaves: list) -> list:
    """
    Build a complete Merkle Tree from a list of leaf data bytes.
    Returns the full tree as a list of levels, bottom to top.
    """
    if not leaves:
        raise ValueError("Cannot build a Merkle Tree with no leaves.")

    current = [_hash_leaf(leaf) for leaf in leaves]
    tree    = [current]

    while len(current) > 1:
        if len(current) % 2 == 1:
            current.append(current[-1])
        current = [
            _hash_pair(current[i], current[i + 1])
            for i in range(0, len(current), 2)
        ]
        tree.append(current)

    return tree


def get_root(tree: list) -> str:
    """Return the Merkle root."""
    return tree[-1][0]


def get_proof(tree: list, index: int) -> list:
    """Generate a Merkle proof for the leaf at index."""
    proof = []
    for level in tree[:-1]:
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        if index % 2 == 0:
            proof.append((level[index + 1], "right"))
        else:
            proof.append((level[index - 1], "left"))
        index //= 2
    return proof


def verify_leaf(leaf_data: bytes, index: int,
                proof: list, root: str) -> bool:
    """Verify that a leaf exists in the tree with the given root."""
    current = _hash_leaf(leaf_data)
    for sibling, position in proof:
        if position == "right":
            current = _hash_pair(current, sibling)
        else:
            current = _hash_pair(sibling, current)
    return current == root


def proof_to_json(proof: list) -> list:
    """Serialize proof to JSON-compatible format."""
    return [[sibling, position] for sibling, position in proof]


def proof_from_json(data: list) -> list:
    """Deserialize proof from JSON format."""
    return [(sibling, position) for sibling, position in data]


if __name__ == "__main__":
    print("Testing Merkle Tree...")
    leaves = [b"event_a", b"event_b", b"event_c", b"event_d"]
    tree   = build_tree(leaves)
    root   = get_root(tree)

    for i, leaf in enumerate(leaves):
        proof    = get_proof(tree, i)
        verified = verify_leaf(leaf, i, proof, root)
        assert verified, f"Leaf {i} failed verification."
    print("  All leaves verified.")

    tampered = b"tampered"
    proof    = get_proof(tree, 1)
    assert not verify_leaf(tampered, 1, proof, root)
    print("  Tamper detection OK.")
    print("  merkle.py OK.")