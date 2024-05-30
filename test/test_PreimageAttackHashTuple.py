from PreimageAttackHashTuple import PyTupleHashPreimageAttack
from os import urandom

def test_PreimageAttackHashTuple():
    h = hash(tuple(urandom(1337)))
    t = PyTupleHashPreimageAttack(h)
    assert hash(t) == h

if __name__ == "__main__":
    test_PreimageAttackHashTuple()