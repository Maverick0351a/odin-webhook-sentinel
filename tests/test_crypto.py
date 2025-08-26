from sentinel.crypto import canonical_json, sha256_cid


def test_canonical_json_and_cid():
    a = {"z": 1, "a": [3, 2, 1]}
    b = {"a": [3, 2, 1], "z": 1}
    ca = canonical_json(a)
    cb = canonical_json(b)
    assert ca == cb  # stable
    cid = sha256_cid(ca)
    assert cid.startswith("sha256:") and len(cid) == 71
