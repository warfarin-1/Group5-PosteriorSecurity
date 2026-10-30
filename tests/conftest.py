import pytest

from posterior import boneh_boyen as bb
from posterior import concealed, cs_params


@pytest.fixture(scope="session")
def concealed_case():
    params = cs_params.setup()
    sk, vk = bb.keygen()
    message = bb.hash_message(b"Part B integration")
    signature = bb.sign(message, sk)
    cs, aux = concealed.convert(signature, message, vk, params)
    return params, sk, vk, message, signature, cs, aux
