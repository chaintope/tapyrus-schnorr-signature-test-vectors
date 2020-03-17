from reference import *
import secrets
from functools import reduce


def generate_vss(seckey, threshold, parties):
    """
    Generate vss and commitment for a party whose seckey is passed.
    :param seckey: secret key of the party.
    :param threshold: number of threshold.
    :param parties: count of party.
    :return: a tuple which has an array of share and commitment.
    """
    coefficients = choose_polynomials(seckey, threshold - 1)

    r = []
    for i in range(parties):
        r.append(compute_share(i, coefficients))

    commitment = compute_commitment(coefficients)
    return (r, commitment)

#
def verify_vss(share, commitment, party_index):
    """
    Verify whether the share allocated by dealer is valid.
    :param share: The share of the party.
    :param commitment: The commitment for the share.
    :param party_index: The index of the party. Starts with 0.
    :return: Boolean result of the verification.
    """
    x = party_index + 1
    assert (0 < x < n)

    expected = point_mul(G, share)

    # compute polynomial on Horner's rule.
    rev = list(reversed(commitment))
    result = reduce(lambda r, c: point_add(c, point_mul(r, x)), rev[1:], rev[0])

    return result == expected


def random_seckey():
    while True:
        secret = secrets.randbits(256)
        if 0 < secret < n:
            return secret


def choose_polynomials(seckey, degree):
    """
    Choose Polynomials
    If the degree is 3 then the polynomials should be `a + b * x + c * x^2 + d * x^3`.
    And it returns Array of integer as `[a, b, c, d]`.
    """
    r = [seckey]
    for i in range(degree):
        r.append(random_seckey())

    return r


def compute_share(party_index, coefficients):
    # compute polynomial on Horner's rule.
    x = party_index + 1
    rev = list(reversed(coefficients))
    return reduce(lambda r, c: (c + (r * x) % n) % n, rev[1:], rev[0])


def compute_commitment(coefficients):
    return list(map(lambda i: point_mul(G, i), coefficients))


if __name__ == '__main__':
    # Number of parties
    parties = 5
    # Threshold
    threshold = 3

    # secret for a party
    seckey = 0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF

    # generate_vss_and_commitment
    (shares, commitment) = generate_vss(seckey, threshold, parties)

    assert (len(shares) == 5)
    assert (len(commitment) == 3)

    for party_index in range(parties):
        assert (verify_vss(shares[party_index], commitment, party_index))
