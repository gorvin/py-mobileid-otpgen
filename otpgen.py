#!/usr/bin/env python
from binascii import hexlify
from hashlib import sha1
from oath import totp
from os.path import basename
import sys


def _extractKeyMaterial(seed):
    """Get the substring which keys are derived from."""
    return seed[7:17]


def _generateKey(seed):
    """Generate key from seed."""
    return hexlify(sha1(_extractKeyMaterial(seed).encode('ascii'))
                   .digest()).decode('ascii')


def generateOTPValue(seed):
    """Generate OTP value from given seed."""
    if type(seed) is not str:
        raise TypeError("Argument seed needs to be str")
    return totp(_generateKey(seed), period=60)


if __name__ == '__main__':
    if (len(sys.argv) != 2):
        sys.exit("Usage: %s [18 digit token seed]" % basename(sys.argv[0]))

    seed = sys.argv[1]

    if (len(seed) != 18):
        sys.exit("Error, seed must be 18 digits")

    print("%s" % generateOTPValue(seed))
