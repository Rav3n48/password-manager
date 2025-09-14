import string
import random


def password_generator(
        length=8, upper=False, lower=False, nums=False, special=False
):
    """Generate a password by customized parameters."""
    chars = ''

    if upper:
        chars += string.ascii_uppercase
    if lower:
        chars += string.ascii_lowercase
    if nums:
        chars += string.digits
    if special:
        chars += string.punctuation

    passwd = ''.join(random.choices(chars, k=length))

    return passwd
