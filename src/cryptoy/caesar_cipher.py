from cryptoy.utils import (
    str_to_unicodes,
    unicodes_to_str,
)

# TP: Chiffrement de César


def caesar_cipher(msg: str, shift: int) -> str:
    unicodes = str_to_unicodes(msg)
    shifted_unicodes = [(x + shift) % 1114112 for x in unicodes]
    return unicodes_to_str(shifted_unicodes)


def encrypt(msg: str, shift: int) -> str:
    return caesar_cipher(msg, shift)


def decrypt(msg: str, shift: int) -> str:
    return caesar_cipher(msg, -shift)


def attack() -> tuple[str, int]:
    s = "恱恪恸急恪恳恳恪恲恮恸急恦恹恹恦恶恺恪恷恴恳恸急恵恦恷急恱恪急恳恴恷恩怱急恲恮恳恪恿急恱恦急恿恴恳恪"
    for i in range(1, 1114112):
        dec = decrypt(s, i)
        if "ennemis" in dec:
            return dec, i
    raise RuntimeError("Failed to attack")
