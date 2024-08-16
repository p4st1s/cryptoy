from math import (
    gcd,
)

from cryptoy.utils import (
    str_to_unicodes,
    unicodes_to_str,
)

# TP: Chiffrement affine


def compute_permutation(a: int, b: int, n: int) -> list[int]:
    perm = []
    for i in range(n):
        perm.append((a * i + b) % n)
    return perm


def compute_inverse_permutation(a: int, b: int, n: int) -> list[int]:
    perm = compute_permutation(a, b, n)
    inv_perm = [0] * n
    for i in range(n):
        inv_perm[perm[i]] = i
    return inv_perm


def encrypt(msg: str, a: int, b: int) -> str:
    unicodes = str_to_unicodes(msg)
    perms = []
    for u in unicodes:
        perms.append((a * u + b) % 1114112)
    return unicodes_to_str(perms)


def encrypt_optimized(msg: str, a: int, b: int) -> str:
    return encrypt(msg, a, b)


def decrypt(msg: str, a: int, b: int) -> str:
    unicodes = str_to_unicodes(msg)
    inv_perms = []
    for u in unicodes:
        inv_perms.append(compute_inverse_permutation(a, b, 1114112)[u])
    return unicodes_to_str(inv_perms)


def decrypt_optimized(msg: str, a_inverse: int, b: int) -> str:
    unicodes = str_to_unicodes(msg)
    inv_perms = []
    for u in unicodes:
        inv_perms.append((a_inverse * (u - b)) % 1114112)
    return unicodes_to_str(inv_perms)


def compute_affine_keys(n: int) -> list[int]:
    keys = []
    for i in range(1, n):
        if gcd(i, n) == 1:
            keys.append(i)
    return keys


def compute_affine_key_inverse(a: int, affine_keys: list[int], n: int) -> int:
    for x in affine_keys:
        if (a * x) % n == 1:
            return x
    raise RuntimeError(f"No inverse for {a}")


def attack() -> tuple[str, tuple[int, int]]:
    ciphertext = "࠾ੵΚઐ௯ஹઐૡΚૡೢఊஞ௯\u0c5bૡీੵΚ៚Κஞїᣍફ௯ஞૡΚր\u05ecՊՊΚஞૡΚՊեԯՊ؇ԯրՊրր"
    b = 58

    for a in compute_affine_keys(b):
        plaintext = decrypt(ciphertext, a, b)
        if "bombe" in plaintext:
            return plaintext, (a, b)


def attack_optimized() -> tuple[str, tuple[int, int]]:
    ciphertext = (
        "જഏ൮ൈ\u0c51ܲ೩\u0c51൛൛అ౷\u0c51ܲഢൈᘝఫᘝా\u0c51\u0cfc൮ܲఅܲᘝ൮ᘝܲాᘝఫಊಝ"
        "\u0c64\u0c64ൈᘝࠖܲೖఅܲఘഏ೩ఘ\u0c51ܲ\u0c51൛൮ܲఅ\u0cfc\u0cfcඁೖᘝ\u0c51"
    )
    keys = compute_affine_keys(1114112)
    for a in keys:
        try:
            a_inverse = compute_affine_key_inverse(a, keys, 1114112)
        except RuntimeError:
            continue

        for b in range(1, 10001):
            plaintext = decrypt_optimized(ciphertext, a_inverse, b)
            if "bombe" in plaintext:
                return plaintext, (a, b)

    raise RuntimeError("Optimized attack failed")
