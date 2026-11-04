import hashlib
from dataclasses import dataclass
from . import number_provider as numbers


def gcd(a, b):
    while b:
        a, b = b, a % b
    return abs(a)


def egcd(a, b):
    if a <= 0 or b <= 0:
        raise ValueError('Аргументы должны быть положительными')

    remainders = [a, b]
    quotients = []

    # Прямой ход алгоритма Евклида: r[i - 2] = q[i - 2] * r[i - 1] + r[i].
    while remainders[-1] != 0:
        q = remainders[-2] // remainders[-1]
        quotients.append(q)
        remainders.append(remainders[-2] - q * remainders[-1])

    gcd_value = remainders[-2]

    # Обратный ход: выражаем НОД через r[0] = a и r[1] = b.
    # coeffs[i] — множитель при r[i] в текущем выражении НОД.
    last_nonzero = len(remainders) - 2
    coeffs = [0] * (last_nonzero + 1)
    coeffs[last_nonzero] = 1
    for i in range(last_nonzero, 1, -1):
        # r[i] = r[i - 2] - q[i - 2] * r[i - 1]
        coefficient = coeffs[i]
        coeffs[i - 2] += coefficient
        coeffs[i - 1] -= coefficient * quotients[i - 2]

    return gcd_value, coeffs[0]


def inverse(k, n):
    d, v = egcd(k, n)
    if d != 1:
        raise ValueError('Обратного элемента не существует')
    # v * k + t * n = 1. Если v отрицателен, прибавляем n до
    # представителя класса вычетов из диапазона 0..n-1.
    while v < 0:
        v += n
    return v


def modexp(a, e, n):
    # a ** e % n
    if e < 0 or n < 2:
        raise ValueError('Неверные аргументы степени')
    return pow(a, e, n)


def hash_bytes(data):
    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest, 'big'), digest.hex()


@dataclass(frozen=True)
class PublicKey:
    p: int
    A: int
    y: int


@dataclass(frozen=True)
class PrivateKey:
    p: int
    A: int
    y: int
    xi: int


@dataclass(frozen=True)
class Signature:
    a: int
    b: int


def make_keys(bits=32, selected_p=None):
    # Генерация/проверка p и разложение p - 1 вынесены
    p, factors = numbers.provide_prime_and_factors(bits, selected_p)
    A = next((g for g in range(2, p) if all(modexp(g, (p-1)//q, p) != 1 for q in factors)), None)
    if A is None:
        raise ValueError('Не удалось найти первообразный корень')
    xi = numbers.random_integer(1, p-2)
    y = modexp(A, xi, p)
    pub, priv = PublicKey(p, A, y), PrivateKey(p, A, y, xi)
    lines = ['ГЕНЕРАЦИЯ КЛЮЧЕЙ', f'p = {p}; p − 1 = {p-1}',
             f'Простые делители p − 1: {factors}', 'A — первообразный корень:']
    for q in factors:
        lines.append(f'A^((p−1)/{q}) mod p = {A}^{(p-1)//q} mod {p} = {modexp(A,(p-1)//q,p)} ≠ 1')
    lines += [f'A = {A}', f'xᵢ = {xi}  (СЕКРЕТНЫЙ ключ)',
              'y = A^xᵢ mod p', f'y = {A}^{xi} mod {p} = {y}',
              f'Открытый ключ (p, A, y) = ({p}, {A}, {y})']
    return pub, priv, '\n'.join(lines)


def sign(data: bytes, key: PrivateKey):
    p, A, xi = key.p, key.A, key.xi
    m, digest = hash_bytes(data)
    while True:
        k = numbers.random_integer(1, p-2)
        if gcd(k, p-1) == 1:
            break
    a = modexp(A, k, p)
    kinv = inverse(k, p-1)
    b = (kinv * (m - xi*a)) % (p-1)
    lhs, rhs = m % (p-1), (xi*a+k*b) % (p-1)
    lines = ['СОЗДАНИЕ ПОДПИСИ', f'SHA-256(M) = {digest}',
             f'm = int(SHA-256(M)) = {m}',
             f'k = {k}; НОД({k}, {p-1}) = {gcd(k,p-1)}',
             'a = A^k mod p', f'a = {A}^{k} mod {p} = {a}',
             'k · k⁻¹ ≡ 1 (mod p−1)',
             f'{k} · {kinv} mod {p-1} = {(k*kinv)%(p-1)}',
             'b = k⁻¹ · (m − xᵢ · a) mod (p−1)',
             f'b = {kinv} · ({m} − {xi} · {a}) mod {p-1} = {b}',
             'm ≡ xᵢ · a + k · b (mod p−1)',
             f'{lhs} = ({xi} · {a} + {k} · {b}) mod {p-1} = {rhs}',
             f'Подпись (a, b) = ({a}, {b})',
             'k не передаётся и не сохраняется.']
    return Signature(a,b), '\n'.join(lines)


def verify(data: bytes, sig: Signature, key: PublicKey):
    p, A, y, a, b = key.p, key.A, key.y, sig.a, sig.b
    m, digest = hash_bytes(data)
    lines = ['ПРОВЕРКА ПОДПИСИ', f'SHA-256(M) = {digest}', f'm = {m}',
             f'Проверка диапазонов: 1 ≤ {a} ≤ {p-1}; 0 ≤ {b} ≤ {p-2}']
    if not (1 <= a <= p-1 and 0 <= b <= p-2):
        return False, '\n'.join(lines + ['ОТКЛОНЕНО: компоненты подписи вне диапазона'])
    ya = modexp(y,a,p)
    ab = modexp(a,b,p)
    c1 = ya * ab % p
    c2 = modexp(A,m,p)
    ok = c1 == c2
    lines += ['c₁ = y^a · a^b mod p',
              f'c₁ = {y}^{a} · {a}^{b} mod {p}',
              f'c₁ = ({ya} · {ab}) mod {p} = {c1}',
              'c₂ = A^m mod p', f'c₂ = {A}^{m} mod {p} = {c2}',
              f'c₁ = c₂ ? {c1} = {c2} → {"ДА, ПОДПИСЬ ВЕРНА" if ok else "НЕТ, ПОДПИСЬ НЕВЕРНА"}']
    return ok, '\n'.join(lines)
