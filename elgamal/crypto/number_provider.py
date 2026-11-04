import secrets
# Заменить целиком, Оставить как точку входа функцию provide_prime_and_factors
# ? Возможно поделить? Не для всего же нужны делители

def random_integer(low: int, high: int) -> int:
    if low > high:
        raise ValueError('Empty range')
    return low + secrets.randbelow(high - low + 1)


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for q in small:
        if n % q == 0:
            return n == q
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    if n < 2**64:
        bases = (2, 325, 9375, 28178, 450775, 9780504, 1795265022)
    else:
        bases = [random_integer(2, n - 2) for _ in range(40)]
    for base in bases:
        a = base % n
        if a == 0:
            continue
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    if bits < 4:
        raise ValueError('bits must be >= 4')
    while True:
        candidate = random_integer(2**(bits-1), 2**bits - 1) | 1 | (1 << (bits - 1))
        if is_prime(candidate):
            return candidate


def distinct_prime_factors(n: int) -> list[int]:
    """Temporary trial division: practical only for small n or smooth n."""
    factors = []
    d = 2
    while d * d <= n:
        if n % d == 0:
            factors.append(d)
            while n % d == 0:
                n //= d
        d = 3 if d == 2 else d + 2
    if n > 1:
        factors.append(n)
    return factors


def generate_prime_with_factors(bits: int) -> tuple[int, list[int]]:
    """Temporary safe-prime generator: p=2q+1, q prime; factors of p-1 = [2,q]."""
    if bits < 5:
        raise ValueError('bits must be >= 5')
    while True:
        q = generate_prime(bits - 1)
        p = 2 * q + 1
        if p.bit_length() == bits and is_prime(p):
            return p, [2, q]


def provide_prime_and_factors(bits: int, selected_p: int | None = None) -> tuple[int, list[int]]:
    """Единая точка получения p и простых делителей p - 1.

    TODO: заменить ТЕЛО
    этой функции вызовами :
      * при selected_p is None: генерация простого p и выдача множителей p - 1;
      * иначе: проверка введённого p на простоту и выдача множителей p - 1.

    Контракт: (p, [различные простые делители p - 1]).
    """
    if selected_p is None:
        return generate_prime_with_factors(bits)

    p = int(selected_p)
    if p < 5 or not is_prime(p):
        raise ValueError('p должно быть простым числом ≥ 5')
    return p, distinct_prime_factors(p - 1)
