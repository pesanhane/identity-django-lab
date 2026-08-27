import time

import pyotp


def generate_secret():
    """
    Gera um segredo TOTP aleatório.
    """
    return pyotp.random_base32()


def generate_totp_uri(user, secret):
    """
    Gera a URI otpauth:// usada por aplicações autenticadoras.
    """
    totp = pyotp.TOTP(secret)

    return totp.provisioning_uri(
        name=user.email or user.username,
        issuer_name="Identity Management System",
    )


def verify_totp_code(secret, code):
    """
    Valida um código TOTP.

    Aceita uma janela de tolerância de 1 intervalo.
    """
    if not secret or not code:
        return False

    totp = pyotp.TOTP(secret)

    return totp.verify(
        code,
        valid_window=1,
    )


def get_totp_counter():
    """
    Retorna o contador TOTP correspondente ao instante atual.

    O TOTP normalmente utiliza intervalos de 30 segundos.
    """
    return int(time.time()) // 30


def verify_totp_code_with_counter(secret, code):
    """
    Valida um código TOTP e retorna o contador correspondente.

    A janela de tolerância é de:
        contador atual - 1
        contador atual
        contador atual + 1

    Retorna:
        int  -> código válido e contador correspondente
        None -> código inválido
    """
    if not secret or not code:
        return None

    totp = pyotp.TOTP(secret)
    current_counter = get_totp_counter()

    for counter in (
        current_counter - 1,
        current_counter,
        current_counter + 1,
    ):
        expected_code = totp.at(counter * 30)

        if expected_code == str(code):
            return counter

    return None


def generate_current_code(secret):
    """
    Gera o código TOTP atualmente válido.
    Útil principalmente para testes.
    """
    if not secret:
        return None

    return pyotp.TOTP(secret).now()
