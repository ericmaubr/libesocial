"""`.pfx` em BER (o que certificadora entrega): a cryptography abre com UserWarning "falling back to
parsing as BER". Decisao do Eric (2026-10-31): BER e aceito e o log fica limpo. O primeiro teste e o
sentinela: se uma versao futura da cryptography passar a RECUSAR BER, ele falha com a explicacao.

Fixture `fixtures/acme_ber.pfx`: certificado ACME autoassinado (senha `senha-teste`), exportado pelo Windows
(Export-PfxCertificate) e com o envelope externo reescrito em comprimento indefinido (BER, nao DER)."""
import os
import warnings

import pytest
from cryptography.hazmat.primitives.serialization import pkcs12

from esocial.utils import pkcs12_data

PFX = os.path.join(os.path.dirname(__file__), 'fixtures', 'acme_ber.pfx')
SENHA = 'senha-teste'


def test_sentinela_cryptography_ainda_aceita_ber():
    with open(PFX, 'rb') as fp:
        dados = fp.read()
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        try:
            pkcs12.load_pkcs12(dados, SENHA.encode())
        except ValueError as exc:
            pytest.fail(
                'A cryptography passou a recusar .pfx em BER (o aviso "falling back to parsing as BER" '
                f'virou erro): {exc}. Os .pfx de certificadora vem em BER: decidir com o Eric antes de '
                'atualizar a cryptography (converter o .pfx para DER ao cadastrar?).'
            )


def test_pkcs12_data_abre_ber_sem_aviso():
    with warnings.catch_warnings():
        warnings.simplefilter('error')
        dados = pkcs12_data(PFX, SENHA)
    assert 'ACME COMERCIO LTDA:00000000000191' in dados['cert'].subject.rfc4514_string()
