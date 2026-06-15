# Copyright 2018, Qualita Seguranca e Saude Ocupacional. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ==============================================================================
"""Regression tests for S-1.3 layout support and the esocial_version
propagation fix.

Context
-------
Production eSocial now requires the S-1.3 layout (event namespace
.../evtFechaEvPer/v_S_01_03_00). Two problems prevented sending S-1.3 events:

1. `XMLValidate` and `xsd_fromdoc` froze the default `esocial_version` at import
   time (to whatever `__esocial_version__` was), so changing it later had no
   effect on validation.
2. `WSClient.add_event` validated the signed event WITHOUT passing
   `self.esocial_version`, so a client created with
   `WSClient(esocial_version='S-1.3')` still validated against the default
   layout and failed.

These tests pin S-1.3 explicitly so they do not depend on the package default
(and therefore do not require S-1.3 fixtures for the other events).
"""
import os

import esocial
from esocial import xml
from esocial import client

from esocial.tests import here


S13 = 'S-1.3'


def _ws_s13():
    employer_id = {'tpInsc': 1, 'nrInsc': '12345678901234'}
    return client.WSClient(
        pfx_file=os.path.join(here, 'certs', 'libesocial-cert-test.pfx'),
        pfx_passw='cert@test',
        employer_id=employer_id,
        target=2,
        esocial_version=S13,
    )


def test_s13_xsd_is_bundled():
    """The S-1.3 schema folder must ship with the package."""
    xsd_dir = os.path.join(os.path.dirname(esocial.__file__), 'xsd', 'vS-1.3')
    assert os.path.isdir(xsd_dir), 'Missing xsd/vS-1.3 folder'
    for f in ('evtFechaEvPer.xsd', 'tipos.xsd', 'xmldsig-core-schema.xsd'):
        assert os.path.exists(os.path.join(xsd_dir, f)), 'Missing {} in vS-1.3'.format(f)


def test_xsd_fromdoc_respects_explicit_version():
    """xsd_fromdoc must resolve the schema for the version passed in, not the
    frozen import-time default."""
    evt = xml.load_fromfile(os.path.join(here, 'xml', 'S-1299-vS-1.3-not_signed.xml'))
    schema = xml.xsd_fromdoc(evt, esocial_version=S13)
    assert schema is not None


def test_validate_s13_fechamento_body():
    """The S-1.3 evtFechaEvPer body (incl. naoValid=N) must validate against the
    S-1.3 schema; only the enveloped Signature should be missing before signing."""
    evt = xml.load_fromfile(os.path.join(here, 'xml', 'S-1299-vS-1.3-not_signed.xml'))
    validator = xml.XMLValidate(evt, esocial_version=S13)
    is_valid = validator.isvalid()
    assert not is_valid, 'Unsigned event unexpectedly valid'
    errors = [e.message for e in validator.last_errors]
    assert all('Signature' in m for m in errors), \
        'Expected only the missing-Signature error, got: {}'.format(errors)


def test_add_event_1299_s13_uses_client_version():
    """Core regression: WSClient(esocial_version='S-1.3').add_event must sign AND
    validate the event against the S-1.3 schema (previously it validated against
    the frozen default and raised XMLValidateError)."""
    ws = _ws_s13()
    evt = xml.load_fromfile(os.path.join(here, 'xml', 'S-1299-vS-1.3-not_signed.xml'))
    try:
        evt_id, evt_signed = ws.add_event(evt, gen_event_id=True)
    except xml.XMLValidateError as err:
        raise AssertionError(
            'add_event failed to validate a valid S-1.3 event: {}'.format(err.errors))
    fecha_tag = xml.find(evt_signed.getroot(), 'evtFechaEvPer')
    assert fecha_tag.get('Id') == evt_id
