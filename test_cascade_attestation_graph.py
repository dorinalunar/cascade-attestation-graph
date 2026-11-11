import contextlib
import json
from pathlib import Path
import re
import sys
import types

try:
    import pytest
except ImportError:
    class _FallbackPytest:
        @staticmethod
        @contextlib.contextmanager
        def raises(exc_type, match=None):
            try:
                yield
            except exc_type as exc:
                if match and not re.search(match, str(exc)):
                    raise AssertionError(f"Pattern {match!r} not found in {str(exc)!r}")
                return
            raise AssertionError(f"Did not raise {exc_type}")

    pytest = _FallbackPytest()


def _install_genlayer_mock():
    if "genlayer" in sys.modules:
        return

    mock_gl = types.ModuleType("genlayer")

    class _UserError(Exception):
        pass

    class _Return:
        def __init__(self, calldata):
            self.calldata = calldata

    class _VM:
        UserError = _UserError
        Return = _Return

        @staticmethod
        def run_nondet_unsafe(leader_fn, validator_fn):
            result = leader_fn()
            wrapped = _Return(result)
            if not validator_fn(wrapped):
                raise _UserError("Validator rejected leader adjudication seal")
            return result

    class _WebResponse:
        def __init__(self, status: int, body: bytes):
            self.status = status
            self.body = body

    class _Web:
        _mock_get = None

        @classmethod
        def get(cls, url: str):
            if callable(cls._mock_get):
                return cls._mock_get(url)
            if cls._mock_get is not None:
                return cls._mock_get
            raise _UserError("No mock web response configured")

    class _Nondet:
        web = _Web
        _mock_response = None

        @classmethod
        def exec_prompt(cls, prompt_text: str, response_format: str = "json"):
            if callable(cls._mock_response):
                return cls._mock_response(prompt_text)
            if cls._mock_response is not None:
                return cls._mock_response
            raise _UserError("No mock LLM response configured")

    class _WriteProxy:
        def __call__(self, fn):
            return fn

        def payable(self, fn):
            return fn

    class _PublicProxy:
        write = _WriteProxy()

        def view(self, fn):
            return fn

    class _EvmProxy:
        transfers = []

        @classmethod
        def contract_interface(cls, iface_cls):
            class _BoundInterface:
                def __init__(self, target_addr):
                    self.target_addr = target_addr

                def emit_transfer(self, value):
                    cls.transfers.append((str(self.target_addr), int(value)))

            return _BoundInterface

    class Address(str):
        pass

    class _Message:
        sender_address = Address("0x38409cCa5f5ca70F3fe189638a87862318b478dd")
        contract_address = Address("0x45d5b9fCEe51A8E58327E6C9eCa060bc7777559c")
        value = 0
        timestamp = 1762800000
        chain_id = 61999

    class _Contract:
        def __init__(self, *args, **kwargs):
            pass

        def __init_subclass__(cls, **kwargs):
            super().__init_subclass__(**kwargs)
            orig_init = cls.__init__

            def _wrapped_init(self, *args, **kw):
                for attr, anno in getattr(cls, "__annotations__", {}).items():
                    anno_str = str(anno)
                    if "TreeMap" in anno_str:
                        setattr(self, attr, {})
                    elif "DynArray" in anno_str:
                        setattr(self, attr, [])
                orig_init(self, *args, **kw)

            cls.__init__ = _wrapped_init

    class _GenericMeta(type):
        def __getitem__(cls, item):
            return cls

    class TreeMap(dict, metaclass=_GenericMeta):
        pass

    class DynArray(list, metaclass=_GenericMeta):
        pass

    mock_gl.vm = _VM
    mock_gl.nondet = _Nondet
    mock_gl.public = _PublicProxy()
    mock_gl.evm = _EvmProxy
    mock_gl.message = _Message
    mock_gl.Contract = _Contract
    mock_gl.Address = Address
    mock_gl.TreeMap = TreeMap
    mock_gl.DynArray = DynArray
    mock_gl.u256 = int
    mock_gl.allow_storage = lambda x: x
    mock_gl.gl = mock_gl
    mock_gl._WebResponse = _WebResponse
    mock_gl.__all__ = [
        "gl",
        "Address",
        "TreeMap",
        "DynArray",
        "u256",
        "allow_storage",
    ]

    sys.modules["genlayer"] = mock_gl


_install_genlayer_mock()

import genlayer as gl_mod  # noqa: E402
from CascadeAttestationGraph import (  # noqa: E402
    CODE_ATTESTATION_CONFIRMED,
    CODE_REVOCATION_CONFIRMED,
    CODE_UNANCHORED_QUOTE,
    PROTOCOL_TAG,
    STATE_CASCADE_HALTED,
    STATE_DISQUALIFIED,
    STATE_PENDING,
    STATE_REVOKED,
    STATE_SETTLED,
    STATE_VERIFIED,
    VERDICT_CONFIRMED,
    VERDICT_INDETERMINATE,
    VERDICT_REFUTED,
    VERTEX_KIND_ATTESTATION,
    VERTEX_KIND_MILESTONE,
    CascadeAttestationGraph,
    _normalize_https_uri,
)

GOVERNOR = gl_mod.Address("0x38409cCa5f5ca70F3fe189638a87862318b478dd")
BENEFICIARY = gl_mod.Address("0x7777777777777777777777777777777777777777")
OUTSIDER = gl_mod.Address("0x9999999999999999999999999999999999999999")
TRUSTED_HOSTS = ["raw.githubusercontent.com", "security.genlayer.io"]


def _reset_msg(sender=GOVERNOR, value=0, timestamp=1762800000):
    gl_mod.gl.message.sender_address = sender
    gl_mod.gl.message.value = value
    gl_mod.gl.message.timestamp = timestamp


def test_uri_normalization_and_host_allowlist():
    uri = _normalize_https_uri(
        "  https://RAW.githubusercontent.com/dorinalunar//repo/trail/  ",
        TRUSTED_HOSTS,
    )
    assert uri == "https://raw.githubusercontent.com/dorinalunar/repo/trail"

    with pytest.raises(gl_mod.gl.vm.UserError, match="HTTPS_SCHEME_REQUIRED"):
        _normalize_https_uri("http://raw.githubusercontent.com/file.txt", TRUSTED_HOSTS)

    with pytest.raises(gl_mod.gl.vm.UserError, match="UNTRUSTED_ARTIFACT_HOST"):
        _normalize_https_uri("https://evil.example.com/file.txt", TRUSTED_HOSTS)

    with pytest.raises(gl_mod.gl.vm.UserError, match="PATH_TRAVERSAL_FORBIDDEN"):
        _normalize_https_uri("https://raw.githubusercontent.com/a/../b/file.txt", TRUSTED_HOSTS)


def test_end_to_end_selective_cascade_revocation_and_disjoint_settlement():
    dataset_path = Path(__file__).parent / "sample_dataset.json"
    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    scenario = dataset["scenarios"][0]

    _reset_msg(sender=GOVERNOR, value=0)
    contract = CascadeAttestationGraph(TRUSTED_HOSTS)
    assert contract.protocol_version() == PROTOCOL_TAG

    # 1. Fund vault
    _reset_msg(sender=GOVERNOR, value=scenario["initial_deposit_wei"])
    contract.fund_vault()
    _reset_msg(sender=GOVERNOR, value=0)

    # 2. Register all 4 vertices across Branch A and Branch B
    for v_def in scenario["vertices"]:
        contract.register_vertex(
            v_def["vertex_id"],
            v_def["vertex_kind"],
            v_def["upstream_ids"],
            v_def["artifact_uri"],
            v_def["claim_scope"],
            v_def["escrowed_wei"],
            BENEFICIARY,
        )

    artifacts = scenario["artifacts"]

    def mock_web_get(url: str):
        entry = artifacts[url]
        return gl_mod._WebResponse(200, entry["body"].encode("utf-8"))

    def mock_llm_prompt(prompt_text: str):
        for url, entry in artifacts.items():
            if entry["body"] in prompt_text:
                return {"verdict": entry["verdict"], "excerpt": entry["excerpt"]}
        raise AssertionError("Unexpected prompt payload")

    gl_mod.gl.nondet.web._mock_get = mock_web_get
    gl_mod.gl.nondet._mock_response = mock_llm_prompt

    # 3. Verify upstream attestations and downstream milestones
    res_a1 = contract.verify_vertex("att-audit-a1")
    assert res_a1["verdict"] == VERDICT_CONFIRMED
    assert res_a1["audit_code"] == CODE_ATTESTATION_CONFIRMED

    res_a2 = contract.verify_vertex("ms-deploy-a2")
    assert res_a2["state"] == STATE_VERIFIED

    res_b1 = contract.verify_vertex("att-audit-b1")
    assert res_b1["verdict"] == VERDICT_CONFIRMED

    res_b2 = contract.verify_vertex("ms-release-b2")
    assert res_b2["state"] == STATE_VERIFIED

    # 4. Revoke root A1 via CVE security advisory
    rev_res = contract.revoke_vertex(
        "att-audit-a1",
        "https://security.genlayer.io/advisories/cve-2026-9901.txt",
    )
    assert rev_res["verdict"] == VERDICT_CONFIRMED
    assert rev_res["audit_code"] == CODE_REVOCATION_CONFIRMED

    # Verify Branch A is REVOKED / CASCADE_HALTED while Branch B remains VERIFIED
    assert contract.get_vertex("att-audit-a1")["state"] == STATE_REVOKED
    assert contract.get_vertex("ms-deploy-a2")["state"] == STATE_CASCADE_HALTED
    assert contract.get_vertex("att-audit-b1")["state"] == STATE_VERIFIED
    assert contract.get_vertex("ms-release-b2")["state"] == STATE_VERIFIED

    telemetry = contract.get_vault_telemetry()
    expected_tel = scenario["expected_post_revocation_telemetry"]
    for k, v in expected_tel.items():
        assert telemetry[k] == v

    # 5. Attempting to settle halted milestone A2 must revert
    with pytest.raises(gl_mod.gl.vm.UserError, match="VERTEX_CASCADE_HALTED"):
        contract.settle_vertex("ms-deploy-a2")

    # 6. Disjoint milestone B2 settles cleanly and emits EVM transfer
    gl_mod.gl.evm.transfers.clear()
    paid_b2 = contract.settle_vertex("ms-release-b2")
    assert paid_b2 == 2500
    assert gl_mod.gl.evm.transfers == [(str(BENEFICIARY), 2500)]
    assert contract.get_vertex("ms-release-b2")["state"] == STATE_SETTLED

    # 7. Reclaim frozen escrow from A1 and A2 back to unallocated vault
    contract.reclaim_frozen_escrow("att-audit-a1")
    contract.reclaim_frozen_escrow("ms-deploy-a2")
    final_tel = contract.get_vault_telemetry()
    assert final_tel["vault_frozen_wei"] == 0
    assert final_tel["vault_unallocated_wei"] == 6000
    assert final_tel["vault_disbursed_wei"] == 2500


def test_unanchored_quote_and_disqualification_refund():
    _reset_msg(sender=GOVERNOR, value=0)
    contract = CascadeAttestationGraph(TRUSTED_HOSTS)
    _reset_msg(sender=GOVERNOR, value=5000)
    contract.fund_vault()
    _reset_msg(sender=GOVERNOR, value=0)

    contract.register_vertex(
        "att-bad-quote",
        VERTEX_KIND_ATTESTATION,
        [],
        "https://raw.githubusercontent.com/dorinalunar/cascade-attestation-graph/main/evidence/bad.txt",
        "Soundness audit",
        1200,
        BENEFICIARY,
    )

    gl_mod.gl.nondet.web._mock_get = lambda url: gl_mod._WebResponse(
        200,
        b"Audit report states critical failure in module X with unresolved vulnerabilities.",
    )
    # LLM hallucinates a quote not in payload
    gl_mod.gl.nondet._mock_response = lambda prompt: {
        "verdict": VERDICT_CONFIRMED,
        "excerpt": "completely fabricated quote not in text",
    }

    seal = contract.verify_vertex("att-bad-quote")
    assert seal["verdict"] == VERDICT_INDETERMINATE
    assert seal["audit_code"] == CODE_UNANCHORED_QUOTE

    v_info = contract.get_vertex("att-bad-quote")
    assert v_info["state"] == STATE_DISQUALIFIED
    assert v_info["escrowed_wei"] == 0

    # Escrowed 1200 wei is automatically returned to unallocated vault & sponsor credit
    tel = contract.get_vault_telemetry()
    assert tel["vault_unallocated_wei"] == 5000
    assert tel["vault_escrowed_wei"] == 0


if __name__ == "__main__":
    test_uri_normalization_and_host_allowlist()
    test_end_to_end_selective_cascade_revocation_and_disjoint_settlement()
    test_unanchored_quote_and_disqualification_refund()
    print("[PASS] All CascadeAttestationGraph test suites succeeded.")
