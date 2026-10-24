import json
import sys
from contextlib import nullcontext
from types import SimpleNamespace

import httpx
import pytest

from packages.gateway.providers import LocalHFProvider, RealProvider
from packages.gateway.structured import json_text
from packages.ifc.models import MeetingFacts


def test_missing_meeting_facts_are_explicit_and_partial_facts_rejected():
    assert MeetingFacts(day=None, time=None).day is None
    with pytest.raises(ValueError, match="both"):
        MeetingFacts(day="Tuesday", time=None)


@pytest.mark.parametrize("url", ["https://example.com/v1", "http://localhost:8081/v1"])
def test_llamacpp_rejects_nonliteral_loopback(monkeypatch, url):
    monkeypatch.setenv("MECHA_ALLOW_NETWORK", "1")
    monkeypatch.setenv("MECHA_LOCAL_URL", url)
    with pytest.raises(ValueError, match="literal loopback"):
        RealProvider("llamacpp")


def test_llamacpp_accepts_explicit_loopback(monkeypatch):
    monkeypatch.setenv("MECHA_ALLOW_NETWORK", "1")
    monkeypatch.setenv("MECHA_LOCAL_URL", "http://127.0.0.1:8081/v1")
    assert RealProvider("llamacpp").url == "http://127.0.0.1:8081/v1/chat/completions"


@pytest.mark.anyio
async def test_anthropic_system_boundary_and_bounded_text_transport(monkeypatch):
    monkeypatch.setenv("MECHA_ALLOW_NETWORK", "1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-provider-test-key")
    requests = []

    def handle(request):
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={"content": [{"text": "fake answer"}]})

    original = httpx.AsyncClient
    monkeypatch.setattr(
        "packages.gateway.providers.httpx.AsyncClient",
        lambda **kwargs: original(transport=httpx.MockTransport(handle), **kwargs),
    )
    provider = RealProvider("anthropic")
    result = await provider.complete(
        [
            {"role": "system", "content": "trusted instructions"},
            {"role": "user", "content": "fake request"},
        ],
        "fake-model",
    )
    assert result == "fake answer"
    assert requests[0]["system"] == "trusted instructions"
    assert requests[0]["messages"] == [{"role": "user", "content": "fake request"}]
    assert requests[0]["max_tokens"] <= 1024


def test_json_wrapper_never_extracts_or_executes_embedded_code():
    assert json_text('```json\n{"action":"read_email"}\n```') == '{"action":"read_email"}'
    assert json_text('narration {"unsafe":true}') == 'narration {"unsafe":true}'
    with pytest.raises(ValueError):
        json_text("a" * 16385)


def test_local_cpu_model_is_explicit_float32_cached_and_never_downloads(tmp_path, monkeypatch):
    loaded, generations = [], []

    class Tokens:
        shape = (1, 2)

        def __getitem__(self, key):
            return "new tokens"

    class Weights:
        def float(self):
            loaded.append("float32")
            return self

        def eval(self):
            return self

        def generate(self, **kwargs):
            generations.append(kwargs)
            return Tokens()

    class Loader:
        @staticmethod
        def from_pretrained(path, **kwargs):
            assert kwargs["local_files_only"] and not kwargs["trust_remote_code"]
            loaded.append(path)
            return Weights()

    class Tokenizer:
        eos_token_id = 1

        def apply_chat_template(self, messages, **kwargs):
            return "fake serialized chat"

        def __call__(self, text, **kwargs):
            return {"input_ids": Tokens()}

        def decode(self, tokens, **kwargs):
            assert tokens == "new tokens"
            return '{"action":"read_email"}'

    class TokenizerLoader:
        @staticmethod
        def from_pretrained(path, **kwargs):
            assert kwargs["local_files_only"] and not kwargs["trust_remote_code"]
            return Tokenizer()

    monkeypatch.setitem(sys.modules, "torch", SimpleNamespace(inference_mode=nullcontext))
    monkeypatch.setitem(
        sys.modules,
        "transformers",
        SimpleNamespace(AutoModelForCausalLM=Loader, AutoTokenizer=TokenizerLoader),
    )
    provider = LocalHFProvider(str(tmp_path))
    assert provider._complete([{"role": "user", "content": "fake request"}])
    assert provider._complete([{"role": "user", "content": "fake request"}])
    assert loaded.count("float32") == 1 and len(loaded) == 2
    assert all(g["max_time"] == 60 and g["max_new_tokens"] == 192 for g in generations)
