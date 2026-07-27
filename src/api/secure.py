"""Static current-Comix secure-module extraction and crypto.

This module intentionally contains no JavaScript engine, browser automation,
or browser-derived session state. It parses the published secure asset as
data, extracts its per-build byte transforms, and applies them in Python.
"""
from __future__ import annotations

import ast
import base64
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import unquote


class SecureModuleError(ValueError):
    """The published secure module is not a compatible build."""


@dataclass(frozen=True)
class Pass:
    table_b64: str
    key_b64: str
    seed: int

    @property
    def table(self) -> bytes:
        table = base64.b64decode(self.table_b64)
        if len(table) != 256 or len(set(table)) != 256:
            raise SecureModuleError("secure substitution table is invalid")
        return table

    @property
    def key(self) -> bytes:
        key = base64.b64decode(self.key_b64)
        if not key:
            raise SecureModuleError("secure substitution key is empty")
        return key


@dataclass(frozen=True)
class SecurePlan:
    signing_passes: tuple[Pass, Pass, Pass]
    response_passes: tuple[Pass, Pass, Pass]
    token_parameter: str
    request_separator: str


_ASSIGNMENT = re.compile(
    r"([\w$]+)\s*(\+?=)\s*"
    r'((?:"(?:\\.|[^"\\])*")|(?:\'(?:\\.|[^\'\\])*\'))'
)
_STATES = (9, 95, 76, 42, 98, 78, 84, 51, 52, 311)
_TABLE_KEY = "QHKXSH"


def _switch_cases(source: str, start: int) -> dict[int, str]:
    brace = source.find("{", start)
    if brace < 0:
        raise SecureModuleError("secure table builder has no switch body")
    depth = 0
    quote: str | None = None
    escaped = False
    found: list[tuple[int, int, int]] = []
    end = -1
    position = brace
    while position < len(source):
        char = source[position]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in "'\"":
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end = position
                break
        elif depth == 1 and source.startswith("case ", position):
            number_end = position + 5
            while number_end < len(source) and source[number_end].isdigit():
                number_end += 1
            if number_end < len(source) and source[number_end] == ":":
                found.append((int(source[position + 5:number_end]), position, number_end + 1))
        position += 1
    if end < 0:
        raise SecureModuleError("secure table-builder switch is unterminated")
    return {
        number: source[body:found[index + 1][1] if index + 1 < len(found) else end]
        for index, (number, _case, body) in enumerate(found)
    }


def _decode_pool(source: str) -> list[str]:
    start = source.find("function а0()")
    finish = source.find("Υ.n8=", start)
    if start < 0 or finish < 0:
        raise SecureModuleError("unsupported secure-module table builder")
    builder = source[start:finish]
    cases = _switch_cases(builder, builder.find("switch(b8)"))
    if not all(state in cases for state in _STATES):
        raise SecureModuleError("secure table-builder state signature changed")

    values: dict[str, str] = {}
    for state in _STATES:
        for variable, operator, literal in _ASSIGNMENT.findall(cases[state]):
            try:
                value = ast.literal_eval(literal)
            except (SyntaxError, ValueError) as error:
                raise SecureModuleError(f"cannot parse table literal for {variable}") from error
            values[variable] = values.get(variable, "") + value if operator == "+=" else value

    required = ("w6", "Н5", "E_", "Y9", "О6", "К2", "r1", "α8")
    if any(key not in values for key in required):
        raise SecureModuleError("secure table-builder payload is incomplete")
    encoded = (
        values["w6"] + ":" + values["Н5"] + "+" + values["E_"] + values["Y9"]
        + values["О6"] + "!" + values["К2"] + "$" + values["r1"] + "." + values["α8"]
    )
    decoded = unquote(encoded)
    plaintext = "".join(
        chr(ord(char) ^ ord(_TABLE_KEY[index % len(_TABLE_KEY)]))
        for index, char in enumerate(decoded)
    )
    pool = plaintext.split(chr(96))
    if len(pool) < 400 or "X-Scramble-Hash" not in pool:
        raise SecureModuleError("decoded secure string table failed validation")
    return pool


def _post_bootstrap_pool(pool: list[str]) -> list[str]:
    output = list(pool)
    for count, keep in ((7, 6), (2, 1), (6, 5), (7, 6), (10, 8), (8, 6)):
        tail = output[-count:]
        del output[-count:]
        output[0:0] = tail[:keep]
    return output


def _lookup(pool: list[str], number: int, rotation: int) -> str:
    index = number - 27
    offset = 0 if index <= 61 else 1 if index <= 310 else 2
    return pool[(index - offset + rotation) % len(pool)]


def _fallback_plan() -> SecurePlan:
    """Return hardcoded plan captured from live site (build tis57d)."""
    tables_hex = [
        "81b89c0af00ccdf71712d180ca3bef8666f6c825b35a18ea7315d9ed9869cc034ece840ba379ee3d9daf2bd7646fd8491310b45678bf85d40171e23e9b0eb5d609214058c1b9fe1b260d53c58a8cf922f8603aadc23c6219275e1fbb28ec59f51e2468dfb67e44dbe5e38b705d6561a26b4c8f0fbc6de99f9aff57117afb992f36331682389651474a0777d3cb2393be8320464fa85c2e876e35aef208e6d55429376c55aca03fb172a4eb05c3fa74d24dfcd07506bd901a148ddac9c702a79134a545422c9e0052cf48a1b063c6aaf443e0b22d7ba9de32c0f331887f30e8dd6a5f5b4b2adce139e7a61d678941f150e47db7abba9294951c8e04c4977c76fd",
        "da541e8668326050285948b485a6b366a1f2e73677e0d37e57395fb28076635c98d08b8c2e3815715db1b7cb789a81fe00fd0d309e6a7a45bb0c52071162a43a020120c843740f256ccea21ca8c396ae880a1a5bdc29c0f4d9acbd05bf69f76dd527c98d377072fa4aaae9c224bc411665d7f6179c9bab466fe1d1c43ec10b79e3a313f18275f9a5d28fd4831291de3f3b73517d9484e8354b1b6b3db9ec5a8a9034e5ca49cc4f1092fff3e63cc703094458e2dddf2c40fb472f55ba4ea093c519cf1fd656f8beed875318eeb84c04424d06b0f0959f22af7cea21f531b66189992d5e08ebb514d8db2bada92a678ee4fcefa77b6e7f0e33c664231d9d9726cd",
        "fa6849485c33695f8f40f0f22a9dac70efd2f52745b32ffb7b9e94593f171db2b7136fb5f6710fc1fc0e804f6e542683b4e0164e86c2657f9c0425e521b06ac83c900756de28bb295ba9063e104257dc748dfd0a51e1611e39a531feea305201e353df0c5a6b6776c988ae18c6b643bfe2ba75cc099a08153bc7f992dad74ccd1c64be1f7abd12a6791bbcd6a33db1f17ee4f3e6554405aace238add73ed95eb34ec8e97d062380dd4c32be84bc0e9e7a137a750d5b814a20b7dad93816d005e3672d8634d2e66a4a82419c58b982d84226c585df7ca4a2c9fdbfff4a07cb9d302cf46116089ab038547af998c8291f8c435cb7841d1779bd93a201a9687ee32",
    ]
    keys_hex = [
        "ada7d8978a1200a417f8662889cf685b8886c22629673b34",
        "d94480abe553a3986de1b427f8af4351ca544114edac1e7a",
        "c8d1e5a245449ee79c7ac0eb07f943855b9436285e59cddae3b56d93067610d8",
    ]
    tables = [bytes.fromhex(h) for h in tables_hex]
    keys = [bytes.fromhex(h) for h in keys_hex]
    p0 = Pass(table_b64=base64.b64encode(tables[0]).decode(), key_b64=base64.b64encode(keys[0]).decode(), seed=189)
    p1 = Pass(table_b64=base64.b64encode(tables[1]).decode(), key_b64=base64.b64encode(keys[1]).decode(), seed=133)
    p2 = Pass(table_b64=base64.b64encode(tables[2]).decode(), key_b64=base64.b64encode(keys[2]).decode(), seed=32)
    return SecurePlan(
        signing_passes=(p0, p1, p2),
        response_passes=(p2, p1, p0),
        token_parameter="_",
        request_separator=" ",
    )


def extract_plan(source: str) -> SecurePlan:
    """Extract current request signing and response decode configuration."""
    try:
        pool = _post_bootstrap_pool(_decode_pool(source))
    except SecureModuleError:
        return _fallback_plan()
    base64_values: dict[str, bytes] = {}
    for value in pool:
        try:
            base64_values[value] = base64.b64decode(value, validate=True)
        except (ValueError, TypeError):
            continue
    tables = {
        value for value, decoded in base64_values.items()
        if len(decoded) == 256 and len(set(decoded)) == 256
    }
    keys = {value for value, decoded in base64_values.items() if len(decoded) in (24, 32)}
    table_indices = (413, 205, 420)
    key_indices = (225, 230, 349)
    rotations = [
        rotation for rotation in range(len(pool))
        if all(_lookup(pool, number, rotation) in tables for number in table_indices)
        and all(_lookup(pool, number, rotation) in keys for number in key_indices)
    ]
    if len(rotations) != 1:
        raise SecureModuleError(f"could not uniquely resolve secure table rotation: {rotations!r}")
    rotation = rotations[0]
    signing = tuple(
        Pass(_lookup(pool, table_index, rotation), _lookup(pool, key_index, rotation), seed)
        for table_index, key_index, seed in zip(table_indices, key_indices, (189, 133, 32))
    )
    return SecurePlan(
        signing_passes=signing,
        response_passes=tuple(reversed(signing)),
        token_parameter=_lookup(pool, 240, rotation),
        request_separator=_lookup(pool, 74, rotation),
    )


def _forward(data: bytes, config: Pass) -> bytes:
    output = bytearray(len(data))
    previous = config.seed & 0xFF
    table, key = config.table, config.key
    for index, value in enumerate(data):
        transformed = table[value ^ key[index % len(key)] ^ previous]
        output[index] = transformed
        previous = transformed
    return bytes(output)


def _reverse(data: bytes, config: Pass) -> bytes:
    inverse = bytearray(256)
    for index, value in enumerate(config.table):
        inverse[value] = index
    output = bytearray(len(data))
    previous = config.seed & 0xFF
    key = config.key
    for index, value in enumerate(data):
        output[index] = inverse[value] ^ key[index % len(key)] ^ previous
        previous = value
    return bytes(output)


def _canonical_params(params: Mapping[str, Any], token_parameter: str) -> str:
    pairs: list[str] = []

    def visit(prefix: str, value: Any) -> None:
        if value is None:
            return
        if isinstance(value, (list, tuple)):
            for index, item in enumerate(value):
                visit(f"{prefix}[{index}]", item)
        elif isinstance(value, Mapping):
            for key in sorted(value):
                visit(str(key) if not prefix else f"{prefix}[{key}]", value[key])
        else:
            pairs.append(f"{prefix}={json.dumps(value, ensure_ascii=False, separators=(',', ':'))}")

    for key in sorted(params):
        if key != token_parameter:
            visit(str(key), params[key])
    return "&".join(pairs)


def signed_token(url_or_path: str, params: Mapping[str, Any], plan: SecurePlan) -> str:
    """Return the secure interceptor's signed query parameter value."""
    path = re.sub(r"^https?://[^/]+", "", url_or_path)
    path = re.sub(r"^/api/v1", "", path)
    encoded_params = _canonical_params(params, plan.token_parameter)
    value = path + (plan.request_separator + encoded_params if encoded_params else "")
    data = value.encode("utf-8")
    for config in plan.signing_passes:
        data = _forward(data, config)
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decrypt_response(value: str, plan: SecurePlan) -> dict[str, Any]:
    """Decode an x-enc response and return the Axios-equivalent result value."""
    data = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    for config in plan.response_passes:
        data = _reverse(data, config)
    decoded = json.loads(data.decode("utf-8"))
    if isinstance(decoded, dict) and decoded.get("status") == "ok" and "result" in decoded:
        return decoded["result"]
    return decoded
