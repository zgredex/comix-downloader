# Browser-free architecture and AI handoff

## Non-negotiable boundary

The active downloader must remain browser-free. Do not add nodriver, Selenium,
Playwright, Chromium, browser cookies, canvas extraction, a JavaScript runtime,
or a captured plaintext/keystream fallback.

The only network client in the active path is curl_cffi. The only asset
analysis is static Python parsing.

## Modules

| Module | Responsibility |
| --- | --- |
| src/api/secure.py | Static current secure-module extraction, token signing, and API response decryption. |
| src/api/comix.py | BrowserFreeComix cache and ComixAPI facade used by GUI and CLI. |
| src/utils/session.py | Thread-local curl_cffi sessions for concurrent image transfers. |
| src/core/downloader.py | Retained bounded chapter/image worker pools, retries, and format dispatch. |
| gui/ | Retained PyQt6/QML interface with browser-free bridges. |

## Secure asset extraction

The current secure module stores a string pool in a percent-escaped payload.
The parser:

1. Locates the published function а0() table builder.
2. Reassembles normal-branch string assignments.
3. Percent-decodes and XORs the data with repeating QHKXSH.
4. Applies the six fixed bootstrap table shuffles.
5. Solves the remaining table rotation by identifying exactly three 256-byte
   permutations and exactly three 24/24/32-byte base64 keys.

If these invariants do not hold, SecureModuleError is raised. Update the
static parser, do not bypass it with a browser.

## Request signing

The request interceptor signs the normalized API path and existing query
parameters. The token belongs in the query parameter currently named _.

For every asset-derived pass with permutation P, key K, and seed s:

~~~
previous = s
for each input byte:
    output = P[input XOR K[index modulo key length] XOR previous]
    previous = output
~~~

The three forward passes are URL-safe-base64 encoded without padding.

## Response decoding

The API body has an e field with a base64url value. Decode it and apply the
same passes in reverse order:

~~~
inverse[P[index]] = index
previous = seed
for each ciphertext byte:
    output = inverse[ciphertext] XOR K[index modulo key length] XOR previous
    previous = ciphertext
~~~

The result is UTF-8 JSON. A successful wrapper with status ok is unwrapped to
its result member, matching the website client.

## Concurrency

Each image worker receives a thread-local curl_cffi Session. This avoids
sharing mutable session state between ThreadPoolExecutor workers while
retaining Chrome-like TLS behavior. Chapter workers are also bounded by
DownloadConfig.

Always validate one full chapter after changing signing, decoding, retries, or
worker counts:

1. API returns the expected page count.
2. All CBZ image entries have valid image signatures.
3. zipfile.testzip() returns no error.

## Upstream provenance

The upstream GUI, CLI, exporter, data model, retry, and worker-pool structure
were retained under its MIT license. See NOTICE.md. Browser-dependent source
was deliberately removed rather than left as an unused fallback.
