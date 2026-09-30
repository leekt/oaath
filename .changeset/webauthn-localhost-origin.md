---
"@oaath/sdk": patch
---

`kernelKey` WebAuthn input accepts `http://localhost` and `http://*.localhost`
origins, with an optional port, alongside https. Browsers treat these as secure
contexts for WebAuthn, so local development and virtual-authenticator suites
can build and sign an OAAth session.
