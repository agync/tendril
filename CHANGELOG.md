# Changelog

## [0.2.1](https://github.com/agync/tendril/compare/v0.2.1...v0.2.1) (2026-11-28)


### Bug Fixes

* **ci:** publish npm from a local path ([3c0042b](https://github.com/agync/tendril/commit/3c0042b5c986656a707b9faad378575fd1f592ac))

## [0.2.1](https://github.com/agync/tendril/compare/v0.2.0...v0.2.1) (2026-11-28)

0.2.0 was tagged but not published. 0.2.1 is the first release of the 0.2 line and also ships every change listed under 0.2.0 below. See `docs/reference/upgrading-0.2.md` for what callers need to change.


### ⚠ BREAKING CHANGES

* **core:** reject CRLs that drop revocations
* **session:** refuse revoked and pending peers
* **pairing:** notify on revoke by default
* **swift:** add TendrilError.refused case
* **ffi:** return -8 when the host refuses

### Features

* **ffi:** return -8 when the host refuses ([93d8fc7](https://github.com/agync/tendril/commit/93d8fc709b9b56ba82a662471d7f36e3790948dc))
* **pairing:** notify on revoke by default ([ce3d1fd](https://github.com/agync/tendril/commit/ce3d1fd149278d553aa8699aa47267feb572432e))
* **session:** refuse revoked and pending peers ([aefef0f](https://github.com/agync/tendril/commit/aefef0f1238f0d1efa16b23d563485e57518daa2))
* **swift:** add TendrilError.refused case ([985ac79](https://github.com/agync/tendril/commit/985ac79be90d9d78b816fae6e98e639d6bebcb63))


### Bug Fixes

* **apple:** make XCFramework build reproducible ([12402d3](https://github.com/agync/tendril/commit/12402d33534f946c8693e4c29c2e004293cf9c07))
* **core:** reject CRLs that drop revocations ([5ea5241](https://github.com/agync/tendril/commit/5ea5241fc244be484d87bf316ca1f569fcb5fc19))

## [0.2.0](https://github.com/agync/tendril/compare/v0.1.0...v0.2.0) (2026-11-28)


### ⚠ BREAKING CHANGES

* **runtime:** name n0 relays and add p2p bind

### Features

* **apple:** add remote SwiftPM and release flow ([2e35dd0](https://github.com/agync/tendril/commit/2e35dd00c7b756f0d612e7957eeeced3bef0477c))
* **bindings:** add verify_route_set to Python and Node ([f178566](https://github.com/agync/tendril/commit/f178566d252c72a2ffe5f453ddf259f7d4ccbcb0))
* **bindings:** report refusals in Python, Node, Web ([7509b52](https://github.com/agync/tendril/commit/7509b52571f225dfb04a49e58f49ca0a9eb8a08f))
* **cli:** add refusal host controls and audit event ([3eb2c9d](https://github.com/agync/tendril/commit/3eb2c9db8c65a8b1215e0b40f02ed132da93b3a0))
* **cli:** record a refusal notice on revoke ([ca80e43](https://github.com/agync/tendril/commit/ca80e43b7d3dfbffcb51014b3c3eb6cff0c126bb))
* **core:** add external ML-DSA and identity v2 ([381d4da](https://github.com/agync/tendril/commit/381d4da10b4a9d0d564c3786136a09e95f74ff74))
* **core:** add low-power policy and LKG affinity ([4a7889b](https://github.com/agync/tendril/commit/4a7889b7a4d16cc01e9eaccf9d33c92aeb72fcc9))
* **core:** add refusal types and limiter ([aee13b8](https://github.com/agync/tendril/commit/aee13b86217de59f9744dff40e306e48d8d2130e))
* **core:** fold held revocations into a roster ([69b88e0](https://github.com/agync/tendril/commit/69b88e01597af0918f9439fb40e0371a07ca4566))
* **core:** refuse known revoked and pending peers ([f6bc094](https://github.com/agync/tendril/commit/f6bc0944152a02067e83e9a269834b8fc9e92271))
* **enroll:** store routes on every surface ([b4d95c0](https://github.com/agync/tendril/commit/b4d95c00621c64a116afdcb7db91fd4871a4cc63))
* **ffi,bindings:** wire power profile & wake ([944979c](https://github.com/agync/tendril/commit/944979ccd8a3b038b264d14198ba0eb550f751d6))
* **ffi:** add custody, extension, and wake ABI ([a266e76](https://github.com/agync/tendril/commit/a266e7620ebf8507fffd1fd9b44d1938a9b0aeb2))
* **ffi:** add session peer id across bindings ([76bd452](https://github.com/agync/tendril/commit/76bd4522cea827aefcbb5426a9d83659f8eb2842))
* **ffi:** expose authenticated refusal ([93f5e23](https://github.com/agync/tendril/commit/93f5e23487950309d8e693fa5c77a71ffc64a416))
* **go:** report routes on enrollment result ([39878c8](https://github.com/agync/tendril/commit/39878c8611ea9dd82b8729c33e45705108967035))
* **go:** return RefusedError for refusals ([76daa12](https://github.com/agync/tendril/commit/76daa12db2f8506046d90e29d7d9c0c48ac2f12f))
* **kotlin:** replay route vectors, set P2P keys ([61f4d22](https://github.com/agync/tendril/commit/61f4d2220d6b5eeaa69c4e7bf075e10886f0e2af))
* **kotlin:** throw TendrilRefusedException ([0298e19](https://github.com/agync/tendril/commit/0298e1913906f6eb91db4f3d1d4da9f05623fd36))
* **mobile,web:** cut mobile & web battery drain ([7de8e3c](https://github.com/agync/tendril/commit/7de8e3c4f69e05866801fb103c1b34b166f7285d))
* **p2p:** add port mapping and bind options ([ea77ef7](https://github.com/agync/tendril/commit/ea77ef78e57277bc4ede1b0bd20ab1a54a3c9f5b))
* **pairing:** return host routes on m2m enrolment ([b4759f1](https://github.com/agync/tendril/commit/b4759f1a9fe1d4a77c7fb2a1f21ed22b6e108365))
* **policy:** order operator routes first, then source ([fd74736](https://github.com/agync/tendril/commit/fd74736ee95ee1431442857a0bdffa8a27931848))
* **relay:** add Cloudflare DO worker and guide ([131f9b8](https://github.com/agync/tendril/commit/131f9b8496c5091326c64ba3b4d13f0c789443d4))
* **relay:** add PaaS config, healthz, and deploy ([9939e3e](https://github.com/agync/tendril/commit/9939e3eaa5028ea6e053a6e09188128d587bf998))
* **relay:** add standby pool and 0-RTT fast-open ([1ba00fb](https://github.com/agync/tendril/commit/1ba00fb1948b828c2527a111e2f20dc2abd6824d))
* **roster:** manage pending host claims ([d59d3c8](https://github.com/agync/tendril/commit/d59d3c8caa73590393f7d218016e542c96395593))
* **runtime:** add low-power listeners & watchers ([d530303](https://github.com/agync/tendril/commit/d53030310e847f01cf3daa68259b888456e63789))
* **runtime:** add reachability, LKG race, & wake ([1a5cd8d](https://github.com/agync/tendril/commit/1a5cd8d64f4a58755be999301098775e5da93ca4))
* **runtime:** classify refusals and half-close ([c6771aa](https://github.com/agync/tendril/commit/c6771aa2aabda221b0c715ee180c5d0b64e13258))
* **runtime:** commit held revocations under one lock ([4e495fa](https://github.com/agync/tendril/commit/4e495fa381fd06f23616e1b8b0af60ceae6cc588))
* **runtime:** name n0 relays and add p2p bind ([e84b99c](https://github.com/agync/tendril/commit/e84b99c3feaaaffd8f722d0fbd0cb6ca913bdff6))
* **runtime:** refuse revoked and pending peers ([ee34165](https://github.com/agync/tendril/commit/ee341653c12052dda3fb36bf20389749d8c97833))
* **runtime:** run the local provider on Windows ([9765c21](https://github.com/agync/tendril/commit/9765c21a887fecbcd5018274544700351b1b61c2))
* **site:** reorder landing sections ([555bf1a](https://github.com/agync/tendril/commit/555bf1a5131a331e9a2c82e1d159dcd51187958a))
* **site:** show groups and pair setups ([7626a93](https://github.com/agync/tendril/commit/7626a93fb9e836cff4cee4752cce94d7be712918))
* **swift:** add configureP2p and route coverage ([bea5878](https://github.com/agync/tendril/commit/bea58785f7b42bb7d99cf70c3b35541421d1eff9))
* **swift:** add SE custody and background APIs ([236fad5](https://github.com/agync/tendril/commit/236fad5c8b1c11ca9c77c47a305794c81e45eec1))
* **swift:** throw TendrilError.refused on refusal ([f8f6aa1](https://github.com/agync/tendril/commit/f8f6aa1b099f04c2a265043482dc82fdab95d00c))
* **wake:** add direct HTTP/2 APNs wake provider ([26520d0](https://github.com/agync/tendril/commit/26520d04c7313eb5e24c5fca75179b7ae61bf14f))
* **web:** multi-route fallback and broker+ws ([dacd7a0](https://github.com/agync/tendril/commit/dacd7a0dd15f9da601e01ba1048ab15dfe2dfa0c))
* **webrtc:** add in-band direct upgrade ([1ed74a9](https://github.com/agync/tendril/commit/1ed74a9f7539170034a5a072f1676d790a964fb8))
* **webtransport:** add opt-in wt direct path ([cdb3f6e](https://github.com/agync/tendril/commit/cdb3f6e0667e795e7c25f1b95e9fadeef81e38ef))


### Bug Fixes

* **bindings:** commit held revocations before group reads ([48def3b](https://github.com/agync/tendril/commit/48def3b542744f241ff5e764b2925d9ef27f2cb9))
* **bindings:** share one revocation fold in Python and Node ([42e5188](https://github.com/agync/tendril/commit/42e518811640c753875e577b4eb07e78d3c97943))
* **bindings:** tidy refusal codes and docs ([1276485](https://github.com/agync/tendril/commit/1276485ea10a9b6f55ca7920ff070eb61622d5a4))
* **cli:** carry held revocations through the shared fold ([e3e53fe](https://github.com/agync/tendril/commit/e3e53fe535d0ae844b2a820bc0a3d2a7afa891e0))
* **core:** make the revocation fold idempotent ([fb45729](https://github.com/agync/tendril/commit/fb457291a773b37958105a0d472b172ef2c71cf0))
* **core:** never let a newer CRL drop a revocation ([90758c3](https://github.com/agync/tendril/commit/90758c300dadf380e60f1ef475e42e93567b5f1e))
* **core:** order held entry folds so a fold is idempotent ([a4a408a](https://github.com/agync/tendril/commit/a4a408aff06f89573ceba3179241ef729a805035))
* **docs:** self-host Cloudflare deploy badge ([65b4933](https://github.com/agync/tendril/commit/65b4933709cba0fcbe890d4b84b3bf3e85d0607b))
* **egress:** block Teredo and local-use NAT64 ([1750128](https://github.com/agync/tendril/commit/1750128752a9989699ab4a3979f3bc2472a206e0))
* **egress:** block Teredo in wt host check ([3275210](https://github.com/agync/tendril/commit/3275210a59431e908e193bb3b879f3db65d7fe0e))
* **egress:** block the Blocked set outside hint dials ([b515e27](https://github.com/agync/tendril/commit/b515e2714b07f38e015b91e41304b3040c2e1ebe))
* **egress:** check direct, overlay and iroh relay dials ([cf7c07c](https://github.com/agync/tendril/commit/cf7c07c2fd6b6b3f532e1772c719de9c0b224920))
* **egress:** close iroh relay policy gaps ([4fb6429](https://github.com/agync/tendril/commit/4fb6429df6a65268b4f79597b24e325e795615cb))
* **ffi:** keep held revocations across reloads ([7d5cc2d](https://github.com/agync/tendril/commit/7d5cc2dcc730f130d4d299c9e96fff8aa88e8b03))
* **ffi:** make endpoint close a terminal hosting state ([9441ad5](https://github.com/agync/tendril/commit/9441ad51a34948250d05836e21d3cb918019b05d))
* **identity:** check host_id at every responder ([b2c2c0e](https://github.com/agync/tendril/commit/b2c2c0eb0be0b047f43f7d2718e9560137ed85ca))
* **identity:** refuse an invalid local host_id ([97e2dc3](https://github.com/agync/tendril/commit/97e2dc3c1f349132f8824f84feb146c39ba6bd05))
* **p2p:** harden surface options and enrol tests ([51ce429](https://github.com/agync/tendril/commit/51ce4290b71d0c51363aa7bffd3d18b0c6a1347d))
* **pairing:** enforce route checks in initiators ([c914187](https://github.com/agync/tendril/commit/c9141875764f5f26f9825d3b5c7c8547b8f8ec42))
* **pairing:** reject a caller pin that disagrees ([69c9374](https://github.com/agync/tendril/commit/69c9374e356c946f25a84d7f915ff326b32b2f44))
* **relay:** bound registration lifetime and keys ([4eac281](https://github.com/agync/tendril/commit/4eac2810cee8a948d3b972284cc2e0ae14ca8454))
* **roster:** keep pending claim ops off entries ([08353c6](https://github.com/agync/tendril/commit/08353c6319b4ee73704923e5d6ca2b6af9f90eb7))
* **roster:** keep pending hosts off their host_id ([b25c1c8](https://github.com/agync/tendril/commit/b25c1c8569dc2c4d2b031364fb8661cda85e18a9))
* **runtime:** gate Unix sockets for Windows ([99d73fc](https://github.com/agync/tendril/commit/99d73fc2bbcaa6885aaded85d98924f0726fb941))
* **runtime:** persist enrol state only on change ([ad32c52](https://github.com/agync/tendril/commit/ad32c52fde4a9f0902ddecd80aa104266de63a79))
* **web:** order WebRTC E2E ping before data ([2de09d7](https://github.com/agync/tendril/commit/2de09d711792a80cc4740aa1e7796260a894c272))
* **web:** redact raw URL echoes in dial errors ([e569523](https://github.com/agync/tendril/commit/e569523111ef80d727ddd5d7f935acad41da5f94))

## 0.1.0 (2026-11-24)


### ⚠ BREAKING CHANGES

* **pairing:** add multi-route pairing URIs
* **groups:** SessionEvent, SessionAction and V2SessionAction gain new variants. V2InnerFrame::Frame.payload is now Zeroizing<Vec<u8>>. SessionHello gains a groups field that pre-groups peers reject.

### Features

* **bindings:** add Go cgo binding and tests ([bb4b5e2](https://github.com/agync/tendril/commit/bb4b5e28a728c8961f4210f93677231e0bb1422f))
* **bindings:** add Python PyO3 and Node N-API ([49864a5](https://github.com/agync/tendril/commit/49864a5bcc16f92672b0604378e698da71561722))
* **bindings:** add v2 and relay auth to C-ABI ([8bafa0d](https://github.com/agync/tendril/commit/8bafa0dbf62c171d47bc2ba62edc47ce8a1bccbc))
* **bindings:** expose m2m enrollment in all sdks ([d7a8820](https://github.com/agync/tendril/commit/d7a88203307fc1ccb3a30fe474da6416b5ea807b))
* **bindings:** support hybrid pq in runtime/sdks ([5ef999c](https://github.com/agync/tendril/commit/5ef999c17ea0b15061dc2f87d61c62db7eaa7849))
* **bindings:** wire p2p-iroh into FFI and SDKs ([7d3263d](https://github.com/agync/tendril/commit/7d3263da77a09901cc896d553dc5d7e1cd5e2dd0))
* **cli,ffi:** add relay auth, v2, and wake ([0a24ed4](https://github.com/agync/tendril/commit/0a24ed445922f2875249ec468fbf61105676d643))
* **cli:** add cli, conformance peer, and docs ([3db6904](https://github.com/agync/tendril/commit/3db69040df505b5e3eaa8f7ba6038bd1dd1975d3))
* **cli:** add embedded relay and path flags ([85df399](https://github.com/agync/tendril/commit/85df39969cda60d2c2c9d0587ae8180a529fb722))
* **core:** add HKDF P2P identity seed derivation ([5a74db1](https://github.com/agync/tendril/commit/5a74db1089508f541ed279a4e042cd51b7fec4d0))
* **core:** add hybrid pq noise xxhfs and mldsa65 ([1ce0a49](https://github.com/agync/tendril/commit/1ce0a49412b5564b4089b476ebaeab01a1b18662))
* **core:** add relay auth, PAKE pad, v2 vectors ([e4a5ea8](https://github.com/agync/tendril/commit/e4a5ea888254780945bec9e93e488dd47812e4e8))
* **core:** add roster relay hint updates ([76d4ec4](https://github.com/agync/tendril/commit/76d4ec4fe401d4495d4678004adbee0b2b9b726e))
* **core:** add sans-io state machines and policy ([9345608](https://github.com/agync/tendril/commit/934560817fb5e24c27242d98a2d5518f6f07547b))
* **core:** add v2 session control send helpers ([b86b6cb](https://github.com/agync/tendril/commit/b86b6cb7e03a4ad6aeb9148717744cd59c61fdaf))
* **core:** add Wire v2 and Relay v2 primitives ([5a24465](https://github.com/agync/tendril/commit/5a24465521453494663d09764961916cb6b7a401))
* **core:** implement m2m enrollment and burn log ([bc7bbb1](https://github.com/agync/tendril/commit/bc7bbb147f08de64e17579e99d45d708b93183d5))
* **core:** pin signing key of code-paired peers ([18d72a1](https://github.com/agync/tendril/commit/18d72a19a360501f1c9d07353b4a4098ac1c9602))
* **ffi:** add tendril-ffi C ABI crate and header ([6e1f278](https://github.com/agync/tendril/commit/6e1f2784c70a7f964d731b88cd9a8a7deec9518d))
* **ffi:** serve relay sibling links from hub ([0a6cbc3](https://github.com/agync/tendril/commit/0a6cbc3183e6f3c8a5e3c1ae9f749c9daf2d01f0))
* **go:** add group bindings ([7b0073d](https://github.com/agync/tendril/commit/7b0073d513ae9e7fd1f7218a5faab5886dbd7d72))
* **go:** add pairing URI and route calls ([06b7f99](https://github.com/agync/tendril/commit/06b7f9996a2022a134799076e278763645a0c3ea))
* **groups:** add small peer mesh groups ([03d9ef5](https://github.com/agync/tendril/commit/03d9ef577a327474f0f29274909722a41fed8fa4))
* **groups:** link group siblings over relays ([54da009](https://github.com/agync/tendril/commit/54da00997e5f22ef9ebdaef2227e6b5dbdf39e23))
* **groups:** sealed runtime state for mobile ([3bdb6b1](https://github.com/agync/tendril/commit/3bdb6b112eb3bd14ae9db36061098367ddc91a8f))
* **kotlin:** add group JNI bindings ([328edc9](https://github.com/agync/tendril/commit/328edc9dab151ba50587ea118d403c8e0fc1b2d5))
* **kotlin:** add pairing URI and route calls ([6708faa](https://github.com/agync/tendril/commit/6708faa69917c91f73e7bb79ae74aafa85ac7d49))
* **mobile:** add kotlin jni and swift wrappers ([6216184](https://github.com/agync/tendril/commit/6216184adc306ffdacc90a0d653e0fb8e3659f30))
* **node:** add group bindings ([f900801](https://github.com/agync/tendril/commit/f90080149e4b26dccf51c7da5235c43855271946))
* **node:** add pairing URI and route APIs ([2ad2ca4](https://github.com/agync/tendril/commit/2ad2ca4fc375b26925bb42627d92be08008f9203))
* **node:** add Wire v2 and transport config ([0bc2e5d](https://github.com/agync/tendril/commit/0bc2e5d236db80d16819c9b6f5c9126be38a9b5d))
* **pairing:** add multi-route pairing URIs ([e0cf199](https://github.com/agync/tendril/commit/e0cf19941f900ebba95b8a9bfa4082e0e9cba5c5))
* **python:** add group bindings ([4b36f75](https://github.com/agync/tendril/commit/4b36f755c500bdc3fe9cfc37a8a0892a2d33769b))
* **python:** add pairing URI and route APIs ([0557eeb](https://github.com/agync/tendril/commit/0557eebcd20c146848a412ea2de6973cba25b9f6))
* **python:** add relay auth, v2, and wake ([21c57e2](https://github.com/agync/tendril/commit/21c57e2f4b0e718277ab0f6c468615ed96ca50f1))
* **relay,runtime:** add auth, v2 router, harden ([2c104bc](https://github.com/agync/tendril/commit/2c104bc4c3f603975a9437924c09abb02a895b67))
* **relay:** add relay v1 spec and wss server ([e463669](https://github.com/agync/tendril/commit/e463669b607ef535feda8f3a5fea8c55367e2366))
* **runtime:** add /v2/relay and Wire v2 drivers ([00dd2f0](https://github.com/agync/tendril/commit/00dd2f0b6fa28aebf7a90441089883bf7c4b6bfa))
* **runtime:** add optional WakeProvider subsystem ([776eac3](https://github.com/agync/tendril/commit/776eac38ad379935df6937fb5750275ef85b9cef))
* **runtime:** add PeerID rate limit and P2P dial ([9a27595](https://github.com/agync/tendril/commit/9a2759576050f031cad571e6598a978812bbb1d5))
* **runtime:** add runtime and path providers ([67006d0](https://github.com/agync/tendril/commit/67006d0c1f20d3eda18ba303314b74fcd70de655))
* **runtime:** add six-rung path providers ([2958348](https://github.com/agync/tendril/commit/2958348884544f184583107a0b924a5c5dc30953))
* **runtime:** wire m2m enrollment in cli and ffi ([51d08de](https://github.com/agync/tendril/commit/51d08def4f71237217c51d728f026dcbe11290ab))
* **site:** add small peer groups ([ab0237a](https://github.com/agync/tendril/commit/ab0237a196ec464eb575604229cdedec84f2932a))
* **site:** add the landing page and docs site ([c6284f3](https://github.com/agync/tendril/commit/c6284f3067f0134797214873276409902ece9249))
* **site:** show seamless pairing ([542ab19](https://github.com/agync/tendril/commit/542ab19729b2389f9316aa44f292fda063f38d55))
* **spec:** freeze v1 specs and conformance vectors ([6699f42](https://github.com/agync/tendril/commit/6699f420ace1d24540267ccbfec0bef0db9fdf02))
* **swift:** add pairing URI and route calls ([a688818](https://github.com/agync/tendril/commit/a688818336c15a934e4a369af072c2203ac7b1e1))
* **swift:** add TendrilGroup ([845e65b](https://github.com/agync/tendril/commit/845e65bd2f2ca9e1c7502d82e8134e9c030328bc))
* **vectors:** update pq vectors and go verifier ([0f5a776](https://github.com/agync/tendril/commit/0f5a776f79fe341fa6f862e44df188874c262b8d))
* **wasm,web:** add v2, relay auth, and p2p ([e0742ff](https://github.com/agync/tendril/commit/e0742ffe8a65b1274adb24450e6d7d133a075c6c))
* **wasm:** add tendril-wasm sans-io core crate ([c6e8ef6](https://github.com/agync/tendril/commit/c6e8ef6d37dd1b0b1d2a6f5190449cba4797b3f3))
* **web:** add multi-route pairing ([70a9e35](https://github.com/agync/tendril/commit/70a9e35fb2db1dae52dd216b95c1192efacbbe72))
* **web:** add opt-in WASM iroh browser transport ([50b62a5](https://github.com/agync/tendril/commit/50b62a53659cd0d5973b1e980d08f9892d10d9c8))
* **web:** add TendrilWebGroup ([fd80308](https://github.com/agync/tendril/commit/fd803084d98f74eaaa78a05dc640ce235abddb59))
* **web:** add web sdk, demo app, and chrome e2e ([17bd2ff](https://github.com/agync/tendril/commit/17bd2ff8be5e00f118195d79a6a814db311967c5))


### Bug Fixes

* **audit:** fix utf8 host check and p2p pre-cap ([9d63531](https://github.com/agync/tendril/commit/9d635315980a7de7710ea1a69a6c7ff0dab196cc))
* **audit:** fold minor review hardening notes ([6be53ca](https://github.com/agync/tendril/commit/6be53cac764613f282488cf5a5632bfc307535a0))
* **audit:** resolve batch 2a review findings ([9b58df7](https://github.com/agync/tendril/commit/9b58df7d52e7f4c99d4f13f340540bd687e0c3cd))
* **bindings:** address maintainer review findings ([ccb43ad](https://github.com/agync/tendril/commit/ccb43ad965b73a133f79a9df18159ca0e19f138e))
* **bindings:** address phase 4 review findings ([04db69b](https://github.com/agync/tendril/commit/04db69bcc1dfc3a3f3b723abc0673d6695c5c57b))
* **bindings:** harden node, go, mobile, and jni ([ea7abe2](https://github.com/agync/tendril/commit/ea7abe2882b2e33b352f89c03ec0bd564b79b775))
* **bindings:** lock roster commits, gate v1 dial ([36f4f75](https://github.com/agync/tendril/commit/36f4f75ee2e258878be7b114ee7269da486f9a35))
* **bindings:** polish node/py v2 and wake tests ([caec48a](https://github.com/agync/tendril/commit/caec48adb4b15e805d2fe9bc4fbade38e3552e73))
* **bindings:** zeroize mobile jni and keychain mem ([aa96e74](https://github.com/agync/tendril/commit/aa96e74794d9708cabd894ff6f0fc43f9f4e52f9))
* **ci:** fix ndk awk, macos cert, release target ([791f3c2](https://github.com/agync/tendril/commit/791f3c2c9107137c5a2dd251470b34dc4aa694a0))
* **cli:** allow leading hyphen in b64url args ([3957d9a](https://github.com/agync/tendril/commit/3957d9a4b839ed00392ac48083e1c6a254226eb7))
* **cli:** fail closed on roster store errors ([e62c924](https://github.com/agync/tendril/commit/e62c924fabe5b8d56057a3cdf42c7ec3597f1764))
* **cli:** harden revocation, files, p2p, v2 ([045fb97](https://github.com/agync/tendril/commit/045fb9799687296e085a467c23665bae6a9280ce))
* **core:** apply phase 1 review hardening notes ([32cd018](https://github.com/agync/tendril/commit/32cd018349a6c487f9045342976e169636e45ed9))
* **core:** close stamp race, crl, and key gaps ([657c683](https://github.com/agync/tendril/commit/657c683747a5656aaea9c826b5c4993de10b1fd7))
* **core:** enforce ancestor path bounds on grants ([000a0c8](https://github.com/agync/tendril/commit/000a0c84b03c56698c92b51d877330d85db9d7ba))
* **core:** harden dh, crl, rekey, rotation, jcs ([e0fa8cc](https://github.com/agync/tendril/commit/e0fa8cc8c9b22a38f33b84d4f0de74ca3c89e57a))
* **core:** harden zeroize, paths, and pairing uri ([f89da1d](https://github.com/agync/tendril/commit/f89da1d20cc03f3c3f9074afd12792da96de47ea))
* **core:** match canonical CRL ids, gate v1 floor ([d9cd88c](https://github.com/agync/tendril/commit/d9cd88cc73b2c61852fcd1f0ec47af2a50ca316b))
* **core:** pad pair responses to handshake buckets ([3189f9c](https://github.com/agync/tendril/commit/3189f9cac3d6d44c1c1b3698bc5bb5e1a7d90154))
* **core:** scope local CRLs, guard rotation/floors ([b61aae5](https://github.com/agync/tendril/commit/b61aae5acd4d1eda7c2cb9cf5a2440071c0589da))
* **core:** split PAKE msg1, pad msg3, bound caches ([6d12565](https://github.com/agync/tendril/commit/6d12565553859cda6e31aedb83430813f197b618))
* **ffi,go:** enforce Roster methods and read sync ([280900b](https://github.com/agync/tendril/commit/280900b0cf571cf090e9d0e1e4532494ff518f7c))
* **ffi:** bound group accept lock wait by deadline ([90da308](https://github.com/agync/tendril/commit/90da308bca4039aa200af8383160428148fca7a5))
* **ffi:** close router race and align FFI docs ([4bb7fdb](https://github.com/agync/tendril/commit/4bb7fdbf1ff44f685235d8336c7a582f82870b47))
* **ffi:** harden persistence, locking, and routing ([5a05b40](https://github.com/agync/tendril/commit/5a05b40d41c7c1afeafbb300d52accd3b2c3c4d2))
* **ffi:** serialize roster writes under store lock ([8766383](https://github.com/agync/tendril/commit/87663834902b19e7c1e19102ebf3d8f15116cd04))
* **ffi:** set android soname and 16k alignment ([bc9b1f0](https://github.com/agync/tendril/commit/bc9b1f0362bb6d8cf938a3ddcddee87e1fd49366))
* **groups:** bind root CRL authority to root key ([cd1d4c5](https://github.com/agync/tendril/commit/cd1d4c58c8325337335a9fb9e04699a0b76651e9))
* **groups:** cap first-contact pins per peer ([2b9e13d](https://github.com/agync/tendril/commit/2b9e13dff294b296996a9774004d7638f6f53b96))
* **groups:** commit bootstrap secrets on kept path ([bf3e9d0](https://github.com/agync/tendril/commit/bf3e9d0e347784c3d727c62d27cd22d2690120eb))
* harden pre-auth, relay host, and cli checks ([5b192b4](https://github.com/agync/tendril/commit/5b192b49f5b086dda038fc0912d94d812cd2c758))
* **hardening:** close p3 audit items and notes ([573e367](https://github.com/agync/tendril/commit/573e36714cd034d2ff66737ec0be9f04a52b627a))
* **pairing:** gate unpinned host pins on sas ([db12878](https://github.com/agync/tendril/commit/db128788c8349b8c6c1d35e48cbf472a060ab5bd))
* polish web tick, cli ticket perms, docs ([10123a0](https://github.com/agync/tendril/commit/10123a0bc8562136f454bf66f7e9a1b5d933082f))
* **relay:** harden proxy, v1 sockets, key files ([c0121e3](https://github.com/agync/tendril/commit/c0121e36890d8c69e970e539b69ec5cecc13fa77))
* **relay:** harden rate limits, tls, and urls ([20c7511](https://github.com/agync/tendril/commit/20c75115e373d398cd2bb46fb3f33d254e551027))
* resolve hybrid pq review findings ([e6621dd](https://github.com/agync/tendril/commit/e6621dd4747fdb6cc70a42b73123792afca3cf27))
* **runtime:** enforce PeerID and P2P pair policy ([d0333ae](https://github.com/agync/tendril/commit/d0333aeb10fbe422e1886a5255a7a9334be394ff))
* **runtime:** fix lock order, uaf, and store ([073e1f5](https://github.com/agync/tendril/commit/073e1f50be5094dd413917f454b68c06c0405723))
* **runtime:** harden p2p privacy, policy, and cli ([0caffbd](https://github.com/agync/tendril/commit/0caffbdbba70a6bd50f6145c98394140eeac34ef))
* **runtime:** isolate router and live revocation ([1d91687](https://github.com/agync/tendril/commit/1d916877beb996468e6258c72f60b02c5dd27e67))
* **runtime:** normalize broker ws url validation ([3e61632](https://github.com/agync/tendril/commit/3e6163274ba9cbf0e9f7562c3fdf605696ab6f31))
* **runtime:** persist fork revokes, free PAKE lock ([edb850c](https://github.com/agync/tendril/commit/edb850cfc941ade01e223d38d6fbfa267c07de62))
* **runtime:** pin relay DNS, gate private relays ([6b38f19](https://github.com/agync/tendril/commit/6b38f1912ba9c5f47611f347b835886bba5d65d3))
* **runtime:** preflight v1 wire floor before dial ([4736fa8](https://github.com/agync/tendril/commit/4736fa8bddf905f23ae455cee9cdd9919bc988b5))
* **runtime:** retry accepts, cap per-key half-open ([2438d6e](https://github.com/agync/tendril/commit/2438d6e66c4a954a1a356156bfa3393c599add11))
* **runtime:** split session locking and ffi state ([61e513b](https://github.com/agync/tendril/commit/61e513b25fc598872b4ff8eb9a87087ca9686539))
* **site:** use the new package names ([a75715a](https://github.com/agync/tendril/commit/a75715ae7fae4070c6eaff9d50efd82b016bb636))
* **swift:** fix Swift 6 FFI and testing build ([7fe22fc](https://github.com/agync/tendril/commit/7fe22fcccc7af8ff4fd2e2c4adaf40396d7688e5))
* **test:** ignore foreign loopback connections ([6c03570](https://github.com/agync/tendril/commit/6c03570edfc38c49cde0275cb55097a752969845))
* **wasm,web:** zeroize exports and preserve host ([8d6247b](https://github.com/agync/tendril/commit/8d6247b5eaeecf0a469f64259f59a1bd986d5fe4))
* **wasm:** fail closed on token without relay ([35c19ee](https://github.com/agync/tendril/commit/35c19eea1a61abe3f59143a356e3961abbec1fa3))
* **wasm:** harden relay, v2, and memory handling ([e99991c](https://github.com/agync/tendril/commit/e99991c14249ba5f829867beed2d34343fed54af))
* **web:** coalesce group audit events ([a5f4ef2](https://github.com/agync/tendril/commit/a5f4ef280de66b787ae01e3c72a3d81334c84ebb))
* **web:** harden relay host, vault, demo, types ([70eb16b](https://github.com/agync/tendril/commit/70eb16b67c599b789949a7451c8880e4ae12a703))
* **web:** harden sdk, relay stream, demo, and docs ([9f3927d](https://github.com/agync/tendril/commit/9f3927d64e6e6cb9d21cc96b1f967bdbf44e054f))
* **web:** resolve iroh close race and lazy load ([d252545](https://github.com/agync/tendril/commit/d25254530ad3dcb70799754005e5325e54ba5b3f))
* **web:** warm iroh WASM before timeout and gzip ([7749dc9](https://github.com/agync/tendril/commit/7749dc97cdd5666de45067dd39e6f51fbf5cc1ad))
