# Changelog

## [2.6.1](https://github.com/coreruleset/go-ftw/compare/v2.6.0...v2.6.1) (2026-10-07)


### Bug Fixes

* **deps:** update module github.com/corazawaf/coraza/v3 to v3.8.1 [security] ([#675](https://github.com/coreruleset/go-ftw/issues/675)) ([9334419](https://github.com/coreruleset/go-ftw/commit/93344198cd87bc746de1a8903eeafd1cfa69b875))
* **deps:** update module github.com/coreruleset/ftw-tests-schema/v2 to v3 in go.mod ([#672](https://github.com/coreruleset/go-ftw/issues/672)) ([737f712](https://github.com/coreruleset/go-ftw/commit/737f7123aa46c1e6d1049220322e0ec4be31db73))
* **ftwhttp:** reject raw CR/LF characters in header values ([#670](https://github.com/coreruleset/go-ftw/issues/670)) ([4234c3e](https://github.com/coreruleset/go-ftw/commit/4234c3e02166e57fdd3574e6a9a07ae2f1513630))

## [2.6.0](https://github.com/coreruleset/go-ftw/compare/v2.5.0...v2.6.0) (2026-09-20)


### Features

* **quantitative:** add --threshold and multi-rule --rule support ([#656](https://github.com/coreruleset/go-ftw/issues/656)) ([83f941c](https://github.com/coreruleset/go-ftw/commit/83f941c6f55715c9d8c8f9374defc1a6b915607c))


### Bug Fixes

* **deps:** update all major dependencies to v3 in .github/workflows/release.yml ([#667](https://github.com/coreruleset/go-ftw/issues/667)) ([7f24117](https://github.com/coreruleset/go-ftw/commit/7f2411793c10b34d0d7d17c598e77546a372ba9e))
* **deps:** update module golang.org/x/net to v0.56.0 [security] ([#654](https://github.com/coreruleset/go-ftw/issues/654)) ([163e779](https://github.com/coreruleset/go-ftw/commit/163e779574c4b32cb640c620fbf89650ba11d81e))
* **deps:** update module golang.org/x/net to v0.58.0 in go.mod ([#665](https://github.com/coreruleset/go-ftw/issues/665)) ([32878e6](https://github.com/coreruleset/go-ftw/commit/32878e6b5c97d8d458327afcee98527b2ff3c0a8))
* fail instead of skipping unparseable test files ([#661](https://github.com/coreruleset/go-ftw/issues/661)) ([8b20bbd](https://github.com/coreruleset/go-ftw/commit/8b20bbd95a369507bd8540556f7e5d0c08624e90)), closes [#660](https://github.com/coreruleset/go-ftw/issues/660)
* **output:** emit valid GitHub Actions workflow commands for -o github ([#664](https://github.com/coreruleset/go-ftw/issues/664)) ([067f6c0](https://github.com/coreruleset/go-ftw/commit/067f6c09ef86b6499a2cdbdf4f6f34f81988bee7))
