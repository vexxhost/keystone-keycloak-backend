# Changelog

## [0.5.0](https://github.com/vexxhost/keystone-keycloak-backend/compare/v0.4.0...v0.5.0) (2026-02-05)


### Features

* add more documentation and findings ([462bdd1](https://github.com/vexxhost/keystone-keycloak-backend/commit/462bdd1bf6f10f1300a3259dddf919efa4bb7227))
* add pagination support ([043ad04](https://github.com/vexxhost/keystone-keycloak-backend/commit/043ad0477ffd40e0a0077b1795f040549ee9d6ce))
* optimize hint methods ([3c56452](https://github.com/vexxhost/keystone-keycloak-backend/commit/3c56452eba2fdd2edcb8578166e55462a7a89719))
* use briefRepresentation only for users related methods ([c353ea8](https://github.com/vexxhost/keystone-keycloak-backend/commit/c353ea89a7a2f5c59981785078965d0f0d129c6f))


### Bug Fixes

* add flake8 exceptions and make black higher priority ([97fb011](https://github.com/vexxhost/keystone-keycloak-backend/commit/97fb0115f28e73f431e302f8b953fdd4bbe3b3f2))
* flake8 syntax ([3dc7da7](https://github.com/vexxhost/keystone-keycloak-backend/commit/3dc7da75bdb21e4e69217e1ad101e926218a6d03))
* remove exact flag when contains/startswith filter overwrites equals ([def7c7b](https://github.com/vexxhost/keystone-keycloak-backend/commit/def7c7b70c13af3958ef63dde2bd89ef165acd6d))
* remove pagination ([dc96ae3](https://github.com/vexxhost/keystone-keycloak-backend/commit/dc96ae3b5687fc93ad0fcf088df75ebe9f5917e8))


### Documentation

* add comment explaining why briefRepresentation is not used for groups ([5c8e012](https://github.com/vexxhost/keystone-keycloak-backend/commit/5c8e012f4acdb3f94e8b166252d87dd2b084a52a))

## [0.4.0](https://github.com/vexxhost/keystone-keycloak-backend/compare/v0.3.0...v0.4.0) (2025-12-09)


### Features

* add missing tenacity dependency ([12bf878](https://github.com/vexxhost/keystone-keycloak-backend/commit/12bf8781a24d4d9db0afa1f81cd590e1d8f91b64))

## [0.3.0](https://github.com/vexxhost/keystone-keycloak-backend/compare/v0.2.0...v0.3.0) (2025-12-08)


### Features

* add service account auth [A8E-64] ([#56](https://github.com/vexxhost/keystone-keycloak-backend/issues/56)) ([03e0044](https://github.com/vexxhost/keystone-keycloak-backend/commit/03e00443fe0b20c4589f7212635d918ad9824a96))
* expose user attributes for email and description ([085a1d0](https://github.com/vexxhost/keystone-keycloak-backend/commit/085a1d096216eb3214f9244eae9ee04d22b41c6e))

## [0.2.0](https://github.com/vexxhost/keystone-keycloak-backend/compare/v0.1.8...v0.2.0) (2024-10-30)


### Miscellaneous Chores

* release 0.2.0 ([a8377e6](https://github.com/vexxhost/keystone-keycloak-backend/commit/a8377e64bee169f590b62ed839ce3b45df104ef1))

## [0.1.8](https://github.com/vexxhost/keystone-keycloak-backend/compare/v0.1.7...v0.1.8) (2024-02-23)


### Bug Fixes

* remove vendor keycloak use ([3ec569d](https://github.com/vexxhost/keystone-keycloak-backend/commit/3ec569d5323c6f3272f8599fe6f41d535289a04d))

## [0.1.7](https://github.com/vexxhost/keystone-keycloak-backend/compare/v0.1.6...v0.1.7) (2024-02-07)


### Miscellaneous Chores

* switch python-keycloak to dependencies ([1d9017a](https://github.com/vexxhost/keystone-keycloak-backend/commit/1d9017a737d1aa35d679c78820abf761d79c92b2))

## [0.1.6](https://github.com/vexxhost/keystone-keycloak-backend/compare/v0.1.5...v0.1.6) (2023-10-11)


### Miscellaneous Chores

* release 0.1.6 ([a5feb70](https://github.com/vexxhost/keystone-keycloak-backend/commit/a5feb70d09f7623604fcbd9c2f001f74285a95d5))

## [0.1.5](https://github.com/vexxhost/keystone-keycloak-backend/compare/v0.1.4...v0.1.5) (2023-08-17)


### Bug Fixes

* only add groups iff there is subgroups ([6360479](https://github.com/vexxhost/keystone-keycloak-backend/commit/63604793eff2d1d1b56249bad79bc435eebfa596))

## [0.1.4](https://github.com/vexxhost/keystone-keycloak-backend/compare/v0.1.3...v0.1.4) (2023-08-16)


### Bug Fixes

* add password_expires_at ([7103ca0](https://github.com/vexxhost/keystone-keycloak-backend/commit/7103ca0a93ee9273d4692563208ad998358abccd))

## [0.1.3](https://github.com/vexxhost/keystone-keycloak-backend/compare/v0.1.2...v0.1.3) (2023-08-16)


### Bug Fixes

* KeyError on federated auth ([fe8ce19](https://github.com/vexxhost/keystone-keycloak-backend/commit/fe8ce19fd1791c80a41aae3f91a7287db66efb76))

## [0.1.2](https://github.com/vexxhost/keystone-keycloak-backend/compare/v0.1.1...v0.1.2) (2023-08-16)


### Bug Fixes

* drop dependency on keystone ([e0f3083](https://github.com/vexxhost/keystone-keycloak-backend/commit/e0f30832053e74123cca9d7fe6df50a9ee5f0302))

## [0.1.1](https://github.com/vexxhost/keystone-keycloak-backend/compare/v0.1.0...v0.1.1) (2023-08-03)


### Bug Fixes

* enable coinstallability ([#1](https://github.com/vexxhost/keystone-keycloak-backend/issues/1)) ([58dabda](https://github.com/vexxhost/keystone-keycloak-backend/commit/58dabda4415d72d034e7808bed19c607c1fa4310))

## 0.1.0 (2023-08-03)


### Bug Fixes

* enable coinstallability ([#1](https://github.com/vexxhost/keystone-keycloak-backend/issues/1)) ([58dabda](https://github.com/vexxhost/keystone-keycloak-backend/commit/58dabda4415d72d034e7808bed19c607c1fa4310))
