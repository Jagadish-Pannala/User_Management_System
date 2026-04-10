# UMS Test Suite

## Folder structure

```
tests/
├── conftest.py                                      ← shared fixtures (all tests)
├── pytest.ini                                       ← pytest config
├── requirements-test.txt
│
├── unit/                                            ← no DB, no HTTP, mocks only
│   ├── conftest.py                                  ← mock fixtures
│   ├── Business_Layer/
│   │   ├── services/
│   │   │   └── test_auth_service.py                 ← login_user() logic
│   │   └── utils/
│   │       ├── test_input_validators.py             ← validate_email_format()
│   │       ├── test_password_utils.py               ← verify_password()
│   │       └── test_jwt_encode.py                   ← token_create()
│   └── Data_Access_Layer/
│       └── dao/
│           └── test_auth_dao.py                     ← get_user_login_data()
│                                                       check_user_first_login()
│                                                       update_last_login()
│
├── integration/                                     ← real DB + real HTTP
│   ├── conftest.py                                  ← db session, client, fixtures
│   └── Api_Layer/
│       └── routes/
│           └── test_auth_routes.py                  ← POST /auth/login routes
│
└── contract/                                        ← response shape verification
    └── test_auth_contract.py                        ← login response contract
```

## How to run

```bash
# All tests
pytest tests/

# Unit tests only (fast, no DB needed)
pytest tests/unit/ -v

# Integration tests (needs DB running)
pytest tests/integration/ -v

# Contract tests
pytest tests/contract/ -v

# Specific file
pytest tests/unit/Business_Layer/services/test_auth_service.py -v

# With coverage report
pytest tests/unit/ --cov=Business_Layer --cov-report=term-missing
```

## Naming convention

```
test_<function_or_route>_<scenario>_<expected_outcome>

Examples:
  test_login_user_valid_credentials_returns_access_token
  test_login_user_not_found_raises_404
  test_verify_password_wrong_password_raises_401
  test_check_user_first_login_no_last_login_returns_true
```

## Layer → Test type mapping

| Source file                              | Test type   | Test file                                      |
|------------------------------------------|-------------|------------------------------------------------|
| Business_Layer/services/auth_service.py  | Unit        | unit/Business_Layer/services/test_auth_service |
| Business_Layer/utils/input_validators.py | Unit        | unit/Business_Layer/utils/test_input_validators|
| Business_Layer/utils/password_utils.py   | Unit        | unit/Business_Layer/utils/test_password_utils  |
| Business_Layer/utils/jwt_encode.py       | Unit        | unit/Business_Layer/utils/test_jwt_encode      |
| Data_Access_Layer/dao/auth_dao.py        | Unit        | unit/Data_Access_Layer/dao/test_auth_dao       |
| Api_Layer/routes/auth_routes.py          | Integration | integration/Api_Layer/routes/test_auth_routes  |
| POST /auth/login response shape          | Contract    | contract/test_auth_contract                    |
