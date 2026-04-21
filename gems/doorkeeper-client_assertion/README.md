# doorkeeper-client_assertion

`private_key_jwt` client authentication for [Doorkeeper](https://github.com/doorkeeper-gem/doorkeeper).

> **Status**: in-app gem (Step 1). Lives under `gems/doorkeeper-client_assertion/` in the `doorkeeper-openid_connect` repo. Step 2 will extract it to an independent repository with a gemspec and standalone test suite.

## Supported specifications

- [Client Authentication using private_key_jwt](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication) (OpenID Connect Core 1.0 Section 9)
- [RFC 7521](https://datatracker.ietf.org/doc/html/rfc7521) — Assertion Framework for OAuth 2.0 Client Authentication
- [RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523) — JWT Profile for OAuth 2.0 Client Authentication

## Installation

Generate and run the migration to add `jwks` and `token_endpoint_auth_method` columns to `oauth_applications`:

```sh
rails generate doorkeeper:client_assertion:migration
rake db:migrate
```

This migration adds:
- `jwks` — stores the client's public keys as a JSON Web Key Set
- `token_endpoint_auth_method` — specifies the authentication method (`private_key_jwt`, `client_secret_basic`, etc.)
- Removes the NOT NULL constraint from `secret` (JWT authentication does not require a client secret)

> **Note**: The `change_column_null` for `secret` duplicates `rails generate doorkeeper:remove_application_secret_not_null_constraint` (see TODO below).

Configure the gem in an initializer (TODO: install generator not yet implemented — create manually for now):

```ruby
# config/initializers/doorkeeper_client_assertion.rb
Doorkeeper::ClientAssertion.configure do
  # client_assertion_algorithms %w[RS256 ES256]
  # jwt_assertion_exp_tolerance 300
  # on_jwt_verification_failure ->(error, context) { }
end
```

## Configuration

All settings are optional. The defaults cover the most common use cases.

- **`client_assertion_algorithms`**
  - Algorithms accepted for JWT client assertion signatures.
  - Default: `%w[RS256 ES256]`
  - Example: `client_assertion_algorithms %w[RS256 RS384 RS512 ES256 ES384 ES512]`

- **`jwt_assertion_exp_tolerance`**
  - Clock skew tolerance in seconds applied when validating `exp`, `nbf`, and `iat` claims.
  - Default: `300` (5 minutes)
  - Example: `jwt_assertion_exp_tolerance 600`

- **`on_jwt_verification_failure`**
  - Callback invoked when JWT verification fails. Useful for logging or monitoring.
  - Default: no-op
  - Example:
    ```ruby
    on_jwt_verification_failure ->(error, context) do
      Rails.logger.warn "[ClientAssertion] #{error.class}: #{error.message} (app: #{context[:application_id]})"
    end
    ```

## Usage

### Registering a client with private_key_jwt

Create an `Doorkeeper::Application` with `token_endpoint_auth_method: 'private_key_jwt'` and a JWKS containing the client's public key(s):

```ruby
Doorkeeper::Application.create!(
  name: 'My Client',
  redirect_uri: 'https://client.example.com/callback',
  token_endpoint_auth_method: 'private_key_jwt',
  jwks: {
    keys: [
      {
        kty: 'EC',
        crv: 'P-256',
        x: 'WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis',
        y: 'y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE',
        kid: 'key-1'
      }
    ]
  }.to_json
)
```

When the JWKS contains multiple keys, each key MUST have a `kid` so the server can select the correct one (OpenID Connect Core Section 10.1).

### Authenticating at the token endpoint

Send a signed JWT as `client_assertion` with `client_assertion_type` set to the registered URN ([RFC 7521 Section 4.2](https://datatracker.ietf.org/doc/html/rfc7521#section-4.2)):

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=...
&redirect_uri=https://client.example.com/callback
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=eyJhbGc...
```

The JWT must contain the following claims ([RFC 7523 Section 3](https://datatracker.ietf.org/doc/html/rfc7523#section-3)):

| Claim | Requirement | Value |
|-------|-------------|-------|
| `iss` | REQUIRED (RFC 7523) | client_id |
| `sub` | REQUIRED (RFC 7523) | client_id |
| `aud` | REQUIRED (RFC 7523) | token endpoint URL (without query string) |
| `exp` | REQUIRED (RFC 7523) | expiration time |
| `iat` | REQUIRED (OIDC Core Section 9) | issuance time |

---

## TODO

### Add an install generator for the initializer

Currently only a migration generator exists (`doorkeeper:client_assertion:migration`).
An install generator should create `config/initializers/doorkeeper_client_assertion.rb` so users can configure the gem without hand-writing the block:

```ruby
Doorkeeper::ClientAssertion.configure do
  # client_assertion_algorithms %w[RS256 ES256]
  # jwt_assertion_exp_tolerance 300
  # on_jwt_verification_failure ->(error, context) { }
end
```

**Candidate**: add `InstallGenerator` alongside the existing `MigrationGenerator`, following the same pattern as `doorkeeper-openid_connect`'s install generator.

---

### Remove `change_column_null` from the migration template once doorkeeper#1775 ships

`generators/doorkeeper/client_assertion/templates/migration.rb.erb` currently includes:

```ruby
# TODO: Remove this line once doorkeeper-gem/doorkeeper#1775 is released
# Users can then use: rails generate doorkeeper:remove_application_secret_not_null_constraint
change_column_null :oauth_applications, :secret, true
```

Once doorkeeper ships `remove_application_secret_not_null_constraint` and the minimum supported doorkeeper version is bumped accordingly, remove the `change_column_null` line from the template and update the setup instructions to run that generator separately.

---

### Investigate moving `jwks_format` out of `self.prepended`

In `application_extension.rb`, the `jwks_format` validation method is currently defined inside `self.prepended` via `base.class_eval`:

```ruby
def self.prepended(base)
  base.class_eval do
    validate :jwks_format, if: -> { uses_private_key_jwt? }

    private

    def jwks_format
      # ...
    end
  end
end
```

The `class_eval` block is required for `validate :jwks_format` because Rails resolves the method name on the receiver class at call time—but since `prepend` inserts the module into the inheritance chain, instance methods defined directly in the module body should be visible to the class.

Investigate whether `validate` and `jwks_format` can be split:

```ruby
def self.prepended(base)
  base.validate :jwks_format, if: -> { uses_private_key_jwt? }
end

private

def jwks_format
  # ...
end
```

Points to verify: Rails callback resolution with `prepend`, Ruby version compatibility, and whether `private` in the module body correctly hides the method from the public API.
