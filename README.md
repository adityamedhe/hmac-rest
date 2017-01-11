#hmac-rest
[http://github.com/adityamedhe/hmac-rest] (http://github.com/adityamedhe/hmac-rest)

## Purpose
*Compatible with ExpressJS*.

This package allows you to build REST endpoints using HMAC authentication, using a traditional username password user store.

## Required HTTP Headers
- `hmacdate`: should be a date string in ISO format
- `authentication`: should be a string of the format:
hmac (space) (username) : (sha256 HMAC hash). For example: "hmac adimedhe:9283ur9283ur01983ur018u".

### How to compute hash?
Compute a SHA256 HMAC Hash using any popular crypto library (Google CryptoJS recommended). 

- The string input for the hash should be: 
HTTP Method + Request URL (after host) + `hmacdate` header value.
- The hash secret should be the user password, as stored in user store.

## API

###Creating object:

`var HmacRest = require('hmac-rest');`

###Using as an *ExpressJS* middleware:

`app.use(new HmacRest (verify_function, error_json))`

- `verify_function` is a function supplied by user which receives two parameters: `(username, done)`. 

    - `username` is the ID of the user whose authentication is to be done.
    - `done` is a function callback with the parameters `(err, secret)` which has to be invoked by `(verify_function)`, passing in the secret of the user, as retrieved from user store.

- `error_json` is the JSON object to be sent as response, along with a HTTP 401 / 400 Header, when authentication fails / authentication information is missing.

