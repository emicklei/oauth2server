https://github.com/oauth2-proxy/oauth2-proxy


## example requests

### authorize
```
https://some.app/authorize
?client_id=9a6a1dbe-546f-4983-96b0-23b267aaba76
&response_type=code
&code_challenge=RxFIhaomS9xD-5CsQY0M1csAodfNU_-j6fId0tHco2g
&code_challenge_method=S256
&redirect_uri=http%3A%2F%2F127.0.0.1%3A33418
&state=%2FNtqQEX04IkuttS%2BiHqVFA%3D%3D
```

### token
```
https://some.app/token
?client_id=9a6a1dbe-546f-4983-96b0-23b267aaba76
&grant_type=authorization_code
&code=1e6b0a73-06c0-4622-bc6a-d6929e70efe1
&redirect_uri=http%3A%2F%2F127.0.0.1%3A33418
&code_verifier=9122e976a511934fb8918c766d2e9e34ad5a75e89d0859ff292dfcb1a92160e3
&client_secret=a021fce1-ebd0-4862-a8c1-ded798adbaae"
```