# ciphertrust-sdk

 Thales CipherTrust API

 ## Installation

 ```bash
 >>> python -m pip install ciphertrust-sdk
 ```

## Usage

This is a baseline SDK that allows you to pass the url path and parmeters for each action:

* GET
* POST
* DELETE
* PATCH

Please see the CipherTrust Manager Playground to see full url_paths. This will only pass the authorization and return the results as described within the documentation. It can be leveraged to handle authorization and return the work for orchestration.

__Creating API Authentication:__

```python
from ciphertrust.api import API
import json

# User based credentials
username = "username"
passwd = "secretpassword"
host = "thales-host01.example.com"
api = API(username=username,password=passwd,hostname=host,verify="/path/to/certificate.pem")

response = api.get.call(url_path="vault/keys2/")
print(json.dumps(response, indent=2))
```

__Sample Output:__

```json
{
    "skip": 0,
    "limit": 10,
    "total": 100,
    "resources": [
      {
        "id": "",
        "uri": "",
        "account": "",
        "application": "",
        "devAccount": "",
        "createdAt": "",
        "name": "",
        "updatedAt": "",
        "activationDate": "",
        "state": "",
        "usageMask": 0,
        "meta": null,
        "objectType": "",
        "sha1Fingerprint": "",
        "sha256Fingerprint": "",
        "defaultIV": "",
        "version": 0,
        "algorithm": "",
        "size": 0,
        "muid": ""
      }
    ]
}
```