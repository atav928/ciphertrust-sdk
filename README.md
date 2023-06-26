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

## Version

| Version | Build | Changes |
| ------- | ----- | ------- |
| **0.0.1** | **final** | Test Relese; basic functionality |
| **1.0.1** | **final** | Available Release with API and Auth functionality |
| **1.0.2** | **a1** | Removed print |
| **1.0.2** | **a2** | Added metrics in calls and additional awaits to call on mutliple calls |
| **1.0.2** | **final** | See notes below |

### Known Bugs/Futue Features

__TODO:__

* &#9745; Create a metrics fucntion to return
* &#9745; Delete all private aand passwords being printed
* &#9744; Add logging or streaming or none
* &#9744; Add own metrics
  * &#9744; Generic metrics wrapper
  * &#9744; Logging metrics wrapper
* &#9745; Create an average, mean, total time depending on calls being made for when you want to do a full list of keys
* &#9745; Missing delete https action

#### Release Notes

#### v1.0.2

* Added Generic Metrics to each call with additional statistics that can be used.
* Added async to handle multle requests; still need to take advantage of it.
* Removed disclosure of secrets in debug prints.

__Known Bugs:__

* Too many calls cause crash or non-responsive requests leading to time out.

#### v1.0.1

Initial usable release

* Allows ability to run get functions in a wrapper.
* Supply all changes and updates with the standard get request using the api.get() call.
