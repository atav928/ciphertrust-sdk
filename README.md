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

<details><summary>Sample Output:</summary>
<p>

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

</p></details>

## CipherTrust API Documenation

### Keys

#### Method POSTS

__Create:__

Creates a new key
Endpoint: /v1/vault/keys2/
Required: __alias__

<details><summary>Create Body Schema</summary><p>

```json
{
    "activationDate": string,
    "algorithm": string,
    "aliases": [
        {
            "alias": string,
            "index": integer,
            "type": string
        }
    ],
    "archiveDate": string,
    "certType": string,
    "compromiseDate": string,
    "compromiseOccurrenceDate": string,
    "curveid": string,
    "deactivationDate": string,
    "defaultIV": string,
    "destroyDate": string,
    "format": string,
    "generateKeyId": boolean,
    "hkdfCreateParameters": {
        "hashAlgorithm": string,
        "ikmKeyName": string,
        "info": string,
        "salt": string
    },
    "id": string,
    "idSize": integer,
    "keyId": string,
    "macSignBytes": string,
    "macSignKeyIdentifier": string,
    "macSignKeyIdentifierType": string,
    "material": string,
    "meta": {
        "ownerId": string
    },
    "muid": string,
    "name": string,
    "objectType": string,
    "padded": boolean,
    "password": string,
    "processStartDate": string,
    "protectStopDate": string,
    "publicKeyParameters": {
        "activationDate": string,
        "aliases": [
            {
                "alias": string,
                "index": integer,
                "type": string
            }
        ],
        "archiveDate": string,
        "deactivationDate": string,
        "meta": {        },
        "name": string,
        "state": string,
        "undeletable": boolean,
        "unexportable": boolean,
        "usageMask": integer
    },
    "revocationMessage": string,
    "revocationReason": string,
    "rotationFrequencyDays": string,
    "signingAlgo": string,
    "size": integer,
    "state": string,
    "undeletable": boolean,
    "unexportable": boolean,
    "usageMask": integer,
    "uuid": string,
    "wrapHKDF": {
        "hashAlgorithm": string,
        "info": string,
        "okmLen": integer,
        "salt": string
    },
    "wrapIV": string,
    "wrapKeyIDType": string,
    "wrapKeyName": string,
    "wrapPBE": {
        "dklen": integer,
        "hashAlgorithm": string,
        "iteration": integer,
        "password": string,
        "passwordIdentifier": string,
        "passwordIdentifierType": string,
        "purpose": string,
        "salt": string
    },
    "wrapPublicKey": string,
    "wrapPublicKeyPadding": string,
    "wrappingEncryptionAlgo": string,
    "wrappingHashAlgo": string,
    "wrappingMethod": string,
    "xts": boolean
}
```

</p></details>

__Export:__

Returns metadata and the material of the latest version of the key matching the given id and the JWT's account claim.

Endpoint: /v1/vault/keys2/_{id}_/export

<details><summary>Export Body Schema</summary><p>

```json
{
    "combineXts": boolean,
    "format": string,
    "macSignKeyIdentifier": string,
    "macSignKeyIdentifierType": string,
    "padded": boolean,
    "password": string,
    "pemWrap": boolean,
    "signingAlgo": string,
    "wrapHKDF": {
        "hashAlgorithm": string,
        "info": string,
        "okmLen": integer,
        "salt": string
    },
    "wrapIV": string,
    "wrapJWE": {
        "contentEncryptionAlgorithm": string,
        "jwtIdentifier": string,
        "keyEncryptionAlgorithm": string,
        "keyIdentifier": string
    },
    "wrapKeyIDType": string,
    "wrapKeyName": string,
    "wrapPBE": {
        "dklen": integer,
        "hashAlgorithm": string,
        "iteration": integer,
        "password": string,
        "passwordIdentifier": string,
        "passwordIdentifierType": string,
        "purpose": string,
        "salt": string
    },
    "wrapPublicKey": string,
    "wrapPublicKeyPadding": string,
    "wrapSymmetricKeyName": string,
    "wrappingEncryptionAlgo": string,
    "wrappingHashAlgo": string,
    "wrappingMethod": string
}
```

</p></details>

__Query-Keys:__

This operation searches for keys stored on the CipherTrust Manager. The operation is similar to the list operation. The differences are (a) a lot more search parameters can be passed in, and (b) the search parameters are passed in the body of an HTTP POST request instead of being passed as query parameters in a HTTP GET request. Normally, this operation returns a list of keys, secrets, etc., that satisfy the search criteria. When the returnOnlyIDs input parameter is specified as true, this operation just returns a list of key IDs.

<details><summary>Query Keys Body Schema</summary><p>

```json
{
    "activationAfter": string,
    "activationAt": string,
    "activationBefore": string,
    "algorithm": string,
    "algorithms": [
        string
    ],
    "aliases": [
        string
    ],
    "archiveAfter": string,
    "archiveAt": string,
    "archiveBefore": string,
    "certFields": {
        "certLength": integer,
        "certType": string,
        "dsalg": string,
        "issuerANFields": {
            "dns": [
                string
            ],
            "emailAddress": [
                string
            ],
            "ipAddress": [
                string
            ],
            "uri": [
                string
            ]
        },
        "issuerDNFields": {
            "c": [
                string
            ],
            "cn": string,
            "dc": [
                string
            ],
            "dnq": [
                string
            ],
            "email": [
                string
            ],
            "l": [
                string
            ],
            "o": [
                string
            ],
            "ou": [
                string
            ],
            "sn": string,
            "st": [
                string
            ],
            "street": [
                string
            ],
            "t": [
                string
            ],
            "uid": [
                string
            ]
        },
        "serialNumber": string,
        "subjectANFields": {
            "dns": [
                string
            ],
            "emailAddress": [
                string
            ],
            "ipAddress": [
                string
            ],
            "uri": [
                string
            ]
        },
        "subjectDNFields": {
            "c": [
                string
            ],
            "cn": string,
            "dc": [
                string
            ],
            "dnq": [
                string
            ],
            "email": [
                string
            ],
            "l": [
                string
            ],
            "o": [
                string
            ],
            "ou": [
                string
            ],
            "sn": string,
            "st": [
                string
            ],
            "street": [
                string
            ],
            "t": [
                string
            ],
            "uid": [
                string
            ]
        },
        "x509SerialNumber": string
    },
    "compromiseAfter": string,
    "compromiseAt": string,
    "compromiseBefore": string,
    "compromiseOccurranceAfter": string,
    "compromiseOccurranceAt": string,
    "compromiseOccurranceBefore": string,
    "createdAfter": string,
    "createdAt": string,
    "createdBefore": string,
    "curveIDs": [
        string
    ],
    "deactivationAfter": string,
    "deactivationAt": string,
    "deactivationBefore": string,
    "destroyAfter": string,
    "destroyAt": string,
    "destroyBefore": string,
    "id": string,
    "limit": integer,
    "linkTypes": [
        string
    ],
    "metaContains": string,
    "name": string,
    "neverExportable": boolean,
    "neverExported": boolean,
    "objectTypes": [
        string
    ],
    "processStartAfter": string,
    "processStartAt": string,
    "processStartBefore": string,
    "protectStopAfter": string,
    "protectStopAt": string,
    "protectStopBefore": string,
    "returnOnlyIDs": boolean,
    "revocationReason": string,
    "revocationReasons": [
        string
    ],
    "rotationDateReached": boolean,
    "sha1Fingerprint": string,
    "sha1Fingerprints": [
        string
    ],
    "sha256Fingerprint": string,
    "sha256Fingerprints": [
        string
    ],
    "size": integer,
    "sizes": [
        integer
    ],
    "skip": integer,
    "states": [
        string
    ],
    "updatedAfter": string,
    "updatedAt": string,
    "updatedBefore": string,
    "uri": string,
    "usageMask": integer,
    "usageMasks": [
        integer
    ],
    "version": integer,
    "versions": [
        integer
    ]
}
```

</p></details>

## Logging & Streaming

Set up local logging for any commands exectued within this SDK for tracking and debug as well as providing readable metrics. By default there is no log file created and only logs are streamed to the console screen in a default color scheme with level set to INFO. To adjust you must provide a yaml configuration file called __ciphertrust-sdk.yaml__ in one of two locations:

1. __\<USERHOME\>__/.config/ciphertrust-sdk.yaml
1. /etc/ciphertrust-sdk.yaml

__Configuration File Example:__

```yaml
LOGDIR: "/var/logs"
LOGSTREAM: true
LOGSET: true
LOGNAME: "ciphertrust_sdk.log"
LOGFILE: true
LOGLEVEL: "DEBUG"
LOGMAXBYTES: 10485760
LOGBACKUPCOUNT: 10
```

If logfile is set to true without specifying a __LOGDIR__ the log file will check the operating system and set up the log directory in the expected default location:

1. Windows: /tmp
1. MacOS: ~/Library/Logs/
1. Linux: /var/log/

## Version

| Version | Build | Changes |
| ------- | ----- | ------- |
| __0.0.1__ | __final__ | Test Relese; basic functionality |
| __1.0.1__ | __final__ | Available Release with API and Auth functionality |
| __1.0.2__ | __a1__ | Removed print |
| __1.0.2__ | __a2__ | Added metrics in calls and additional awaits to call on mutliple calls |
| __1.0.2__ | __final__ | See notes below |
| __1.0.3__ | __final__ | See notes below |
| __1.0.4__ | __final__ | See notes below |
| __1.0.5__ | __final__ | Fixed bug passing directory param in downloads call |
| __1.0.6__ | __final__ | HOTFIX with generic call |
| __1.0.7__ | __hotfix__ | Fixes issues with not raising proper errors when params are being passed |
| __1.0.7__ | __feature__ | Adjusted and tested remaining http calls; see notes for details |
| __1.0.7__ | __feature__ | Adjusted responses for all types of API calls |
| __1.0.8__ | __a1__ | Added Error Response handling to ensure metrics in responses and error reporting; reformated logging messages and added splunk style logs with color responses |
| __1.0.8__ | __a2__ | Added a 30s buffer to expiration of Auth Token |
| __1.0.8__ | __a3__ | Synced error and standard format json response under response_statistics and request_parmeters |
| __1.0.8__ | __final__ | Formated responses to return statatics on calls as well as data from call being made |
| __1.0.9__ | __hotfix__ | Added dependencies to requirements to fix installation issues |
| __1.0.10__ | __final__ | Added features and adjustments for auth timeout |
| __1.0.11__ | __final__ | Fixed issues with processing time and timezones |
| __1.0.12__ | __final__ | Migrated auth end and start times to epoch |

### Known Bugs/Futue Features

__TODO:__

* &#9745; Create a metrics fucntion to return
* &#9745; Delete all private aand passwords being printed
* &#9745; Add logging or streaming or none
* &#9744; Add own metrics
  * &#9744; Generic metrics wrapper
  * &#9744; Logging metrics wrapper
* &#9745; Create an average, mean, total time depending on calls being made for when you want to do a full list of keys
* &#9745; Missing delete https action
* &#9745; Create a download method to handle downlaoding files
* &#9745; Error in calucation for x_processing_time for a HTTP Error code ex: error="HTTPError: 422 Client Error: Unprocessable Entity,exec_time_elapsed="-14399.518375",exec_time_end="1689378714.406082",exec_time_start="1689378713.924067",exec_time_total="-14399.518375",x_processing_time="-14399.518375"
* &#9744; Documentation states return response should be JSON, but sometimes POST will return plain/text. Need to append "Accept": "application/json" to force a json response.
  * &#9744; Build out handle method for a text return if json obj is not returned.
* &#9744; remove statistics if not necessary for standard interacations.

__Known Bugs:__

* Issues with usability of code, needs reformating to make both useful and return statistics.
* unable to get post response when decrypting data.

#### Release Notes

#### v1.0.13

* Updated Requests Library dependencies.

#### v1.0.12

* Changed Start/End auth times to epoch.
* Updated requirements file.
* Added Iterations tracking in auth.

#### v1.0.11

* Fixed issue with error returning negative processing time.

#### v1.0.10

* Increased the length of time for a token by decresing the value used to compare the token is still valid from 30s to 15s.
* Added _expiration_offset_ to AuthParams which is called in Auth class to allow for adjusting the token offset.
  * Value is set for float, but could take int.
  * Cannot use a negative number as that will cause an issue.
* Migrated to use current time and convert to GMT when necessary.

__Bug Fix:__

* Fixed issue with Auth where there was an incorrect comparison in auth token forcing a creation of a new token each call.
* Adjusted time being returned to local time vs UTC.

#### v1.0.9

__Bug Fix:__

* Fixed dependency issue.

#### v1.0.8

* Changed all timestamps to utc epoch float.
* Updated formatting of logging.
* Added easy_logger to help processs on screen and rotating log formats.
* Added configuration for logger through a yaml configuration file.
* Sets a default logger configuration if one isn't supplied in a config location area.

#### v1.0.7

* Issues when parsing response depending on call done with GET due to parameters not being stripped out.
  * Created a RequestParam that strips out any additional variable arguments getting passed to avoid this issue.
  * Added error handling to ensure that proper error response is reported when issue occurs.
  * Raises local class CipherTrust Exceptions.
* Issues with PATCH, POST, and DELETE HTTP Operations due to how CipherTrust responds and how the SDK expected a response back.
  * Adjusted how each call is handled stripping out unnecessary params only passing the proper ones.
  * Adjusted how responses that are OK without any content are reorganized and responded to.
* CipherTrust responds with Zulu based time; so adjusted the response times on the API calls to follow suite.
  * Due to this all exec_time_end and exec_time_start times need to be parsed and converted properly to be able to make correct time calls.
* Adjusted requests.headers response to ensure no Dict issues are raised.
* Added status code to response to bundle into the response as with the different calls there are different OK codes that can designate the proper changes.
* Removed raising HTTP Error or CipherTrustAPI Error and send back an error message response for digestion on the other side.

#### v1.0.6

* __HOTFIX__ Issue with sandard get call passes invalid arg to response.

__TODO:__

* Need to build additional async requests when calling multiple items.
* Build out ability to send multiple requests and hold the type of requests to make it easier to use the SDK.

#### v1.0.5

* Bug fixed with passing "save_dir" into get call for downloading log files.

#### v1.0.4

* Updated standard download log file to include hostname in filename.

#### v1.0.3

* Fixed bug with headers returning a requests.exceptions.JSONDecodeError due to the way headers are formated.
* Added more timeing metrics for quanitfying calls.
* Added ability to request a download when stream=True is passed in call.

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
