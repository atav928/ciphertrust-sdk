# Changelog

* Issues with CipherTrust `v2.7` that made a change in the backend database and how refresh tokens are handled. Since they are not deleted and infinite they are filling up servers causing them to become unresponsive.
  * This is fixed in upcoming releases.
  * Updated code to enforce `auth` refresh if the `refresh_token_lifetime` is set.
  * If `refresh_token_lifetime` is not set the default is `0` which is infinite.
* __TODO:__ Add a way to monitor the passage of `refresh_token_revoke_unused_in` as that timmer can revoke a token if it is not used after a period of time.
* It is recommended to set the parameters accordingly as to not fill up the database with unusable tokens.
