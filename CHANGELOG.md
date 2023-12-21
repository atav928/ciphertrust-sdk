# Changelog

* Issues with CipherTrust `v2.7` a change in the schema possibly causes issues if `lifetime` or `refresh expire` options are not set filling up the database causing excessive CPU.
  * This is adjusted fixed in later releases.
  * Updated code to enforce `auth` refresh if the `refresh_token_lifetime` is set.
  * If `refresh_token_lifetime` is not set the default is `0` which is infinite.
* __TODO:__ Add a way to monitor the passage of `refresh_token_revoke_unused_in` as that timmer can revoke a token if it is not used after a period of time.
* It is recommended to set the parameters accordingly as to not fill up the database with unusable tokens.

## v1.0.19

* __BUG FIX:__ Optional `renew_refresh_token` param during `auth jwt token`; Yet this is not the behavior in older versions and code was built where a new `refresh_token_id` was always returned. Under newer versions this is not the case.
  * Code adjusts a raised `KeyValue` error handling any return.
  * Allows for accepting and using a new `refresh_token_id` or under new code leverage the existing `token_id`.
