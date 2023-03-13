# JSON-RPC API usage

Apart from Python, the FreeIPA API is also available through HTTPS exchanging
requests in JSON-RPC format.

## Basic usage

Before sending requests to the FreeIPA server, we need to properly authenticate.

It is possible to authenticate both through Kerberos and password.

### Kerberos authentication

To authenticate via Kerberos, it is needed to have actual credentials in the
credentials cache first. After this, we need to send a login request to the
FreeIPA endpoint, `https://$IPAHOSTNAME/ipa/session/login_kerberos`.

```bash
$ export KRB5CCNAME=FILE:/path/to/ccache
$ export COOKIEJAR=/path/to/my.cookie
$ export IPAHOSTNAME=ipa-master.example.com
$ kinit -k -t /path/to/service.keytab service/ipa-client.example.com
$ curl -v  \
        -H referer:https://$IPAHOSTNAME/ipa  \
        -c $COOKIEJAR -b $COOKIEJAR \
        --cacert /etc/ipa/ca.crt  \
        --negotiate -u : \
        -X POST \
        https://$IPAHOSTNAME/ipa/session/login_kerberos
```

If authentication was successful, `$COOKIEJAR` will contain all session cookies
returned from the server. We will need to pass this with every request we send
to the server.

### Password authentication

For password authentication, we just need to post it over HTTPS.

```bash
$ export COOKIEJAR=/path/to/my.cookie
$ export IPAHOSTNAME=ipa-master.example.com
$ s_username=admin s_password=mYSecReT1P2 curl -v  \
        -H referer:https://$IPAHOSTNAME/ipa  \
        -H "Content-Type:application/x-www-form-urlencoded" \
        -H "Accept:text/plain"\
        -c $COOKIEJAR -b $COOKIEJAR \
        --cacert /etc/ipa/ca.crt  \
        --data "user=$s_username&password=$s_password" \
        -X POST \
        https://$IPAHOSTNAME/ipa/session/login_password
```

Same as kerberos authentication, we will need to pass the sessions cookies with
every request.

### Request and Response format

A JSON-RPC request consists of three properties:

* `method`: A string containing the name of the name that will be called.
* `params`: the array of parameters for the command.
* `id`: the request id, it can be of any type, the response will match it.

The response received from the server consists of four properties:

* `result`: The returned Object from the command. If the command failed, this
  will be null.
* `principal`: The Kerberos principal under which identity the command was performed.
* `error`: An Error object containing information about the command if it
  failed. If it succeeded, this will be null.
* `ìd`: An ID matching the request this response is replying to.

### Sending a request

Requests should be sent to the API endpoint
`https://$IPAHOSTNAME/ipa/session/json` over HTTPS. The content type must be set
to `application/json` and session cookies obtained when authentication must be
passed with the request.

An example request for the `user_find` command would be:

```bash
curl -v  \
	-H referer:https://$IPAHOSTNAME/ipa  \
        -H "Content-Type:application/json" \
        -H "Accept:applicaton/json"\
        -c $COOKIEJAR -b $COOKIEJAR \
        --cacert /etc/ipa/ca.crt  \
        -d  '{"method":"user_find","params":[[""],{}],"id":0}' \
        -X POST \
        https://$IPAHOSTNAME/ipa/session/json
```

An easy way to understand how IPA requests are built is via the CLI, by passing
the `-vv` option to an IPA command.

```bash
$ ipa -vv user-find 
ipa: INFO: Request: {
    "id": 0,
    "method": "user_find/1",
    "params": [
        [],
        {
            "version": "2.251"
        }
    ]
}

[...]
```

## Converting JSON-RPC requests to Python

FreeIPA provides methods to convert JSON-RPC requests to Python format. This is
included in the `freeipa-python-ipaserver` package in Fedora.

```python
from ipaserver.rpcserver import jsonserver

json_request = '{"method":"user_find","params":[[""],{}],"id":0}'
j = jsonserver(api) # `api` is the initialized IPA API object

(name, args, opts, response_id) = j.unmarshal(json_request)

result = api.Command[name](*args, **opts)
```

## Reporting issues

To report issues related to API usage, they should be reproducible using the API
through Python, in order to discard errors related to misconstruction of
JSON-RPC requests. These requests can be converted to Python using the steps
mentioned earlier.
