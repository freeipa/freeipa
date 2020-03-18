def application(environ, start_response):
    start_response('200 OK', [('Content-Type', 'text/plain')])
    remote_user = environ.get('REMOTE_USER')

    if remote_user is not None:
        yield "LOGGED IN AS: {}\n".format(remote_user).encode('utf8')
    else:
        yield b"NOT LOGGED IN\n"

    yield b"\nREMOTE_* REQUEST VARIABLES:\n\n"

    for k, v in environ.items():
        if k.startswith('REMOTE_'):
            yield "  {}: {}\n".format(k, v).encode('utf8')
