def application(environ, start_response):
    start_response('200 OK', [('Content-Type', 'text/plain')])
    logged_in = 'REMOTE_USER' in environ

    if logged_in:
        yield "LOGGED IN AS: {}\n".format(environ['REMOTE_USER']).encode('utf8')
    else:
        yield b"NOT LOGGED IN\n"

    yield b"\nREMOTE_* REQUEST VARIABLES:\n\n"

    for k, v in environ.items():
        if k.startswith('REMOTE_'):
            yield "  {}: {}\n".format(k, v).encode('utf8')

