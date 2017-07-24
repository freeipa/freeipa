# WebUI Unit Tests

How to run tests:

1. Run "autoreconf" command in the root of the repository
2. Run "./configure" in the root of the repository
3. Go to install/ui/src/libs/ directory
4. Run "$ make" - this step generates loader.js which is necessary for load
    current API version into WebUI. This version is necessary for checking
    response of each API call.
5. Go to install/ui/test
6. Run "$ firefox index.html"

Only Firefox browser is supported, because Google Chrome does not allow
to fetch files using AJAX and file:// protocol.

For more information about WebUI unit tests please read following:
https://www.freeipa.org/page/FreeIPAv2:UI_Unit_Tests
