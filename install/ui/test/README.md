# WebUI Unit Tests

## Prerequisites

1. Run `./autogen.sh` command in the root of the repository
2. Run `make -C install/ui/src/libs/` - this step generates loader.js which is necessary for load
    current API version into WebUI. This version is necessary for checking
    response of each API call.

## Running tests:

### In browser

1. Go to install/ui/test
2. Run `firefox index.html`

Only Firefox browser is supported, because Google Chrome does not allow
to fetch files using AJAX and file:// protocol.

### From command line:

1. Go to `install/ui`
2. Run `npm install`, it installs required packages specified
    in package.json file
3. Run `grunt --verbose qunit`

For more information about WebUI unit tests please read following:
https://www.freeipa.org/page/FreeIPAv2:UI_Unit_Tests
