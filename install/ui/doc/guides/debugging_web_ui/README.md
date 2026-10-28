# Debugging Web UI - FreeIPA 3.2 and later

## Introduction

Since version 3.2 (not released yet) FreeIPA Web UI uses [AMD modules](http://dojotoolkit.org/documentation/tutorials/1.8/modules/). The change also lead to introduction of JavaScript builder&compiler. Code is build into one JavaScript file by Dojo builder and further compiled by UglifyJS compiler. Overall it makes UI faster but it made debugging of production version more complicated -- such code is quite hard to read.

This document tries to describe how to report runtime error in FreeIPA Web UI.

## Browser developer tools

The main prerequisite is to know how to inspect code and thrown JS errors in browser developer tools. This document will deal only with Chrome/Chromium developer tools because, in authors option, they are the most advanced (compared to Internet Explorer 9, Firefox, Opera).

Chrome Developer tools are [documented](https://developers.google.com/chrome-developer-tools).

## JavaScript console

[JavaScript console][1] can be opened by `ctrl + shift + j` keyboard shortcut, or by `F12` and choosing `console` tab in developer tools.

Error reporting perspective, Console serves for displaying errors. If there is a unexpected error it usually indicates a bug. The error message can be expanded, it will display a call stack with source file names, line number and a link to a [Script Panel][2]. The top line is usually the source of the error.

### Expected errors

Web UI needs to have established session. If it doesn't have one, first JSON-RPC command to FreeIPA API will fail with HTTP 401 Unauthorized error. Web UI will try to authenticate by Kerberos ticket. If user doesn't have a valid ticket it will raise another error.

The output looks like this:

    POST https://vm-061.idm.lab.eng.brq.redhat.com/ipa/session/json 401 (Unauthorized) jquery.js:4
    GET https://vm-061.idm.lab.eng.brq.redhat.com/ipa/session/login_kerberos?_=1363177904558 401 (Unauthorized) jquery.js:4

Please ignore these two errors.

## Script panel

[Script panel][2] provides graphical interface to a debugger. One can inspect and step through the code.

### Compiled code

If the code is compiled, it is  usually one or several dense lines. Such code is completely unreadable -> unusable for error reporting. One should use `Pretty print` feature executed by button with `{}` icon located on the bottom. Pretty print will add proper formatting to the code. It may be required to reload the page and reproduce the bug again to have console link to new line number. At this point the Error console contains error with usable line numbers which are helpful for developers.

### Debugging with source codes

Even better reporting is when one have and can use source codes. The compiled Web UI layer is located in `/usr/share/ipa/ui/js/freeipa/app.js` file. One can copy files from source git repository in `install/ui/src/freeipa/` directory to the `/usr/share/ipa/ui/js/freeipa/` directory (in will replace the `app.js` file). By doing that, next reload of Web UI will use source files (clearing browser cache may be required). After that all JavaScript errors will contain proper source code name and line number.

A tool was made to made this task easier. It's located in git repo at `install/ui/util/sync.sh`. One can copy the files form dev machine to test machine by:

    sync.sh --host root@test.machine -fc

Notes:

* `root` is user with write rights to `/usr/share/ipa/ui/js/freeipa/` directory
* `test.machine` is name of test machine
* `-f` option is shortcut for `--freeipa`
* `-c` option is shortcut for `--clean` - wipes the content of destination directory
* working directory is `install/ui/util` in git directory
* without using `--host` option it can also work on local computer (not much tested)

If one did not backup the original app.js file, he can make new one and sync it there by:


    make-ui.sh
    sync.sh --host root@test.machine -fcC

Notes:

* `-C` is shortcut for `--compiled` and means that the compiled version, made by `make-ui.sh`, will be copied.
* `make-ui.sh` requires to have Java installed in order to work (uses Rhino)

## Conclusion

While reporting an UI bug it's good to check if there is some JavaScript error and if so, send a call stack with line numbers, preferably the ones by using source codes. If source codes are not available, pretty print function should be used and send also code (~15 lines on both sides) around the bug.

The most valuable information in order of preference are:

- steps to reproduce
- JavaScript error text with call stack with line numbers and source code names
- sreenshots

[1]: https://developers.google.com/chrome-developer-tools/docs/console
[2]: https://developers.google.com/chrome-developer-tools/docs/scripts
