// Heavily inspired by Dave Townsend's post:
// Playing with windows in restartless (bootstrapped) extensions
// http://www.oxymoronical.com/blog/2011/01/Playing-with-windows-in-restartless-bootstrapped-extensions

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cu = Components.utils;

var WindowListener = {

    setupBrowserUI: function(domWindow) {
        var doc = domWindow.document;
        domWindow.kerberosauth_listener = kerberosauth_listener(domWindow);
        doc.addEventListener('kerberos-auth-config', domWindow.kerberosauth_listener, false, true);
    },

    tearDownBrowserUI: function(domWindow) {

        var doc = domWindow.document;
        doc.removeEventListener('kerberos-auth-config', domWindow.kerberosauth_listener);
        delete domWindow.kerberosauth_listener;
    },

    // nsIWindowMediatorListener functions
    onOpenWindow: function(xulWindow) {
        // A new window has opened
        var domWindow = xulWindow.QueryInterface(Ci.nsIInterfaceRequestor).
                                  getInterface(Ci.nsIDOMWindowInternal);

        // Wait for it to finish loading
        domWindow.addEventListener("load", function listener() {
            domWindow.removeEventListener("load", listener, false);

            // If this is a browser window then setup its UI
            if (domWindow.document.documentElement.getAttribute("windowtype") === "navigator:browser") {
                WindowListener.setupBrowserUI(domWindow);
            }
        }, false);
    },

    onCloseWindow: function(xulWindow) {
    },

    onWindowTitleChange: function(xulWindow, newTitle) {
    }
};

function startup(data, reason) {
    var wm = Cc["@mozilla.org/appshell/window-mediator;1"].getService(Ci.nsIWindowMediator);

    Cu['import']("chrome://kerberosauth/content/kerberosauth.js");

    // Get the list of browser windows already open
    var windows = wm.getEnumerator("navigator:browser");
    while (windows.hasMoreElements()) {
        var domWindow = windows.getNext().QueryInterface(Ci.nsIDOMWindow);

        WindowListener.setupBrowserUI(domWindow);
    }

    // Wait for any new browser windows to open
    wm.addListener(WindowListener);
}

function shutdown(data, reason) {
    // When the application is shutting down we normally don't have to clean
    // up any UI changes made
    if (reason == APP_SHUTDOWN)
        return;

    var wm = Cc["@mozilla.org/appshell/window-mediator;1"].
        getService(Ci.nsIWindowMediator);

    // Get the list of browser windows already open
    var windows = wm.getEnumerator("navigator:browser");
    while (windows.hasMoreElements()) {
        var domWindow = windows.getNext().QueryInterface(Ci.nsIDOMWindow);
        WindowListener.tearDownBrowserUI(domWindow);
    }

    // Stop listening for any new browser windows to open
    wm.removeListener(WindowListener);

    Cu.unload("chrome://kerberosauth/content/kerberosauth.js");
}

function install() {}
function uninstall() {}