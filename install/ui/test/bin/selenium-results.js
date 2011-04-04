if (!arguments.length) {
    print('Usage: selenium-results.js <results html>');
    quit();
}

load('lib/env.rhino.1.2.js');
load('../jquery.js');

window.location = arguments[0];

var labels = {
    result: 'Result',
    numTestTotal: 'Total',
    numTestPasses: 'Passed',
    numCommandFailures: 'Failed'
};

$('table:first tr:lt(10)').each(function() {
    var tr = $(this);

    var td = tr.children().first();

    var name = td.text().replace(/:$/, '');
    var label = labels[name];
    if (!label) return;

    td = td.next();
    var value = td.text();
    print(label+': '+value);
});
