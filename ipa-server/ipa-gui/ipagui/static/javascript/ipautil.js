
/*
 * Escapes the ' " and \ characters in a string, so
 * it can be embedded inside a dynamically generated string.
 */
function jsStringEscape(input) {
    return input.gsub(/(['"\\])/, function(match){ return "\\" + match[0];} );
}
