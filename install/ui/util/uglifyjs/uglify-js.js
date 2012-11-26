// Modified version of the orignal uglify-js.js. Modified to be runnable
// under rhino by Petr Vobornik, Red Hat
// writeFile(), read() code written by John Resig.

function uglify(orig_code, options){
    options || (options = {});
    var jsp = uglify.parser;
    var pro = uglify.uglify;

    var ast = jsp.parse(orig_code, options.strict_semicolons); // parse code and get the initial AST
    ast = pro.ast_mangle(ast, options.mangle_options); // get a new AST with mangled names
    ast = pro.ast_squeeze(ast, options.squeeze_options); // get an AST with compression optimizations
    var final_code = pro.gen_code(ast, options.gen_options); // compressed code here
    return final_code;
};

uglify.parser = require("./lib/parse-js");
uglify.uglify = require("./lib/process");
uglify.consolidator = require("./lib/consolidator");

module.exports = uglify


importPackage(java.io);

function writeFile( file, stream ) {
    var buffer = new PrintWriter( new FileWriter( file ) );
    buffer.print( stream );
    buffer.close();
}

function read( file ) {
    var f = new File(file);
    var reader = new BufferedReader(new FileReader(f));
    var line = null;
    var buffer = new java.lang.StringBuffer(f.length());
    while( (line = reader.readLine()) != null) {
        buffer.append(line);
        buffer.append("\n");
    }
    return buffer.toString();
}

var options = {
    ast: false,
    consolidate: false,
    mangle: true,
    mangle_toplevel: false,
    no_mangle_functions: false,
    squeeze: true,
    make_seqs: true,
    dead_code: true,
    verbose: false,
    show_copyright: true,
    out_same_file: false,
    max_line_length: 32 * 1024,
    unsafe: false,
    reserved_names: null,
    defines: { },
    lift_vars: false,
    codegen_options: {
        ascii_only: false,
        beautify: false,
        indent_level: 4,
        indent_start: 0,
        quote_keys: false,
        space_colon: false,
        inline_script: false
    },
    make: false,
    output: true            // stdout
};

if (arguments.length < 2) {
    print('Invalid input\nUsage: uglify inputFile outputFile');
    quit();
}

if (arguments.indexOf('-v')) {
    print('Uglifying '+arguments[0] +'\nOutput: '+arguments[1]);
}

//read input file
var input = read(arguments[0]) + '';
var output = uglify(input, options);
writeFile(arguments[1], output);