//
// Dojo builder profile file
//


var profile = (function(){

    var js_files = /\.js$/;

    return {
        resourceTags: {

            // all JavaScript files are AMD modules
            amd: function(filename, mid) {
                return js_files.test(filename);
            }
        }
    };
})();