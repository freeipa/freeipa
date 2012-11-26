//
// Dojo builder profile file
//


var profile = (function(){
    return {
        resourceTags: {

            // all JavaScript files are AMD modules
            amd: function(filename, mid) {
                return /\.js$/.test(filename);
            }
        }
    };
})();