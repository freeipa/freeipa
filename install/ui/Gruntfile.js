module.exports = function(grunt) {
    grunt.initConfig({
        qunit: {
            all: [
                'test/all_tests.html'
            ]
        }
    });

    grunt.loadNpmTasks('grunt-contrib-qunit');
};
