module.exports = function(grunt) {
    grunt.initConfig({
        qunit_junit: {
            options: {}
        },
        qunit: {
            options: {
                puppeteer: {
                    args: [
                        "--allow-file-access-from-files",
                        "--no-sandbox"
                    ]
                },
            },
            all: [
                'test/all_tests.html'
            ]
        }
    });

    grunt.loadNpmTasks('grunt-qunit-junit');
    grunt.loadNpmTasks('grunt-contrib-qunit');
    grunt.registerTask('test', ['qunit_junit', 'qunit']);
};
