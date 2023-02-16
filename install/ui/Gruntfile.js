module.exports = function(grunt) {
    grunt.initConfig({
        qunit_junit: {
            options: {}
        },
        qunit: {
            options: {
                puppeteer: {
                    ignoreDefaultArgs: true,
                    args: [
                        "--headless",
                        "--disable-web-security",
                        "--allow-file-access-from-files"
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
