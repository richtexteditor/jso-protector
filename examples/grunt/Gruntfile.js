"use strict";

module.exports = function configureGrunt(grunt) {
  grunt.initConfig({
    jsoProtector: {
      release: {
        options: {
          apiKey: process.env.JSO_API_KEY,
          apiPassword: process.env.JSO_API_PASSWORD,
          input: "dist",
          output: "dist-protected",
          preset: "balanced",
          exclude: ["**/vendor/**"],
          manifest: "dist-protected/jso-manifest.json",
          maxGrowthRatio: 8
        },
        files: [{
          expand: true,
          cwd: "dist",
          src: ["**/*.js", "!**/*.map"],
          dest: "dist-protected"
        }]
      }
    }
  });

  require("jso-protector/grunt")(grunt);
  grunt.registerTask("protect", ["jsoProtector:release"]);
};
