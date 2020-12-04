/*global module:false*/
module.exports = function(grunt) {
  var awsAccountName = grunt.option('awsaccountname') || '<%= pkg.key_disabler.aws.account_name %>';
  var awsAccountId = grunt.option('awsaccountid') || '<%= pkg.key_disabler.aws.account_id %>';
  var awsRegion = grunt.option('region') || '<%= pkg.key_disabler.lambda.aws.region %>';
  var skipUsernames = grunt.option('skipusers') || '<%= pkg.key_disabler.iam.skip_usernames %>';
  var throttle = grunt.option('throttle') || '<%= pkg.key_disabler.lambda.throttle %>';

  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),

    bumpup: {
      file: 'package.json'
    },

    replace: {
      dist: {
        options: {
          patterns: [
            {
              match: 'buildversion',
              replacement: '<%= pkg.version %>'
            },
            {
              match: 'awsaccountname',
              replacement: awsAccountName
            },
            {
              match: 'awsaccountid',
              replacement: awsAccountId
            },            
            {
              match: 'deploymentregion',
              replacement: awsRegion
            },
            {
              match: 'skipusernames',
              replacement: skipUsernames
            },
            {
              match: 'emailfrom',
              replacement: '<%= pkg.key_disabler.email.from %>'
            },
            {
              match: 'emailadmin',
              replacement: '<%= pkg.key_disabler.email.admin.enabled %>'
            },
            {
              match: 'emailadminto',
              replacement: '<%= pkg.key_disabler.email.admin.to %>'
            },
            {
              match: 'emailuser',
              replacement: '<%= pkg.key_disabler.email.user %>'
            },
            {
              match: 'maskaccesskeylength',
              replacement: '<%= pkg.key_disabler.mask_accesskey_length %>'
            },
            {
              match: 'first_warning_num_days',
              replacement: '<%= pkg.key_disabler.keystates.first_warning.days %>'
            },
            {
              match: 'first_warning_message',
              replacement: '<%= pkg.key_disabler.keystates.first_warning.message %>'
            },
            {
              match: 'last_warning_num_days',
              replacement: '<%= pkg.key_disabler.keystates.last_warning.days %>'
            },
            {
              match: 'last_warning_message',
              replacement: '<%= pkg.key_disabler.keystates.last_warning.message %>'
            },
            {
              match: 'key_max_age_in_days',
              replacement: '<%= pkg.key_disabler.keystates.expired.days %>'
            },
            {
              match: 'key_expired_message',
              replacement: '<%= pkg.key_disabler.keystates.expired.message %>'
            },
            {
              match: 'key_young_message',
              replacement: '<%= pkg.key_disabler.keystates.young.message %>'
            },
            {
              match: 'throttle',
              replacement: throttle
            }
          ]
        },
        files: [
          {expand: true, flatten: true, src: ['../lambda/src/RotateAccessKey.py'], dest: '../lambda/build/'}
        ]
      }
    },

    rename: {
      release: {
        files: [{
          src: ['../releases/AccessKeyRotationPackage.zip'],
          dest: '../releases/AccessKeyRotationPackage.<%= pkg.version %>.zip'
        }]
      }
    },

    exec: {
      package_lambda_function: {
        cmd: './scripts/createZipPackage.sh'
      },
      create_lambda_policy: {
        cmd: './scripts/createLambdaAccessKeyRotationPolicy.sh "<%= pkg.key_disabler.iam.lambda.policyname %>" "<%= pkg.key_disabler.iam.lambda.rolename %>" ' + awsRegion
      },
      create_lambda_function: {
        cmd: './scripts/createLambdaFunction.sh AccessKeyRotationPackage.<%= pkg.version %>.zip <%= pkg.version %> "<%= pkg.key_disabler.lambda.function_name %>" "<%= pkg.key_disabler.iam.lambda.rolename %>" <%= pkg.key_disabler.lambda.timeout %> <%= pkg.key_disabler.lambda.memory %> ' + awsRegion
      },
      create_scheduled_event: {
        cmd: './scripts/createScheduledEvent.sh "<%=pkg.key_disabler.lambda.function_name %>" "<%= pkg.key_disabler.lambda.schedule.rulename %>" "<%= pkg.key_disabler.lambda.schedule.description %>" "<%= pkg.key_disabler.lambda.schedule.expression %>" ' + awsRegion
      },
    }

  });

  // Load NPM grunt tasks
  grunt.loadNpmTasks('grunt-contrib-watch');
  grunt.loadNpmTasks('grunt-exec');
  grunt.loadNpmTasks('grunt-replace');
  grunt.loadNpmTasks('grunt-contrib-rename');
  grunt.loadNpmTasks('grunt-bumpup');

  // Default task.
  //grunt.registerTask('default', 'watch');

  grunt.registerTask('build', ['replace']);
  grunt.registerTask('renamePackage', 'rename:release');

  grunt.registerTask('createLambdaPolicy', 'exec:create_lambda_policy');
  grunt.registerTask('packageLambdaFunction', 'exec:package_lambda_function');
  grunt.registerTask('createLambdaFunction', 'exec:create_lambda_function');
  grunt.registerTask('createScheduledEvent', 'exec:create_scheduled_event');

  grunt.registerTask('deployLambda', ['build', 'exec:package_lambda_function', 'renamePackage', 'exec:create_lambda_policy', 'exec:create_lambda_function', 'exec:create_scheduled_event']);
};
