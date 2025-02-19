'use strict'
const t = require('tap')
const { SecRunner, TestType, Severity, HttpMethod, AttackParamLocation } = require('@sectester/runner')
const startServer = require('../../setup-server')

let runner;
let server;
let baseUrl = process.env.BRIGHT_TARGET_URL || 'http://localhost:5000';

// Setup and Teardown

t.beforeEach(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  });
  await runner.init();

  server = await startServer();
});

t.afterEach(async () => {
  await runner.clear();
  await server.close();
});

t.setTimeout(15 * 60 * 1000); // 15 minutes

// Test cases

t.test('PUT /api/user', async t => {
  const promise = runner
    .createScan({
      name: t.name,
      tests: [
        TestType.SQL_INJECTION,
        TestType.CROSS_SITE_REQUEST_FORGERY,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.FULL_PATH_DISCLOSURE,
        TestType.HTML_INJECTION,
        TestType.ID_ENUMERATION,
        TestType.INSECURE_OUTPUT_HANDLING,
        TestType.LOCAL_FILE_INCLUSION,
        TestType.OS_COMMAND_INJECTION,
        TestType.PASSWORD_RESET_POISONING,
        TestType.SECRET_TOKENS_LEAK,
        TestType.SERVER_SIDE_JS_INJECTION,
        TestType.SERVER_SIDE_REQUEST_FORGERY,
        TestType.SERVER_SIDE_TEMPLATE_INJECTION,
        TestType.STORED_CROSS_SITE_SCRIPTING,
        TestType.UNVALIDATED_REDIRECT,
        TestType.CROSS_SITE_SCRIPTING
      ],
      attackParamLocations: [
        AttackParamLocation.BODY,
        AttackParamLocation.HEADER
      ]
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.PUT,
      url: `${baseUrl}/api/user`,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer <token>'
      },
      body: {
        user: {
          email: 'updateduser@example.com',
          username: 'updateduser',
          password: 'newpassword123',
          bio: 'Updated bio',
          image: 'http://example.com/image.jpg'
        }
      }
    });

  await t.resolves(promise);
});
