'use strict'
const t = require('tap')
const { SecRunner, TestType, Severity, HttpMethod } = require('@sectester/runner')
const startServer = require('../setup-server')

let runner;
let server;

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

// Security Test Cases

t.test('DELETE /api/articles/:slug/comments/:id', async t => {
  const promise = runner
    .createScan({
      name: t.name,
      tests: [
        TestType.SQL_INJECTION,
        TestType.CROSS_SITE_REQUEST_FORGERY,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.EXPOSED_DATABASE_DETAILS,
        TestType.FULL_PATH_DISCLOSURE,
        TestType.IMPROPER_ASSET_MANAGEMENT,
        TestType.INSECURE_OUTPUT_HANDLING,
        TestType.LOCAL_FILE_INCLUSION,
        TestType.OS_COMMAND_INJECTION,
        TestType.SECRET_TOKENS_LEAK,
        TestType.SERVER_SIDE_REQUEST_FORGERY,
        TestType.STORED_CROSS_SITE_SCRIPTING,
        TestType.UNVALIDATED_REDIRECT,
        TestType.XPATH_INJECTION,
        TestType.XML_EXTERNAL_ENTITY_INJECTION,
        TestType.CROSS_SITE_SCRIPTING
      ],
      attackParamLocations: [
        'path',
        'header'
      ]
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.DELETE,
      url: `${process.env.BRIGHT_TARGET_URL || 'http://localhost:3000'}/api/articles/test-slug/comments/1`,
      headers: {
        Authorization: 'Token jwt.token.here'
      }
    });

  await t.resolves(promise);
});
