'use strict'
const t = require('tap')
const { SecRunner, TestType, Severity, HttpMethod } = require('@sectester/runner')
const startServer = require('../../setup-server')

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

// Security Test Cases

t.test('POST /api/users/login', async t => {
  const promise = runner
    .createScan({
      name: t.name,
      tests: [
        TestType.BRUTE_FORCE_LOGIN,
        TestType.CROSS_SITE_REQUEST_FORGERY,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.FULL_PATH_DISCLOSURE,
        TestType.INSECURE_OUTPUT_HANDLING,
        TestType.SQL_INJECTION,
        TestType.SECRET_TOKENS_LEAK,
        TestType.UNVALIDATED_REDIRECT
      ],
      attackParamLocations: []
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.POST,
      url: `${process.env.BRIGHT_TARGET_URL}/api/users/login`,
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        user: {
          email: 'string',
          password: 'string'
        }
      })
    });

  await t.resolves(promise);
});
