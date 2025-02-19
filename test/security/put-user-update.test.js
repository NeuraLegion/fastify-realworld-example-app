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

t.test('PUT /api/user', async t => {
  const promise = runner
    .createScan({
      name: t.name,
      tests: [
        TestType.SQL_INJECTION,
        TestType.CROSS_SITE_REQUEST_FORGERY,
        TestType.EXCESSIVE_DATA_EXPOSURE,
        TestType.INSECURE_OUTPUT_HANDLING,
        TestType.SECRET_TOKENS_LEAK,
        TestType.HTML_INJECTION,
        TestType.STORED_CROSS_SITE_SCRIPTING
      ],
      attackParamLocations: []
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.PUT,
      url: 'http://localhost:3000/api/user',
      headers: {
        'Authorization': 'Token jwt.token.here',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        user: {
          email: 'string',
          username: 'string',
          password: 'string',
          bio: 'string',
          image: 'string'
        }
      })
    });

  await t.resolves(promise);
});
