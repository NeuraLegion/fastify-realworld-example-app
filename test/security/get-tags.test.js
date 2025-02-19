'use strict'
const t = require('tap')
const { SecRunner } = require('@sectester/runner')
const { TestType, Severity, HttpMethod } = require('@sectester/scan')
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

t.test('GET /api/tags - SQL_INJECTION and EXCESSIVE_DATA_EXPOSURE', async t => {
  const promise = runner
    .createScan({
      name: t.name,
      tests: [TestType.SQL_INJECTION, TestType.EXCESSIVE_DATA_EXPOSURE],
      attackParamLocations: []
    })
    .threshold(Severity.LOW)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.GET,
      url: 'http://localhost:3000/api/tags'
    });

  await t.resolves(promise);
});
