'use strict'
const t = require('tap')
const { Configuration } = require('@sectester/core');
const { SecRunner } = require('@sectester/runner');```
const { TestType, Severity } = require('@sectester/scan');
const startServer = require('../setup-server')

const configuration = new Configuration({ hostname: 'app.brightsec.com' });

let runner;

async function setupRunner() {
  runner = new SecRunner(configuration);
  await runner.init();
}

async function teardownRunner() {
  await runner.clear();
}

async function runSecurityTestXSS() {
  const scan = runner.createScan({
    tests: [TestType.XSS],
    threshold: Severity.MEDIUM,
    timeout: 300000, // 5 minutes
  });

  await scan.run({
    method: 'GET',
    url: 'http://localhost:3000/profiles/johndoe',
  });
}

async function runSecurityTestBrokenAccessControl(method, url) {
  const scan = runner.createScan({
    tests: [TestType.BROKEN_ACCESS_CONTROL],
    threshold: Severity.MEDIUM,
    timeout: 300000, // 5 minutes
  });

  await scan.run({
    method: method,
    url: url,
    headers: { Authorization: 'Bearer <token>' },
  });
}

setupRunner();

// Test for XSS vulnerability on the /profiles/johndoe endpoint

t.test('GET /profiles/johndoe for XSS', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  const response = await server.inject({
    method: 'GET',
    url: '/profiles/johndoe'
  })
  t.equal(response.statusCode, 200, 'returns a status code of 200 OK')

  await runSecurityTestXSS();

  t.end()
})

// Test for broken access control on the /profiles/johndoe/follow endpoint

t.test('POST /profiles/johndoe/follow without login', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  const response = await server.inject({
    method: 'POST',
    url: '/profiles/johndoe/follow'
  })
  t.equal(response.statusCode, 401, 'returns a status code of 401 Unauthorized')

  await runSecurityTestBrokenAccessControl('POST', 'https://localhost:3000/profiles/johndoe/follow');

  t.end()
})

t.test('DELETE /profiles/johndoe/follow without proper authorization', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  const response = await server.inject({
    method: 'DELETE',
    url: '/profiles/johndoe/follow',
    headers: { Authorization: 'Bearer <token>' }
  })
  t.equal(response.statusCode, 403, 'returns a status code of 403 Forbidden')

  await runSecurityTestBrokenAccessControl('DELETE', 'https://localhost:3000/profiles/johndoe/follow');

  t.end()
})

teardownRunner();
