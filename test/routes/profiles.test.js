'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

const configuration = { hostname: 'app.brightsec.com' }
let runner;

// Initialize SecRunner before running tests
async function initializeSecRunner() {
  runner = new SecRunner(configuration);
  await runner.init();
}

// Clear SecRunner after tests
async function clearSecRunner() {
  await runner.clear();
}

// Run security tests for GET /profiles/johndoe
async function runGetProfileSecurityTests() {
  const scan = runner.createScan({
    tests: [
      'broken_access_control',
      TestType.JWT,
      'excessive_data_exposure',
      TestType.ID_ENUMERATION
    ]
  });

  await scan.run({
    method: 'GET',
    url: 'http://localhost:3000/profiles/johndoe',
    headers: { Authorization: 'Bearer <optional_token>' }
  });
}

// Run security tests for POST /profiles/johndoe/follow
async function runPostFollowProfileSecurityTests() {
  const scan = runner.createScan({
    tests: [
      TestType.BROKEN_ACCESS_CONTROL,
      TestType.CSRF,
      'jwt'
    ]
  });

  const target = {
    method: 'POST',
    url: 'http://localhost:3000/profiles/johndoe/follow',
    headers: {
      Authorization: 'Bearer <token>'
    },
    body: {}
  };

  await scan.run(target);
}

// Run security tests for DELETE /profiles/johndoe/follow
async function runDeleteFollowProfileSecurityTests() {
  const scan = runner.createScan({
    tests: [TestType.BROKEN_ACCESS_CONTROL, TestType.CSRF, TestType.JWT]
  });

  await scan.run({
    method: 'DELETE',
    url: 'http://localhost:3000/profiles/johndoe/follow',
    headers: { Authorization: 'Bearer <token>' }
  });
}

// Main test block
initializeSecRunner().then(() => {
  t.test('GET /profiles/johndoe', async t => {
    const server = await startServer()
    t.teardown(() => server.close())

    const response = await server.inject({
      method: 'GET',
      url: '/profiles/johndoe',
      headers: { Authorization: 'Bearer <optional_token>' }
    })
    t.equal(response.statusCode, 200, 'returns a status code of 200 OK')

    await runGetProfileSecurityTests();

    t.end()
  })

  t.test('POST /profiles/johndoe/follow without login', async t => {
    const server = await startServer()
    t.teardown(() => server.close())

    const response = await server.inject({
      method: 'POST',
      url: '/profiles/johndoe/follow'
    })
    t.equal(response.statusCode, 401, 'returns a status code of 401 Unauthorized')

    await runPostFollowProfileSecurityTests();

    t.end()
  })

  t.test('DELETE /profiles/johndoe/follow security tests', async t => {
    const server = await startServer()
    t.teardown(() => server.close())

    await runDeleteFollowProfileSecurityTests();

    t.end()
  })
}).finally(clearSecRunner);
