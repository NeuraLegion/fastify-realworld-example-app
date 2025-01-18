'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

// Set timeout for tests
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('POST /api/articles/{slug}/favorite', async t => {
  let runner
  const server = await startServer()
  t.teardown(() => server.close())

  // Initialize SecTester runner
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  })
  await runner.init()

  // Clear SecTester runner after each test
  t.teardown(() => runner.clear())

  // Run security tests
  await runner.createScan({
    tests: [TestType.JWT, TestType.CSRF, TestType.BROKEN_ACCESS_CONTROL, 'HTTP_METHOD_FUZZING'],
    attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.BODY]
  })
  .threshold(Severity.MEDIUM)
  .timeout(15 * 60 * 1000)
  .run({
    method: 'POST',
    url: `${server.baseUrl}/api/articles/{slug}/favorite`,
    headers: { 'Authorization': 'Token jwt.token.here' },
    body: {}
  })

  t.end()
})