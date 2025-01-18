'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

// Set timeout for tests
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('GET /articles/example-article/comments', async t => {
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
    tests: [TestType.JWT, TestType.BROKEN_ACCESS_CONTROL, TestType.EXCESSIVE_DATA_EXPOSURE, 'http_method_fuzzing'],
    attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.PATH, AttackParamLocation.QUERY]
  })
  .threshold(Severity.MEDIUM)
  .timeout(15 * 60 * 1000)
  .run({
    method: 'GET',
    url: `${server.baseUrl}/articles/example-article/comments`,
    headers: {
      Authorization: 'Token optional_jwt_token'
    }
  })

  t.end()
})