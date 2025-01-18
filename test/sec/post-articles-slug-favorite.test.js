'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
const testTimeout = 15 * 60 * 1000 // 15 minutes

// Set the timeout for the tests
jest.setTimeout(testTimeout)

t.test('SecTester integration for POST /articles/{slug}/favorite', async t => {
  let server
  let baseUrl

  t.before(async () => {
    server = await startServer()
    const address = server.server.address()
    baseUrl = `http://localhost:${address.port}`
  })

  t.teardown(() => server.close())

  t.beforeEach(async () => {
    runner = new SecRunner({
      hostname: process.env.BRIGHT_HOSTNAME
    })
    await runner.init()
  })

  t.afterEach(() => runner.clear())

  t.test('Security tests for POST /articles/{slug}/favorite', async t => {
    await runner.createScan({
      tests: [TestType.JWT, TestType.CSRF, TestType.BROKEN_ACCESS_CONTROL, 'http_method_fuzzing', TestType.XSS],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER]
    })
    .threshold(Severity.MEDIUM)
    .timeout(testTimeout)
    .run({
      method: 'POST',
      url: `${baseUrl}/articles/test-slug/favorite`,
      headers: {
        'Authorization': 'Token jwt.token.here'
      },
      body: {}
    })

    t.end()
  })

  t.end()
})
