'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
const testTimeout = 15 * 60 * 1000 // 15 minutes

// Set the timeout for the tests
jest.setTimeout(testTimeout)

t.test('SecTester integration for GET /api/user', async t => {
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

  // Placeholder for actual test cases
  t.test('Security tests for GET /api/user', async t => {
    await runner
      .createScan({
        tests: [TestType.BROKEN_ACCESS_CONTROL, TestType.JWT, 'EXCESSIVE_DATA_EXPOSURE', TestType.HTTP_METHOD_FUZZING],
        attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.QUERY]
      })
      .threshold(Severity.MEDIUM)
      .timeout(testTimeout)
      .run({
        method: 'GET',
        url: `${baseUrl}/api/user`,
        headers: { 'Authorization': 'Bearer <token>' }
      })

    t.end()
  })

  t.end()
})
