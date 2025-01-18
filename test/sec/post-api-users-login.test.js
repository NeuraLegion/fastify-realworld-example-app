'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
const testTimeout = 15 * 60 * 1000 // 15 minutes

// Set the timeout for the tests
jest.setTimeout(testTimeout)

t.test('POST /api/users/login security tests', async t => {
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

  t.test('Security tests for POST /api/users/login', async t => {
    await runner
      .createScan({
        tests: [TestType.BruteForce, TestType.Csrf, TestType.Sqli, TestType.Xss],
        attackParamLocations: [AttackParamLocation.BODY]
      })
      .threshold(Severity.MEDIUM)
      .timeout(testTimeout)
      .run({
        method: 'POST',
        url: `${baseUrl}/api/users/login`,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user: {
            email: 'user@example.com',
            password: 'password123'
          }
        })
      })

    t.end()
  })

  t.end()
})
