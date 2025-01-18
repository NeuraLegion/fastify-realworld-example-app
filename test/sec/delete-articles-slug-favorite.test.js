'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
const testTimeout = 15 * 60 * 1000 // 15 minutes

// Set the timeout for the tests
jest.setTimeout(testTimeout)

t.test('DELETE /articles/{slug}/favorite', async t => {
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

  t.test('security tests', async t => {
    await runner.createScan({
      tests: [TestType.JWT, TestType.BROKEN_ACCESS_CONTROL, 'csrf', TestType.HTTP_METHOD_FUZZING],
      attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.PATH]
    })
    .threshold(Severity.MEDIUM)
    .timeout(testTimeout)
    .run({
      method: 'DELETE',
      url: `${baseUrl}/articles/{slug}/favorite`,
      headers: { 'Authorization': 'Token jwt.token.here' }
    })

    t.end()
  })

  t.end()
})
