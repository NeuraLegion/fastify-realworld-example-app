'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('DELETE /articles/:slug', async t => {
  let server

  t.beforeEach(async () => {
    server = await startServer()
    runner = new SecRunner({
      hostname: process.env.BRIGHT_HOSTNAME
    })
    await runner.init()
  })

  t.teardown(async () => {
    await runner.clear()
    await server.close()
  })

  t.test('Security tests', async t => {
    await runner.createScan({
      tests: [TestType.BROKEN_ACCESS_CONTROL, TestType.JWT, 'csrf', TestType.SQLI],
      attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.PATH]
    })
    .threshold(Severity.MEDIUM)
    .timeout(15 * 60 * 1000)
    .run({
      method: 'DELETE',
      url: `${server.baseUrl}/articles/:slug`,
      headers: { 'Authorization': 'Token jwt.token.here' }
    })

    t.end()
  })

  t.end()
})
