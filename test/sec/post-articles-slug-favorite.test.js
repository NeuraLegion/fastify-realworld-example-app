'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('Security tests for POST /articles/:slug/favorite', async t => {
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

  t.test('POST /articles/:slug/favorite', async t => {
    await runner.createScan({
      tests: [TestType.JWT, 'csrf', TestType.BROKEN_ACCESS_CONTROL, 'http_method_fuzzing', TestType.XSS],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER]
    })
    .threshold(Severity.MEDIUM)
    .timeout(15 * 60 * 1000)
    .run({
      method: 'POST',
      url: `${server.baseUrl}/articles/:slug/favorite`,
      headers: { 'Authorization': 'Token jwt.token.here' },
      body: {}
    })

    t.end()
  })

  t.end()
})
