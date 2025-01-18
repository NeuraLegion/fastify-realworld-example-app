'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('Security tests for POST /profiles/johndoe/follow', async t => {
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

  t.test('POST /profiles/johndoe/follow', async t => {
    await runner.createScan({
      tests: [TestType.JWT, TestType.CSRF, TestType.BROKEN_ACCESS_CONTROL, 'business_constraint_bypass'],
      attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.BODY]
    })
    .threshold(Severity.MEDIUM)
    .timeout(15 * 60 * 1000)
    .run({
      method: 'POST',
      url: `${server.baseUrl}/profiles/johndoe/follow`,
      headers: {
        'Authorization': 'Token required_jwt_token'
      },
      body: {}
    })

    t.end()
  })

  t.end()
})
