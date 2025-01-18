'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('Security tests for GET /profiles/johndoe', async t => {
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

  t.test('GET /profiles/johndoe', async t => {
    await runner
      .createScan({
        tests: [TestType.BROKEN_ACCESS_CONTROL, TestType.JWT, 'EXCESSIVE_DATA_EXPOSURE'],
        attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.PATH]
      })
      .threshold(Severity.MEDIUM)
      .timeout(15 * 60 * 1000)
      .run({
        method: 'GET',
        url: '/profiles/johndoe',
        headers: { 'Authorization': 'Token optional_jwt_token' }
      })

    t.end()
  })

  t.end()
})
