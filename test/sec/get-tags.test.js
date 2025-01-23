'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, Severity, AttackParamLocation, HttpMethod } = require('@sectester/runner')

let runner

// Increase timeout if necessary
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('security tests for GET /tags', async t => {
  let server
  t.before(async () => {
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

  t.test('excessive_data_exposure', async t => {
    await runner.createScan({
      tests: [TestType.ExcessiveDataExposure],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.MEDIUM)
    .run({
      method: HttpMethod.GET,
      url: '/api/tags'
    })
    t.end()
  })

  t.test('improper_asset_management', async t => {
    await runner.createScan({
      tests: ['improper_asset_management'],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.MEDIUM)
    .run({
      method: HttpMethod.GET,
      url: '/api/tags'
    })
    t.end()
  })

  t.end()
})