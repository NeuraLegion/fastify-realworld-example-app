'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, Severity, AttackParamLocation, HttpMethod } = require('@sectester/runner')

let runner

// Increase timeout if necessary
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('security tests for GET /articles/:slug/comments', async t => {
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

  t.test('broken_access_control', async t => {
    await runner.createScan({
      tests: [TestType.BROKEN_ACCESS_CONTROL],
      attackParamLocations: [AttackParamLocation.PATH]
    })
    .threshold(Severity.HIGH)
    .run({
      method: HttpMethod.GET,
      url: `${server.baseUrl}/articles/test-slug/comments`
    })
    t.end()
  })

  t.test('excessive_data_exposure', async t => {
    await runner.createScan({
      tests: [TestType.EXCESSIVE_DATA_EXPOSURE],
      attackParamLocations: [AttackParamLocation.PATH]
    })
    .threshold(Severity.HIGH)
    .run({
      method: HttpMethod.GET,
      url: `${server.baseUrl}/articles/test-slug/comments`
    })
    t.end()
  })

  t.test('id_enumeration', async t => {
    await runner.createScan({
      tests: [TestType.ID_ENUMERATION],
      attackParamLocations: [AttackParamLocation.PATH]
    })
    .threshold(Severity.HIGH)
    .run({
      method: HttpMethod.GET,
      url: `${server.baseUrl}/articles/test-slug/comments`
    })
    t.end()
  })

  t.end()
})