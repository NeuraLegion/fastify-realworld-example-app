'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, Severity, AttackParamLocation, HttpMethod } = require('@sectester/runner')

let runner

// Increase timeout if necessary
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('security tests for GET /api/articles/example-article/comments', async t => {
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
      url: 'http://localhost:5000/api/articles/example-article/comments'
    })
    t.end()
  })

  t.test('csrf', async t => {
    await runner.createScan({
      tests: [TestType.Csrf],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.MEDIUM)
    .run({
      method: HttpMethod.GET,
      url: 'http://localhost:5000/api/articles/example-article/comments'
    })
    t.end()
  })

  t.test('broken_access_control', async t => {
    await runner.createScan({
      tests: [TestType.BrokenAccessControl],
      attackParamLocations: [AttackParamLocation.QUERY]
    })
    .threshold(Severity.MEDIUM)
    .run({
      method: HttpMethod.GET,
      url: 'http://localhost:5000/api/articles/example-article/comments'
    })
    t.end()
  })

  t.end()
})