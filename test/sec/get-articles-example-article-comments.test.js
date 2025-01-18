'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('Security tests for GET /articles/example-article/comments', async t => {
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

  t.test('GET /articles/example-article/comments', async t => {
    await runner.createScan({
      tests: [TestType.JWT, 'excessive_data_exposure', 'broken_access_control'],
      attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.PATH]
    })
    .threshold(Severity.MEDIUM)
    .timeout(15 * 60 * 1000)
    .run({
      method: 'GET',
      url: 'http://localhost:3000/articles/example-article/comments',
      headers: { 'Authorization': 'Token optional_jwt_token' }
    })

    t.end()
  })

  t.end()
})
