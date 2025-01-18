'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('DELETE /articles/example-article/comments/1', async t => {
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

  await runner.createScan({
    tests: [TestType.BROKEN_ACCESS_CONTROL, TestType.JWT, 'id_enumeration'],
    attackParamLocations: [AttackParamLocation.PATH]
  })
  .threshold(Severity.MEDIUM)
  .timeout(15 * 60 * 1000)
  .run({
    method: 'DELETE',
    url: 'http://localhost:3000/articles/example-article/comments/1',
    headers: { 'Authorization': 'Token required_jwt_token' }
  })

  t.end()
})
