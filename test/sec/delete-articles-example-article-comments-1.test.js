'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, Severity, AttackParamLocation, HttpMethod } = require('@sectester/runner')

let runner

// Increase timeout if necessary
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('security tests', async t => {
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

  t.test('DELETE /api/articles/example-article/comments/1', async t => {
    await runner.createScan({
      tests: [TestType.BROKEN_ACCESS_CONTROL, TestType.CSRF, 'id_enumeration'],
      attackParamLocations: [AttackParamLocation.PATH]
    })
    .threshold(Severity.MEDIUM)
    .run({
      method: HttpMethod.DELETE,
      url: 'http://localhost:5000/api/articles/example-article/comments/1'
    })
    t.end()
  })

  t.end()
})