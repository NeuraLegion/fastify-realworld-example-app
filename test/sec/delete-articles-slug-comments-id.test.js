'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity, HttpMethod } = require('@sectester/runner')

let runner

// Increase timeout if necessary
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('DELETE /articles/:slug/comments/:id', async t => {
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

  t.test('security tests', async t => {
    await runner.createScan({
      tests: [TestType.JWT, TestType.BROKEN_ACCESS_CONTROL, 'csrf', 'id_enumeration'],
      attackParamLocations: [AttackParamLocation.PATH]
    })
    .threshold(Severity.MEDIUM)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.DELETE,
      url: '/articles/some-slug/comments/1',
      headers: { Authorization: 'Token jwt.token.here' }
    })

    t.end()
  })

  t.end()
})