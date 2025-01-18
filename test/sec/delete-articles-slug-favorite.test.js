'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('DELETE /articles/:slug/favorite', async t => {
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
    tests: [TestType.JWT, TestType.BROKEN_ACCESS_CONTROL, 'CSRF', TestType.HTTP_METHOD_FUZZING],
    attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.PATH]
  })
  .threshold(Severity.MEDIUM)
  .timeout(15 * 60 * 1000)
  .run({
    method: 'DELETE',
    url: `${server.baseUrl}/articles/:slug/favorite`,
    headers: { 'Authorization': 'Token jwt.token.here' }
  })

  t.end()
})
