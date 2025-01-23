'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity, HttpMethod } = require('@sectester/runner')

let runner

// Increase timeout if necessary
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('security tests for DELETE /profiles/johndoe/follow', async t => {
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

  t.test('DELETE /profiles/johndoe/follow', async t => {
    await runner.createScan({
      tests: [
        TestType.BROKEN_ACCESS_CONTROL,
        TestType.CSRF,
        TestType.ID_ENUMERATION,
        TestType.JWT
      ],
      attackParamLocations: [AttackParamLocation.HEADER]
    })
    .threshold(Severity.MEDIUM)
    .run({
      method: HttpMethod.DELETE,
      url: `${server.baseUrl}/profiles/johndoe/follow`,
      headers: {
        Authorization: 'Bearer <token>'
      }
    })
    t.end()
  })

  t.end()
})