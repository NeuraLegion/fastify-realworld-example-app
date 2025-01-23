'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, Severity, AttackParamLocation, HttpMethod } = require('@sectester/runner')

let runner

// Increase timeout if necessary
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('security tests for POST /profiles/johndoe/follow', async t => {
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

  t.test('POST /profiles/johndoe/follow', async t => {
    await runner.createScan({
      tests: [
        TestType.BROKEN_ACCESS_CONTROL,
        TestType.CSRF,
        TestType.BRUTE_FORCE_LOGIN,
        TestType.JWT
      ],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.MEDIUM)
    .run({
      method: HttpMethod.POST,
      url: '/profiles/johndoe/follow',
      headers: {
        Authorization: 'Bearer <token>'
      }
    })

    t.end()
  })

  t.end()
})