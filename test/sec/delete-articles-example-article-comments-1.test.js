'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('DELETE /articles/example-article/comments/1', async t => {
  let runner
  const server = await startServer()
  t.teardown(() => server.close())

  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  })
  await runner.init()

  t.teardown(() => runner.clear())

  await runner.createScan({
    tests: [TestType.JWT, TestType.BROKEN_ACCESS_CONTROL, 'csrf', 'id_enumeration'],
    attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.PATH]
  })
  .threshold(Severity.MEDIUM)
  .timeout(15 * 60 * 1000)
  .run({
    method: 'DELETE',
    url: `${server.baseUrl}/articles/example-article/comments/1`,
    headers: {
      Authorization: 'Token required_jwt_token'
    }
  })

  t.end()
})