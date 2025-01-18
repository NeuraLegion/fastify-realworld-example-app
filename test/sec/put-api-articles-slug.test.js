'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('PUT /api/articles/{slug}', async t => {
  let runner
  const server = await startServer()
  t.teardown(() => server.close())

  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  })
  await runner.init()

  t.teardown(() => runner.clear())

  await runner.createScan({
    tests: [
      TestType.JWT,
      TestType.CSRF,
      TestType.MASS_ASSIGNMENT,
      TestType.SQLI,
      TestType.XSS,
      TestType.BROKEN_ACCESS_CONTROL
    ],
    attackParamLocations: [
      AttackParamLocation.BODY,
      AttackParamLocation.HEADER,
      AttackParamLocation.PATH
    ]
  })
  .threshold(Severity.MEDIUM)
  .timeout(15 * 60 * 1000)
  .run({
    method: 'PUT',
    url: `${server.baseUrl}/api/articles/{slug}`,
    headers: {
      'Authorization': 'Token jwt.token.here',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      article: {
        title: 'string',
        description: 'string',
        body: 'string'
      }
    })
  })

  t.end()
})