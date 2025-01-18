'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner

// Increase the timeout for the tests
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('PUT /articles/{slug}', async t => {
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

  t.test('Security tests', async t => {
    await runner.createScan({
      tests: [TestType.JWT, TestType.CSRF, TestType.MASS_ASSIGNMENT, TestType.XSS, TestType.SQLI],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER]
    })
    .threshold(Severity.MEDIUM)
    .timeout(15 * 60 * 1000)
    .run({
      method: 'PUT',
      url: `${server.baseUrl}/articles/{slug}`,
      headers: {
        'Authorization': 'Token jwt.token.here'
      },
      body: {
        mimeType: 'application/json',
        text: JSON.stringify({
          article: {
            title: 'string',
            description: 'string',
            body: 'string'
          }
        })
      }
    })

    t.end()
  })

  t.end()
})
