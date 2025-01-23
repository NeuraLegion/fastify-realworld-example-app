'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, Severity, AttackParamLocation, HttpMethod } = require('@sectester/runner')

let runner

// Increase timeout if necessary
jest.setTimeout(15 * 60 * 1000) // 15 minutes

t.test('PUT /articles/:slug', async t => {
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
      tests: [
        TestType.BROKEN_ACCESS_CONTROL,
        TestType.CSRF,
        TestType.SQLI,
        TestType.XSS,
        TestType.JWT,
        'insecure_output_handling'
      ],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.MEDIUM)
    .timeout(15 * 60 * 1000)
    .run({
      method: HttpMethod.PUT,
      url: `${server.baseUrl}/articles/test-article`,
      headers: {
        Authorization: 'Bearer <token>'
      },
      body: {
        article: {
          title: 'string',
          description: 'string',
          body: 'string'
        }
      }
    })

    t.end()
  })

  t.end()
})