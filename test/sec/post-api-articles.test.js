'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType, AttackParamLocation, Severity } = require('@sectester/runner')

let runner


t.test('setup', async t => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME
  })
  await runner.init()
  t.end()
})

t.teardown(async () => {
  await runner.clear()
})


it('POST /api/articles', async () => {
  const server = await startServer()
  t.teardown(() => server.close())

  await runner
    .createScan({
      tests: [TestType.JWT, TestType.CSRF, TestType.MASS_ASSIGNMENT, TestType.XSS, TestType.SQLI],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.MEDIUM)
    .timeout(15 * 60 * 1000) // 15 minutes
    .run({
      method: 'POST',
      url: '/api/articles',
      headers: {
        'Authorization': 'Token jwt.token.here',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        article: {
          title: 'string',
          description: 'string',
          body: 'string',
          tagList: ['string']
        }
      })
    })
})
