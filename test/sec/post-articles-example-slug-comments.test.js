'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { SecRunner, TestType } = require('@sectester/runner')

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


// Test case for POST /articles/example-slug/comments

t.test('POST /articles/example-slug/comments', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  await runner.createScan({
    tests: [TestType.CSRF, TestType.XSS, TestType.JWT, 'excessive_data_exposure', 'mass_assignment'],
    attackParamLocations: ['body', 'header']
  })
  .threshold('medium')
  .timeout(60000)
  .run({
    method: 'POST',
    url: 'http://localhost:3000/articles/example-slug/comments',
    headers: { 'Authorization': 'Bearer <token>' },
    body: { 'comment': { 'body': 'This is a comment.' } }
  })

  t.end()
})
