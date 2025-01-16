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


// Test case for DELETE /articles/example-slug/comments/1

t.test('DELETE /articles/example-slug/comments/1', async t => {
  const server = await startServer()
  t.teardown(() => server.close())

  await runner.createScan({
    tests: [TestType.BROKEN_ACCESS_CONTROL, 'csrf', 'id_enumeration'],
    attackParamLocations: ['path', 'header']
  })
  .threshold('medium')
  .timeout(60000)
  .run({
    method: 'DELETE',
    url: 'http://localhost:3000/articles/example-slug/comments/1',
    headers: {
      'Authorization': 'Bearer <token>'
    }
  })

  t.end()
})
