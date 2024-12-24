'use strict'
const t = require('tap')
const startServer = require('../setup-server')
const { Configuration, SecRunner } = require('@sectester/runner');
const { TestType, Severity } = require('@sectester/scan');

const configuration = new Configuration({ hostname: 'app.brightsec.com' });

const scanSettings = {
  tests: [TestType.SQLI, TestType.XSS, TestType.BROKEN_ACCESS_CONTROL],
  threshold: Severity.MEDIUM,
  timeout: 300000, // 5 minutes
};

async function runSecurityTests(target) {
  const runner = new SecRunner(configuration);
  await runner.init();
  const scan = runner.createScan(scanSettings);
  await scan.run(target);
  await runner.clear();
}

// Test for creating an article
async function testCreateArticle(t) {
  const server = await startServer();
  t.teardown(() => server.close());

  const target = {
    method: 'POST',
    url: 'https://localhost:8000/articles',
    headers: { 'Authorization': 'Token jwt.token.here' },
    body: { article: { title: 'string', description: 'string', body: 'string', tagList: ['string'] } }
  };

  await runSecurityTests(target);

  const response = await server.inject({
    method: 'POST',
    url: '/api/articles',
    headers: { 'Authorization': 'Token jwt.token.here' },
    payload: {
      article: {
        title: 'string',
        description: 'string',
        body: 'string',
        tagList: ['string']
      }
    }
  });
  t.equal(response.statusCode, 201, 'returns a status code of 201 Created');
  t.end();
}

// Test for updating an article
async function testUpdateArticle(t) {
  const server = await startServer();
  t.teardown(() => server.close());

  const target = {
    method: 'PUT',
    url: 'http://localhost:3000/api/articles/test-article',
    headers: { 'Authorization': 'Token jwt.token.here' },
    body: {
      article: {
        title: 'string',
        description: 'string',
        body: 'string'
      }
    }
  };

  await runSecurityTests(target);

  const response = await server.inject(target);
  t.equal(response.statusCode, 200, 'returns a status code of 200 OK');
  t.end();
}

// Test for deleting an article with invalid token
async function testDeleteArticleInvalidToken(t) {
  const server = await startServer();
  t.teardown(() => server.close());

  const target = {
    method: 'DELETE',
    url: 'https://localhost:3000/articles/{slug}',
    headers: { Authorization: 'Token jwt.token.here' }
  };

  await runSecurityTests(target);

  const response = await server.inject({
    method: 'DELETE',
    url: '/api/articles/test-article',
    headers: { Authorization: 'Token invalid.token.here' }
  });
  t.equal(response.statusCode, 401, 'returns a status code of 401 Unauthorized');
  t.end();
}

// Test for deleting article favorite without authorization
async function testDeleteArticleFavorite(t) {
  const server = await startServer();
  t.teardown(() => server.close());

  const target = {
    method: 'DELETE',
    url: 'http://localhost:3000/articles/{slug}/favorite',
    headers: { Authorization: 'Token jwt.token.here' }
  };

  await runSecurityTests(target);

  const response = await server.inject({
    method: 'DELETE',
    url: '/articles/{slug}/favorite',
    headers: { Authorization: 'Token jwt.token.here' }
  });
  t.equal(response.statusCode, 401, 'returns a status code of 401 Unauthorized');
  t.end();
}

// Run all tests
t.test('create article with SQLi and XSS tests', testCreateArticle);
t.test('update article with potential vulnerabilities', testUpdateArticle);
t.test('delete article with invalid token', testDeleteArticleInvalidToken);
t.test('delete article favorite without authorization', testDeleteArticleFavorite);
