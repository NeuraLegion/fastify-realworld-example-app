import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, Severity, TestType } from '@sectester/scan';

const timeout = 300000;

let runner!: SecRunner;
let baseUrl!: string;

beforeAll(async () => {
  runner = new SecRunner({ hostname: 'app.neuralegion.com' });
  await runner.init();
  baseUrl = 'http://localhost:3000';
});

afterAll(() => runner.clear());

jest.setTimeout(timeout);

describe('/api/articles', () => {
  it('GET / should not have excessive data exposure, sqli, xss, csrf, http method fuzzing, or mass assignment vulnerabilities', async () => {
    await runner
      .createScan({
        tests: [
          'excessive_data_exposure',
          TestType.SQLI,
          TestType.XSS,
          TestType.CSRF,
          TestType.HTTP_METHOD_FUZZING,
          TestType.MASS_ASSIGNMENT
        ],
        attackParamLocations: [
          AttackParamLocation.QUERY,
          AttackParamLocation.BODY
        ]
      })
      .threshold(Severity.MEDIUM)
      .timeout(timeout)
      .run({
        method: 'GET',
        url: 'http://localhost:3000/api/articles',
        query: {
          tag: 'string',
          author: 'string',
          favorited: 'string',
          limit: 'number',
          offset: 'number'
        }
      });
  });

  it('GET /slug-example should not have broken access control, excessive data exposure, or id enumeration vulnerabilities', async () => {
    await runner
      .createScan({
        tests: ['broken_access_control', 'excessive_data_exposure', TestType.ID_ENUMERATION],
        attackParamLocations: [AttackParamLocation.PATH]
      })
      .threshold(Severity.MEDIUM)
      .timeout(timeout)
      .run({
        method: 'GET',
        url: `${baseUrl}/api/articles/slug-example`
      });
  });

  it('POST /api/articles should not have vulnerabilities', async () => {
    await runner
      .createScan({
        tests: [TestType.JWT, TestType.CSRF, TestType.MASS_ASSIGNMENT, TestType.XSS, TestType.SQLI],
        attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER]
      })
      .threshold(Severity.MEDIUM)
      .timeout(timeout)
      .run({
        method: 'POST',
        url: `${baseUrl}/api/articles`,
        headers: {
          'Authorization': 'Token jwt.token.here',
          'Content-Type': 'application/json'
        },
        body: {
          article: {
            title: 'string',
            description: 'string',
            body: 'string',
            tagList: ['string']
          }
        }
      });
  });

  describe('PUT /articles/slug-example', () => {
    it('should not have vulnerabilities', async () => {
      await runner
        .createScan({
          tests: [TestType.JWT, TestType.CSRF, TestType.MASS_ASSIGNMENT, TestType.XSS, TestType.SQLI],
          attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER]
        })
        .threshold(Severity.MEDIUM)
        .timeout(timeout)
        .run({
          method: 'PUT',
          url: `${baseUrl}/api/articles/slug-example`,
          headers: {
            Authorization: 'Token jwt.token.here',
            'Content-Type': 'application/json'
          },
          body: {
            article: {
              title: 'string',
              description: 'string',
              body: 'string'
            }
          }
        });
    });
  });

  describe('DELETE /articles/slug-example', () => {
    it('should not have broken access control, jwt, csrf, or http method fuzzing vulnerabilities', async () => {
      await runner
        .createScan({
          tests: [
            'broken_access_control',
            TestType.JWT,
            TestType.CSRF,
            TestType.HTTP_METHOD_FUZZING
          ],
          attackParamLocations: [AttackParamLocation.HEADER]
        })
        .threshold(Severity.MEDIUM)
        .timeout(timeout)
        .run({
          method: 'DELETE',
          url: 'http://localhost:3000/api/articles/slug-example',
          headers: {
            Authorization: 'Token jwt.token.here'
          }
        });
    });
  });

  describe('DELETE /articles/slug-example/favorite', () => {
    it('should pass security tests', async () => {
      await runner
        .createScan({
          tests: [TestType.JWT, TestType.BROKEN_ACCESS_CONTROL, TestType.CSRF, TestType.HTTP_METHOD_FUZZING],
          attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.PATH]
        })
        .threshold(Severity.MEDIUM)
        .timeout(timeout)
        .run({
          method: 'DELETE',
          url: `${baseUrl}/api/articles/slug-example/favorite`,
          headers: { Authorization: 'Token jwt.token.here' }
        });
    });
  });
});

describe('/api/articles/feed', () => {
  it('should not have security issues', async () => {
    await runner
      .createScan({
        tests: [TestType.JWT, 'excessive_data_exposure', 'broken_access_control', TestType.CSRF, TestType.HTTP_METHOD_FUZZING],
        attackParamLocations: [AttackParamLocation.QUERY, AttackParamLocation.HEADER]
      })
      .threshold(Severity.MEDIUM)
      .timeout(timeout)
      .run({
        method: 'GET',
        url: `${baseUrl}/api/articles/feed`,
        headers: { Authorization: 'Token jwt.token.here' },
        query: { limit: 'number', offset: 'number' }
      });
  });
});

describe('/api/articles/slug-example/favorite', () => {
  it('POST / should pass security tests', async () => {
    await runner
      .createScan({
        tests: [TestType.JWT, TestType.CSRF, TestType.BROKEN_ACCESS_CONTROL, TestType.HTTP_METHOD_FUZZING, TestType.XSS],
        attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.BODY]
      })
      .threshold(Severity.MEDIUM)
      .timeout(timeout)
      .run({
        method: 'POST',
        url: `${baseUrl}/api/articles/slug-example/favorite`,
        headers: { Authorization: 'Token jwt.token.here' },
        body: {}
      });
  });
});

describe('/api/articles/sample-article/comments', () => {
  it('GET / should not have broken access control, csrf, excessive data exposure, or xss vulnerabilities', async () => {
    await runner
      .createScan({
        tests: [TestType.BROKEN_ACCESS_CONTROL, TestType.CSRF, TestType.EXCESSIVE_DATA_EXPOSURE, TestType.XSS],
        attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.QUERY, AttackParamLocation.BODY]
      })
      .threshold(Severity.MEDIUM)
      .timeout(timeout)
      .run({
        method: 'GET',
        url: 'http://example.com/api/articles/sample-article/comments',
        headers: { Authorization: 'Bearer <optional_token>' }
      });
  });

  it('POST / should not have CSRF, XSS, SQLi, Broken Access Control, or Excessive Data Exposure', async () => {
    await runner
      .createScan({
        tests: [TestType.CSRF, TestType.XSS, TestType.SQLI, 'broken_access_control', 'excessive_data_exposure'],
        attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER]
      })
      .threshold(Severity.MEDIUM)
      .timeout(timeout)
      .run({
        method: 'POST',
        url: 'http://example.com/api/articles/sample-article/comments',
        headers: {
          Authorization: 'Bearer <token>',
          'Content-Type': 'application/json'
        },
        body: { comment: { body: 'This is a comment.' } }
      });
  });
});

describe('/api/articles/sample-article/comments/:id', () => {
  it('DELETE /:id should not have broken access control, CSRF, or ID enumeration vulnerabilities', async () => {
    await runner
      .createScan({
        tests: [TestType.BROKEN_ACCESS_CONTROL, TestType.CSRF, TestType.ID_ENUMERATION],
        attackParamLocations: [AttackParamLocation.PATH]
      })
      .threshold(Severity.MEDIUM)
      .timeout(timeout)
      .run({
        method: 'DELETE',
        url: 'http://example.com/api/articles/sample-article/comments/123',
        headers: { Authorization: 'Bearer <token>' }
      });
  });
});
