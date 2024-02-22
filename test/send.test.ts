import ApipostRequest from '../src/ApipostRequest';

test('works', async () => {
  let apipostSend = new ApipostRequest();
  let target = {
    target_id: 'testid',
    method: 'GET',
    url: 'http://www.baidu.com',
    request: {
      url: 'http://www.baidu.com',
      auth: {
        type: 'noauth',
        kv: {
          key: '',
          value: '',
        },
        bearer: {
          key: '',
        },
        basic: {
          username: '',
          password: '',
        },
      },
      body: {
        mode: 'none',
        parameter: [],
        raw: '',
      },
      header: {
        parameter: [],
      },
      query: {
        parameter: [],
      },
    },
  };
  let result:any = await apipostSend.request(target, {});

  expect(result.status).toBe('success');

});
