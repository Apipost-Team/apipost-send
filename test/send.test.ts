import ApipostRequest from '../src/ApipostRequest';

test('works', async () => {
  let apipostSend = new ApipostRequest();

  let target = {
    target_id: 'testid',
    method: 'GET',
    url: 'http://www.baidu.com',
    
    request: {
      url: 'http://www.baidu.com',
      query_add_equal: -1,
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
        parameter: [
          {
            param_id: "248d387e7e0001",
            description: "",
            field_type: "String",
            is_checked: 1,
            key: "name",
            not_null: 1,
            value: "name",
          },
          {
            param_id: "248d387e7e0003",
            description: "",
            field_type: "String",
            is_checked: 1,
            key: "noname",
            not_null: 1,
            value: "",
          },
        ]
      },
    },
  };

  let result:any = await apipostSend.request(target, {});

  expect(result.status).toBe('success');

});
