import ApipostRequest from '../src/ApipostRequest'


describe('works', () => {

  new ApipostRequest({});

  it('转换成完整类型', () => {
    expect('success').toBe(`success`);
  });
});

