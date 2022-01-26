const helpers = require("../src/helpers/general-helpers");

const generalHelpers = helpers();

describe("All general helpers function accordingly", () => {
  test("Join Search works", () => {
    const baseSearchResult = [
      { id: 1, randomField: "x", similarField: "y" },
      { id: 1, randomField: "x2", similarField: "y2" },
      { id: 1, randomField: "x3", similarField: "y3" },
      { id: 1, randomField: "x4", similarField: "y4" },
      { id: 2, randomField: "p", similarField: "z" },
      { id: 2, randomField: "p1", similarField: "z1" },
    ];
    const joinResult = generalHelpers.joinSearch(
      baseSearchResult,
      "id",
      "similarField"
    );

    expect(joinResult[2]).toBe(undefined);
    expect(joinResult.length).toBe(2);
    expect(joinResult[0].similarField.length).toBe(4);
  });

  test("Part search parsed works", () => {
    const partBaseArray = [
      {
        partId: 1,
        applicationPartName: "partName1",
        allowed: "*",
        optionId: 1,
      },
      {
        partId: 2,
        applicationPartName: "partName2",
        allowed: "*",
        optionId: 2,
      },
      {
        partId: 3,
        applicationPartName: "partName3",
        allowed: "select",
        optionId: 3,
      },
      {
        partId: 3,
        applicationPartName: "partName3",
        allowed: "create",
        optionId: 4,
      },
    ];

    const parsedSearch = generalHelpers.parsePartSearch(partBaseArray);

    expect(parsedSearch[0].id).toBe(1);

    expect(parsedSearch[2].allowed.length).toBe(2);

    expect(parsedSearch[2].id).toBe(3);

    expect(parsedSearch[2].applicationPartName).toBe("partName3");
  });

  test("Role search parsed works", () => {
    const roleBaseArray = [
      {
        id: 1,
        identifier: "rol1",
        partId: 1,
        applicationPart: "partName1",
        allowed: "*",
        optionId: 1,
      },
      {
        id: 1,
        identifier: "rol1",
        partId: 1,
        applicationPart: "partName1",
        allowed: "select",
        optionId: 2,
      },
      {
        id: 2,
        identifier: "rol2",
        partId: 1,
        applicationPart: "partName2",
        allowed: "*",
        optionId: 3,
      },
      {
        id: 2,
        identifier: "rol2",
        partId: 1,
        applicationPart: "partName3",
        allowed: "create",
        optionId: 4,
      },
    ];

    const parsedSearch = generalHelpers.parseRoleSearch(roleBaseArray);

    expect(parsedSearch[1].id).toBe(2);

    expect(parsedSearch[0].parts.length).toBe(1);

    expect(parsedSearch[1].parts.length).toBe(2);
  });

  test("Subject search parsed works", () => {
    const userBaseArray = [
      {
        id: 1,
        subjectId: 1,
        name: "name1",
        username: "user1",
        roleDeleted: false,
        roleId: 1,
        roleIdentifier: "rol1",
        partId: 1,
        applicationPart: "part1",
        allowed: "*",
      },
      {
        id: 1,
        subjectId: 1,
        name: "name1",
        username: "user1",
        roleDeleted: false,
        roleId: 1,
        roleIdentifier: "rol1",
        partId: 1,
        applicationPart: "part1",
        allowed: "select",
      },
      {
        id: 1,
        subjectId: 1,
        name: "name1",
        username: "user1",
        roleDeleted: false,
        roleId: 2,
        roleIdentifier: "rol2",
        partId: 3,
        applicationPart: "part3",
        allowed: "select",
      },
      {
        id: 1,
        subjectId: 1,
        name: "name1",
        username: "user1",
        roleDeleted: false,
        roleId: 2,
        roleIdentifier: "rol2",
        partId: 4,
        applicationPart: "part4",
        allowed: "*",
      },
      {
        id: 2,
        subjectId: 2,
        name: "name2",
        username: "user2",
        roleDeleted: true,
        roleId: 2,
        roleIdentifier: "rol2",
        partId: 4,
        applicationPart: "part4",
        allowed: "*",
      },
    ];

    const clientBaseArray = [
      {
        id: 1,
        subjectId: 1,
        name: "name1",
        identifier: "user1",
        roleDeleted: false,
        roleId: 1,
        roleIdentifier: "rol1",
        partId: 1,
        applicationPart: "part1",
        allowed: "*",
      },
      {
        id: 1,
        subjectId: 1,
        name: "name1",
        identifier: "user1",
        roleDeleted: false,
        roleId: 1,
        roleIdentifier: "rol1",
        partId: 1,
        applicationPart: "part1",
        allowed: "select",
      },
      {
        id: 1,
        subjectId: 1,
        name: "name1",
        identifier: "user1",
        roleDeleted: false,
        roleId: 2,
        roleIdentifier: "rol2",
        partId: 3,
        applicationPart: "part3",
        allowed: "select",
      },
      {
        id: 1,
        subjectId: 1,
        name: "name1",
        identifier: "user1",
        roleDeleted: false,
        roleId: 2,
        roleIdentifier: "rol2",
        partId: 4,
        applicationPart: "part4",
        allowed: "*",
      },
      {
        id: 2,
        subjectId: 2,
        name: "name2",
        identifier: "user2",
        roleDeleted: false,
        roleId: 2,
        roleIdentifier: "rol2",
        partId: 4,
        applicationPart: "part4",
        allowed: "*",
      },
      {
        id: 2,
        subjectId: 2,
        name: "name2",
        identifier: "user2",
        roleDeleted: true,
        roleId: 3,
        roleIdentifier: "rol3",
        partId: 5,
        applicationPart: "part5",
        allowed: "*",
      },
    ];

    const parsedSearch = generalHelpers.parseSubjectSearch(userBaseArray);

    const parsedSearchClient = generalHelpers.parseSubjectSearch(
      clientBaseArray,
      "client"
    );

    expect(parsedSearch[0].id).toBe(1);

    expect(parsedSearch[0].roles[0].parts.length).toBe(1);

    expect(parsedSearch[0].roles[0].parts[0].allowed.length).toBe(2);

    expect(parsedSearch[2]).toBe(undefined);

    expect(parsedSearch[0].username).toBe("user1");

    expect(parsedSearchClient[0].id).toBe(1);

    expect(parsedSearchClient[0].roles[0].parts.length).toBe(1);

    expect(parsedSearchClient[0].roles[0].parts[0].allowed.length).toBe(2);

    expect(parsedSearchClient[2]).toBe(undefined);

    expect(parsedSearchClient[0].identifier).toBe("user1");
  });

  test("Compare keys works", () => {
    const testObjectOne = { keyOne: 1, keyTwo: 1 };
    const testObjectTwo = { keyTwo: 2, keyOne: 2 };
    const testObjectThree = { keyTwo: 3, keyThree: 3 };

    const result = generalHelpers.compareKeys(testObjectOne, testObjectTwo);

    const secondResult = generalHelpers.compareKeys(
      testObjectOne,
      testObjectThree
    );
    expect(secondResult).toBe(false);
    expect(result).toBe(true);
  });

  test("Validate body", () => {
    const mockReq = () => {
      const request = {};
      request.body = { option: "some" };
      return request;
    };

    const mockRes = () => {
      const response = {};
      response.status = jest.fn().mockReturnValue(response);
      response.json = jest.fn();
      response.locals = {};
      return response;
    };

    const res = mockRes();

    const req = mockReq();

    const mockNext = jest.fn();

    const optionOne = { option: { type: "string" } };

    generalHelpers.validateBody(optionOne).validate(req, res, mockNext);

    expect(mockNext).toHaveBeenCalledTimes(1);

    req.body.option = [];

    generalHelpers.validateBody(optionOne).validate(req, res, mockNext);

    expect(mockNext).toHaveBeenCalledTimes(1);
    expect(res.json).toHaveBeenCalledWith({
      code: 400000,
      message: `Invalid body; option is not an string`,
    });

    const optionArray = { option: { type: "array" } };

    generalHelpers.validateBody(optionArray).validate(req, res, mockNext);

    expect(mockNext).toHaveBeenCalledTimes(2);

    req.body.option = { key: 2 };

    generalHelpers.validateBody(optionArray).validate(req, res, mockNext);

    expect(mockNext).toHaveBeenCalledTimes(2);

    expect(res.json).toHaveBeenCalledWith({
      code: 400000,
      message: `Invalid body; option is not an array`,
    });

    const optionObject = { option: { type: "object" } };

    generalHelpers.validateBody(optionObject).validate(req, res, mockNext);

    expect(mockNext).toHaveBeenCalledTimes(3);

    req.body.option = 2;

    generalHelpers.validateBody(optionObject).validate(req, res, mockNext);

    expect(mockNext).toHaveBeenCalledTimes(3);

    expect(res.json).toHaveBeenCalledWith({
      code: 400000,
      message: `Invalid body; option is not an object`,
    });

    const optionNumber = { option: { type: "number" } };

    generalHelpers.validateBody(optionNumber).validate(req, res, mockNext);

    expect(mockNext).toHaveBeenCalledTimes(4);

    req.body.option = "some";

    generalHelpers.validateBody(optionNumber).validate(req, res, mockNext);

    expect(mockNext).toHaveBeenCalledTimes(4);

    expect(res.json).toHaveBeenCalledWith({
      code: 400000,
      message: `Invalid body; option is not a number`,
    });

    const optionDefault = { option: { type: "default" } };

    generalHelpers.validateBody(optionDefault).validate(req, res, mockNext);

    expect(mockNext).toHaveBeenCalledTimes(5);

    const optionNone = { none: { type: "default" } };

    generalHelpers.validateBody(optionNone).validate(req, res, mockNext);

    expect(res.json).toHaveBeenCalledWith({
      code: 400000,
      message: "Invalid body",
    });
  });
});
