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

  test("Resource search parsed works", () => {
    const resourceBaseArray = [
      {
        resourceId: 1,
        applicationResourceName: "resourceName1",
        allowed: "*",
        permissionId: 1,
      },
      {
        resourceId: 2,
        applicationResourceName: "resourceName2",
        allowed: "*",
        permissionId: 2,
      },
      {
        resourceId: 3,
        applicationResourceName: "resourceName3",
        allowed: "select",
        permissionId: 3,
      },
      {
        resourceId: 3,
        applicationResourceName: "resourceName3",
        allowed: "create",
        permissionId: 4,
      },
    ];

    const parsedSearch = generalHelpers.parseResourceSearch(resourceBaseArray);

    expect(parsedSearch[0].id).toBe(1);

    expect(parsedSearch[2].allowed.length).toBe(2);

    expect(parsedSearch[2].id).toBe(3);

    expect(parsedSearch[2].applicationResourceName).toBe("resourceName3");
  });

  test("Role search parsed works", () => {
    const roleBaseArray = [
      {
        id: 1,
        identifier: "rol1",
        resourceId: 1,
        applicationResource: "resourceName1",
        allowed: "*",
        permissionId: 1,
      },
      {
        id: 1,
        identifier: "rol1",
        resourceId: 1,
        applicationResource: "resourceName1",
        allowed: "select",
        permissionId: 2,
      },
      {
        id: 2,
        identifier: "rol2",
        resourceId: 1,
        applicationResource: "resourceName2",
        allowed: "*",
        permissionId: 3,
      },
      {
        id: 2,
        identifier: "rol2",
        resourceId: 1,
        applicationResource: "resourceName3",
        allowed: "create",
        permissionId: 4,
      },
    ];

    const parsedSearch = generalHelpers.parseRoleSearch(roleBaseArray);

    expect(parsedSearch[1].id).toBe(2);

    expect(parsedSearch[0].resources.length).toBe(1);

    expect(parsedSearch[1].resources.length).toBe(2);
  });

  test("Subject search parsed works", () => {
    const userBaseArray = [
      {
        id: 1,
        subjectId: 1,
        name: "name1",
        description: "desc",
        username: "user1",
        roleDeleted: false,
        roleId: 1,
        roleIdentifier: "rol1",
        resourceId: 1,
        applicationResource: "resource1",
        allowed: "*",
      },
      {
        id: 1,
        subjectId: 1,
        name: "name1",
        description: "desc",
        username: "user1",
        roleDeleted: false,
        roleId: 1,
        roleIdentifier: "rol1",
        resourceId: 1,
        applicationResource: "resource1",
        allowed: "select",
      },
      {
        id: 1,
        subjectId: 1,
        name: "name1",
        username: "user1",
        description: "desc",
        roleDeleted: false,
        roleId: 2,
        roleIdentifier: "rol2",
        resourceId: 3,
        applicationResource: "resource3",
        allowed: "select",
      },
      {
        id: 1,
        subjectId: 1,
        name: "name1",
        username: "user1",
        roleDeleted: false,
        description: "desc",
        roleId: 2,
        roleIdentifier: "rol2",
        resourceId: 4,
        applicationResource: "resource4",
        allowed: "*",
      },
      {
        id: 2,
        subjectId: 2,
        name: "name2",
        username: "user2",
        description: "desc",
        roleDeleted: true,
        roleId: 2,
        roleIdentifier: "rol2",
        resourceId: 4,
        applicationResource: "resource4",
        allowed: "*",
      },
    ];

    const clientBaseArray = [
      {
        id: 1,
        description: "desc",
        subjectId: 1,
        name: "name1",
        identifier: "user1",
        roleDeleted: false,
        roleId: 1,
        roleIdentifier: "rol1",
        resourceId: 1,
        applicationResource: "resource1",
        allowed: "*",
      },
      {
        id: 1,
        description: "desc",
        subjectId: 1,
        name: "name1",
        identifier: "user1",
        roleDeleted: false,
        roleId: 1,
        roleIdentifier: "rol1",
        resourceId: 1,
        applicationResource: "resource1",
        allowed: "select",
      },
      {
        id: 1,
        description: "desc",
        subjectId: 1,
        name: "name1",
        identifier: "user1",
        roleDeleted: false,
        roleId: 2,
        roleIdentifier: "rol2",
        resourceId: 3,
        applicationResource: "resource3",
        allowed: "select",
      },
      {
        id: 1,
        description: "desc",
        subjectId: 1,
        name: "name1",
        identifier: "user1",
        roleDeleted: false,
        roleId: 2,
        roleIdentifier: "rol2",
        resourceId: 4,
        applicationResource: "resource4",
        allowed: "*",
      },
      {
        id: 2,
        subjectId: 2,
        description: "desc",
        name: "name2",
        identifier: "user2",
        roleDeleted: false,
        roleId: 2,
        roleIdentifier: "rol2",
        resourceId: 4,
        applicationResource: "resource4",
        allowed: "*",
      },
      {
        id: 2,
        subjectId: 2,
        description: "desc",
        name: "name2",
        identifier: "user2",
        roleDeleted: true,
        roleId: 3,
        roleIdentifier: "rol3",
        resourceId: 5,
        applicationResource: "resource5",
        allowed: "*",
      },
    ];

    const parsedSearch = generalHelpers.parseSubjectSearch(userBaseArray);

    const parsedSearchClient = generalHelpers.parseSubjectSearch(
      clientBaseArray,
      "client"
    );

    expect(parsedSearch[0].id).toBe(1);

    expect(parsedSearch[0].roles[0].resources.length).toBe(1);

    expect(parsedSearch[0].roles[0].resources[0].allowed.length).toBe(2);

    expect(parsedSearch[2]).toBe(undefined);

    expect(parsedSearch[0].username).toBe("user1");

    expect(parsedSearch[0].description).toBe("desc");

    expect(parsedSearchClient[0].id).toBe(1);

    expect(parsedSearchClient[0].roles[0].resources.length).toBe(1);

    expect(parsedSearchClient[0].roles[0].resources[0].allowed.length).toBe(2);

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
      request.body = { permission: "some" };
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

    const permissionOne = { permission: { type: "string" } };

    generalHelpers.validateBody(permissionOne).validate(req, res, mockNext);

    expect(mockNext).toHaveBeenCalledTimes(1);

    req.body.permission = [];

    generalHelpers.validateBody(permissionOne).validate(req, res, mockNext);

    expect(mockNext).toHaveBeenCalledTimes(1);
    expect(res.json).toHaveBeenCalledWith({
      code: 400000,
      message: `Invalid body; permission is not an string`,
    });

    const permissionArray = { permission: { type: "array" } };

    generalHelpers.validateBody(permissionArray).validate(req, res, mockNext);

    expect(mockNext).toHaveBeenCalledTimes(2);

    req.body.permission = { key: 2 };

    generalHelpers.validateBody(permissionArray).validate(req, res, mockNext);

    expect(mockNext).toHaveBeenCalledTimes(2);

    expect(res.json).toHaveBeenCalledWith({
      code: 400000,
      message: `Invalid body; permission is not an array`,
    });

    const permissionObject = { permission: { type: "object" } };

    generalHelpers.validateBody(permissionObject).validate(req, res, mockNext);

    expect(mockNext).toHaveBeenCalledTimes(3);

    req.body.permission = 2;

    generalHelpers.validateBody(permissionObject).validate(req, res, mockNext);

    expect(mockNext).toHaveBeenCalledTimes(3);

    expect(res.json).toHaveBeenCalledWith({
      code: 400000,
      message: `Invalid body; permission is not an object`,
    });

    const permissionNumber = { permission: { type: "number" } };

    generalHelpers.validateBody(permissionNumber).validate(req, res, mockNext);

    expect(mockNext).toHaveBeenCalledTimes(4);

    req.body.permission = "some";

    generalHelpers.validateBody(permissionNumber).validate(req, res, mockNext);

    expect(mockNext).toHaveBeenCalledTimes(4);

    expect(res.json).toHaveBeenCalledWith({
      code: 400000,
      message: `Invalid body; permission is not a number`,
    });

    const permissionDefault = { permission: { type: "default" } };

    generalHelpers.validateBody(permissionDefault).validate(req, res, mockNext);

    expect(mockNext).toHaveBeenCalledTimes(5);

    const permissionRequired = { required: { type: "string", required: true } };

    generalHelpers
      .validateBody(permissionRequired)
      .validate(req, res, mockNext);

    expect(res.json).toHaveBeenCalledWith({
      code: 400000,
      message: "Invalid body; required is required",
    });
  });
});
