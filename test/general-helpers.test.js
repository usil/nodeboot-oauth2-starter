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

  test("Parse path no route", () => {
    const path = generalHelpers.parsePathNoRoute("/");
    expect(path).toBe("/");

    const pathThree = generalHelpers.parsePathNoRoute("/event/");
    expect(pathThree).toBe("/event");
  });

  test("Parse With Route", () => {
    const path = generalHelpers.parsePathWithRoute("/");
    expect(path).toBe("");

    const pathThree = generalHelpers.parsePathWithRoute("/event/");
    expect(pathThree).toBe("/event");

    const pathFour = generalHelpers.parsePathWithRoute("/event");
    expect(pathFour).toBe("/event");
  });

  test("Handle error 400, external error", () => {
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
    const mockNext = jest.fn();

    generalHelpers.handleError400(res, mockNext, true, "test", 400000);

    expect(mockNext).toHaveBeenCalled();
  });

  test("Handle error 400, internal error", () => {
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
    const mockNext = jest.fn();

    generalHelpers.handleError400(res, mockNext, false, "test", 400000, 400);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ code: 400000, message: "test" });
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

  test("Validate body", () => {
    generalHelpers.handleError400 = jest.fn();

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

    expect(generalHelpers.handleError400).toHaveBeenCalledTimes(1);

    expect(generalHelpers.handleError400).toHaveBeenCalledWith(
      res,
      mockNext,
      true,
      `Invalid body; permission is not an string`,
      400003
    );

    const permissionArray = { permission: { type: "array" } };

    generalHelpers.validateBody(permissionArray).validate(req, res, mockNext);

    expect(mockNext).toHaveBeenCalledTimes(2);

    req.body.permission = { key: 2 };

    generalHelpers.validateBody(permissionArray).validate(req, res, mockNext);

    expect(generalHelpers.handleError400).toHaveBeenCalledTimes(2);

    expect(generalHelpers.handleError400).toHaveBeenCalledWith(
      res,
      mockNext,
      true,
      `Invalid body; permission is not an array`,
      400002
    );

    const permissionObject = { permission: { type: "object" } };

    generalHelpers.validateBody(permissionObject).validate(req, res, mockNext);

    expect(mockNext).toHaveBeenCalledTimes(3);

    req.body.permission = 2;

    generalHelpers.validateBody(permissionObject).validate(req, res, mockNext);

    expect(generalHelpers.handleError400).toHaveBeenCalledTimes(3);

    expect(generalHelpers.handleError400).toHaveBeenCalledWith(
      res,
      mockNext,
      true,
      `Invalid body; permission is not an object`,
      400005
    );

    const permissionNumber = { permission: { type: "number" } };

    generalHelpers.validateBody(permissionNumber).validate(req, res, mockNext);

    expect(mockNext).toHaveBeenCalledTimes(4);

    req.body.permission = "some";

    generalHelpers.validateBody(permissionNumber).validate(req, res, mockNext);

    expect(generalHelpers.handleError400).toHaveBeenCalledTimes(4);

    expect(generalHelpers.handleError400).toHaveBeenCalledWith(
      res,
      mockNext,
      true,
      `Invalid body; permission is not a number`,
      400004
    );

    const permissionBoolean = { permission: { type: "boolean" } };
    req.body.permission = true;
    generalHelpers.validateBody(permissionBoolean).validate(req, res, mockNext);

    expect(mockNext).toHaveBeenCalledTimes(5);

    req.body.permission = "some";

    generalHelpers.validateBody(permissionBoolean).validate(req, res, mockNext);

    expect(generalHelpers.handleError400).toHaveBeenCalledTimes(5);

    expect(generalHelpers.handleError400).toHaveBeenCalledWith(
      res,
      mockNext,
      true,
      `Invalid body; permission is not a boolean`,
      400006
    );

    const permissionDefault = { permission: { type: "default" } };

    generalHelpers.validateBody(permissionDefault).validate(req, res, mockNext);

    expect(mockNext).toHaveBeenCalledTimes(6);

    const permissionRequired = { required: { type: "string", required: true } };

    generalHelpers
      .validateBody(permissionRequired)
      .validate(req, res, mockNext);

    expect(generalHelpers.handleError400).toHaveBeenCalledTimes(6);

    expect(generalHelpers.handleError400).toHaveBeenCalledWith(
      res,
      mockNext,
      true,
      "Invalid body; required is required",
      400001
    );
  });
});
