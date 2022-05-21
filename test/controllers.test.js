const authControllers = require("../src/helpers/routes/controllers.js");
const bcrypt = require("bcrypt");
const generalHelpers = require("../src/helpers/general-helpers.js");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

describe("All auth controllers work", () => {
  test("Handle error", () => {
    const knex = {};

    const controllers = authControllers(knex, "secret");

    const errorOne = controllers.handleError("error", 500000, 500, "test");

    expect(errorOne.onLibrary).toBe("nodeboot-oauth2-starter");
    expect(errorOne.onFile).toBe("controller.js");
    expect(errorOne.onFunction).toBe("test");
    expect(errorOne.statusCode).toBe(500);
    expect(errorOne.errorCode).toBe(500000);

    const controllersNoExternal = authControllers(
      knex,
      "secret",
      "24h",
      "key",
      "::client.app",
      false
    );

    const errorTwo = controllersNoExternal.handleError(
      "error",
      500000,
      500,
      "test"
    );

    expect(errorTwo.message).toBe("error");
    expect(errorTwo.code).toBe(500000);
  });

  test("Handle error 500", () => {
    const knex = {};

    const testError = new Error("test");

    const controllers = authControllers(knex, "secret");

    const errorOne = controllers.handleError500(500000, testError, "test");

    expect(errorOne.onLibrary).toBe("nodeboot-oauth2-starter");
    expect(errorOne.onFile).toBe("controller.js");
    expect(errorOne.onFunction).toBe("test");
    expect(errorOne.statusCode).toBe(500);
    expect(errorOne.errorCode).toBe(500000);

    const controllersNoExternal = authControllers(
      knex,
      "secret",
      "24h",
      "key",
      "::client.app",
      false
    );

    const errorTwo = controllersNoExternal.handleError500(
      500000,
      testError,
      "test"
    );

    expect(errorTwo.message).toBe("test");
    expect(errorTwo.code).toBe(500000);
  });

  test("Handle error 409", () => {
    const knex = {};

    const controllers = authControllers(knex, "secret");

    const errorOne = controllers.handleNotUniqueError409(
      "test",
      400000,
      "test"
    );

    expect(errorOne.onLibrary).toBe("nodeboot-oauth2-starter");
    expect(errorOne.onFile).toBe("controller.js");
    expect(errorOne.onFunction).toBe("test");
    expect(errorOne.statusCode).toBe(409);
    expect(errorOne.errorCode).toBe(400000);

    const controllersNoExternal = authControllers(
      knex,
      "secret",
      "24h",
      "key",
      "::client.app",
      false
    );

    const errorTwo = controllersNoExternal.handleNotUniqueError409(
      "test",
      400000,
      "test"
    );

    expect(errorTwo.message).toBe(`That test is already on use`);
    expect(errorTwo.code).toBe(400000);
  });

  test("Call next or res", () => {
    const knex = {};

    const controllers = authControllers(knex, "secret");

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
    const next = jest.fn();

    const jsonCall = { message: "ok" };

    controllers.callNextOrResOnError(res, next, jsonCall);

    expect(next).toHaveBeenCalledWith(jsonCall);

    const controllersNoExternal = authControllers(
      knex,
      "secret",
      "24h",
      "key",
      "::client.app",
      false
    );

    controllersNoExternal.callNextOrResOnError(res, next, jsonCall, 400);

    expect(res.json).toHaveBeenCalledWith(jsonCall);
    expect(res.status).toHaveBeenCalledWith(400);
  });

  test("Creates the user in a transaction", async () => {
    const reqBody = {
      username: "username",
      encryptedPassword: "encrypted",
      name: "name",
      roles: ["admin"],
    };

    const trxMock = {
      table: jest.fn().mockReturnThis(),
      insert: jest.fn().mockResolvedValue([1]),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");

    await controllers.createUserTransaction(trxMock, reqBody);

    expect(trxMock.insert).toHaveBeenCalledTimes(3);

    expect(trxMock.table).toHaveBeenCalledWith("OAUTH2_Users");
    expect(trxMock.table).toHaveBeenCalledWith("OAUTH2_Subjects");
    expect(trxMock.table).toHaveBeenCalledWith("OAUTH2_SubjectRole");
  });

  test("Creates the user in a transaction fails", async () => {
    const reqBody = {
      username: "username",
      encryptedPassword: "encrypted",
      name: "name",
      roles: ["admin"],
    };

    const trxMock = {
      table: jest.fn().mockReturnThis(),
      insert: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");

    await expect(
      controllers.createUserTransaction(trxMock, reqBody)
    ).rejects.toThrow();
  });

  test("Create user", async () => {
    const bcryptSpy = jest.spyOn(bcrypt, "hash").mockImplementation(() => {
      return "hashed";
    });

    const mockedReq = {
      body: {
        password: "pass",
        username: "LUIS",
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnValue([]),
      transaction: jest.fn(),
    };

    const mockNext = jest.fn();

    const controllers = authControllers(knexMock, "secret");

    controllers.createUserTransaction = jest.fn().mockReturnValue(1);

    await controllers.createUser(mockedReq, mockRes, mockNext);

    expect(bcryptSpy).toHaveBeenCalled();
    expect(knexMock.table).toHaveBeenCalledWith("OAUTH2_Users");
    expect(knexMock.select).toHaveBeenCalled();
    expect(knexMock.where).toHaveBeenCalledWith("username", "luis");
    expect(mockRes.status).toHaveBeenCalledWith(201);
    expect(mockRes.json).toHaveBeenCalledWith({
      code: 200001,
      message: "User added",
      content: { userId: -1 },
    });
    expect(knexMock.transaction).toHaveBeenCalled();

    bcryptSpy.mockRestore();
  });

  test("Create user, duplicated", async () => {
    const mockedReq = {
      body: {
        password: "pass",
        username: "LUIS",
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnValue([{ username: "luis" }]),
      transaction: jest.fn(),
    };

    const mockNext = jest.fn();

    const controllers = authControllers(knexMock, "secret");

    controllers.handleNotUniqueError409 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    await controllers.createUser(mockedReq, mockRes, mockNext);

    expect(controllers.handleNotUniqueError409).toHaveBeenCalledWith(
      "username",
      409101,
      "createUser"
    );
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Create user errors", async () => {
    const bcryptSpy = jest.spyOn(bcrypt, "hash").mockImplementation(() => {
      return "hashed";
    });

    const mockedReq = {
      body: {
        password: "pass",
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = {
      transaction: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const nextMock = jest.fn();

    const controllers = authControllers(knexMock, "secret");

    controllers.handleError500 = jest.fn();

    controllers.callNextOrResOnError = jest.fn();

    await controllers.createUser(mockedReq, mockRes, nextMock);

    expect(controllers.handleError500).toHaveBeenCalled();

    expect(controllers.callNextOrResOnError).toHaveBeenCalled();

    bcryptSpy.mockRestore();
  });

  test("Creates the client in a transaction", async () => {
    const cryptoSpy = jest.spyOn(crypto, "randomBytes");

    const reqBody = {
      identifier: "identifier",
      encryptedAccessToken: "encrypted",
      name: "name",
      roles: ["admin"],
    };

    const trxMock = {
      table: jest.fn().mockReturnThis(),
      insert: jest.fn().mockResolvedValue([1]),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");

    await controllers.createClientTransaction(trxMock, reqBody);

    expect(trxMock.insert).toHaveBeenCalledTimes(3);
    expect(trxMock.table).toHaveBeenCalledWith("OAUTH2_Clients");
    expect(trxMock.table).toHaveBeenCalledWith("OAUTH2_SubjectRole");
    expect(trxMock.table).toHaveBeenCalledWith("OAUTH2_Subjects");
    expect(cryptoSpy).toHaveBeenCalled();
    cryptoSpy.mockRestore();
  });

  test("Creates the client in a transaction with long live", async () => {
    const reqBody = {
      identifier: "identifier",
      encryptedAccessToken: "encrypted",
      name: "name",
      roles: ["admin"],
    };

    const trxMock = {
      table: jest.fn().mockReturnThis(),
      insert: jest.fn().mockResolvedValue([1]),
      update: jest.fn().mockReturnThis(),
      where: jest.fn().mockResolvedValue([1]),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");

    await controllers.createClientTransaction(trxMock, reqBody, true);

    expect(trxMock.insert).toHaveBeenCalledTimes(3);
    expect(trxMock.table).toHaveBeenCalledWith("OAUTH2_Clients");
    expect(trxMock.table).toHaveBeenCalledWith("OAUTH2_SubjectRole");
    expect(trxMock.table).toHaveBeenCalledWith("OAUTH2_Subjects");
    expect(trxMock.where).toHaveBeenCalledWith("OAUTH2_Clients.id", "=", 1);
  });

  test("Creates the client in a fails", async () => {
    const reqBody = {
      identifier: "identifier",
      encryptedAccessToken: "encrypted",
      name: "name",
      roles: ["admin"],
    };

    const trxMock = {
      table: jest.fn().mockReturnThis(),
      insert: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");

    await expect(
      controllers.createClientTransaction(trxMock, reqBody)
    ).rejects.toThrow();
  });

  test("Create client", async () => {
    const mockedReq = {
      body: {
        identifier: "pass",
      },
      query: {
        longLive: true,
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnValue([]),
      transaction: jest.fn(),
    };

    const nextMock = jest.fn();

    const controllers = authControllers(knexMock, "secret");

    await controllers.createClient(mockedReq, mockRes, nextMock);

    expect(mockRes.status).toHaveBeenCalledWith(201);
    expect(knexMock.transaction).toHaveBeenCalled();
    expect(knexMock.table).toHaveBeenCalledWith("OAUTH2_Clients");
    expect(knexMock.select).toHaveBeenCalled();
    expect(knexMock.where).toHaveBeenCalledWith("identifier", "pass");
  });

  test("Create client, duplicated", async () => {
    const mockedReq = {
      body: {
        identifier: "pass",
      },
      query: {
        longLive: true,
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnValue([{ id: 1 }]),
      transaction: jest.fn(),
    };

    const nextMock = jest.fn();

    const controllers = authControllers(knexMock, "secret");

    controllers.handleNotUniqueError409 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    await controllers.createClient(mockedReq, mockRes, nextMock);

    expect(controllers.handleNotUniqueError409).toHaveBeenCalledWith(
      "identifier",
      409102,
      "createClient"
    );
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Create client error", async () => {
    const bcryptSpy = jest.spyOn(bcrypt, "hash").mockImplementation(() => {
      return "hashed";
    });

    const mockedReq = {
      body: {
        identifier: "pass",
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnValue([]),
      transaction: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const nextMock = jest.fn();

    const controllers = authControllers(knexMock, "secret");

    controllers.handleError500 = jest.fn();

    controllers.callNextOrResOnError = jest.fn();

    await controllers.createClient(mockedReq, mockRes, nextMock);

    expect(controllers.handleError500).toHaveBeenCalled();

    expect(controllers.callNextOrResOnError).toHaveBeenCalled();

    bcryptSpy.mockRestore();
  });

  test("Creates the role in a transaction", async () => {
    const reqBody = {
      identifier: "identifier",
      allowedObject: { allowed: ["*", "select"] },
    };

    const trxMock = {
      table: jest.fn().mockReturnThis(),
      insert: jest.fn().mockResolvedValue([1]),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");

    await controllers.createRoleTransaction(trxMock, reqBody);

    expect(trxMock.insert).toHaveBeenCalledTimes(2);
    expect(trxMock.table).toHaveBeenCalledWith("OAUTH2_RolePermission");
    expect(trxMock.table).toHaveBeenCalledWith("OAUTH2_Roles");
  });

  test("Creates the role in a transaction fails", async () => {
    const reqBody = {
      identifier: "identifier",
      allowedObject: { allowed: ["*", "select"] },
    };

    const trxMock = {
      table: jest.fn().mockReturnThis(),
      insert: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");

    await expect(
      controllers.createRoleTransaction(trxMock, reqBody)
    ).rejects.toThrow();
  });

  test("Create role", async () => {
    const mockedReq = {
      body: {
        identifier: "identifier",
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnValue([]),
      transaction: jest.fn(),
    };

    const nextMock = jest.fn();

    const controllers = authControllers(knexMock, "secret");

    await controllers.createRole(mockedReq, mockRes, nextMock);

    expect(mockRes.status).toHaveBeenCalledWith(201);
    expect(mockRes.json).toHaveBeenCalledWith({
      code: 200001,
      message: "Role added",
      content: { roleId: -1 },
    });
    expect(knexMock.table).toHaveBeenCalledWith("OAUTH2_Roles");
    expect(knexMock.select).toHaveBeenCalled();
    expect(knexMock.where).toHaveBeenCalledWith("identifier", "identifier");
  });

  test("Create role, duplicated", async () => {
    const mockedReq = {
      body: {
        identifier: "identifier",
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnValue([{ id: 1 }]),
      transaction: jest.fn(),
    };

    const nextMock = jest.fn();

    const controllers = authControllers(knexMock, "secret");

    controllers.handleNotUniqueError409 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    await controllers.createRole(mockedReq, mockRes, nextMock);

    expect(controllers.handleNotUniqueError409).toHaveBeenCalledWith(
      "identifier",
      409103,
      "createRole"
    );
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Create role error", async () => {
    const mockedReq = {
      body: {
        identifier: "identifier",
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnValue([]),
      transaction: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const nextMock = jest.fn();

    const controllers = authControllers(knexMock, "secret");

    controllers.handleError500 = jest.fn();

    controllers.callNextOrResOnError = jest.fn();

    await controllers.createRole(mockedReq, mockRes, nextMock);

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Create application", async () => {
    const mockedReq = {
      body: {
        identifier: "identifier",
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnValue([]),
      insert: jest.fn().mockReturnValue([1]),
    };

    const nextMock = jest.fn();

    const controllers = authControllers(knexMock, "secret");

    await controllers.createApplication(mockedReq, mockRes, nextMock);

    expect(mockRes.status).toHaveBeenCalledWith(201);
    expect(mockRes.json).toHaveBeenCalledWith({
      code: 200001,
      message: "Application added",
      content: { applicationId: 1 },
    });
    expect(knexMock.table).toHaveBeenCalledWith("OAUTH2_Applications");
    expect(knexMock.select).toHaveBeenCalled();
    expect(knexMock.where).toHaveBeenCalledWith("identifier", "identifier");
  });

  test("Create application, duplicated", async () => {
    const mockedReq = {
      body: {
        identifier: "identifier",
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnValue([{ id: 1 }]),
      insert: jest.fn().mockReturnValue([1]),
    };

    const nextMock = jest.fn();

    const controllers = authControllers(knexMock, "secret");

    controllers.handleNotUniqueError409 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    await controllers.createApplication(mockedReq, mockRes, nextMock);

    expect(controllers.handleNotUniqueError409).toHaveBeenCalledWith(
      "identifier",
      409104,
      "createApplication"
    );
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Create application error", async () => {
    const mockedReq = {
      body: {
        identifier: "identifier",
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnValue([]),
      insert: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const nextMock = jest.fn();

    const controllers = authControllers(knexMock, "secret");

    controllers.handleError500 = jest.fn();

    controllers.callNextOrResOnError = jest.fn();

    await controllers.createApplication(mockedReq, mockRes, nextMock);

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Create application resource", async () => {
    const mockedReq = {
      body: {
        resourceIdentifier: "identifier",
        applications_id: 1,
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = {
      table: jest.fn().mockReturnThis(),
      insert: jest.fn().mockReturnValue([1]),
    };

    const controllers = authControllers(knexMock, "secret");

    await controllers.createApplicationResource(mockedReq, mockRes);

    expect(mockRes.status).toHaveBeenCalledWith(201);
    expect(mockRes.json).toHaveBeenCalled();
    expect(knexMock.table).toHaveBeenCalledWith("OAUTH2_ApplicationResource");
  });

  test("Create application resource error", async () => {
    const mockedReq = {
      body: {
        resourceIdentifier: "identifier",
        applications_id: 1,
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = {
      table: jest.fn().mockReturnThis(),
      insert: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const controllers = authControllers(knexMock, "secret");

    controllers.handleError500 = jest.fn();

    controllers.callNextOrResOnError = jest.fn();

    await controllers.createApplicationResource(mockedReq, mockRes, jest.fn());

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Create permission", async () => {
    const mockedReq = {
      body: {
        allowed: "allowed",
        applicationResource_id: 1,
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = {
      table: jest.fn().mockReturnThis(),
      insert: jest.fn().mockReturnValue([1]),
    };

    const controllers = authControllers(knexMock, "secret");

    await controllers.createPermission(mockedReq, mockRes);

    expect(mockRes.status).toHaveBeenCalledWith(201);
    expect(mockRes.json).toHaveBeenCalled();
    expect(knexMock.table).toHaveBeenCalledWith("OAUTH2_Permissions");
  });

  test("Create permission error", async () => {
    const mockedReq = {
      body: {
        allowed: "allowed",
        applicationResource_id: 1,
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = {
      table: jest.fn().mockReturnThis(),
      insert: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const controllers = authControllers(knexMock, "secret");

    controllers.handleError500 = jest.fn();

    controllers.callNextOrResOnError = jest.fn();

    await controllers.createPermission(mockedReq, mockRes, jest.fn());

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Get users", async () => {
    const mockedReq = {
      query: {
        itemsPerPage: 10,
        pageIndex: 1,
        order: "asc",
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const userBaseArray = [
      {
        id: 1,
        subjectId: 1,
        name: "name1",
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
        roleDeleted: true,
        roleId: 2,
        roleIdentifier: "rol2",
        resourceId: 4,
        applicationResource: "resource4",
        allowed: "*",
      },
    ];

    const knexMock = jest.fn().mockImplementation((objectOrString) => {
      const knex = {};
      knex.limit = jest.fn().mockReturnValue(knex);
      knex.offset = jest.fn().mockReturnValue(knex);
      knex.orderBy = jest.fn();
      knex.select = jest.fn().mockReturnValue(knex);
      knex.where = jest.fn().mockReturnValueOnce(knex);
      knex.table = jest.fn().mockReturnValue(knex);
      knex.count = jest.fn().mockResolvedValue([{ "count(*)": 2 }]);
      knex.join = jest.fn().mockImplementation((some) => {
        knex.where = jest.fn().mockReturnValueOnce(userBaseArray);
        return knex;
      });
      return knex;
    });

    const helper = generalHelpers();

    const parsedUsers = helper.parseSubjectSearch(userBaseArray, "user");

    const controllers = authControllers(knexMock, "secret");

    await controllers.getUsers(mockedReq, mockRes);

    expect(knexMock).toHaveBeenCalledTimes(3);

    expect(knexMock).toHaveBeenCalledWith("OAUTH2_Users");

    expect(mockRes.status).toHaveBeenCalledWith(200);

    expect(mockRes.json).toHaveBeenCalledWith({
      code: 200000,
      message: "Select completed",
      content: {
        items: parsedUsers,
        pageIndex: 1,
        itemsPerPage: 10,
        totalItems: 2,
        totalPages: 1,
      },
    });
  });

  test("Get users not query", async () => {
    const mockedReq = {
      query: {},
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const userBaseArray = [
      {
        id: 1,
        subjectId: 1,
        name: "name1",
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
        roleDeleted: true,
        roleId: 2,
        roleIdentifier: "rol2",
        resourceId: 4,
        applicationResource: "resource4",
        allowed: "*",
      },
    ];

    const knexMock = jest.fn().mockImplementation((objectOrString) => {
      const knex = {};
      knex.limit = jest.fn().mockReturnValue(knex);
      knex.offset = jest.fn().mockReturnValue(knex);
      knex.orderBy = jest.fn();
      knex.select = jest.fn().mockReturnValue(knex);
      knex.where = jest.fn().mockReturnValueOnce(knex);
      knex.table = jest.fn().mockReturnValue(knex);
      knex.count = jest.fn().mockResolvedValue([{ "count(*)": 2 }]);
      knex.join = jest.fn().mockImplementation((some) => {
        knex.where = jest.fn().mockReturnValueOnce(userBaseArray);
        return knex;
      });
      return knex;
    });

    const helper = generalHelpers();

    const parsedUsers = helper.parseSubjectSearch(userBaseArray, "user");

    const controllers = authControllers(knexMock, "secret");

    await controllers.getUsers(mockedReq, mockRes);

    expect(knexMock).toHaveBeenCalledTimes(3);

    expect(knexMock).toHaveBeenCalledWith("OAUTH2_Users");

    expect(mockRes.status).toHaveBeenCalledWith(200);

    expect(mockRes.json).toHaveBeenCalledWith({
      code: 200000,
      message: "Select completed",
      content: {
        items: parsedUsers,
        pageIndex: 0,
        itemsPerPage: 5,
        totalItems: 2,
        totalPages: 1,
      },
    });
  });

  test("Get users fails", async () => {
    const mockedReq = {
      query: {
        itemsPerPage: 10,
        pageIndex: 1,
        order: "asc",
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = jest.fn().mockImplementation((objectOrString) => {
      const knex = {};
      knex.limit = jest.fn().mockReturnValue(knex);
      knex.offset = jest.fn().mockReturnValue(knex);
      knex.orderBy = jest.fn();
      knex.select = jest.fn().mockReturnValue(knex);
      knex.where = jest.fn().mockReturnValueOnce(knex);
      knex.table = jest.fn().mockReturnValue(knex);
      knex.count = jest.fn().mockResolvedValue([{ "count(*)": 2 }]);
      knex.join = jest.fn().mockImplementation((some) => {
        knex.where = jest.fn().mockRejectedValueOnce(new Error("Async error"));
        return knex;
      });
      return knex;
    });

    const controllers = authControllers(knexMock, "secret");

    controllers.handleError500 = jest.fn();

    controllers.callNextOrResOnError = jest.fn();

    await controllers.getUsers(mockedReq, mockRes, jest.fn());

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Get one user by id", async () => {
    const mockedReq = {
      params: {
        id: 1,
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const userBaseArray = [
      {
        id: 1,
        subjectId: 1,
        name: "name1",
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
        roleId: 2,
        roleIdentifier: "rol2",
        resourceId: 4,
        applicationResource: "resource4",
        allowed: "*",
      },
    ];

    const mockKnex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      join: jest.fn().mockReturnThis(),
      where: jest.fn().mockResolvedValue(userBaseArray),
    };

    const controllers = authControllers(mockKnex, "secret");

    await controllers.getUser(mockedReq, mockRes);

    expect(mockKnex.select).toHaveBeenCalledWith(
      "OAUTH2_Users.id",
      "OAUTH2_Users.username",
      "OAUTH2_Subjects.description",
      "OAUTH2_Subjects.id as subjectId",
      "OAUTH2_Subjects.name",
      "OAUTH2_ApplicationResource.resourceIdentifier as applicationResource",
      "OAUTH2_ApplicationResource.id as resourceId",
      "OAUTH2_Permissions.allowed",
      "OAUTH2_Roles.id as roleId",
      "OAUTH2_Roles.identifier as roleIdentifier"
    );

    expect(mockKnex.join).toHaveBeenCalledWith(
      "OAUTH2_Subjects",
      `OAUTH2_Users.subject_id`,
      "OAUTH2_Subjects.id"
    );

    expect(mockKnex.join).toHaveBeenCalledWith(
      "OAUTH2_SubjectRole",
      `OAUTH2_Users.subject_id`,
      "OAUTH2_SubjectRole.subject_id"
    );

    expect(mockKnex.join).toHaveBeenCalledWith(
      "OAUTH2_Roles",
      `OAUTH2_Roles.id`,
      "OAUTH2_SubjectRole.roles_id"
    );

    expect(mockKnex.join).toHaveBeenCalledWith(
      "OAUTH2_ApplicationResource",
      `OAUTH2_ApplicationResource.id`,
      "OAUTH2_Permissions.applicationResource_id"
    );

    expect(mockRes.status).toHaveBeenCalledWith(200);
  });

  test("Get one user by id incorrect params", async () => {
    const mockedReq = {
      params: {
        id: "nan",
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const mockKnex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      join: jest.fn().mockReturnThis(),
      where: jest.fn(),
    };

    const controllers = authControllers(mockKnex, "secret");

    controllers.handleError = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    await controllers.getUser(mockedReq, mockRes, jest.fn());

    expect(controllers.handleError).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Get one user by id, user does not exist", async () => {
    const mockedReq = {
      params: {
        id: 1,
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const mockKnex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      join: jest.fn().mockReturnThis(),
      where: jest.fn().mockResolvedValue([]),
    };

    const controllers = authControllers(mockKnex, "secret");

    controllers.handleError = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    await controllers.getUser(mockedReq, mockRes);

    expect(controllers.handleError).toHaveBeenLastCalledWith(
      "User does not exist",
      404002,
      404,
      "getUser"
    );
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Get one user by id fails", async () => {
    const mockedReq = {
      params: {
        id: 1,
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const mockKnex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      join: jest.fn().mockReturnThis(),
      where: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const controllers = authControllers(mockKnex, "secret");

    controllers.handleError500 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    await controllers.getUser(mockedReq, mockRes, jest.fn());

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Get me user", async () => {
    const userBaseArray = [
      {
        id: 1,
        subjectId: 1,
        name: "name1",
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
        roleId: 2,
        roleIdentifier: "rol2",
        resourceId: 4,
        applicationResource: "resource4",
        allowed: "*",
      },
    ];

    const mockedReq = {
      params: {
        id: 1,
      },
    };

    const mockRes = {
      locals: {
        user: { subjectType: "user", username: "user" },
      },
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const mockKnex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      join: jest.fn().mockReturnThis(),
      where: jest.fn().mockResolvedValue(userBaseArray),
    };

    const controllers = authControllers(mockKnex, "secret");
    await controllers.getMe(mockedReq, mockRes);

    expect(mockKnex.select).toHaveBeenCalledWith(
      "OAUTH2_Users.id",
      "OAUTH2_Users.username",
      "OAUTH2_Subjects.description",
      "OAUTH2_Subjects.id as subjectId",
      "OAUTH2_Subjects.name",
      "OAUTH2_ApplicationResource.resourceIdentifier as applicationResource",
      "OAUTH2_ApplicationResource.id as resourceId",
      "OAUTH2_Permissions.allowed",
      "OAUTH2_Roles.id as roleId",
      "OAUTH2_Roles.deleted as roleDeleted",
      "OAUTH2_Roles.identifier as roleIdentifier"
    );

    expect(mockRes.status).toHaveBeenCalledWith(200);
  });

  test("Get me user incorrect type", async () => {
    const userBaseArray = [
      {
        id: 1,
        subjectId: 1,
        name: "name1",
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
        roleId: 2,
        roleIdentifier: "rol2",
        resourceId: 4,
        applicationResource: "resource4",
        allowed: "*",
      },
    ];

    const mockedReq = {
      params: {
        id: 1,
      },
    };

    const mockRes = {
      locals: {
        user: { subjectType: "client", username: "client" },
      },
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const mockKnex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      join: jest.fn().mockReturnThis(),
      where: jest.fn().mockResolvedValue(userBaseArray),
    };

    const controllers = authControllers(mockKnex, "secret");

    controllers.handleError = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    await controllers.getMe(mockedReq, mockRes, jest.fn());

    expect(controllers.handleError).toHaveBeenCalledWith(
      `Invalid subject type client`,
      400003,
      400,
      "getMe"
    );
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Get me user fails", async () => {
    const mockedReq = {
      params: {
        id: 1,
      },
    };

    const mockRes = {
      locals: {
        user: { subjectType: "user", username: "user" },
      },
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const mockKnex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      join: jest.fn().mockReturnThis(),
      where: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const controllers = authControllers(mockKnex, "secret");

    controllers.handleError500 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    await controllers.getMe(mockedReq, mockRes, jest.fn());

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Get clients", async () => {
    const mockedReq = {
      query: {
        itemsPerPage: 10,
        pageIndex: 1,
        order: "asc",
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const userBaseArray = [
      {
        id: 1,
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
        name: "name2",
        identifier: "user2",
        roleDeleted: true,
        roleId: 2,
        roleIdentifier: "rol2",
        resourceId: 4,
        applicationResource: "resource4",
        allowed: "*",
      },
    ];

    const knexMock = jest.fn().mockImplementation((objectOrString) => {
      const knex = {};
      knex.limit = jest.fn().mockReturnValue(knex);
      knex.offset = jest.fn().mockReturnValue(knex);
      knex.orderBy = jest.fn().mockReturnValue(userBaseArray);
      knex.select = jest.fn().mockReturnValue(knex);
      knex.where = jest.fn().mockReturnValue(knex);
      knex.table = jest.fn().mockReturnValue(knex);
      knex.count = jest.fn().mockResolvedValue([{ "count(*)": 2 }]);
      knex.join = jest.fn().mockReturnValue(knex);
      return knex;
    });

    const helper = generalHelpers();

    const parsedUsers = helper.parseSubjectSearch(userBaseArray, "client");

    const controllers = authControllers(knexMock, "secret");

    await controllers.getClients(mockedReq, mockRes);

    expect(knexMock).toHaveBeenCalledTimes(3);

    expect(knexMock).toHaveBeenCalledWith("OAUTH2_Clients");

    expect(mockRes.status).toHaveBeenCalledWith(200);

    expect(mockRes.json).toHaveBeenCalledWith({
      code: 200000,
      message: "Select completed",
      content: {
        items: parsedUsers,
        pageIndex: 1,
        itemsPerPage: 10,
        totalItems: 2,
        totalPages: 1,
      },
    });
  });

  test("Get clients fails", async () => {
    const mockedReq = {
      query: {
        itemsPerPage: 10,
        pageIndex: 1,
        order: "asc",
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = jest.fn().mockImplementation((objectOrString) => {
      const knex = {};
      knex.limit = jest.fn().mockReturnValue(knex);
      knex.offset = jest.fn().mockReturnValue(knex);
      knex.orderBy = jest.fn();
      knex.select = jest.fn().mockReturnValue(knex);
      knex.where = jest.fn().mockReturnValueOnce(knex);
      knex.table = jest.fn().mockReturnValue(knex);
      knex.count = jest.fn().mockResolvedValue([{ "count(*)": 2 }]);
      knex.join = jest.fn().mockImplementation((some) => {
        knex.where = jest.fn().mockRejectedValueOnce(new Error("Async error"));
        return knex;
      });
      return knex;
    });

    const controllers = authControllers(knexMock, "secret");

    controllers.handleError500 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    await controllers.getClients(mockedReq, mockRes, jest.fn());

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Get clients not query", async () => {
    const mockedReq = {
      query: {},
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const userBaseArray = [
      {
        id: 1,
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
        name: "name2",
        identifier: "user2",
        roleDeleted: true,
        roleId: 2,
        roleIdentifier: "rol2",
        resourceId: 4,
        applicationResource: "resource4",
        allowed: "*",
      },
    ];

    const knexMock = jest.fn().mockImplementation((objectOrString) => {
      const knex = {};
      knex.limit = jest.fn().mockReturnValue(knex);
      knex.offset = jest.fn().mockReturnValue(knex);
      knex.orderBy = jest.fn().mockReturnValue(userBaseArray);
      knex.select = jest.fn().mockReturnValue(knex);
      knex.where = jest.fn().mockReturnValue(knex);
      knex.table = jest.fn().mockReturnValue(knex);
      knex.count = jest.fn().mockResolvedValue([{ "count(*)": 2 }]);
      knex.join = jest.fn().mockReturnValue(knex);
      return knex;
    });

    const helper = generalHelpers();

    const parsedUsers = helper.parseSubjectSearch(userBaseArray, "client");

    const controllers = authControllers(knexMock, "secret");

    await controllers.getClients(mockedReq, mockRes);

    expect(knexMock).toHaveBeenCalledTimes(3);

    expect(knexMock).toHaveBeenCalledWith("OAUTH2_Clients");

    expect(mockRes.status).toHaveBeenCalledWith(200);

    expect(mockRes.json).toHaveBeenCalledWith({
      code: 200000,
      message: "Select completed",
      content: {
        items: parsedUsers,
        pageIndex: 0,
        itemsPerPage: 5,
        totalItems: 2,
        totalPages: 1,
      },
    });
  });

  test("Delete user transaction", async () => {
    const trxMock = {
      table: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      update: jest.fn().mockResolvedValue([1]),
    };

    const controllers = authControllers(trxMock, "secret");
    await controllers.deleteUserTransaction(trxMock, 1);

    expect(trxMock.table).toHaveBeenCalledWith("OAUTH2_Users");
    expect(trxMock.table).toHaveBeenCalledWith("OAUTH2_Subjects");
  });

  test("Delete user transaction fails", async () => {
    const trxMock = {
      table: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      update: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const controllers = authControllers(trxMock, "secret");
    await expect(
      controllers.deleteUserTransaction(trxMock, 1)
    ).rejects.toThrow();
  });

  test("Delete user", async () => {
    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnValue([{ id: 1 }]),
      transaction: jest.fn(),
    };

    const req = {
      params: {
        subjectId: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const controllers = authControllers(knex, "secret");

    await controllers.deleteUser(req, res);

    expect(knex.transaction).toHaveBeenCalled();

    expect(res.status).toHaveBeenCalledWith(201);

    expect(res.json).toHaveBeenCalledWith({
      code: 200001,
      message: "User deleted",
    });
  });

  test("Delete user, does not exists", async () => {
    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnValue([]),
      transaction: jest.fn(),
    };

    const req = {
      params: {
        subjectId: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const controllers = authControllers(knex, "secret");

    controllers.handleError = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    await controllers.deleteUser(req, res);

    expect(controllers.handleError).toHaveBeenCalledWith(
      "User does not exist",
      404002,
      404,
      "deleteUser"
    );

    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Delete user fails", async () => {
    const knex = {
      transaction: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const req = {
      params: {
        subjectId: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const controllers = authControllers(knex, "secret", jest.fn());

    controllers.handleError500 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    await controllers.deleteUser(req, res);

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Delete client transaction", async () => {
    const trxMock = {
      table: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      update: jest.fn().mockResolvedValue([1]),
    };

    const controllers = authControllers(trxMock, "secret");
    await controllers.deleteClientTransaction(trxMock, 1);

    expect(trxMock.table).toHaveBeenCalledWith("OAUTH2_Clients");
    expect(trxMock.table).toHaveBeenCalledWith("OAUTH2_Subjects");
  });

  test("Delete client transaction fails", async () => {
    const trxMock = {
      table: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      update: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const controllers = authControllers(trxMock, "secret");
    await expect(
      controllers.deleteClientTransaction(trxMock, 1)
    ).rejects.toThrow();
  });

  test("Delete client", async () => {
    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnValue([{ id: 1 }]),
      transaction: jest.fn(),
    };

    const req = {
      params: {
        subjectId: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const controllers = authControllers(knex, "secret");

    await controllers.deleteClient(req, res);

    expect(knex.transaction).toHaveBeenCalled();

    expect(res.status).toHaveBeenCalledWith(201);
    expect(res.json).toHaveBeenCalledWith({
      code: 200001,
      message: "Client deleted",
    });
  });

  test("Delete client, does not exist", async () => {
    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnValue([]),
      transaction: jest.fn(),
    };

    const req = {
      params: {
        subjectId: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const controllers = authControllers(knex, "secret");

    controllers.handleError = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    await controllers.deleteClient(req, res);

    expect(controllers.handleError).toHaveBeenCalledWith(
      "Client does not exist",
      404003,
      404,
      "deleteClient"
    );
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Delete client fails", async () => {
    const knex = {
      transaction: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const req = {
      params: {
        subjectId: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const controllers = authControllers(knex, "secret");
    controllers.handleError500 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();
    await controllers.deleteClient(req, res);

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Delete role", async () => {
    const req = {
      params: {
        id: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const updateFunction = jest.fn().mockResolvedValue([1]);

    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest
        .fn()
        .mockReturnValueOnce([{ id: 1 }])
        .mockReturnValueOnce({
          update: updateFunction,
        }),
    };

    const controllers = authControllers(knex, "secret");

    await controllers.deleteRole(req, res);

    expect(knex.table).toHaveBeenCalledWith("OAUTH2_Roles");
    expect(knex.where).toHaveBeenCalledWith({ id: 1 });
    expect(updateFunction).toHaveBeenCalledWith("deleted", true);

    expect(res.status).toHaveBeenCalledWith(201);
    expect(res.json).toHaveBeenCalledWith({
      code: 200001,
      message: "Role deleted",
    });
  });

  test("Delete role, does not exist", async () => {
    const req = {
      params: {
        id: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnValue([]),
      update: jest.fn().mockResolvedValue([1]),
    };

    const controllers = authControllers(knex, "secret");

    controllers.handleError = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    await controllers.deleteRole(req, res);

    expect(controllers.handleError).toHaveBeenCalledWith(
      "Role does not exist",
      404004,
      404,
      "deleteRole"
    );
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Delete role fails", async () => {
    const req = {
      params: {
        id: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {
      table: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      update: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const controllers = authControllers(knex, "secret");
    controllers.handleError500 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();
    await controllers.deleteRole(req, res);

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Update user", async () => {
    const req = {
      body: {
        name: "new name",
      },
      params: {
        subjectId: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const updateFunction = jest.fn().mockResolvedValue([1]);

    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest
        .fn()
        .mockReturnValueOnce([{ id: 1 }])
        .mockReturnValueOnce({
          update: updateFunction,
        }),
    };

    const controllers = authControllers(knex, "secret");

    await controllers.updateUser(req, res);

    expect(knex.table).toHaveBeenCalledWith("OAUTH2_Subjects");
    expect(knex.where).toHaveBeenCalledWith({ id: 1 });
    expect(updateFunction).toHaveBeenCalledWith({ name: "new name" });

    expect(res.status).toHaveBeenCalledWith(201);
  });

  test("Update user, user does not exists", async () => {
    const req = {
      body: {
        name: "new name",
      },
      params: {
        subjectId: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnValue([]),
    };

    const controllers = authControllers(knex, "secret");

    controllers.handleError = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    await controllers.updateUser(req, res);

    expect(knex.table).toHaveBeenCalledWith("OAUTH2_Users");
    expect(knex.select).toHaveBeenCalled();
    expect(knex.where).toHaveBeenCalledWith("subject_id", 1);
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
    expect(controllers.handleError).toHaveBeenCalled();
  });

  test("Update user fails", async () => {
    const req = {
      body: {
        name: "new name",
      },
      params: {
        id: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {
      table: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      update: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const controllers = authControllers(knex, "secret");
    controllers.handleError500 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();
    await controllers.updateUser(req, res);

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Update client", async () => {
    const req = {
      body: {
        name: "new name",
      },
      params: {
        subjectId: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const updateFunction = jest.fn().mockResolvedValue([1]);

    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest
        .fn()
        .mockReturnValueOnce([{ id: 1 }])
        .mockReturnValueOnce({
          update: updateFunction,
        }),
    };

    const controllers = authControllers(knex, "secret");

    await controllers.updateClient(req, res);

    expect(knex.table).toHaveBeenCalledWith("OAUTH2_Subjects");
    expect(knex.where).toHaveBeenCalledWith({ id: 1 });
    expect(updateFunction).toHaveBeenCalledWith({ name: "new name" });

    expect(res.status).toHaveBeenCalledWith(201);
  });

  test("Update client, client does not exists", async () => {
    const req = {
      body: {
        name: "new name",
      },
      params: {
        subjectId: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnValue([]),
    };

    const controllers = authControllers(knex, "secret");

    controllers.handleError = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    await controllers.updateClient(req, res);

    expect(knex.table).toHaveBeenCalledWith("OAUTH2_Clients");
    expect(knex.where).toHaveBeenCalledWith("subject_id", 1);

    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
    expect(controllers.handleError).toHaveBeenCalled();
  });

  test("Update client fails", async () => {
    const req = {
      body: {
        name: "new name",
      },
      params: {
        id: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {
      table: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      update: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const controllers = authControllers(knex, "secret");
    controllers.handleError500 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();
    await controllers.updateClient(req, res);

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Update password", async () => {
    const req = {
      body: {
        newPassword: "123",
        oldPassword: "1234",
      },
      params: {
        id: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest
        .fn()
        .mockResolvedValue([1])
        .mockResolvedValueOnce([{ password: "1234" }]),
      update: jest.fn().mockReturnThis(),
    };

    const bcryptSpyCompare = jest
      .spyOn(bcrypt, "compare")
      .mockImplementation(() => {
        return true;
      });

    const bcryptSpyHash = jest.spyOn(bcrypt, "hash").mockImplementation(() => {
      return "hashed";
    });

    const controllers = authControllers(knex, "secret");

    await controllers.updatePassword(req, res);

    expect(res.status).toHaveBeenCalledWith(201);

    expect(knex.table).toHaveBeenCalledWith("OAUTH2_Users");
    expect(knex.where).toHaveBeenCalledWith({ id: 1 });
    expect(knex.update).toHaveBeenCalledWith({ password: "hashed" });

    expect(bcryptSpyCompare).toHaveBeenCalled();
    expect(bcryptSpyHash).toHaveBeenCalled();

    bcryptSpyCompare.mockRestore();
    bcryptSpyHash.mockRestore();
  });

  test("Update password, user does not exist", async () => {
    const req = {
      body: {
        newPassword: "123",
        oldPassword: "1234",
      },
      params: {
        id: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnValue([]),
      update: jest.fn().mockReturnThis(),
    };

    const bcryptSpyCompare = jest
      .spyOn(bcrypt, "compare")
      .mockImplementation(() => {
        return true;
      });

    const bcryptSpyHash = jest.spyOn(bcrypt, "hash").mockImplementation(() => {
      return "hashed";
    });

    const controllers = authControllers(knex, "secret");

    controllers.handleError = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    await controllers.updatePassword(req, res);

    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
    expect(controllers.handleError).toHaveBeenCalledWith(
      "User does not exist",
      404006,
      404,
      "updatePassword"
    );

    bcryptSpyCompare.mockRestore();
    bcryptSpyHash.mockRestore();
  });

  test("Update password incorrect original password", async () => {
    const req = {
      body: {
        newPassword: "123",
        oldPassword: "1234",
      },
      params: {
        id: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest
        .fn()
        .mockResolvedValue([1])
        .mockResolvedValueOnce([{ password: "1234" }]),
      update: jest.fn().mockReturnThis(),
    };

    const bcryptSpyCompare = jest
      .spyOn(bcrypt, "compare")
      .mockImplementation(() => {
        return false;
      });

    const bcryptSpyHash = jest.spyOn(bcrypt, "hash").mockImplementation(() => {
      return "hashed";
    });

    const controllers = authControllers(knex, "secret");

    controllers.handleError = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    await controllers.updatePassword(req, res);

    expect(controllers.handleError).toHaveBeenCalledWith(
      "Incorrect password",
      401002,
      401,
      "updatePassword"
    );
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();

    bcryptSpyCompare.mockRestore();
    bcryptSpyHash.mockRestore();
  });

  test("Update password fails", async () => {
    const req = {
      body: {
        newPassword: "123",
        oldPassword: "1234",
      },
      params: {
        id: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockRejectedValueOnce(new Error("Async error")),
      update: jest.fn().mockReturnThis(),
    };

    const bcryptSpyCompare = jest
      .spyOn(bcrypt, "compare")
      .mockImplementation(() => {
        return true;
      });

    const bcryptSpyHash = jest.spyOn(bcrypt, "hash").mockImplementation(() => {
      return "hashed";
    });

    const controllers = authControllers(knex, "secret");
    controllers.handleError500 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();
    await controllers.updatePassword(req, res);

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();

    bcryptSpyCompare.mockRestore();
    bcryptSpyHash.mockRestore();
  });

  test("Select roles basic", async () => {
    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockResolvedValue([{ id: 1, identifier: "admin" }]),
    };

    const req = {
      query: {
        basic: "true",
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const controllers = authControllers(knex, "secret");

    await controllers.getRoles(req, res);

    expect(knex.table).toHaveBeenCalledWith("OAUTH2_Roles");

    expect(knex.where).toHaveBeenCalledWith({ deleted: false });

    expect(knex.select).toHaveBeenCalledWith(
      "OAUTH2_Roles.id",
      "OAUTH2_Roles.identifier"
    );

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({
      code: 200000,
      message: "Select completed",
      content: [{ id: 1, identifier: "admin" }],
    });
  });

  test("Select roles with pagination", async () => {
    const mockedReq = {
      query: {
        itemsPerPage: 10,
        pageIndex: 1,
        order: "asc",
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const rolesBaseArray = [
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

    const knexMock = jest.fn().mockImplementation((objectOrString) => {
      const knex = {};
      knex.limit = jest.fn().mockReturnValue(knex);
      knex.offset = jest.fn().mockReturnValue(knex);
      knex.orderBy = jest.fn();
      knex.select = jest.fn().mockReturnValue(knex);
      knex.where = jest.fn().mockReturnValueOnce(knex);
      knex.table = jest.fn().mockReturnValue(knex);
      knex.count = jest.fn().mockResolvedValue([{ "count(*)": 2 }]);
      knex.join = jest.fn().mockImplementation((some) => {
        knex.where = jest.fn().mockReturnValueOnce(rolesBaseArray);
        return knex;
      });
      return knex;
    });

    const helper = generalHelpers();

    const parsedRoles = helper.parseRoleSearch(rolesBaseArray);

    const controllers = authControllers(knexMock, "secret");

    await controllers.getRoles(mockedReq, mockRes);

    expect(knexMock).toHaveBeenCalledTimes(3);

    expect(knexMock).toHaveBeenCalledWith("OAUTH2_Roles");

    expect(mockRes.status).toHaveBeenCalledWith(200);

    expect(mockRes.json).toHaveBeenCalledWith({
      code: 200000,
      message: "Select completed",
      content: {
        items: parsedRoles,
        pageIndex: 1,
        itemsPerPage: 10,
        totalItems: 2,
        totalPages: 1,
      },
    });
  });

  test("Select roles with pagination no query", async () => {
    const mockedReq = {
      query: {},
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const rolesBaseArray = [
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

    const knexMock = jest.fn().mockImplementation((objectOrString) => {
      const knex = {};
      knex.limit = jest.fn().mockReturnValue(knex);
      knex.offset = jest.fn().mockReturnValue(knex);
      knex.orderBy = jest.fn();
      knex.select = jest.fn().mockReturnValue(knex);
      knex.where = jest.fn().mockReturnValueOnce(knex);
      knex.table = jest.fn().mockReturnValue(knex);
      knex.count = jest.fn().mockResolvedValue([{ "count(*)": 2 }]);
      knex.join = jest.fn().mockImplementation((some) => {
        knex.where = jest.fn().mockReturnValueOnce(rolesBaseArray);
        return knex;
      });
      return knex;
    });

    const helper = generalHelpers();

    const parsedRoles = helper.parseRoleSearch(rolesBaseArray);

    const controllers = authControllers(knexMock, "secret");

    await controllers.getRoles(mockedReq, mockRes);

    expect(knexMock).toHaveBeenCalledTimes(3);

    expect(knexMock).toHaveBeenCalledWith("OAUTH2_Roles");

    expect(mockRes.status).toHaveBeenCalledWith(200);

    expect(mockRes.json).toHaveBeenCalledWith({
      code: 200000,
      message: "Select completed",
      content: {
        items: parsedRoles,
        pageIndex: 0,
        itemsPerPage: 5,
        totalItems: 2,
        totalPages: 1,
      },
    });
  });

  test("Select roles with pagination fails", async () => {
    const mockedReq = {
      query: {},
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = jest.fn().mockImplementation((objectOrString) => {
      const knex = {};
      knex.limit = jest.fn().mockReturnValue(knex);
      knex.offset = jest.fn().mockReturnValue(knex);
      knex.orderBy = jest.fn();
      knex.select = jest.fn().mockReturnValue(knex);
      knex.where = jest.fn().mockReturnValueOnce(knex);
      knex.table = jest.fn().mockReturnValue(knex);
      knex.count = jest.fn().mockResolvedValue([{ "count(*)": 2 }]);
      knex.join = jest.fn().mockImplementation((some) => {
        knex.where = jest.fn().mockRejectedValueOnce(new Error("Async error"));
        return knex;
      });
      return knex;
    });

    const controllers = authControllers(knexMock, "secret");
    controllers.handleError500 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();
    await controllers.getRoles(mockedReq, mockRes);

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Select resource basic", async () => {
    const knex = () => {
      const knexObjs = {};
      knexObjs.table = jest.fn().mockReturnValue(knexObjs);
      knexObjs.select = jest.fn().mockReturnValue(knexObjs);
      knexObjs.join = jest.fn().mockReturnValue(knexObjs);
      knexObjs.where = jest
        .fn()
        .mockReturnValueOnce(knexObjs)
        .mockReturnValueOnce([
          {
            resourceId: 1,
            applicationResourceName: "resourceName1",
            allowed: "*",
            permissionId: 1,
          },
        ]);
      return knexObjs;
    };

    const mockKnex = knex();

    const req = {
      query: {
        basic: "true",
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const helpers = generalHelpers();

    const parsedResources = helpers.parseResourceSearch([
      {
        resourceId: 1,
        applicationResourceName: "resourceName1",
        allowed: "*",
        permissionId: 1,
      },
    ]);

    const controllers = authControllers(mockKnex, "secret");

    await controllers.getResources(req, res);

    expect(mockKnex.table).toHaveBeenCalledWith("OAUTH2_ApplicationResource");

    expect(mockKnex.where).toHaveBeenCalledWith(
      "OAUTH2_ApplicationResource.deleted",
      false
    );

    expect(mockKnex.select).toHaveBeenCalledWith(
      "OAUTH2_ApplicationResource.resourceIdentifier as applicationResourceName",
      "OAUTH2_ApplicationResource.id as resourceId",
      "OAUTH2_Permissions.allowed",
      "OAUTH2_Permissions.id as permissionId"
    );

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({
      code: 200000,
      message: "Select completed",
      content: parsedResources,
    });
  });

  test("Select resource with pagination", async () => {
    const mockedReq = {
      query: {
        itemsPerPage: 10,
        pageIndex: 1,
        order: "asc",
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const resourcesBaseArray = [
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

    const knexMock = jest.fn().mockImplementation((objectOrString) => {
      const knex = {};
      knex.limit = jest.fn().mockReturnValue(knex);
      knex.offset = jest.fn().mockReturnValue(knex);
      knex.orderBy = jest.fn().mockResolvedValue(resourcesBaseArray);
      knex.select = jest.fn().mockReturnValue(knex);
      knex.where = jest
        .fn()
        .mockReturnValue(resourcesBaseArray)
        .mockReturnValueOnce(knex)
        .mockReturnValueOnce(knex);
      knex.table = jest.fn().mockReturnValue(knex);
      knex.count = jest.fn().mockResolvedValue([{ "count(*)": 2 }]);
      knex.join = jest.fn().mockReturnValue(knex);
      return knex;
    });

    const helper = generalHelpers();

    const parsedResources = helper.parseResourceSearch(resourcesBaseArray);

    const controllers = authControllers(knexMock, "secret");

    await controllers.getResources(mockedReq, mockRes);

    expect(knexMock).toHaveBeenCalledTimes(3);

    expect(knexMock).toHaveBeenCalledWith("OAUTH2_ApplicationResource");

    expect(mockRes.status).toHaveBeenCalledWith(200);

    expect(mockRes.json).toHaveBeenCalledWith({
      code: 200000,
      message: "Select completed",
      content: {
        items: [],
        pageIndex: 1,
        itemsPerPage: 10,
        totalItems: 2,
        totalPages: 1,
      },
    });
  });

  test("Select resources with pagination no query", async () => {
    const mockedReq = {
      query: {},
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const resourcesBaseArray = [
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

    const knexMock = jest.fn().mockImplementation((objectOrString) => {
      const knex = {};
      knex.limit = jest.fn().mockReturnValue(knex);
      knex.offset = jest.fn().mockReturnValue(knex);
      knex.orderBy = jest.fn().mockResolvedValue(resourcesBaseArray);
      knex.select = jest.fn().mockReturnValue(knex);
      knex.where = jest
        .fn()
        .mockReturnValue(resourcesBaseArray)
        .mockReturnValueOnce(knex)
        .mockReturnValueOnce(knex);
      knex.table = jest.fn().mockReturnValue(knex);
      knex.count = jest.fn().mockResolvedValue([{ "count(*)": 2 }]);
      knex.join = jest.fn().mockReturnValue(knex);
      return knex;
    });

    const helper = generalHelpers();

    const parsedResources = helper.parseResourceSearch(resourcesBaseArray);

    const controllers = authControllers(knexMock, "secret");

    await controllers.getResources(mockedReq, mockRes);

    expect(knexMock).toHaveBeenCalledTimes(3);

    expect(knexMock).toHaveBeenCalledWith("OAUTH2_ApplicationResource");

    expect(mockRes.status).toHaveBeenCalledWith(200);

    expect(mockRes.json).toHaveBeenCalledWith({
      code: 200000,
      message: "Select completed",
      content: {
        items: [],
        pageIndex: 0,
        itemsPerPage: 5,
        totalItems: 2,
        totalPages: 1,
      },
    });
  });

  test("Select resources with pagination fails", async () => {
    const mockedReq = {
      query: {
        itemsPerPage: 10,
        pageIndex: 1,
        order: "asc",
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = jest.fn().mockImplementation((objectOrString) => {
      const knex = {};
      knex.limit = jest.fn().mockReturnValue(knex);
      knex.offset = jest.fn().mockReturnValue(knex);
      knex.orderBy = jest.fn();
      knex.select = jest.fn().mockReturnValue(knex);
      knex.where = jest.fn().mockReturnValue(knex);
      knex.table = jest.fn().mockReturnValue(knex);
      knex.count = jest.fn().mockRejectedValueOnce(new Error("Async error"));
      knex.join = jest.fn().mockReturnValue(knex);
      return knex;
    });

    const controllers = authControllers(knexMock, "secret");
    controllers.handleError500 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();
    await controllers.getResources(mockedReq, mockRes);

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Update role permissions transaction", async () => {
    const reqBody = {
      newAllowedObject: {
        permission: [{ id: 1 }],
      },
      originalAllowedObject: {
        permission: [{ id: 2 }],
      },
    };

    const roleId = 1;

    const trxMock = {
      table: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      del: jest.fn(),
      insert: jest.fn().mockResolvedValue([1]),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");

    await controllers.updateRolePermissionsTransaction(
      trxMock,
      roleId,
      reqBody
    );

    expect(trxMock.del).toHaveBeenCalledTimes(1);
    expect(trxMock.table).toHaveBeenCalledWith("OAUTH2_RolePermission");
  });

  test("Update role permissions transaction second branch", async () => {
    const reqBody = {
      newAllowedObject: {
        permission: [{ id: 2 }],
      },
      originalAllowedObject: {
        permission: [{ id: 2 }],
      },
    };

    const roleId = 1;

    const trxMock = {
      table: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      del: jest.fn(),
      insert: jest.fn().mockResolvedValue([1]),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");

    await controllers.updateRolePermissionsTransaction(
      trxMock,
      roleId,
      reqBody
    );

    expect(trxMock.table).not.toHaveBeenCalled();
  });

  test("Update role permissions transaction fails", async () => {
    const reqBody = {
      newAllowedObject: {
        permission: [{ id: 1 }],
      },
      originalAllowedObject: {
        permission: [{ id: 2 }],
      },
    };

    const roleId = 1;

    const trxMock = {
      table: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      del: jest.fn(),
      insert: jest.fn().mockRejectedValueOnce(new Error("Async value")),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");

    await expect(
      controllers.updateRolePermissionsTransaction(trxMock, roleId, reqBody)
    ).rejects.toThrow();
  });

  test("Update role permissions", async () => {
    const knex = {
      transaction: jest.fn(),
    };
    const req = {
      params: {
        id: 1,
      },
      body: {},
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockResolvedValue([1]),
    };
    const controllers = authControllers(knex, "secret");
    await controllers.updateRolePermissions(req, res);

    expect(knex.transaction).toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(201);
  });

  test("Update role permissions fails", async () => {
    const knex = {
      transaction: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };
    const req = {
      params: {
        id: 1,
      },
      body: {},
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockResolvedValue([1]),
    };
    const controllers = authControllers(knex, "secret");
    controllers.handleError500 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();
    await controllers.updateRolePermissions(req, res);

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Update resource permissions transaction", async () => {
    const reqBody = {
      newResourcePermissions: [{ allowed: "*" }],
      originalResourcePermissions: [{ allowed: "select" }],
    };

    const roleId = 1;

    const trxMock = {
      table: jest.fn().mockReturnThis(),
      where: jest.fn().mockResolvedValue([1]),
      update: jest.fn().mockReturnThis(),
      insert: jest.fn().mockResolvedValue([1]),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");

    await controllers.updateResourcePermissionsTransaction(
      trxMock,
      roleId,
      reqBody
    );

    expect(trxMock.update).toHaveBeenCalledTimes(1);
    expect(trxMock.table).toHaveBeenCalledWith("OAUTH2_Permissions");
  });

  test("Update resource permissions transaction second branch", async () => {
    const reqBody = {
      newResourcePermissions: [{ allowed: "*" }],
      originalResourcePermissions: [{ allowed: "*" }],
    };

    const roleId = 1;

    const trxMock = {
      table: jest.fn().mockReturnThis(),
      where: jest.fn().mockResolvedValue([1]),
      update: jest.fn().mockReturnThis(),
      insert: jest.fn().mockResolvedValue([1]),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");

    await controllers.updateResourcePermissionsTransaction(
      trxMock,
      roleId,
      reqBody
    );

    expect(trxMock.insert).not.toHaveBeenCalled();
  });

  test("Update resource permissions transaction fails", async () => {
    const reqBody = {
      newResourcePermissions: [{ allowed: "*" }],
      originalResourcePermissions: [{ allowed: "select" }],
    };

    const roleId = 1;

    const trxMock = {
      table: jest.fn().mockReturnThis(),
      where: jest.fn().mockRejectedValueOnce(new Error("Async error")),
      update: jest.fn().mockReturnThis(),
      insert: jest.fn().mockResolvedValue([1]),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");

    await expect(
      controllers.updateResourcePermissionsTransaction(trxMock, roleId, reqBody)
    ).rejects.toThrow();
  });

  test("Update resources permissions", async () => {
    const knex = {
      transaction: jest.fn(),
    };
    const req = {
      params: {
        id: 1,
      },
      body: {},
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockResolvedValue([1]),
    };
    const controllers = authControllers(knex, "secret");
    await controllers.updateResourcePermissions(req, res);

    expect(knex.transaction).toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(201);
  });

  test("Update resources permissions fails", async () => {
    const knex = {
      transaction: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };
    const req = {
      params: {
        id: 1,
      },
      body: {},
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockResolvedValue([1]),
    };
    const controllers = authControllers(knex, "secret");
    controllers.handleError500 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();
    await controllers.updateResourcePermissions(req, res);

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Create resource fails", async () => {
    const req = {
      body: {
        resourceIdentifier: "ident",
        applications_id: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockResolvedValue([1]),
    };

    const knex = {
      table: jest.fn().mockReturnThis(),
      insert: jest.fn().mockResolvedValue([1]),
    };

    const controllers = authControllers(knex, "secret");
    await controllers.createResource(req, res);

    expect(knex.table).toHaveBeenCalledWith("OAUTH2_ApplicationResource");
    expect(knex.table).toHaveBeenCalledWith("OAUTH2_Permissions");

    const permissionsToInsert = [
      { allowed: "*", applicationResource_id: 1 },
      { allowed: "create", applicationResource_id: 1 },
      { allowed: "update", applicationResource_id: 1 },
      { allowed: "delete", applicationResource_id: 1 },
      { allowed: "select", applicationResource_id: 1 },
    ];

    expect(knex.insert).toHaveBeenCalledWith(permissionsToInsert);

    expect(res.status).toHaveBeenCalledWith(201);
  });

  test("Create resource", async () => {
    const req = {
      body: {
        resourceIdentifier: "ident",
        applications_id: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockResolvedValue([1]),
    };

    const knex = {
      table: jest.fn().mockReturnThis(),
      insert: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const controllers = authControllers(knex, "secret");
    controllers.handleError500 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();
    await controllers.createResource(req, res);

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Delete resource transaction", async () => {
    const resourceId = 1;

    const trxMock = {
      table: jest.fn().mockReturnThis(),
      where: jest.fn().mockResolvedValue([1]),
      update: jest.fn().mockReturnThis(),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");
    await controllers.deleteResourceTransaction(trxMock, resourceId);

    expect(trxMock.table).toHaveBeenCalledWith("OAUTH2_ApplicationResource");
    expect(trxMock.table).toHaveBeenCalledWith("OAUTH2_Permissions");
  });

  test("Delete resource transaction fails", async () => {
    const resourceId = 1;

    const trxMock = {
      table: jest.fn().mockReturnThis(),
      where: jest.fn().mockRejectedValueOnce(new Error("Async error")),
      update: jest.fn().mockReturnThis(),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");
    await expect(
      controllers.deleteResourceTransaction(trxMock, resourceId)
    ).rejects.toThrow();
  });

  test("Delete resource", async () => {
    const req = {
      params: {
        id: 1,
      },
    };

    const knex = {
      transaction: jest.fn(),
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockResolvedValue([1]),
    };

    const controllers = authControllers(knex, "secret");
    await controllers.deleteResource(req, res);

    expect(knex.transaction).toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(201);
  });

  test("Delete resource fails", async () => {
    const req = {
      params: {
        id: 1,
      },
    };

    const knex = {
      transaction: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockResolvedValue([1]),
    };

    const controllers = authControllers(knex, "secret");
    controllers.handleError500 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();
    await controllers.deleteResource(req, res);

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Select applications", async () => {
    const req = {};
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockResolvedValue([1]),
    };
    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockResolvedValue([1]),
    };
    const controllers = authControllers(knex, "secret");
    await controllers.selectApplications(req, res);

    expect(knex.table).toHaveBeenCalledWith("OAUTH2_Applications");
    expect(knex.select).toHaveBeenCalled();

    expect(res.status).toHaveBeenCalledWith(200);
  });

  test("Select applications fails", async () => {
    const req = {};
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockResolvedValue([1]),
    };
    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };
    const controllers = authControllers(knex, "secret");
    controllers.handleError500 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();
    await controllers.selectApplications(req, res);

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Login works", async () => {
    const bcryptSpy = jest.spyOn(bcrypt, "compare").mockImplementation(() => {
      return true;
    });
    const jwtSpy = jest.spyOn(jwt, "sign").mockImplementation(() => {
      return "token";
    });
    const req = {
      body: {
        username: "admin",
        password: "password",
      },
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockResolvedValue([1]),
    };
    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      join: jest.fn().mockReturnThis(),
      where: jest.fn().mockResolvedValue([
        {
          username: "admin",
          roles: "admin",
          id: 1,
          name: "Admin",
          password: "password",
        },
      ]),
    };

    const controllers = authControllers(knex, "secret");
    await controllers.login(req, res);

    expect(res.status).toHaveBeenCalledWith(201);
    expect(bcryptSpy).toHaveBeenCalled();
    expect(jwtSpy).toHaveBeenCalled();
    expect(knex.table).toHaveBeenCalledWith("OAUTH2_Users");

    bcryptSpy.mockRestore();
    jwtSpy.mockRestore();
  });

  test("Login, username does not exist", async () => {
    const bcryptSpy = jest.spyOn(bcrypt, "compare").mockImplementation(() => {
      return true;
    });
    const jwtSpy = jest.spyOn(jwt, "sign").mockImplementation(() => {
      return "token";
    });
    const req = {
      body: {
        username: "admin",
        password: "password",
      },
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockResolvedValue([1]),
    };
    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      join: jest.fn().mockReturnThis(),
      where: jest.fn().mockResolvedValue([]),
    };

    const controllers = authControllers(knex, "secret");

    controllers.handleError = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    await controllers.login(req, res);

    expect(controllers.handleError).toHaveBeenCalledWith(
      "Username does not exist",
      404007,
      404,
      "login"
    );

    expect(controllers.callNextOrResOnError).toHaveBeenCalled();

    bcryptSpy.mockRestore();
    jwtSpy.mockRestore();
  });

  test("Login, incorrect password", async () => {
    const bcryptSpy = jest.spyOn(bcrypt, "compare").mockImplementation(() => {
      return false;
    });
    const jwtSpy = jest.spyOn(jwt, "sign").mockImplementation(() => {
      return "token";
    });
    const req = {
      body: {
        username: "admin",
        password: "password",
      },
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockResolvedValue([1]),
    };
    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      join: jest.fn().mockReturnThis(),
      where: jest.fn().mockResolvedValue([
        {
          username: "admin",
          roles: "admin",
          id: 1,
          name: "Admin",
          password: "password",
        },
      ]),
    };

    const controllers = authControllers(knex, "secret");

    controllers.handleError = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    await controllers.login(req, res);

    expect(controllers.handleError).toHaveBeenCalledWith(
      "Incorrect password",
      401001,
      401,
      "login"
    );

    expect(controllers.callNextOrResOnError).toHaveBeenCalled();

    bcryptSpy.mockRestore();
    jwtSpy.mockRestore();
  });

  test("Login fails", async () => {
    const bcryptSpy = jest.spyOn(bcrypt, "compare").mockImplementation(() => {
      return true;
    });
    const jwtSpy = jest.spyOn(jwt, "sign").mockImplementation(() => {
      throw new Error("Async error");
    });
    const req = {
      body: {
        username: "admin",
        password: "password",
      },
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockResolvedValue([1]),
    };
    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      join: jest.fn().mockReturnThis(),
      where: jest.fn().mockResolvedValue([
        {
          username: "admin",
          roles: "admin",
          id: 1,
          name: "Admin",
          password: "password",
        },
      ]),
    };

    const controllers = authControllers(knex, "secret");
    controllers.handleError500 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();
    await controllers.login(req, res);

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();

    bcryptSpy.mockRestore();
    jwtSpy.mockRestore();
  });

  test("Token generator non grant type", async () => {
    const req = {
      body: {
        grant_type: "none",
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");
    controllers.handleError = jest.fn();
    controllers.callNextOrResOnError = jest.fn();
    await controllers.token(req, res);

    expect(controllers.handleError).toHaveBeenCalledWith(
      "Unsupported grand type",
      400002,
      400,
      "token"
    );
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Token generator clients", async () => {
    const req = {
      body: {
        grant_type: "client_credentials",
        client_id: 1,
        client_secret: "secret",
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");
    controllers.handleClientToken = jest
      .fn()
      .mockResolvedValue([{ result: "result" }, null]);
    await controllers.token(req, res);

    expect(res.status).toHaveBeenCalledWith(201);
    expect(res.json).toHaveBeenCalledWith({
      message: `Token generated for client ${1}`,
      code: 200000,
      content: { result: "result" },
    });
  });

  test("Token generator clients error 401100", async () => {
    const req = {
      body: {
        grant_type: "client_credentials",
        client_id: 1,
        client_secret: "secret",
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");
    controllers.handleClientToken = jest.fn().mockResolvedValue([null, 401100]);

    controllers.handleError = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    await controllers.token(req, res);

    expect(controllers.handleError).toHaveBeenCalledWith(
      "Incorrect client secret",
      401100,
      401,
      "token"
    );
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Token generator clients error 403100", async () => {
    const req = {
      body: {
        grant_type: "client_credentials",
        client_id: 1,
        client_secret: "secret",
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");
    controllers.handleClientToken = jest.fn().mockResolvedValue([null, 403100]);

    controllers.handleError = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    await controllers.token(req, res);

    expect(controllers.handleError).toHaveBeenCalledWith(
      "Client is not able to generate tokens, use your long live token",
      403100,
      403,
      "token"
    );
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Token generator clients error 404100", async () => {
    const req = {
      body: {
        grant_type: "client_credentials",
        client_id: 1,
        client_secret: "secret",
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");
    controllers.handleClientToken = jest.fn().mockResolvedValue([null, 404100]);

    controllers.handleError = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    await controllers.token(req, res);

    expect(controllers.handleError).toHaveBeenCalledWith(
      `Client with id 1 not found`,
      404100,
      404,
      "token"
    );
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Token generator clients error", async () => {
    const req = {
      body: {
        grant_type: "client_credentials",
        client_id: 1,
        client_secret: "secret",
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");
    controllers.handleClientToken = jest
      .fn()
      .mockResolvedValue([null, "Some Error"]);
    controllers.handleError500 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();
    await controllers.token(req, res);

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Token generator users", async () => {
    const req = {
      body: {
        grant_type: "password",
        username: "username",
        password: "secret",
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");

    controllers.handleUserToken = jest
      .fn()
      .mockResolvedValue([{ result: "result" }, null]);

    await controllers.token(req, res);

    expect(res.status).toHaveBeenCalledWith(201);
    expect(res.json).toHaveBeenCalledWith({
      message: `Token generated for user username`,
      code: 200000,
      content: { result: "result" },
    });
  });

  test("Token generator users error 401200", async () => {
    const req = {
      body: {
        grant_type: "password",
        username: "username",
        password: "secret",
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");

    controllers.handleError = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    controllers.handleUserToken = jest.fn().mockResolvedValue([null, 401200]);

    await controllers.token(req, res);

    expect(controllers.handleError).toHaveBeenCalledWith(
      "Incorrect user password",
      401200,
      401,
      "token"
    );
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Token generator users error 404200", async () => {
    const req = {
      body: {
        grant_type: "password",
        username: "username",
        password: "secret",
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");

    controllers.handleError = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    controllers.handleUserToken = jest.fn().mockResolvedValue([null, 404200]);

    await controllers.token(req, res);

    expect(controllers.handleError).toHaveBeenCalledWith(
      "User not found",
      404200,
      404,
      "token"
    );
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Token generator users error", async () => {
    const req = {
      body: {
        grant_type: "password",
        username: "username",
        password: "secret",
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");

    controllers.handleUserToken = jest
      .fn()
      .mockResolvedValue([null, "Some error"]);
    controllers.handleError500 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();
    await controllers.token(req, res);

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Token generator fails", async () => {
    const req = {
      body: {
        grant_type: "password",
        username: "username",
        password: "secret",
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");

    controllers.handleUserToken = jest
      .fn()
      .mockRejectedValue(new Error("Async error"));
    controllers.handleError500 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();
    await controllers.token(req, res);

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Generate long live token", async () => {
    const bcryptSpy = jest.spyOn(bcrypt, "hash").mockReturnValue(true);

    const req = {
      query: {},
      params: { id: 1 },
      body: {
        identifier: "identifier",
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = {
      table: jest.fn().mockReturnThis(),
      update: jest.fn().mockReturnThis(),
      where: jest.fn().mockResolvedValue("some"),
    };

    const controllers = authControllers(knexMock, "secret");

    await controllers.generateLongLive(req, res);

    expect(res.status).toHaveBeenCalledWith(201);

    expect(knexMock.table).toHaveBeenCalledWith("OAUTH2_Clients");
    expect(knexMock.update).toHaveBeenCalled();
    expect(knexMock.where).toHaveBeenCalledWith("OAUTH2_Clients.id", "=", 1);
    bcryptSpy.mockRestore();
  });

  test("Handle user token", async () => {
    const username = "username";
    const password = "password";
    const bcryptSpy = jest.spyOn(bcrypt, "compare").mockReturnValue(true);
    const jwtSpy = jest.spyOn(jwt, "sign").mockReturnValue("token");

    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      join: jest.fn().mockReturnThis(),
      update: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockResolvedValue([
        {
          id: 1,
          username: "someUser",
          roles: "someRole",
          description: "some description",
          name: "someName",
        },
      ]),
    };

    const controllers = authControllers(knex, "secret");
    const result = await controllers.handleUserToken(username, password);

    expect(bcryptSpy).toHaveBeenCalled();
    expect(result).toStrictEqual([
      {
        jwt_token: "token",
        name: "someName",
        description: "some description",
        user_id: 1,
        username: "someUser",
        roles: ["someRole"],
      },
      null,
    ]);
    bcryptSpy.mockRestore();
    jwtSpy.mockRestore();
  });

  test("Remove long live token", async () => {
    const req = {
      query: {
        remove_long_live: "true",
      },
      params: { id: 1 },
      body: {
        identifier: "identifier",
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {
      table: jest.fn().mockReturnThis(),
      update: jest.fn().mockReturnThis(),
      where: jest.fn().mockResolvedValue("some"),
    };

    const controllers = authControllers(knex, "secret");
    await controllers.generateLongLive(req, res);

    expect(res.status).toHaveBeenCalledWith(201);
    expect(res.json).toHaveBeenCalledWith({
      message: `Token removed`,
      code: 200001,
    });

    expect(knex.table).toHaveBeenCalledWith("OAUTH2_Clients");
    expect(knex.update).toHaveBeenCalledWith({
      access_token: null,
    });
    expect(knex.where).toHaveBeenCalledWith("OAUTH2_Clients.id", "=", 1);
  });

  test("Remove long live token fails", async () => {
    const req = {
      query: {
        remove_long_live: "true",
      },
      body: {
        identifier: "identifier",
        client_id: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {
      table: jest.fn().mockReturnThis(),
      update: jest.fn().mockReturnThis(),
      where: jest.fn().mockRejectedValue(new Error("Async error")),
    };

    const controllers = authControllers(knex, "secret");
    controllers.handleError500 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();
    await controllers.generateLongLive(req, res);

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Handle user token 404200", async () => {
    const username = "username";
    const password = "password";

    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      join: jest.fn().mockReturnThis(),
      update: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockResolvedValue([]),
    };

    const controllers = authControllers(knex, "secret");
    const result = await controllers.handleUserToken(username, password);

    expect(result).toStrictEqual([null, 404200]);
  });

  test("Handle user token 401200", async () => {
    const username = "username";
    const password = "password";
    const bcryptSpy = jest.spyOn(bcrypt, "compare").mockImplementation(() => {
      return false;
    });
    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      join: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockResolvedValue([1]),
    };

    const controllers = authControllers(knex, "secret");
    const result = await controllers.handleUserToken(username, password);

    expect(result).toStrictEqual([null, 401200]);
    bcryptSpy.mockRestore();
  });

  test("Handle client token 404100", async () => {
    const client_id = "username";
    const client_secret = "password";

    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      join: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockResolvedValue([]),
    };

    const controllers = authControllers(knex, "secret");
    const result = await controllers.handleClientToken(
      client_id,
      client_secret
    );

    expect(result).toStrictEqual([null, 404100]);
  });

  test("Handle client token function", async () => {
    const client_id = "username";
    const client_secret = "password";

    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      join: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      andWhere: jest
        .fn()
        .mockResolvedValue([
          { id: 1, roles: "role", client_secret: "x|.|password" },
        ]),
    };

    const decipherSpy = jest
      .spyOn(crypto, "createDecipheriv")
      .mockImplementation(() => {
        return {
          update: jest.fn().mockReturnValue("password"),
          final: jest.fn().mockReturnValue(""),
        };
      });

    const controllers = authControllers(knex, "secret");
    const result = await controllers.handleClientToken(
      client_id,
      client_secret
    );

    expect(decipherSpy).toHaveBeenCalled();
    expect(result[1]).toBe(null);
  });

  test("Handle client token 401100", async () => {
    const client_id = "username";
    const client_secret = "password";
    const bcryptSpy = jest.spyOn(bcrypt, "compare").mockImplementation(() => {
      return false;
    });
    const bufferSpy = jest.spyOn(Buffer, "from");
    const decipherSpy = jest
      .spyOn(crypto, "createDecipheriv")
      .mockImplementation(() => {
        return {
          update: jest.fn().mockReturnValue("u"),
          final: jest.fn().mockReturnValue("U"),
        };
      });

    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      join: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      andWhere: jest
        .fn()
        .mockResolvedValue([{ id: 1, roles: "role", client_secret: "x|.|y" }]),
    };

    const controllers = authControllers(knex, "secret");
    const result = await controllers.handleClientToken(
      client_id,
      client_secret
    );

    expect(result).toStrictEqual([null, 401100]);
    expect(bufferSpy).toHaveBeenCalled();
    expect(decipherSpy).toHaveBeenCalled();

    bcryptSpy.mockRestore();
    bufferSpy.mockRestore();
    decipherSpy.mockRestore();
  });

  test("Get client secret works", async () => {
    const req = {
      params: {
        id: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest
        .fn()
        .mockResolvedValue([{ id: 1, roles: "role", client_secret: "x|.|y" }]),
    };

    const decipherSpy = jest
      .spyOn(crypto, "createDecipheriv")
      .mockImplementation(() => {
        return {
          update: jest.fn().mockReturnValue("u"),
          final: jest.fn().mockReturnValue("U"),
        };
      });

    const controllers = authControllers(knex, "secret");
    await controllers.getClientSecret(req, res);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({
      code: 200000,
      message: "Client secret",
      content: {
        clientSecret: "uU",
      },
    });

    decipherSpy.mockRestore();
  });

  test("Get client secret, client does not exist", async () => {
    const req = {
      params: {
        id: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnValue([]),
    };

    const decipherSpy = jest
      .spyOn(crypto, "createDecipheriv")
      .mockImplementation(() => {
        return {
          update: jest.fn().mockReturnValue("u"),
          final: jest.fn().mockReturnValue("U"),
        };
      });

    const controllers = authControllers(knex, "secret");

    controllers.handleError = jest.fn();
    controllers.callNextOrResOnError = jest.fn();
    await controllers.getClientSecret(req, res);
    expect(controllers.handleError).toHaveBeenCalledWith(
      "Client does not exist",
      404006,
      404,
      "getClientSecret"
    );
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();

    decipherSpy.mockRestore();
  });

  test("Get client secret fails", async () => {
    const req = {
      params: {
        id: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {
      table: jest.fn().mockReturnThis(),
      select: jest.fn().mockReturnThis(),
      where: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const decipherSpy = jest
      .spyOn(crypto, "createDecipheriv")
      .mockImplementation(() => {
        return {
          update: jest.fn().mockReturnValue("u"),
          final: jest.fn().mockReturnValue("U"),
        };
      });

    const controllers = authControllers(knex, "secret");

    controllers.handleError500 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();
    await controllers.getClientSecret(req, res);
    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();

    decipherSpy.mockRestore();
  });

  test("Revoke Token Works", async () => {
    const req = {
      body: {
        revoke: false,
      },
      params: {
        id: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {
      table: jest.fn().mockReturnThis(),
      update: jest.fn().mockReturnThis(),
      where: jest.fn(),
    };

    const controllers = authControllers(knex, "secret");
    await controllers.revokeToken(req, res);

    expect(res.status).toHaveBeenCalledWith(201);

    expect(knex.update).toHaveBeenCalledWith({ revoked: false });
  });

  test("Revoke Token fails", async () => {
    const req = {
      body: {
        revoke: false,
      },
      params: {
        id: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {
      table: jest.fn().mockReturnThis(),
      update: jest.fn().mockReturnThis(),
      where: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const controllers = authControllers(knex, "secret");

    controllers.handleError500 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();

    await controllers.revokeToken(req, res);

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Update subject roles works", async () => {
    const roles = [
      {
        id: 1,
      },
      {
        id: 2,
      },
      {
        id: 4,
      },
    ];

    const originalRolesList = [
      {
        id: 1,
      },
      {
        id: 2,
      },
      {
        id: 3,
      },
    ];

    const req = {
      body: {
        originalRolesList,
        roles,
      },
      params: {
        subjectId: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {
      table: jest.fn().mockReturnThis(),
      del: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnValue(1),
      insert: jest.fn().mockReturnValue(1),
    };

    const controllers = authControllers(knex, "secret");
    await controllers.updateSubjectRoles(req, res);

    expect(knex.table).toHaveBeenCalledWith("OAUTH2_SubjectRole");
    expect(knex.table).toHaveBeenCalledTimes(2);

    expect(knex.del).toHaveBeenCalledTimes(1);

    expect(res.status).toHaveBeenCalledWith(201);
  });

  test("Update subject roles works, fails", async () => {
    const roles = [
      {
        id: 1,
      },
      {
        id: 2,
      },
      {
        id: 4,
      },
    ];

    const originalRolesList = [
      {
        id: 1,
      },
      {
        id: 2,
      },
      {
        id: 3,
      },
    ];

    const req = {
      body: {
        originalRolesList,
        roles,
      },
      params: {
        subjectId: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {
      table: jest.fn().mockReturnThis(),
      del: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnValue(1),
      insert: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const controllers = authControllers(knex, "secret");
    controllers.handleError500 = jest.fn();
    controllers.callNextOrResOnError = jest.fn();
    await controllers.updateSubjectRoles(req, res);

    expect(controllers.handleError500).toHaveBeenCalled();
    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });

  test("Update subject roles works, non valid subject id", async () => {
    const roles = [
      {
        id: 1,
      },
      {
        id: 2,
      },
      {
        id: 4,
      },
    ];

    const originalRolesList = [
      {
        id: 1,
      },
      {
        id: 2,
      },
      {
        id: 3,
      },
    ];

    const req = {
      body: {
        originalRolesList,
        roles,
      },
      params: {
        subjectId: "xx",
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");
    controllers.handleError = jest.fn();
    controllers.callNextOrResOnError = jest.fn();
    await controllers.updateSubjectRoles(req, res);

    expect(controllers.handleError).toHaveBeenCalledWith(
      `xx is not a valid subject id`,
      400009,
      400,
      "updateClient"
    );

    expect(controllers.callNextOrResOnError).toHaveBeenCalled();
  });
});
