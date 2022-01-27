const authControllers = require("../src/helpers/routes/controllers.js");
const bcrypt = require("bcrypt");
const generalHelpers = require("../src/helpers/general-helpers.js");
const jwt = require("jsonwebtoken");

describe("All auth controllers work", () => {
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
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = {
      transaction: jest.fn(),
    };

    const controllers = authControllers(knexMock, "secret");

    await controllers.createUser(mockedReq, mockRes);

    expect(bcryptSpy).toHaveBeenCalled();
    expect(mockRes.status).toHaveBeenCalledWith(201);
    expect(knexMock.transaction).toHaveBeenCalled();

    bcryptSpy.mockRestore();
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

    const controllers = authControllers(knexMock, "secret");

    await controllers.createUser(mockedReq, mockRes);

    expect(mockRes.status).toHaveBeenCalledWith(500);

    bcryptSpy.mockRestore();
  });

  test("Creates the client in a transaction", async () => {
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
      transaction: jest.fn(),
    };

    const controllers = authControllers(knexMock, "secret");

    await controllers.createClient(mockedReq, mockRes);

    expect(bcryptSpy).toHaveBeenCalled();
    expect(mockRes.status).toHaveBeenCalledWith(201);
    expect(knexMock.transaction).toHaveBeenCalled();

    bcryptSpy.mockRestore();
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
      transaction: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const controllers = authControllers(knexMock, "secret");

    await controllers.createClient(mockedReq, mockRes);

    expect(mockRes.status).toHaveBeenCalledWith(500);

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
    expect(trxMock.table).toHaveBeenCalledWith("OAUTH2_RoleOption");
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
      transaction: jest.fn(),
    };

    const controllers = authControllers(knexMock, "secret");

    await controllers.createRole(mockedReq, mockRes);

    expect(mockRes.status).toHaveBeenCalledWith(201);
    expect(mockRes.json).toHaveBeenCalled();
    expect(knexMock.transaction).toHaveBeenCalled();
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
      transaction: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const controllers = authControllers(knexMock, "secret");

    await controllers.createRole(mockedReq, mockRes);

    expect(mockRes.status).toHaveBeenCalledWith(500);
    expect(mockRes.json).toHaveBeenCalled();
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
      insert: jest.fn(),
    };

    const controllers = authControllers(knexMock, "secret");

    await controllers.createApplication(mockedReq, mockRes);

    expect(mockRes.status).toHaveBeenCalledWith(201);
    expect(mockRes.json).toHaveBeenCalled();
    expect(knexMock.table).toHaveBeenCalledWith("OAUTH2_Applications");
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
      insert: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const controllers = authControllers(knexMock, "secret");

    await controllers.createApplication(mockedReq, mockRes);

    expect(mockRes.status).toHaveBeenCalledWith(500);
  });

  test("Create application part", async () => {
    const mockedReq = {
      body: {
        partIdentifier: "identifier",
        applications_id: 1,
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = {
      table: jest.fn().mockReturnThis(),
      insert: jest.fn(),
    };

    const controllers = authControllers(knexMock, "secret");

    await controllers.createApplicationPart(mockedReq, mockRes);

    expect(mockRes.status).toHaveBeenCalledWith(201);
    expect(mockRes.json).toHaveBeenCalled();
    expect(knexMock.table).toHaveBeenCalledWith("OAUTH2_ApplicationPart");
  });

  test("Create application part error", async () => {
    const mockedReq = {
      body: {
        partIdentifier: "identifier",
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

    await controllers.createApplicationPart(mockedReq, mockRes);

    expect(mockRes.status).toHaveBeenCalledWith(500);
  });

  test("Create option", async () => {
    const mockedReq = {
      body: {
        allowed: "allowed",
        applicationPart_id: 1,
      },
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const knexMock = {
      table: jest.fn().mockReturnThis(),
      insert: jest.fn(),
    };

    const controllers = authControllers(knexMock, "secret");

    await controllers.createOption(mockedReq, mockRes);

    expect(mockRes.status).toHaveBeenCalledWith(201);
    expect(mockRes.json).toHaveBeenCalled();
    expect(knexMock.table).toHaveBeenCalledWith("OAUTH2_Options");
  });

  test("Create option error", async () => {
    const mockedReq = {
      body: {
        allowed: "allowed",
        applicationPart_id: 1,
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

    await controllers.createOption(mockedReq, mockRes);

    expect(mockRes.status).toHaveBeenCalledWith(500);
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

    await controllers.getUsers(mockedReq, mockRes);

    expect(mockRes.status).toHaveBeenCalledWith(500);
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
      "OAUTH2_Subjects.id as subjectId",
      "OAUTH2_Subjects.name",
      "OAUTH2_ApplicationPart.partIdentifier as applicationPart",
      "OAUTH2_ApplicationPart.id as partId",
      "OAUTH2_Options.allowed",
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
      "OAUTH2_ApplicationPart",
      `OAUTH2_ApplicationPart.id`,
      "OAUTH2_Options.applicationPart_id"
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

    await controllers.getUser(mockedReq, mockRes);

    expect(mockRes.json).toHaveBeenCalledWith({
      code: 400000,
      message: "Invalid user id",
    });

    expect(mockRes.status).toHaveBeenCalledWith(400);
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

    await controllers.getUser(mockedReq, mockRes);

    expect(mockRes.status).toHaveBeenCalledWith(500);
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
      "OAUTH2_Subjects.id as subjectId",
      "OAUTH2_Subjects.name",
      "OAUTH2_ApplicationPart.partIdentifier as applicationPart",
      "OAUTH2_ApplicationPart.id as partId",
      "OAUTH2_Options.allowed",
      "OAUTH2_Roles.id as roleId",
      "OAUTH2_Roles.deleted as roleDeleted",
      "OAUTH2_Roles.identifier as roleIdentifier"
    );

    expect(mockRes.status).toHaveBeenCalledWith(200);
  });

  test("Get me user no local user", async () => {
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
    ];

    const mockedReq = {};

    const mockRes = {
      locals: {},
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

    expect(mockRes.status).toHaveBeenCalledWith(403);

    expect(mockRes.json).toHaveBeenCalledWith({
      code: 400301,
      message: "Forbidden user",
    });
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
    await controllers.getMe(mockedReq, mockRes);

    expect(mockRes.status).toHaveBeenCalledWith(400);
    expect(mockRes.json).toHaveBeenCalledWith({
      code: 400001,
      message: "Invalid subject user",
    });
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
    await controllers.getMe(mockedReq, mockRes);

    expect(mockRes.status).toHaveBeenCalledWith(500);
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
        roleDeleted: true,
        roleId: 2,
        roleIdentifier: "rol2",
        partId: 4,
        applicationPart: "part4",
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

    await controllers.getClients(mockedReq, mockRes);

    expect(mockRes.status).toHaveBeenCalledWith(500);
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
        roleDeleted: true,
        roleId: 2,
        roleIdentifier: "rol2",
        partId: 4,
        applicationPart: "part4",
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

  test("Update user roles ", async () => {
    const knex = {
      table: jest.fn().mockReturnThis(),
      insert: jest.fn().mockResolvedValue([1]),
    };

    const req = {
      body: {
        roles: [{ id: 1 }, { id: 2 }],
      },
      params: {
        id: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const controllers = authControllers(knex, "secret");
    await controllers.updateUserRoles(req, res);

    expect(knex.table).toHaveBeenCalledWith("OAUTH2_SubjectRole");

    expect(knex.insert).toHaveBeenCalledWith([
      { subject_id: 1, roles_id: 1 },
      { subject_id: 1, roles_id: 2 },
    ]);

    expect(res.status).toHaveBeenCalledWith(201);
  });

  test("Update user roles no user id", async () => {
    const knex = {
      table: jest.fn().mockReturnThis(),
      insert: jest.fn().mockResolvedValue([1]),
    };

    const req = {
      body: {
        roles: [{ id: 1 }, { id: 2 }],
      },
      params: {
        id: "xx",
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const controllers = authControllers(knex, "secret");
    await controllers.updateUserRoles(req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({
      code: 400000,
      message: "User id is not valid",
    });
  });

  test("Update user roles fails", async () => {
    const knex = {
      table: jest.fn().mockReturnThis(),
      insert: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const req = {
      body: {
        roles: [{ id: 1 }, { id: 2 }],
      },
      params: {
        id: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const controllers = authControllers(knex, "secret");
    await controllers.updateUserRoles(req, res);

    expect(res.status).toHaveBeenCalledWith(500);
  });

  test("Update client roles ", async () => {
    const knex = {
      table: jest.fn().mockReturnThis(),
      insert: jest.fn().mockResolvedValue([1]),
    };

    const req = {
      body: {
        roles: [{ id: 1 }, { id: 2 }],
      },
      params: {
        id: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const controllers = authControllers(knex, "secret");
    await controllers.updateClientRoles(req, res);

    expect(knex.table).toHaveBeenCalledWith("OAUTH2_SubjectRole");

    expect(knex.insert).toHaveBeenCalledWith([
      { subject_id: 1, roles_id: 1 },
      { subject_id: 1, roles_id: 2 },
    ]);

    expect(res.status).toHaveBeenCalledWith(201);
  });

  test("Update client roles no user id", async () => {
    const knex = {
      table: jest.fn().mockReturnThis(),
      insert: jest.fn().mockResolvedValue([1]),
    };

    const req = {
      body: {
        roles: [{ id: 1 }, { id: 2 }],
      },
      params: {
        id: "xx",
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const controllers = authControllers(knex, "secret");
    await controllers.updateClientRoles(req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({
      code: 400000,
      message: "User id is not valid",
    });
  });

  test("Update client roles fails", async () => {
    const knex = {
      table: jest.fn().mockReturnThis(),
      insert: jest.fn().mockRejectedValueOnce(new Error("Async error")),
    };

    const req = {
      body: {
        roles: [{ id: 1 }, { id: 2 }],
      },
      params: {
        id: 1,
      },
    };

    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const controllers = authControllers(knex, "secret");
    await controllers.updateClientRoles(req, res);

    expect(res.status).toHaveBeenCalledWith(500);
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

    const controllers = authControllers(knex, "secret");

    await controllers.deleteUser(req, res);

    expect(res.status).toHaveBeenCalledWith(500);
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

    await controllers.deleteClient(req, res);

    expect(res.status).toHaveBeenCalledWith(500);
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

    const knex = {
      table: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      update: jest.fn().mockResolvedValue([1]),
    };

    const controllers = authControllers(knex, "secret");

    await controllers.deleteRole(req, res);

    expect(knex.table).toHaveBeenCalledWith("OAUTH2_Roles");
    expect(knex.where).toHaveBeenCalledWith({ id: 1 });
    expect(knex.update).toHaveBeenCalledWith("deleted", true);

    expect(res.status).toHaveBeenCalledWith(201);
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

    await controllers.deleteRole(req, res);

    expect(res.status).toHaveBeenCalledWith(500);
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

    const knex = {
      table: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      update: jest.fn().mockResolvedValue([1]),
    };

    const controllers = authControllers(knex, "secret");

    await controllers.updateUser(req, res);

    expect(knex.table).toHaveBeenCalledWith("OAUTH2_Subjects");
    expect(knex.where).toHaveBeenCalledWith({ id: 1 });
    expect(knex.update).toHaveBeenCalledWith({ name: "new name" });

    expect(res.status).toHaveBeenCalledWith(201);
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

    await controllers.updateUser(req, res);

    expect(res.status).toHaveBeenCalledWith(500);
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

    const knex = {
      table: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      update: jest.fn().mockResolvedValue([1]),
    };

    const controllers = authControllers(knex, "secret");

    await controllers.updateClient(req, res);

    expect(knex.table).toHaveBeenCalledWith("OAUTH2_Subjects");
    expect(knex.where).toHaveBeenCalledWith({ id: 1 });
    expect(knex.update).toHaveBeenCalledWith({ name: "new name" });

    expect(res.status).toHaveBeenCalledWith(201);
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

    await controllers.updateClient(req, res);

    expect(res.status).toHaveBeenCalledWith(500);
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

    await controllers.updatePassword(req, res);

    expect(res.status).toHaveBeenCalledWith(400);

    expect(bcryptSpyCompare).toHaveBeenCalled();

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

    await controllers.updatePassword(req, res);

    expect(res.status).toHaveBeenCalledWith(500);

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

    await controllers.getRoles(mockedReq, mockRes);

    expect(mockRes.status).toHaveBeenCalledWith(500);
  });

  test("Select parts basic", async () => {
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
            partId: 1,
            applicationPartName: "partName1",
            allowed: "*",
            optionId: 1,
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

    const parsedParts = helpers.parsePartSearch([
      {
        partId: 1,
        applicationPartName: "partName1",
        allowed: "*",
        optionId: 1,
      },
    ]);

    const controllers = authControllers(mockKnex, "secret");

    await controllers.getParts(req, res);

    expect(mockKnex.table).toHaveBeenCalledWith("OAUTH2_ApplicationPart");

    expect(mockKnex.where).toHaveBeenCalledWith(
      "OAUTH2_ApplicationPart.deleted",
      false
    );

    expect(mockKnex.select).toHaveBeenCalledWith(
      "OAUTH2_ApplicationPart.partIdentifier as applicationPartName",
      "OAUTH2_ApplicationPart.id as partId",
      "OAUTH2_Options.allowed",
      "OAUTH2_Options.id as optionId"
    );

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith({
      code: 200000,
      message: "Select completed",
      content: parsedParts,
    });
  });

  test("Select parts with pagination", async () => {
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

    const partsBaseArray = [
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

    const knexMock = jest.fn().mockImplementation((objectOrString) => {
      const knex = {};
      knex.limit = jest.fn().mockReturnValue(knex);
      knex.offset = jest.fn().mockReturnValue(knex);
      knex.orderBy = jest.fn().mockResolvedValue(partsBaseArray);
      knex.select = jest.fn().mockReturnValue(knex);
      knex.where = jest.fn().mockReturnValue(knex);
      knex.table = jest.fn().mockReturnValue(knex);
      knex.count = jest.fn().mockResolvedValue([{ "count(*)": 2 }]);
      knex.join = jest.fn().mockReturnValue(knex);
      return knex;
    });

    const helper = generalHelpers();

    const parsedParts = helper.parsePartSearch(partsBaseArray);

    const controllers = authControllers(knexMock, "secret");

    await controllers.getParts(mockedReq, mockRes);

    expect(knexMock).toHaveBeenCalledTimes(3);

    expect(knexMock).toHaveBeenCalledWith("OAUTH2_ApplicationPart");

    expect(mockRes.status).toHaveBeenCalledWith(200);

    expect(mockRes.json).toHaveBeenCalledWith({
      code: 200000,
      message: "Select completed",
      content: {
        items: parsedParts,
        pageIndex: 1,
        itemsPerPage: 10,
        totalItems: 2,
        totalPages: 1,
      },
    });
  });

  test("Select parts with pagination no query", async () => {
    const mockedReq = {
      query: {},
    };

    const mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    const partsBaseArray = [
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

    const knexMock = jest.fn().mockImplementation((objectOrString) => {
      const knex = {};
      knex.limit = jest.fn().mockReturnValue(knex);
      knex.offset = jest.fn().mockReturnValue(knex);
      knex.orderBy = jest.fn().mockResolvedValue(partsBaseArray);
      knex.select = jest.fn().mockReturnValue(knex);
      knex.where = jest.fn().mockReturnValue(knex);
      knex.table = jest.fn().mockReturnValue(knex);
      knex.count = jest.fn().mockResolvedValue([{ "count(*)": 2 }]);
      knex.join = jest.fn().mockReturnValue(knex);
      return knex;
    });

    const helper = generalHelpers();

    const parsedParts = helper.parsePartSearch(partsBaseArray);

    const controllers = authControllers(knexMock, "secret");

    await controllers.getParts(mockedReq, mockRes);

    expect(knexMock).toHaveBeenCalledTimes(3);

    expect(knexMock).toHaveBeenCalledWith("OAUTH2_ApplicationPart");

    expect(mockRes.status).toHaveBeenCalledWith(200);

    expect(mockRes.json).toHaveBeenCalledWith({
      code: 200000,
      message: "Select completed",
      content: {
        items: parsedParts,
        pageIndex: 0,
        itemsPerPage: 5,
        totalItems: 2,
        totalPages: 1,
      },
    });
  });

  test("Select parts with pagination fails", async () => {
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

    await controllers.getParts(mockedReq, mockRes);

    expect(mockRes.status).toHaveBeenCalledWith(500);
  });

  test("Update role options transaction", async () => {
    const reqBody = {
      newAllowedObject: {
        option: [{ id: 1 }],
      },
      originalAllowedObject: {
        option: [{ id: 2 }],
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

    await controllers.updateRoleOptionsTransaction(trxMock, roleId, reqBody);

    expect(trxMock.del).toHaveBeenCalledTimes(1);
    expect(trxMock.table).toHaveBeenCalledWith("OAUTH2_RoleOption");
  });

  test("Update role options transaction second branch", async () => {
    const reqBody = {
      newAllowedObject: {
        option: [{ id: 2 }],
      },
      originalAllowedObject: {
        option: [{ id: 2 }],
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

    await controllers.updateRoleOptionsTransaction(trxMock, roleId, reqBody);

    expect(trxMock.table).not.toHaveBeenCalled();
  });

  test("Update role options transaction fails", async () => {
    const reqBody = {
      newAllowedObject: {
        option: [{ id: 1 }],
      },
      originalAllowedObject: {
        option: [{ id: 2 }],
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
      controllers.updateRoleOptionsTransaction(trxMock, roleId, reqBody)
    ).rejects.toThrow();
  });

  test("Update role options", async () => {
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
    await controllers.updateRoleOptions(req, res);

    expect(knex.transaction).toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(201);
  });

  test("Update role options fails", async () => {
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
    await controllers.updateRoleOptions(req, res);

    expect(res.status).toHaveBeenCalledWith(500);
  });

  test("Update part options transaction", async () => {
    const reqBody = {
      newPartOptions: [{ allowed: "*" }],
      originalPartOptions: [{ allowed: "select" }],
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

    await controllers.updatePartOptionsTransaction(trxMock, roleId, reqBody);

    expect(trxMock.update).toHaveBeenCalledTimes(1);
    expect(trxMock.table).toHaveBeenCalledWith("OAUTH2_Options");
  });

  test("Update part options transaction second branch", async () => {
    const reqBody = {
      newPartOptions: [{ allowed: "*" }],
      originalPartOptions: [{ allowed: "*" }],
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

    await controllers.updatePartOptionsTransaction(trxMock, roleId, reqBody);

    expect(trxMock.insert).not.toHaveBeenCalled();
  });

  test("Update part options transaction fails", async () => {
    const reqBody = {
      newPartOptions: [{ allowed: "*" }],
      originalPartOptions: [{ allowed: "select" }],
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
      controllers.updatePartOptionsTransaction(trxMock, roleId, reqBody)
    ).rejects.toThrow();
  });

  test("Update part options", async () => {
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
    await controllers.updatePartOptions(req, res);

    expect(knex.transaction).toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(201);
  });

  test("Update part options fails", async () => {
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
    await controllers.updatePartOptions(req, res);

    expect(res.status).toHaveBeenCalledWith(500);
  });

  test("Create part fails", async () => {
    const req = {
      body: {
        partIdentifier: "ident",
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
    await controllers.createPart(req, res);

    expect(knex.table).toHaveBeenCalledWith("OAUTH2_ApplicationPart");
    expect(knex.table).toHaveBeenCalledWith("OAUTH2_Options");

    const optionsToInsert = [
      { allowed: "*", applicationPart_id: 1 },
      { allowed: "create", applicationPart_id: 1 },
      { allowed: "update", applicationPart_id: 1 },
      { allowed: "delete", applicationPart_id: 1 },
      { allowed: "select", applicationPart_id: 1 },
    ];

    expect(knex.insert).toHaveBeenCalledWith(optionsToInsert);

    expect(res.status).toHaveBeenCalledWith(201);
  });

  test("Create part", async () => {
    const req = {
      body: {
        partIdentifier: "ident",
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
    await controllers.createPart(req, res);

    expect(res.status).toHaveBeenCalledWith(500);
  });

  test("Delete part transaction", async () => {
    const partId = 1;

    const trxMock = {
      table: jest.fn().mockReturnThis(),
      where: jest.fn().mockResolvedValue([1]),
      update: jest.fn().mockReturnThis(),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");
    await controllers.deletePartTransaction(trxMock, partId);

    expect(trxMock.table).toHaveBeenCalledWith("OAUTH2_ApplicationPart");
    expect(trxMock.table).toHaveBeenCalledWith("OAUTH2_Options");
  });

  test("Delete part transaction fails", async () => {
    const partId = 1;

    const trxMock = {
      table: jest.fn().mockReturnThis(),
      where: jest.fn().mockRejectedValueOnce(new Error("Async error")),
      update: jest.fn().mockReturnThis(),
    };

    const knex = {};

    const controllers = authControllers(knex, "secret");
    await expect(
      controllers.deletePartTransaction(trxMock, partId)
    ).rejects.toThrow();
  });

  test("Delete parts", async () => {
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
    await controllers.deletePart(req, res);

    expect(knex.transaction).toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(201);
  });

  test("Delete parts fails", async () => {
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
    await controllers.deletePart(req, res);

    expect(res.status).toHaveBeenCalledWith(500);
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
    await controllers.selectApplications(req, res);

    expect(res.status).toHaveBeenCalledWith(500);
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
});
