const authControllers = require("../../src/helpers/routes/controllers");
const bcrypt = require("bcrypt");
const generalHelpers = require("../../src/helpers/general-helpers");

describe('Controllers - user', () => {
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
});