const authControllers = require("../../src/helpers/routes/controllers");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const generalHelpers = require("../../src/helpers/general-helpers");

describe('Controllers - client', () => {
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
        // knex.where = jest.fn().mockRejectedValueOnce(new Error("Async error"));
        knex.where = jest.fn().mockImplementation(() => new Promise.reject("Async error"));
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
});