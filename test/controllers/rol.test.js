const generalHelpers = require("../../src/helpers/general-helpers");
const authControllers = require("../../src/helpers/routes/controllers");

describe('Controllers - rol', () => {
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
});