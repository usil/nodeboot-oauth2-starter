const generalHelpers = require("../../src/helpers/general-helpers");
const authControllers = require("../../src/helpers/routes/controllers");

describe('Controllers - resource', () => {
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
});