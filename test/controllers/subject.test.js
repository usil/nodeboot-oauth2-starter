const authControllers = require("../../src/helpers/routes/controllers");

describe('Controllers - subject', () => {
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