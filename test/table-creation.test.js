const tableCreation = require("../src/helpers/table-creation.js");
const fs = require("fs").promises;
const bcrypt = require("bcrypt");

jest.mock("bcrypt");

const mockKnexCreationSchema = () => {
  const knex = {
    schema: {
      createTable: jest
        .fn()
        .mockResolvedValue(true)
        .mockRejectedValueOnce(new Error("Async error")),
    },
    transaction: jest.fn(),
  };

  return knex;
};

const mockedKnexSchema = () => {
  const knex = {
    schema: {
      dropTableIfExists: jest
        .fn()
        .mockResolvedValue(true)
        .mockRejectedValueOnce(new Error("Async error")),
      hasTable: jest
        .fn()
        .mockResolvedValue(true)
        .mockResolvedValueOnce(true)
        .mockResolvedValueOnce(false)
        .mockResolvedValueOnce(false)
        .mockResolvedValueOnce(true),
    },
  };

  return knex;
};

const mockedNormalKnex = () => {
  const knex = {};
  knex.table = jest.fn().mockReturnValue(knex);
  knex.columnInfo = jest.fn().mockResolvedValue({
    id: {
      type: "string",
    },
  });

  return knex;
};

const mockedNormalErrorKnex = () => {
  const knex = {};
  knex.table = jest.fn().mockReturnValue(knex);
  knex.columnInfo = jest.fn().mockRejectedValueOnce({
    id: {
      type: "string",
    },
  });

  return knex;
};

const mockedTrx = () => {
  const trx = {};

  trx.insert = jest
    .fn()
    .mockResolvedValue([1])
    .mockRejectedValueOnce(new Error("Async error"))
    .mockResolvedValueOnce([1])
    .mockResolvedValueOnce([1])
    .mockResolvedValueOnce([2])
    .mockResolvedValueOnce([3])
    .mockResolvedValueOnce([4])
    .mockResolvedValueOnce([5])
    .mockResolvedValueOnce([6])
    .mockResolvedValueOnce([7])
    .mockResolvedValueOnce([1])
    .mockResolvedValueOnce([1]);

  trx.table = jest.fn().mockReturnValue(trx);

  return trx;
};

describe("Table creation works accordingly", () => {
  test("Correct tables in data base count", async () => {
    const knex = mockedKnexSchema();
    const tableCreationHelper = tableCreation(knex, "secret");

    const count = await tableCreationHelper.dataBaseHasTables();

    expect(count).toBe(1);
  });

  test("Drop tables works", async () => {
    const knex = mockedKnexSchema();
    const tableCreationHelper = tableCreation(knex, "secret");

    await expect(tableCreationHelper.dropTables()).rejects.toThrow();

    await tableCreationHelper.dropTables();

    expect(knex.schema.dropTableIfExists).toHaveBeenCalledTimes(10);

    expect(knex.schema.dropTableIfExists).toHaveBeenCalledWith(
      "OAUTH2_Applications"
    );
  });

  test("Transaction to create works", async () => {
    const fsSpy = jest.spyOn(fs, "writeFile").mockImplementation(() => {});
    const bcryptSpy = jest.spyOn(bcrypt, "hash").mockImplementation(() => {
      return "hashed";
    });

    const knex = mockedKnexSchema();

    const tableCreationHelper = tableCreation(knex, "secret", ["extra"]);

    const trx = mockedTrx();

    await expect(tableCreationHelper.trxCreate(trx)).rejects.toThrow();

    await tableCreationHelper.trxCreate(trx);

    expect(trx.insert).toHaveBeenCalledTimes(16);

    expect(fsSpy).toHaveBeenCalledTimes(1);

    expect(bcryptSpy).toHaveBeenCalledTimes(1);

    bcryptSpy.mockRestore();
    fsSpy.mockRestore();
  });

  test("Create applications table", () => {
    const mockKnexTable = () => {
      const knex = {};
      knex.increments = jest.fn();
      knex.string = jest.fn().mockReturnValue(knex);
      knex.notNullable = jest.fn().mockReturnValue(knex);
      knex.unique = jest.fn();
      knex.boolean = jest.fn().mockReturnValue(knex);
      knex.defaultTo = jest.fn();
      knex.timestamps = jest.fn();
      return knex;
    };

    const knexTable = mockKnexTable();
    const knex = mockKnexCreationSchema();
    const tableCreationHelper = tableCreation(knex, "secret");

    tableCreationHelper.createApplicationsTable(knexTable);

    expect(knexTable.increments).toHaveBeenCalledWith("id");
    expect(knexTable.string).toHaveBeenCalledWith("identifier", 100);
    expect(knexTable.timestamps).toHaveBeenCalledWith(true, true);
    expect(knexTable.boolean).toHaveBeenCalledWith("deleted");
  });

  test("Create applications resource table", () => {
    const mockKnexTable = () => {
      const knex = {};
      knex.increments = jest.fn();
      knex.string = jest.fn().mockReturnValue(knex);
      knex.integer = jest.fn().mockReturnValue(knex);
      knex.unsigned = jest.fn().mockReturnValue(knex);
      knex.notNullable = jest.fn().mockReturnValue(knex);
      knex.unique = jest.fn();
      knex.foreign = jest.fn().mockReturnValue(knex);
      knex.references = jest.fn().mockReturnValue(knex);
      knex.boolean = jest.fn().mockReturnValue(knex);
      knex.defaultTo = jest.fn();
      knex.timestamps = jest.fn();
      return knex;
    };

    const knexTable = mockKnexTable();
    const knex = mockKnexCreationSchema();
    const tableCreationHelper = tableCreation(knex, "secret");

    tableCreationHelper.createApplicationResourceTable(knexTable);

    expect(knexTable.increments).toHaveBeenCalledWith("id");
    expect(knexTable.string).toHaveBeenCalledWith("resourceIdentifier", 100);
    expect(knexTable.integer).toHaveBeenCalledWith("applications_id");
    expect(knexTable.foreign).toHaveBeenCalledWith("applications_id");
    expect(knexTable.references).toHaveBeenCalledWith("OAUTH2_Applications.id");
    expect(knexTable.timestamps).toHaveBeenCalledWith(true, true);
    expect(knexTable.boolean).toHaveBeenCalledWith("deleted");
    expect(knexTable.unique).toHaveBeenCalledWith(["resourceIdentifier", "id"]);
  });

  test("Create subjects table", () => {
    const mockKnexTable = () => {
      const knex = {};
      knex.increments = jest.fn();
      knex.string = jest.fn().mockReturnValue(knex);
      knex.integer = jest.fn().mockReturnValue(knex);
      knex.unsigned = jest.fn().mockReturnValue(knex);
      knex.notNullable = jest.fn().mockReturnValue(knex);
      knex.unique = jest.fn();
      knex.foreign = jest.fn().mockReturnValue(knex);
      knex.references = jest.fn().mockReturnValue(knex);
      knex.boolean = jest.fn().mockReturnValue(knex);
      knex.defaultTo = jest.fn();
      knex.timestamps = jest.fn();
      return knex;
    };

    const knexTable = mockKnexTable();
    const knex = mockKnexCreationSchema();
    const tableCreationHelper = tableCreation(knex, "secret");

    tableCreationHelper.createSubjectsTable(knexTable);

    expect(knexTable.increments).toHaveBeenCalledWith("id");
    expect(knexTable.string).toHaveBeenCalledWith("name", 45);
    expect(knexTable.timestamps).toHaveBeenCalledWith(true, true);
    expect(knexTable.boolean).toHaveBeenCalledWith("deleted");
  });

  test("Create users table", () => {
    const mockKnexTable = () => {
      const knex = {};
      knex.increments = jest.fn();
      knex.string = jest.fn().mockReturnValue(knex);
      knex.integer = jest.fn().mockReturnValue(knex);
      knex.unsigned = jest.fn().mockReturnValue(knex);
      knex.notNullable = jest.fn().mockReturnValue(knex);
      knex.unique = jest.fn();
      knex.foreign = jest.fn().mockReturnValue(knex);
      knex.references = jest.fn().mockReturnValue(knex);
      knex.boolean = jest.fn().mockReturnValue(knex);
      knex.defaultTo = jest.fn();
      knex.timestamps = jest.fn();
      return knex;
    };

    const knexTable = mockKnexTable();
    const knex = mockKnexCreationSchema();
    const tableCreationHelper = tableCreation(knex, "secret");

    tableCreationHelper.createUserTable(knexTable);

    expect(knexTable.increments).toHaveBeenCalledWith("id");
    expect(knexTable.timestamps).toHaveBeenCalledWith(true, true);
    expect(knexTable.boolean).toHaveBeenCalledWith("deleted");

    expect(knexTable.string).toHaveBeenCalledWith("username", 45);
    expect(knexTable.string).toHaveBeenCalledWith("password", 75);

    expect(knexTable.foreign).toHaveBeenCalledWith("subject_id");
    expect(knexTable.references).toHaveBeenCalledWith("OAUTH2_Subjects.id");
  });

  test("Create clients table", () => {
    const mockKnexTable = () => {
      const knex = {};
      knex.increments = jest.fn();
      knex.string = jest.fn().mockReturnValue(knex);
      knex.integer = jest.fn().mockReturnValue(knex);
      knex.unsigned = jest.fn().mockReturnValue(knex);
      knex.notNullable = jest.fn().mockReturnValue(knex);
      knex.unique = jest.fn().mockReturnValue(knex);
      knex.foreign = jest.fn().mockReturnValue(knex);
      knex.references = jest.fn().mockReturnValue(knex);
      knex.boolean = jest.fn().mockReturnValue(knex);
      knex.defaultTo = jest.fn();
      knex.timestamps = jest.fn();
      return knex;
    };

    const knexTable = mockKnexTable();
    const knex = mockKnexCreationSchema();
    const tableCreationHelper = tableCreation(knex, "secret");

    tableCreationHelper.createClientsTable(knexTable);

    expect(knexTable.increments).toHaveBeenCalledWith("id");
    expect(knexTable.timestamps).toHaveBeenCalledWith(true, true);
    expect(knexTable.boolean).toHaveBeenCalledWith("deleted");

    expect(knexTable.string).toHaveBeenCalledWith("identifier", 100);
    expect(knexTable.string).toHaveBeenCalledWith("access_token", 255);
    expect(knexTable.string).toHaveBeenCalledWith("client_id", 60);

    expect(knexTable.foreign).toHaveBeenCalledWith("subject_id");
    expect(knexTable.references).toHaveBeenCalledWith("OAUTH2_Subjects.id");
  });

  test("Create permissions table", () => {
    const mockKnexTable = () => {
      const knex = {};
      knex.increments = jest.fn();
      knex.string = jest.fn().mockReturnValue(knex);
      knex.integer = jest.fn().mockReturnValue(knex);
      knex.unsigned = jest.fn().mockReturnValue(knex);
      knex.notNullable = jest.fn().mockReturnValue(knex);
      knex.unique = jest.fn();
      knex.foreign = jest.fn().mockReturnValue(knex);
      knex.references = jest.fn().mockReturnValue(knex);
      knex.boolean = jest.fn().mockReturnValue(knex);
      knex.defaultTo = jest.fn();
      knex.timestamps = jest.fn();
      return knex;
    };

    const knexTable = mockKnexTable();
    const knex = mockKnexCreationSchema();
    const tableCreationHelper = tableCreation(knex, "secret");

    tableCreationHelper.createPermissionsTable(knexTable);

    expect(knexTable.increments).toHaveBeenCalledWith("id");
    expect(knexTable.timestamps).toHaveBeenCalledWith(true, true);
    expect(knexTable.boolean).toHaveBeenCalledWith("deleted");

    expect(knexTable.string).toHaveBeenCalledWith("allowed", 75);

    expect(knexTable.foreign).toHaveBeenCalledWith("applicationResource_id");
    expect(knexTable.references).toHaveBeenCalledWith(
      "OAUTH2_ApplicationResource.id"
    );
  });

  test("Create roles table", () => {
    const mockKnexTable = () => {
      const knex = {};
      knex.increments = jest.fn();
      knex.string = jest.fn().mockReturnValue(knex);
      knex.integer = jest.fn().mockReturnValue(knex);
      knex.unsigned = jest.fn().mockReturnValue(knex);
      knex.notNullable = jest.fn().mockReturnValue(knex);
      knex.unique = jest.fn();
      knex.foreign = jest.fn().mockReturnValue(knex);
      knex.references = jest.fn().mockReturnValue(knex);
      knex.boolean = jest.fn().mockReturnValue(knex);
      knex.defaultTo = jest.fn();
      knex.timestamps = jest.fn();
      return knex;
    };

    const knexTable = mockKnexTable();
    const knex = mockKnexCreationSchema();
    const tableCreationHelper = tableCreation(knex, "secret");

    tableCreationHelper.createRolesTable(knexTable);

    expect(knexTable.increments).toHaveBeenCalledWith("id");
    expect(knexTable.timestamps).toHaveBeenCalledWith(true, true);
    expect(knexTable.boolean).toHaveBeenCalledWith("deleted");

    expect(knexTable.string).toHaveBeenCalledWith("identifier", 100);
  });

  test("Create subjects roles table", () => {
    const mockKnexTable = () => {
      const knex = {};
      knex.increments = jest.fn();
      knex.string = jest.fn().mockReturnValue(knex);
      knex.integer = jest.fn().mockReturnValue(knex);
      knex.unsigned = jest.fn().mockReturnValue(knex);
      knex.notNullable = jest.fn().mockReturnValue(knex);
      knex.unique = jest.fn();
      knex.foreign = jest.fn().mockReturnValue(knex);
      knex.references = jest.fn().mockReturnValue(knex);
      knex.boolean = jest.fn().mockReturnValue(knex);
      knex.defaultTo = jest.fn();
      knex.timestamps = jest.fn();
      return knex;
    };

    const knexTable = mockKnexTable();
    const knex = mockKnexCreationSchema();
    const tableCreationHelper = tableCreation(knex, "secret");

    tableCreationHelper.createSubjectRolesTable(knexTable);

    expect(knexTable.increments).toHaveBeenCalledWith("id");

    expect(knexTable.unique).toHaveBeenCalledWith(["subject_id", "roles_id"]);

    expect(knexTable.foreign).toHaveBeenCalledWith("roles_id");
    expect(knexTable.references).toHaveBeenCalledWith("OAUTH2_Roles.id");

    expect(knexTable.foreign).toHaveBeenCalledWith("subject_id");
    expect(knexTable.references).toHaveBeenCalledWith("OAUTH2_Subjects.id");
  });

  test("Create role Permission table", () => {
    const mockKnexTable = () => {
      const knex = {};
      knex.increments = jest.fn();
      knex.string = jest.fn().mockReturnValue(knex);
      knex.integer = jest.fn().mockReturnValue(knex);
      knex.unsigned = jest.fn().mockReturnValue(knex);
      knex.notNullable = jest.fn().mockReturnValue(knex);
      knex.unique = jest.fn();
      knex.foreign = jest.fn().mockReturnValue(knex);
      knex.references = jest.fn().mockReturnValue(knex);
      knex.boolean = jest.fn().mockReturnValue(knex);
      knex.defaultTo = jest.fn();
      knex.timestamps = jest.fn();
      return knex;
    };

    const knexTable = mockKnexTable();
    const knex = mockKnexCreationSchema();
    const tableCreationHelper = tableCreation(knex, "secret");

    tableCreationHelper.createRolePermissionTable(knexTable);

    expect(knexTable.increments).toHaveBeenCalledWith("id");

    expect(knexTable.unique).toHaveBeenCalledWith([
      "permissions_id",
      "roles_id",
    ]);

    expect(knexTable.foreign).toHaveBeenCalledWith("permissions_id");
    expect(knexTable.references).toHaveBeenCalledWith("OAUTH2_Permissions.id");

    expect(knexTable.foreign).toHaveBeenCalledWith("roles_id");
    expect(knexTable.references).toHaveBeenCalledWith("OAUTH2_Roles.id");
  });

  test("Create tables works", async () => {
    const knex = mockKnexCreationSchema();
    const tableCreationHelper = tableCreation(knex, "secret");

    const dropTablesSpy = jest
      .spyOn(tableCreationHelper, "dropTables")
      .mockImplementation(() => {});

    await expect(tableCreationHelper.createTables()).rejects.toThrow();

    await tableCreationHelper.createTables();

    expect(knex.schema.createTable).toHaveBeenCalledTimes(10);

    dropTablesSpy.mockRestore();
  });

  test("Audit table works", async () => {
    const knex = mockedKnexSchema();
    const tableCreationHelper = tableCreation(knex, "secret");

    const hasTablesSpy = jest
      .spyOn(tableCreationHelper, "dataBaseHasTables")
      .mockImplementation(() => {
        return 1;
      });

    const createTablesSpy = jest
      .spyOn(tableCreationHelper, "createTables")
      .mockImplementation(() => {});

    await tableCreationHelper.auditDataBase();

    expect(createTablesSpy).toHaveBeenCalled();

    hasTablesSpy.mockRestore();
    createTablesSpy.mockRestore();
  });

  test("Audit table no false count and no inconsistencies", async () => {
    const knex = mockedKnexSchema();
    const tableCreationHelper = tableCreation(knex, "secret");

    const hasTablesSpy = jest
      .spyOn(tableCreationHelper, "dataBaseHasTables")
      .mockImplementation(() => {
        return 0;
      });

    const createTablesSpy = jest
      .spyOn(tableCreationHelper, "createTables")
      .mockImplementation(() => {});

    const auditTableColumnSpy = jest
      .spyOn(tableCreationHelper, "auditTableColumn")
      .mockImplementation(() => {
        return [[], null];
      });

    await tableCreationHelper.auditDataBase();

    expect(createTablesSpy).toHaveBeenCalledTimes(0);
    expect(auditTableColumnSpy).toHaveBeenCalledTimes(9);

    hasTablesSpy.mockRestore();
    createTablesSpy.mockRestore();
    auditTableColumnSpy.mockRestore();
  });

  test("Audit table no false count and inconsistencies", async () => {
    const knex = mockedKnexSchema();
    const tableCreationHelper = tableCreation(knex, "secret");

    const hasTablesSpy = jest
      .spyOn(tableCreationHelper, "dataBaseHasTables")
      .mockImplementation(() => {
        return 0;
      });

    const createTablesSpy = jest
      .spyOn(tableCreationHelper, "createTables")
      .mockImplementation(() => {});

    const auditTableColumnSpy = jest
      .spyOn(tableCreationHelper, "auditTableColumn")
      .mockImplementation(() => {
        return [["i1", "i2"], null];
      });

    await tableCreationHelper.auditDataBase();

    expect(createTablesSpy).toHaveBeenCalledTimes(1);
    expect(auditTableColumnSpy).toHaveBeenCalledTimes(9);

    hasTablesSpy.mockRestore();
    createTablesSpy.mockRestore();
    auditTableColumnSpy.mockRestore();
  });

  test("Audit table no false count and an error", async () => {
    const knex = mockedKnexSchema();
    const tableCreationHelper = tableCreation(knex, "secret");

    const hasTablesSpy = jest
      .spyOn(tableCreationHelper, "dataBaseHasTables")
      .mockImplementation(() => {
        return 0;
      });

    const createTablesSpy = jest
      .spyOn(tableCreationHelper, "createTables")
      .mockImplementation(() => {});

    const auditTableColumnSpy = jest
      .spyOn(tableCreationHelper, "auditTableColumn")
      .mockImplementation(() => {
        return [null, "some error"];
      });

    await expect(tableCreationHelper.auditDataBase()).rejects.toThrow();

    expect(createTablesSpy).toHaveBeenCalledTimes(0);

    hasTablesSpy.mockRestore();
    createTablesSpy.mockRestore();
    auditTableColumnSpy.mockRestore();
  });

  test("Audit table column with error", async () => {
    const knex = mockedNormalErrorKnex();
    const tableCreationHelper = tableCreation(knex, "secret");

    await expect(
      tableCreationHelper.auditTableColumn("table", {
        id: {
          type: "strings",
        },
        otherId: {
          type: "string",
        },
      })
    ).resolves.toStrictEqual([null, undefined]);
  });

  test("Audit table column with inconsistencies", async () => {
    const knex = mockedNormalKnex();
    const tableCreationHelper = tableCreation(knex, "secret");

    const result = await tableCreationHelper.auditTableColumn("table", {
      id: {
        type: "strings",
      },
      otherId: {
        type: "string",
      },
    });

    expect(result[0].length).toBe(2);
  });

  test("Audit table column no inconsistency", async () => {
    const knex = mockedNormalKnex();
    const tableCreationHelper = tableCreation(knex, "secret");

    const result = await tableCreationHelper.auditTableColumn("table", {
      id: {
        type: "string",
      },
    });

    expect(result).toStrictEqual([[], null]);
  });
});
