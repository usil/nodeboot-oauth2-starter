const fs = require("fs").promises;
const path = require("path");
const randomstring = require("randomstring");
const bcrypt = require("bcrypt");
const crypto = require("crypto");

const tableCreation = (
  knex,
  cryptoSecret,
  extraResources = [],
  mainApplicationName = "OAUTH2_main_application",
  clientIdSuffix = "::client.app"
) => {
  const tableCreationObj = {};

  tableCreationObj.tablesExpected = {
    OAUTH2_Subjects: {
      id: {
        defaultValue: null,
        type: "int",
        maxLength: null,
        nullable: false,
      },
      name: {
        defaultValue: null,
        type: "varchar",
        maxLength: 45,
        nullable: false,
      },
    },
    OAUTH2_Users: {
      id: {
        defaultValue: null,
        type: "int",
        maxLength: null,
        nullable: false,
      },
      subject_id: {
        defaultValue: null,
        type: "int",
        maxLength: null,
        nullable: false,
      },
      username: {
        defaultValue: null,
        type: "varchar",
        maxLength: 45,
        nullable: false,
      },
      password: {
        defaultValue: null,
        type: "varchar",
        maxLength: 75,
        nullable: false,
      },
    },
    OAUTH2_Clients: {
      id: {
        defaultValue: null,
        type: "int",
        maxLength: null,
        nullable: false,
      },
      subject_id: {
        defaultValue: null,
        type: "int",
        maxLength: null,
        nullable: false,
      },
      identifier: {
        defaultValue: null,
        type: "varchar",
        maxLength: 100,
        nullable: false,
      },
      access_token: {
        defaultValue: null,
        type: "varchar",
        maxLength: 255,
        nullable: true,
      },
    },
    OAUTH2_SubjectRole: {
      id: {
        defaultValue: null,
        type: "int",
        maxLength: null,
        nullable: false,
      },
      subject_id: {
        defaultValue: null,
        type: "int",
        maxLength: null,
        nullable: false,
      },
      roles_id: {
        defaultValue: null,
        type: "int",
        maxLength: null,
        nullable: false,
      },
    },
    OAUTH2_Roles: {
      id: {
        defaultValue: null,
        type: "int",
        maxLength: null,
        nullable: false,
      },
      identifier: {
        defaultValue: null,
        type: "varchar",
        maxLength: 100,
        nullable: false,
      },
    },
    OAUTH2_Applications: {
      id: {
        defaultValue: null,
        type: "int",
        maxLength: null,
        nullable: false,
      },
      identifier: {
        defaultValue: null,
        type: "varchar",
        maxLength: 100,
        nullable: false,
      },
    },
    OAUTH2_RolePermission: {
      id: {
        defaultValue: null,
        type: "int",
        maxLength: null,
        nullable: false,
      },
      permissions_id: {
        defaultValue: null,
        type: "int",
        maxLength: null,
        nullable: false,
      },
      roles_id: {
        defaultValue: null,
        type: "int",
        maxLength: null,
        nullable: false,
      },
    },
    OAUTH2_Permissions: {
      id: {
        defaultValue: null,
        type: "int",
        maxLength: null,
        nullable: false,
      },
      applicationResource_id: {
        defaultValue: null,
        type: "int",
        maxLength: null,
        nullable: false,
      },
      allowed: {
        defaultValue: null,
        type: "varchar",
        maxLength: 75,
        nullable: false,
      },
    },
    OAUTH2_ApplicationResource: {
      id: {
        defaultValue: null,
        type: "int",
        maxLength: null,
        nullable: false,
      },
      resourceIdentifier: {
        defaultValue: null,
        type: "varchar",
        maxLength: 100,
        nullable: false,
      },
      applications_id: {
        defaultValue: null,
        type: "int",
        maxLength: null,
        nullable: false,
      },
    },
  };

  tableCreationObj.dataBaseHasTables = async () => {
    let falseCount = 0;

    for (const tableExpected in tableCreationObj.tablesExpected) {
      const result = await knex.schema.hasTable(tableExpected);
      if (result === false) {
        falseCount++;
        break;
      }
    }

    return falseCount;
  };

  tableCreationObj.auditTableColumn = async (tableName, columnsToMatch) => {
    try {
      const columns = await knex.table(tableName).columnInfo();
      const tableColumnInconsistencies = [];
      for (const column in columnsToMatch) {
        if (!columns[column]) {
          tableColumnInconsistencies.push(`Column ${column} does not exist`);
        } else {
          if (
            JSON.stringify(columns[column]) !==
            JSON.stringify(columnsToMatch[column])
          )
            tableColumnInconsistencies.push(
              `Column ${column} is not compatible`
            );
        }
      }

      return [tableColumnInconsistencies, null];
    } catch (error) {
      console.log(error);
      return [null, error.message];
    }
  };

  tableCreationObj.auditDataBase = async () => {
    try {
      const falseCount = await tableCreationObj.dataBaseHasTables();

      if (falseCount > 0) {
        console.log("Tables will be created from 0");
        await tableCreationObj.createTables();
      } else {
        let reCreate = false;
        for (const tableExpected in tableCreationObj.tablesExpected) {
          const [inconsistencies, error] =
            await tableCreationObj.auditTableColumn(
              tableExpected,
              tableCreationObj.tablesExpected[tableExpected]
            );

          if (error) {
            throw new Error(
              `An error ocurred while auditing table ${tableExpected}`
            );
          }

          if (inconsistencies.length > 0) {
            reCreate = true;
            console.log(`Table ${tableExpected} inconsistencies in columns:`);
            for (const inconsistency of inconsistencies) {
              console.log(inconsistency + "/n");
            }
            console.log("Tables will be created from 0");
          }
        }
        if (reCreate) {
          await tableCreationObj.createTables();
        }
      }
    } catch (error) {
      console.log(error);
      throw new Error(error.message);
    }
  };

  tableCreationObj.trxCreate = async (trx) => {
    try {
      const applicationId = await trx.table("OAUTH2_Applications").insert({
        identifier: mainApplicationName,
      });

      const applicationResourceIds = [];

      const extraResourceToInsert = extraResources.map((resource) => {
        return {
          applications_id: applicationId[0],
          resourceIdentifier: resource,
        };
      });

      const resourcesToInsert = [
        {
          applications_id: applicationId[0],
          resourceIdentifier: "OAUTH2_global",
        },
        {
          applications_id: applicationId[0],
          resourceIdentifier: "OAUTH2_user",
        },
        {
          applications_id: applicationId[0],
          resourceIdentifier: "OAUTH2_client",
        },
        {
          applications_id: applicationId[0],
          resourceIdentifier: "OAUTH2_application",
        },
        {
          applications_id: applicationId[0],
          resourceIdentifier: "OAUTH2_role",
        },
        {
          applications_id: applicationId[0],
          resourceIdentifier: "OAUTH2_Permission",
        },
      ];

      for (const resource of [...resourcesToInsert, ...extraResourceToInsert]) {
        const applicationResourceId = await trx
          .table("OAUTH2_ApplicationResource")
          .insert(resource);
        applicationResourceIds.push(applicationResourceId[0]);
      }

      const oauthInsert = [];

      for (let index = 0; index < applicationResourceIds.length; index++) {
        if (index === 0) {
          oauthInsert.push({
            applicationResource_id: applicationResourceIds[index],
            allowed: "*",
          });
        } else {
          oauthInsert.push(
            {
              applicationResource_id: applicationResourceIds[index],
              allowed: "*",
            },
            {
              applicationResource_id: applicationResourceIds[index],
              allowed: "create",
            },
            {
              applicationResource_id: applicationResourceIds[index],
              allowed: "update",
            },
            {
              applicationResource_id: applicationResourceIds[index],
              allowed: "delete",
            },
            {
              applicationResource_id: applicationResourceIds[index],
              allowed: "select",
            }
          );
        }
      }

      const permissionId = await trx
        .table("OAUTH2_Permissions")
        .insert(oauthInsert);

      const roleId = await trx.table("OAUTH2_Roles").insert({
        identifier: "admin",
      });

      await trx.table("OAUTH2_RolePermission").insert([
        {
          permissions_id: permissionId[0],
          roles_id: roleId[0],
        },
      ]);

      const subjectId = await trx.table("OAUTH2_Subjects").insert({
        name: "Admin",
        description: "The admin of the application",
      });

      await trx.table("OAUTH2_SubjectRole").insert({
        subject_id: subjectId[0],
        roles_id: roleId[0],
      });

      const password = randomstring.generate();
      const clientSecret = randomstring.generate();
      let clientStringId = randomstring.generate(20);

      clientStringId += clientIdSuffix;

      const encryptedPassword = await bcrypt.hash(password, 10);

      const algorithm = "aes-256-ctr";
      const initVector = crypto.randomBytes(16);
      const key = crypto.scryptSync(cryptoSecret, "salt", 32);
      const cipher = crypto.createCipheriv(algorithm, key, initVector);
      let encryptedData = cipher.update(clientSecret, "utf-8", "hex");
      encryptedData += cipher.final("hex");

      await trx.table("OAUTH2_Users").insert({
        username: "admin",
        password: encryptedPassword,
        subject_id: subjectId[0],
      });

      const hexedInitVector = initVector.toString("hex");

      await trx.table("OAUTH2_Clients").insert({
        identifier: "admin",
        client_id: clientStringId,
        client_secret: hexedInitVector + "|.|" + encryptedData,
        subject_id: subjectId[0],
      });

      await fs.writeFile(
        path.join(process.cwd(), "/credentials.txt"),
        `Credentials for the admin user in it.\n
          Username: admin \n   
          Password: ${password}
          Credentials for the admin client.\n
          client_id: ${clientStringId} \n
          client_secret: ${clientSecret}`
      );

      console.log("Created file credentials.txt in the cwd");
    } catch (error) {
      console.log(error);
      throw new Error(error.message);
    }
  };

  tableCreationObj.createApplicationsTable = (table) => {
    table.increments("id");
    table.string("identifier", 100).notNullable().unique();
    table.boolean("deleted").defaultTo(false);
    table.timestamps(true, true);
  };

  tableCreationObj.createApplicationResourceTable = (table) => {
    table.increments("id");
    table.string("resourceIdentifier", 100).notNullable();
    table.integer("applications_id").unsigned().notNullable();
    table.foreign("applications_id").references("OAUTH2_Applications.id");
    table.boolean("deleted").defaultTo(false);
    table.unique(["resourceIdentifier", "id"]);
    table.timestamps(true, true);
  };

  tableCreationObj.createSubjectsTable = (table) => {
    table.increments("id");
    table.string("name", 45).notNullable();
    table.string("description", 255).notNullable();
    table.boolean("deleted").defaultTo(false);
    table.timestamps(true, true);
  };

  tableCreationObj.createUserTable = (table) => {
    table.increments("id");
    table.integer("subject_id").unsigned().notNullable();
    table.foreign("subject_id").references("OAUTH2_Subjects.id");
    table.string("username", 45).notNullable().unique();
    table.string("password", 75).notNullable();
    table.boolean("deleted").defaultTo(false);
    table.timestamps(true, true);
  };

  tableCreationObj.createClientsTable = (table) => {
    table.increments("id");
    table.string("client_id", 60).unique().notNullable();
    table.integer("subject_id").unsigned().notNullable();
    table.foreign("subject_id").references("OAUTH2_Subjects.id");
    table.string("client_secret", 175).notNullable();
    table.string("identifier", 100).notNullable().unique();
    table.string("access_token", 255);
    table.boolean("revoked").defaultTo(false);
    table.boolean("deleted").defaultTo(false);
    table.timestamps(true, true);
  };

  tableCreationObj.createPermissionsTable = (table) => {
    table.increments("id");
    table.string("allowed", 75).notNullable();
    table.integer("applicationResource_id").unsigned().notNullable();
    table
      .foreign("applicationResource_id")
      .references("OAUTH2_ApplicationResource.id");
    table.boolean("deleted").defaultTo(false);
    table.timestamps(true, true);
  };

  tableCreationObj.createRolesTable = (table) => {
    table.increments("id");
    table.string("identifier", 100).notNullable().unique();
    table.boolean("deleted").defaultTo(false);
    table.timestamps(true, true);
  };

  tableCreationObj.createSubjectRolesTable = (table) => {
    table.increments("id");
    table.integer("subject_id").unsigned().notNullable();
    table.foreign("subject_id").references("OAUTH2_Subjects.id");
    table.integer("roles_id").unsigned().notNullable();
    table.foreign("roles_id").references("OAUTH2_Roles.id");
    table.unique(["subject_id", "roles_id"]);
  };

  tableCreationObj.createRolePermissionTable = (table) => {
    table.increments("id");
    table.integer("permissions_id").unsigned().notNullable();
    table.foreign("permissions_id").references("OAUTH2_Permissions.id");
    table.integer("roles_id").unsigned().notNullable();
    table.foreign("roles_id").references("OAUTH2_Roles.id");
    table.unique(["permissions_id", "roles_id"]);
  };

  tableCreationObj.createTables = async () => {
    try {
      await tableCreationObj.dropTables();

      await knex.schema.createTable(
        "OAUTH2_Applications",
        tableCreationObj.createApplicationsTable
      );

      await knex.schema.createTable(
        "OAUTH2_ApplicationResource",
        tableCreationObj.createApplicationResourceTable
      );

      await knex.schema.createTable(
        "OAUTH2_Subjects",
        tableCreationObj.createSubjectsTable
      );

      await knex.schema.createTable(
        "OAUTH2_Users",
        tableCreationObj.createUserTable
      );

      await knex.schema.createTable(
        "OAUTH2_Clients",
        tableCreationObj.createClientsTable
      );

      await knex.schema.createTable(
        "OAUTH2_Permissions",
        tableCreationObj.createPermissionsTable
      );

      await knex.schema.createTable(
        "OAUTH2_Roles",
        tableCreationObj.createRolesTable
      );

      await knex.schema.createTable(
        "OAUTH2_SubjectRole",
        tableCreationObj.createSubjectRolesTable
      );

      await knex.schema.createTable(
        "OAUTH2_RolePermission",
        tableCreationObj.createRolePermissionTable
      );

      await knex.transaction(tableCreationObj.trxCreate);
    } catch (error) {
      console.log(error);
      throw new Error(error.message);
    }
  };

  tableCreationObj.dropTables = async () => {
    try {
      const tablesToDropInOrder = [
        "OAUTH2_Users",
        "OAUTH2_Clients",
        "OAUTH2_SubjectRole",
        "OAUTH2_Subjects",
        "OAUTH2_RolePermission",
        "OAUTH2_Roles",
        "OAUTH2_Permissions",
        "OAUTH2_ApplicationResource",
        "OAUTH2_Applications",
      ];
      for (const tableName of tablesToDropInOrder) {
        await knex.schema.dropTableIfExists(tableName);
      }
    } catch (error) {
      throw new Error(error.message);
    }
  };

  return tableCreationObj;
};

module.exports = tableCreation;
