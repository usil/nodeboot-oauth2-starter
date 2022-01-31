const fs = require("fs").promises;
const path = require("path");
const randomstring = require("randomstring");
const bcrypt = require("bcrypt");

const tableCreation = (knex, jwtSecret, extraParts = []) => {
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
        nullable: false,
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
    OAUTH2_RoleOption: {
      id: {
        defaultValue: null,
        type: "int",
        maxLength: null,
        nullable: false,
      },
      options_id: {
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
    OAUTH2_Options: {
      id: {
        defaultValue: null,
        type: "int",
        maxLength: null,
        nullable: false,
      },
      applicationPart_id: {
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
    OAUTH2_ApplicationPart: {
      id: {
        defaultValue: null,
        type: "int",
        maxLength: null,
        nullable: false,
      },
      partIdentifier: {
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
      console.log("info", tableName);
      console.log(columns);
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
        identifier: "OAUTH2_master",
      });

      const applicationPartIds = [];

      const extraPartsToInsert = extraParts.map((part) => {
        return { applications_id: applicationId[0], partIdentifier: part };
      });

      const partsToInsert = [
        {
          applications_id: applicationId[0],
          partIdentifier: "OAUTH2_global",
        },
        {
          applications_id: applicationId[0],
          partIdentifier: "OAUTH2_user",
        },
        {
          applications_id: applicationId[0],
          partIdentifier: "OAUTH2_client",
        },
        {
          applications_id: applicationId[0],
          partIdentifier: "OAUTH2_application",
        },
        {
          applications_id: applicationId[0],
          partIdentifier: "OAUTH2_role",
        },
        {
          applications_id: applicationId[0],
          partIdentifier: "OAUTH2_option",
        },
      ];

      for (const part of [...partsToInsert, ...extraPartsToInsert]) {
        const applicationPartId = await trx
          .table("OAUTH2_ApplicationPart")
          .insert(part);
        applicationPartIds.push(applicationPartId[0]);
      }

      const oauthInsert = [];

      for (let index = 0; index < applicationPartIds.length; index++) {
        if (index === 0) {
          oauthInsert.push({
            applicationPart_id: applicationPartIds[index],
            allowed: "*",
          });
        } else {
          oauthInsert.push(
            {
              applicationPart_id: applicationPartIds[index],
              allowed: "*",
            },
            {
              applicationPart_id: applicationPartIds[index],
              allowed: "create",
            },
            {
              applicationPart_id: applicationPartIds[index],
              allowed: "update",
            },
            {
              applicationPart_id: applicationPartIds[index],
              allowed: "delete",
            },
            {
              applicationPart_id: applicationPartIds[index],
              allowed: "select",
            }
          );
        }
      }

      const optionId = await trx.table("OAUTH2_Options").insert(oauthInsert);

      const roleId = await trx.table("OAUTH2_Roles").insert({
        identifier: "admin",
      });

      await trx.table("OAUTH2_RoleOption").insert([
        {
          options_id: optionId[0],
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

      const encryptedPassword = await bcrypt.hash(password, 10);
      const encryptedSecret = await bcrypt.hash(clientSecret, 10);

      await trx.table("OAUTH2_Users").insert({
        username: "admin",
        password: encryptedPassword,
        subject_id: subjectId[0],
      });

      const clientId = await trx.table("OAUTH2_Clients").insert({
        identifier: "admin",
        client_secret: encryptedSecret,
        subject_id: subjectId[0],
      });

      await fs.writeFile(
        path.join(process.cwd(), "/credentials.txt"),
        `Credentials for the admin user in it.\n
          Username: admin \n   
          Password: ${password}
          Credentials for the admin client.\n
          client_id: ${clientId} \n
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

  tableCreationObj.createApplicationPartTable = (table) => {
    table.increments("id");
    table.string("partIdentifier", 100).notNullable();
    table.integer("applications_id").unsigned().notNullable();
    table.foreign("applications_id").references("OAUTH2_Applications.id");
    table.boolean("deleted").defaultTo(false);
    table.unique(["partIdentifier", "id"]);
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
    table.integer("subject_id").unsigned().notNullable();
    table.foreign("subject_id").references("OAUTH2_Subjects.id");
    table.string("client_secret", 75).notNullable();
    table.string("identifier", 100).notNullable().unique();
    table.string("access_token", 255);
    table.boolean("revoked").defaultTo(false);
    table.boolean("deleted").defaultTo(false);
    table.timestamps(true, true);
  };

  tableCreationObj.createOptionsTable = (table) => {
    table.increments("id");
    table.string("allowed", 75).notNullable();
    table.integer("applicationPart_id").unsigned().notNullable();
    table.foreign("applicationPart_id").references("OAUTH2_ApplicationPart.id");
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

  tableCreationObj.createRoleOptionTable = (table) => {
    table.increments("id");
    table.integer("options_id").unsigned().notNullable();
    table.foreign("options_id").references("OAUTH2_Options.id");
    table.integer("roles_id").unsigned().notNullable();
    table.foreign("roles_id").references("OAUTH2_Roles.id");
    table.unique(["options_id", "roles_id"]);
  };

  tableCreationObj.createTables = async () => {
    try {
      await tableCreationObj.dropTables();

      await knex.schema.createTable(
        "OAUTH2_Applications",
        tableCreationObj.createApplicationsTable
      );

      await knex.schema.createTable(
        "OAUTH2_ApplicationPart",
        tableCreationObj.createApplicationPartTable
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
        "OAUTH2_Options",
        tableCreationObj.createOptionsTable
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
        "OAUTH2_RoleOption",
        tableCreationObj.createRoleOptionTable
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
        "OAUTH2_RoleOption",
        "OAUTH2_Roles",
        "OAUTH2_Options",
        "OAUTH2_ApplicationPart",
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