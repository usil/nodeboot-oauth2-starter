const helpers = require("./general-helpers.js");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const generalHelpers = helpers();

const security = (knex, expressSecured) => {
  const securityObj = {};

  securityObj.getExpression = (path, method, params) => {
    let pathToSearch = path;

    pathToSearch = method + "||" + pathToSearch;

    const paramsKeys = Object.keys(params);

    if (paramsKeys.length > 0) {
      for (const param of paramsKeys) {
        pathToSearch = pathToSearch.replace(params[param], `:${param}`);
      }
    }

    return expressSecured.get(pathToSearch);
  };

  securityObj.realGuard = async (req, res, next) => {
    try {
      let securityString = `${req.baseUrl ? req.baseUrl : ""}${req.path}`;

      if (
        securityString.slice(securityString.length - 1) === "/" &&
        securityString !== "/"
      ) {
        securityString = securityString.slice(0, -1);
      }

      const exp = securityObj.getExpression(
        securityString,
        req.method,
        req.params
      );

      if (exp === undefined) {
        console.log(
          `${securityString} parsed as security string. With method ${
            req.method
          } and params ${JSON.stringify(req.params)}`
        );
        return res.status(404).json({
          code: 404001,
          message: "This endpoint does not have a valid security expression",
        });
      }

      if (exp === ":") return next();

      const parsedExp = exp.split(":");

      if (parsedExp.length !== 2) {
        return res
          .status(403)
          .json({ code: 403206, message: "Bad guard input" });
      }

      const user = res.locals.user;

      if (!user) {
        return res.status(403).json({
          code: 403102,
          message: "Subject not authorized; user could not be parsed",
        });
      }

      const subjectTableToSearch =
        user.subjectType === "user" ? "OAUTH2_Users" : "OAUTH2_Clients";

      const userNameOrIdentifier =
        user.subjectType === "user" ? "username" : "identifier";

      if (subjectTableToSearch === "OAUTH2_Clients") {
        const basicUser = (
          await knex
            .table(subjectTableToSearch)
            .select()
            .where("client_id", user.id)
        )[0];

        if (basicUser.revoked === true) {
          return res.status(403).json({
            code: 403104,
            message: "Client authorization credentials have been revoked",
          });
        }
        if (basicUser.access_token !== null) {
          const correctToken = await bcrypt.compare(
            res.locals.access_token,
            basicUser.access_token
          );
          if (!correctToken) {
            return res.status(403).json({
              code: 403105,
              message: "Your token has has expired or has been revoked",
            });
          }
        }
      }

      const userAllowed = await knex
        .table(subjectTableToSearch)
        .select(
          "OAUTH2_Permissions.allowed as allowedTerm",
          "OAUTH2_ApplicationResource.resourceIdentifier as applicationResource"
        )
        .join(
          "OAUTH2_SubjectRole",
          `${subjectTableToSearch}.subject_id`,
          "OAUTH2_SubjectRole.subject_id"
        )
        .join("OAUTH2_Roles", `OAUTH2_Roles.id`, "OAUTH2_SubjectRole.roles_id")
        .join(
          "OAUTH2_RolePermission",
          "OAUTH2_RolePermission.roles_id",
          "OAUTH2_Roles.id"
        )
        .join(
          "OAUTH2_Permissions",
          "OAUTH2_Permissions.id",
          "OAUTH2_RolePermission.permissions_id"
        )
        .join(
          "OAUTH2_ApplicationResource",
          "OAUTH2_ApplicationResource.id",
          "OAUTH2_Permissions.applicationResource_id"
        )
        .where(
          `${subjectTableToSearch}.${userNameOrIdentifier}`,
          user[userNameOrIdentifier]
        )
        .where("OAUTH2_Roles.deleted", false)
        .andWhere(`${subjectTableToSearch}.deleted`, false);

      const patterns = generalHelpers.joinSearch(
        userAllowed,
        "applicationResource",
        "allowedTerm"
      );

      const patternIndex = patterns.findIndex(
        (p) =>
          (p.applicationResource === "OAUTH2_global" &&
            p.allowedTerm.indexOf("*") !== -1) ||
          (p.applicationResource === parsedExp[0] &&
            p.allowedTerm.indexOf("*") !== -1) ||
          (p.applicationResource === parsedExp[0] &&
            p.allowedTerm.indexOf(parsedExp[1]) !== -1)
      );

      if (patternIndex !== -1) return next();

      return res.status(403).json({
        code: 403103,
        message: "Subject not authorized; incorrect permissions",
      });
    } catch (error) {
      console.log("this.error", error);
      return res.status(500).json({ code: 500001, message: error.message });
    }
  };

  securityObj.decodeToken = (jwtSecret) => {
    const decodeObj = {};
    decodeObj.decode = (req, res, next) => {
      if (
        (req.headers &&
          req.headers.authorization &&
          req.headers.authorization.split(" ")[0] === "BEARER") ||
        req.query["access_token"]
      ) {
        const authToken =
          req.query["access_token"] || req.headers.authorization.split(" ")[1];
        jwt.verify(authToken, jwtSecret, (err, decode) => {
          if (err) {
            res.locals.user = undefined;
            return res.status(401).json({
              code: 400001,
              message: "Incorrect token",
            });
          } else {
            res.locals.access_token = authToken;
            res.locals.user = decode.data;
          }
          next();
        });
      } else {
        res.locals.user = undefined;
        next();
      }
    };
    return decodeObj;
  };

  securityObj.guard = () => {
    return securityObj.realGuard;
  };

  return securityObj;
};

module.exports = security;
